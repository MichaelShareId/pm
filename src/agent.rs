//! Minimal ssh-agent client, just enough to keep the session cache's encryption key out of
//! any file: `pm` parks a throwaway ed25519 key in the agent and derives the session key
//! from its (deterministic) signature. Protocol: draft-miller-ssh-agent.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;

const KEY_TYPE: &[u8] = b"ssh-ed25519";
const MAX_REPLY: usize = 256 * 1024;

/// The agent to use, from `SSH_AUTH_SOCK`. `None` inside an SSH login: there the socket is
/// usually a forwarded agent on another machine, which must not hold session keys.
pub fn socket_from_env() -> Option<PathBuf> {
    if std::env::var_os("SSH_CONNECTION").is_some() {
        return None;
    }
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    pub fn connect(socket: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket)
            .with_context(|| format!("connect to ssh-agent {}", socket.display()))?;
        // Never hang a pm command on a stuck agent.
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self { stream })
    }

    /// Add `key`; with `lifetime`, the agent itself deletes it after that many seconds.
    pub fn add(&mut self, key: &SigningKey, comment: &str, lifetime: Option<u32>) -> Result<()> {
        let public = key.verifying_key().to_bytes();
        // Preallocated so the buffer holding the private key never reallocates unwiped.
        let mut msg = Zeroizing::new(Vec::with_capacity(512));
        msg.push(match lifetime {
            Some(_) => SSH2_AGENTC_ADD_ID_CONSTRAINED,
            None => SSH2_AGENTC_ADD_IDENTITY,
        });
        put_string(&mut msg, KEY_TYPE);
        put_string(&mut msg, &public);
        // OpenSSH's ed25519 private key encoding: seed || public key.
        let mut private = Zeroizing::new([0u8; 64]);
        private[..32].copy_from_slice(key.as_bytes());
        private[32..].copy_from_slice(&public);
        put_string(&mut msg, private.as_slice());
        put_string(&mut msg, comment.as_bytes());
        if let Some(secs) = lifetime {
            msg.push(SSH_AGENT_CONSTRAIN_LIFETIME);
            msg.extend_from_slice(&secs.to_be_bytes());
        }
        self.expect_success(&msg, "add key")
    }

    /// Ask the agent to sign `data` with `public`'s key, and check the signature: whatever
    /// answers on the socket can't make pm accept a forged one.
    pub fn sign(&mut self, public: &VerifyingKey, data: &[u8]) -> Result<Signature> {
        let mut msg = vec![SSH2_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, &key_blob(public));
        put_string(&mut msg, data);
        msg.extend_from_slice(&0u32.to_be_bytes());
        let reply = self.request(&msg)?;
        if reply.first() != Some(&SSH2_AGENT_SIGN_RESPONSE) {
            bail!("ssh-agent refused to sign (key expired or removed)");
        }
        let mut outer = Reader(&reply[1..]);
        let mut blob = Reader(outer.string()?);
        if blob.string()? != KEY_TYPE {
            bail!("ssh-agent returned a non-ed25519 signature");
        }
        let bytes: [u8; 64] = blob
            .string()?
            .try_into()
            .context("ssh-agent returned a malformed signature")?;
        let signature = Signature::from_bytes(&bytes);
        public
            .verify_strict(data, &signature)
            .context("ssh-agent returned an invalid signature")?;
        Ok(signature)
    }

    pub fn remove(&mut self, public: &VerifyingKey) -> Result<()> {
        let mut msg = vec![SSH2_AGENTC_REMOVE_IDENTITY];
        put_string(&mut msg, &key_blob(public));
        self.expect_success(&msg, "remove key")
    }

    fn expect_success(&mut self, msg: &[u8], what: &str) -> Result<()> {
        match self.request(msg)?.first() {
            Some(&SSH_AGENT_SUCCESS) => Ok(()),
            Some(&SSH_AGENT_FAILURE) => bail!("ssh-agent refused to {what}"),
            _ => bail!("unexpected ssh-agent reply to {what}"),
        }
    }

    fn request(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let len = u32::try_from(msg.len()).context("ssh-agent request too large")?;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(msg)?;
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .context("read ssh-agent reply")?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_REPLY {
            bail!("bad ssh-agent reply length {len}");
        }
        let mut reply = vec![0u8; len];
        self.stream
            .read_exact(&mut reply)
            .context("read ssh-agent reply")?;
        Ok(reply)
    }
}

fn key_blob(public: &VerifyingKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, KEY_TYPE);
    put_string(&mut blob, public.as_bytes());
    blob
}

fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Result<&'a [u8]> {
        let Some((len, rest)) = self.0.split_first_chunk::<4>() else {
            bail!("truncated ssh-agent reply");
        };
        let len = u32::from_be_bytes(*len) as usize;
        if rest.len() < len {
            bail!("truncated ssh-agent reply");
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// A private `ssh-agent -D` on its own socket, killed on drop.
    pub struct TestAgent {
        child: Child,
        pub socket: PathBuf,
        dir: PathBuf,
    }

    impl TestAgent {
        pub fn start(name: &str) -> Self {
            // Short path: Unix socket paths are limited to ~104 bytes on macOS.
            let dir = PathBuf::from(format!("/tmp/pm-agent-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("s");
            let child = Command::new("ssh-agent")
                .arg("-D")
                .arg("-a")
                .arg(&socket)
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("ssh-agent on PATH");
            for _ in 0..100 {
                if socket.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Self { child, socket, dir }
        }
    }

    impl Drop for TestAgent {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn add_sign_remove() {
        let agent = TestAgent::start("basic");
        let key = key(7);
        let public = key.verifying_key();
        let mut conn = Agent::connect(&agent.socket).unwrap();
        conn.add(&key, "pm test", None).unwrap();

        let a = conn.sign(&public, b"challenge").unwrap();
        let b = conn.sign(&public, b"challenge").unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes(), "ed25519 signatures must be deterministic");

        conn.remove(&public).unwrap();
        assert!(conn.sign(&public, b"challenge").is_err());
    }

    #[test]
    fn agent_enforces_lifetime() {
        let agent = TestAgent::start("lifetime");
        let key = key(8);
        let mut conn = Agent::connect(&agent.socket).unwrap();
        conn.add(&key, "pm test", Some(1)).unwrap();
        assert!(conn.sign(&key.verifying_key(), b"x").is_ok());
        std::thread::sleep(Duration::from_millis(2100));
        assert!(conn.sign(&key.verifying_key(), b"x").is_err());
    }

    /// Manual check against the user's own agent (e.g. macOS launchd's):
    /// `cargo test -- --ignored real_agent`. Adds a throwaway key for at most 5s.
    #[test]
    #[ignore]
    fn real_agent_roundtrip() {
        let socket = socket_from_env().expect("local SSH_AUTH_SOCK");
        let key = key(9);
        let public = key.verifying_key();
        let mut conn = Agent::connect(&socket).unwrap();
        conn.add(&key, "pm test (temporary)", Some(5)).unwrap();
        let signed = conn.sign(&public, b"x");
        conn.remove(&public).unwrap();
        signed.unwrap();
        assert!(conn.sign(&public, b"x").is_err());
    }
}
