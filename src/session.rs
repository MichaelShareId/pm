//! Unlocked-session cache. Preferred form (v3): the master key encrypted with a key derived
//! from an ssh-agent signature, made by a throwaway ed25519 key that lives only in the agent
//! (with the session's hard limit as its agent lifetime). The file alone is useless; once
//! the agent drops the key (lifetime, `pm lock`, `ssh-add -D`, logout) the session is gone.
//! Without a usable agent, falls back to the master key in plaintext (v2).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::agent::{self, Agent};
use crate::config::DataDir;
use crate::crypto::{decrypt, encrypt, master_key_from_hex, master_key_to_hex, MasterKey};

/// Default idle timeout of an unlocked session (3 minutes).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 180;
/// Default hard limit of an unlocked session from its Touch ID unlock (15 minutes).
pub const DEFAULT_SESSION_MAX_SECS: u64 = 900;

/// Delete the session, and its key from the agent so the file can't be unsealed anymore.
pub fn clear(data: &DataDir) -> Result<()> {
    let path = data.session_file();
    if !path.exists() {
        return Ok(());
    }
    if let Ok(raw) = fs::read_to_string(&path) {
        let raw = Zeroizing::new(raw);
        if let Some(Parsed {
            stored: Stored::Sealed(sealed),
            ..
        }) = parse(&raw)
        {
            sealed.forget();
        }
    }
    fs::remove_file(&path).with_context(|| format!("remove session {}", path.display()))?;
    Ok(())
}

/// How long an unlocked session lives.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Sliding idle timeout: each use extends expiry to `now + ttl`. `0` disables caching.
    pub ttl: u64,
    /// Hard limit from the Touch ID unlock that sliding can never pass. `0` = no limit.
    pub max: u64,
}

impl Policy {
    fn deadline(&self, unlocked_at: u64) -> u64 {
        if self.max == 0 {
            u64::MAX
        } else {
            unlocked_at.saturating_add(self.max)
        }
    }
}

/// An unlocked session: the master key plus when Touch ID last unlocked it.
pub struct Session {
    pub key: MasterKey,
    unlocked_at: u64,
    /// How the key is stored on disk; `None` = plaintext fallback.
    sealed: Option<Sealed>,
}

/// The master key sealed with an agent-held key (session file v3).
struct Sealed {
    socket: PathBuf,
    public: [u8; 32],
    challenge: [u8; 32],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Domain separation for what the agent signs.
const SIGN_CONTEXT: &[u8] = b"pm-session-v3\0";

impl Sealed {
    /// Park a fresh ed25519 key in the agent and seal `key` under its signature.
    fn create(socket: &Path, key: &MasterKey, unlocked_at: u64, policy: Policy) -> Result<Self> {
        if socket.to_str().is_none_or(|s| s.contains('\n')) {
            bail!("unsupported SSH_AUTH_SOCK path");
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(seed.as_mut());
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key();
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        // The agent deletes the key at the hard limit, whatever the session file says.
        let lifetime = (policy.max > 0).then(|| u32::try_from(policy.max).unwrap_or(u32::MAX));
        let mut agent = Agent::connect(socket)?;
        agent.add(&signing, "pm session (temporary)", lifetime)?;
        drop(signing);

        let mut sealed = Self {
            socket: socket.to_path_buf(),
            public: public.to_bytes(),
            challenge,
            nonce: Vec::new(),
            ciphertext: Vec::new(),
        };
        let kek = match agent.sign(&public, &sealed.signed_data()) {
            Ok(signature) => sealed.kek(&signature),
            Err(err) => {
                let _ = agent.remove(&public);
                return Err(err);
            }
        };
        let (nonce, ciphertext) = encrypt(&kek, &sealed.aad(unlocked_at), key.as_bytes())?;
        sealed.nonce = nonce;
        sealed.ciphertext = ciphertext;
        Ok(sealed)
    }

    fn open(&self, unlocked_at: u64) -> Result<MasterKey> {
        let public = VerifyingKey::from_bytes(&self.public).context("bad session public key")?;
        let signature = Agent::connect(&self.socket)?.sign(&public, &self.signed_data())?;
        let plaintext = decrypt(
            &self.kek(&signature),
            &self.aad(unlocked_at),
            &self.nonce,
            &self.ciphertext,
        )?;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .context("bad sealed master key length")?;
        Ok(MasterKey::from_bytes(bytes))
    }

    /// Best effort: remove the key from the agent.
    fn forget(&self) {
        if let (Ok(public), Ok(mut agent)) = (
            VerifyingKey::from_bytes(&self.public),
            Agent::connect(&self.socket),
        ) {
            let _ = agent.remove(&public);
        }
    }

    fn signed_data(&self) -> Vec<u8> {
        [SIGN_CONTEXT, &self.challenge].concat()
    }

    /// Ed25519 signatures are deterministic, so the same request yields the same key.
    fn kek(&self, signature: &Signature) -> MasterKey {
        let hk = Hkdf::<Sha256>::new(Some(&self.challenge), &signature.to_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(b"pm session key v3", okm.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        MasterKey::from_bytes(*okm)
    }

    fn aad(&self, unlocked_at: u64) -> Vec<u8> {
        [
            SIGN_CONTEXT,
            &unlocked_at.to_be_bytes(),
            &self.public,
            &self.challenge,
        ]
        .concat()
    }
}

pub fn load(data: &DataDir, policy: Policy) -> Result<Option<Session>> {
    let path = data.session_file();
    if !path.exists() {
        return Ok(None);
    }

    let raw = match fs::read_to_string(&path) {
        Ok(s) => Zeroizing::new(s),
        Err(_) => {
            let _ = clear(data);
            return Ok(None);
        }
    };

    // Older formats (v1 had no unlock time) are dropped: one extra Touch ID prompt.
    let Some(parsed) = parse(&raw) else {
        let _ = clear(data);
        return Ok(None);
    };

    let now = now_secs()?;
    if now >= parsed.expires || now >= policy.deadline(parsed.unlocked_at) {
        let _ = clear(data);
        return Ok(None);
    }

    let unlocked_at = parsed.unlocked_at;
    let session = match parsed.stored {
        Stored::Plain(hex) => master_key_from_hex(hex).map(|key| Session {
            key,
            unlocked_at,
            sealed: None,
        }),
        // Fails once the agent dropped the key (lifetime, `ssh-add -D`, logout): locked.
        Stored::Sealed(sealed) => sealed.open(unlocked_at).map(|key| Session {
            key,
            unlocked_at,
            sealed: Some(sealed),
        }),
    };
    match session {
        Ok(session) => Ok(Some(session)),
        Err(_) => {
            let _ = clear(data);
            Ok(None)
        }
    }
}

struct Parsed<'a> {
    expires: u64,
    unlocked_at: u64,
    stored: Stored<'a>,
}

enum Stored<'a> {
    /// v2: master key hex.
    Plain(&'a str),
    /// v3: sealed with an agent key.
    Sealed(Sealed),
}

/// v2: `v2\n<expires>\n<unlocked_at>\n<key hex>`
/// v3: `v3\n<expires>\n<unlocked_at>\n<agent socket>\n<public>\n<challenge>\n<nonce>\n<ciphertext>`
fn parse(raw: &str) -> Option<Parsed<'_>> {
    let mut lines = raw.lines();
    let version = lines.next()?;
    let expires = lines.next()?.parse().ok()?;
    let unlocked_at = lines.next()?.parse().ok()?;
    let stored = match version {
        "v2" => Stored::Plain(lines.next()?),
        "v3" => Stored::Sealed(Sealed {
            socket: PathBuf::from(lines.next()?),
            public: hex::decode(lines.next()?).ok()?.try_into().ok()?,
            challenge: hex::decode(lines.next()?).ok()?.try_into().ok()?,
            nonce: hex::decode(lines.next()?).ok()?,
            ciphertext: hex::decode(lines.next()?).ok()?,
        }),
        _ => return None,
    };
    Some(Parsed {
        expires,
        unlocked_at,
        stored,
    })
}

/// Start a new session right after a Touch ID unlock. No-op (clears) when `ttl == 0`.
pub fn save(data: &DataDir, key: &MasterKey, policy: Policy) -> Result<()> {
    save_with(data, key, policy, agent::socket_from_env().as_deref())
}

fn save_with(data: &DataDir, key: &MasterKey, policy: Policy, agent: Option<&Path>) -> Result<()> {
    clear(data)?;
    if policy.ttl == 0 {
        return Ok(());
    }
    let unlocked_at = now_secs()?;
    let sealed = match agent.map(|socket| Sealed::create(socket, key, unlocked_at, policy)) {
        Some(Ok(sealed)) => Some(sealed),
        Some(Err(err)) => {
            eprintln!("warning: ssh-agent unusable ({err:#}); session key stored in plaintext file");
            None
        }
        None => {
            eprintln!("warning: no local ssh-agent (SSH_AUTH_SOCK); session key stored in plaintext file");
            None
        }
    };
    let session = Session {
        key: key.clone(),
        unlocked_at,
        sealed,
    };
    write(data, &session, policy)
}

/// Sliding refresh: extend expiry from now, capped at the session's hard limit.
pub fn touch(data: &DataDir, session: &Session, policy: Policy) -> Result<()> {
    write(data, session, policy)
}

fn write(data: &DataDir, session: &Session, policy: Policy) -> Result<()> {
    let now = now_secs()?;
    let unlocked_at = session.unlocked_at;
    let expires = now
        .saturating_add(policy.ttl)
        .min(policy.deadline(unlocked_at));
    if policy.ttl == 0 || expires <= now {
        clear(data)?;
        return Ok(());
    }

    data.ensure_dir()?;
    crate::gitutil::ensure_gitignore(data)?;
    let path = data.session_file();
    let body = Zeroizing::new(match &session.sealed {
        Some(sealed) => format!(
            "v3\n{expires}\n{unlocked_at}\n{}\n{}\n{}\n{}\n{}\n",
            sealed.socket.display(),
            hex::encode(sealed.public),
            hex::encode(sealed.challenge),
            hex::encode(&sealed.nonce),
            hex::encode(&sealed.ciphertext),
        ),
        None => {
            let hex = Zeroizing::new(master_key_to_hex(&session.key));
            format!("v2\n{expires}\n{unlocked_at}\n{}\n", hex.as_str())
        }
    });

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create session {}", path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("write session {}", path.display()))?;
    file.sync_all()?;

    // Ensure permissions even if the file already existed with a looser mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs())
}

/// Seconds left, and whether the key is sealed in the agent (`false` = plaintext file).
pub fn remaining_secs(data: &DataDir) -> Result<Option<(u64, bool)>> {
    let path = data.session_file();
    if !path.exists() {
        return Ok(None);
    }
    let raw = Zeroizing::new(fs::read_to_string(&path)?);
    let Some(parsed) = parse(&raw) else {
        return Ok(None);
    };
    let now = now_secs()?;
    if now >= parsed.expires {
        return Ok(None);
    }
    let sealed = matches!(parsed.stored, Stored::Sealed(_));
    Ok(Some((parsed.expires - now, sealed)))
}

pub fn status_message(data: &DataDir, policy: Policy) -> Result<String> {
    if policy.ttl == 0 {
        return Ok("session caching disabled (PM_SESSION_TTL=0)".into());
    }
    match remaining_secs(data)? {
        Some((left, sealed)) => Ok(format!(
            "unlocked via {} (~{left}s remaining, ttl={}s, max={}s)",
            if sealed { "ssh-agent" } else { "plaintext file" },
            policy.ttl,
            policy.max
        )),
        None => Ok(format!("locked (ttl={}s, max={}s)", policy.ttl, policy.max)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::tests::TestAgent;
    use crate::crypto::generate_master_key;

    fn tmp_data(name: &str) -> DataDir {
        let dir = std::env::temp_dir()
            .join(format!("pm-session-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // DataDir only wraps a path; construct via PM_DATA in real code — use a test helper.
        DataDir::from_path(dir)
    }

    const POLICY: Policy = Policy { ttl: 60, max: 900 };

    #[test]
    fn plaintext_fallback_roundtrip() {
        let data = tmp_data("roundtrip");
        let key = generate_master_key();
        save_with(&data, &key, POLICY, None).unwrap();
        let loaded = load(&data, POLICY).unwrap().expect("session present");
        assert_eq!(master_key_to_hex(&loaded.key), master_key_to_hex(&key));
        clear(&data).unwrap();
        assert!(load(&data, POLICY).unwrap().is_none());

        // An unreachable agent also falls back instead of failing the command.
        save_with(&data, &key, POLICY, Some(Path::new("/nonexistent/agent.sock"))).unwrap();
        assert!(fs::read_to_string(data.session_file()).unwrap().starts_with("v2\n"));
        let _ = fs::remove_dir_all(data.root());
    }

    #[test]
    fn agent_sealed_session() {
        let agent = TestAgent::start("session");
        let data = tmp_data("sealed");
        let key = generate_master_key();
        save_with(&data, &key, POLICY, Some(&agent.socket)).unwrap();

        // The file holds no usable key.
        let body = fs::read_to_string(data.session_file()).unwrap();
        assert!(body.starts_with("v3\n"));
        assert!(!body.contains(&master_key_to_hex(&key)));
        assert_eq!(remaining_secs(&data).unwrap().map(|(_, sealed)| sealed), Some(true));

        let loaded = load(&data, POLICY).unwrap().expect("session present");
        assert_eq!(master_key_to_hex(&loaded.key), master_key_to_hex(&key));
        touch(&data, &loaded, POLICY).unwrap();
        assert!(load(&data, POLICY).unwrap().is_some());

        // `pm lock` removes the key from the agent: a copy of the file is now useless.
        let copy = fs::read_to_string(data.session_file()).unwrap();
        clear(&data).unwrap();
        fs::write(data.session_file(), copy).unwrap();
        assert!(load(&data, POLICY).unwrap().is_none());
        let _ = fs::remove_dir_all(data.root());
    }

    #[test]
    fn agent_lifetime_ends_session() {
        let agent = TestAgent::start("expiry");
        let data = tmp_data("expiry");
        let key = generate_master_key();
        let short = Policy { ttl: 60, max: 1 };
        save_with(&data, &key, short, Some(&agent.socket)).unwrap();
        // The agent drops the key at the hard limit even if the file's limit is ignored.
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(load(&data, Policy { ttl: 60, max: 0 }).unwrap().is_none());
        let _ = fs::remove_dir_all(data.root());
    }

    #[test]
    fn sliding_never_passes_hard_limit() {
        let data = tmp_data("limit");
        let key = generate_master_key();
        let now = now_secs().unwrap();

        // Unlocked 850s ago with max 900: touching may only extend to the 900s deadline.
        let session = Session {
            key,
            unlocked_at: now - 850,
            sealed: None,
        };
        touch(&data, &session, POLICY).unwrap();
        let (left, _) = remaining_secs(&data).unwrap().expect("still unlocked");
        assert!(left <= 50, "expiry extended past hard limit: {left}s left");

        // Past the hard limit: the session is gone, whatever its expiry says.
        let body = format!("v2\n{}\n{}\n{}\n", now + 60, now - 901, "00".repeat(32));
        fs::write(data.session_file(), body).unwrap();
        assert!(load(&data, POLICY).unwrap().is_none());
        assert!(!data.session_file().exists());
        let _ = fs::remove_dir_all(data.root());
    }
}
