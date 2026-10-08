use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::config::DataDir;
use crate::crypto::{master_key_from_hex, master_key_to_hex, MasterKey};

/// Default idle timeout of an unlocked session (3 minutes).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 180;
/// Default hard limit of an unlocked session from its Touch ID unlock (15 minutes).
pub const DEFAULT_SESSION_MAX_SECS: u64 = 900;

pub fn clear(data: &DataDir) -> Result<()> {
    let path = data.session_file();
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("remove session {}", path.display()))?;
    }
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
    let parsed = parse(&raw);
    let Some((expires, unlocked_at, hex)) = parsed else {
        let _ = clear(data);
        return Ok(None);
    };

    let now = now_secs()?;
    if now >= expires || now >= policy.deadline(unlocked_at) {
        let _ = clear(data);
        return Ok(None);
    }

    match master_key_from_hex(hex) {
        Ok(key) => Ok(Some(Session { key, unlocked_at })),
        Err(_) => {
            let _ = clear(data);
            Ok(None)
        }
    }
}

/// `v2\n<expires>\n<unlocked_at>\n<key hex>`
fn parse(raw: &str) -> Option<(u64, u64, &str)> {
    let mut lines = raw.lines();
    if lines.next()? != "v2" {
        return None;
    }
    let expires = lines.next()?.parse().ok()?;
    let unlocked_at = lines.next()?.parse().ok()?;
    let hex = lines.next()?;
    Some((expires, unlocked_at, hex))
}

/// Start a new session right after a Touch ID unlock. No-op (clears) when `ttl == 0`.
pub fn save(data: &DataDir, key: &MasterKey, policy: Policy) -> Result<()> {
    write(data, key, now_secs()?, policy)
}

/// Sliding refresh: extend expiry from now, capped at the session's hard limit.
pub fn touch(data: &DataDir, session: &Session, policy: Policy) -> Result<()> {
    write(data, &session.key, session.unlocked_at, policy)
}

fn write(data: &DataDir, key: &MasterKey, unlocked_at: u64, policy: Policy) -> Result<()> {
    let now = now_secs()?;
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
    let hex = Zeroizing::new(master_key_to_hex(key));
    let body = Zeroizing::new(format!("v2\n{expires}\n{unlocked_at}\n{}\n", hex.as_str()));

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

pub fn remaining_secs(data: &DataDir) -> Result<Option<u64>> {
    let path = data.session_file();
    if !path.exists() {
        return Ok(None);
    }
    let raw = Zeroizing::new(fs::read_to_string(&path)?);
    let Some((expires, _, _)) = parse(&raw) else {
        return Ok(None);
    };
    let now = now_secs()?;
    if now >= expires {
        return Ok(None);
    }
    Ok(Some(expires - now))
}

pub fn status_message(data: &DataDir, policy: Policy) -> Result<String> {
    if policy.ttl == 0 {
        return Ok("session caching disabled (PM_SESSION_TTL=0)".into());
    }
    match remaining_secs(data)? {
        Some(left) => Ok(format!(
            "unlocked (~{left}s remaining, ttl={}s, max={}s)",
            policy.ttl, policy.max
        )),
        None => Ok(format!("locked (ttl={}s, max={}s)", policy.ttl, policy.max)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn roundtrip_and_expiry() {
        let data = tmp_data("roundtrip");
        let key = generate_master_key();
        save(&data, &key, POLICY).unwrap();
        let loaded = load(&data, POLICY).unwrap().expect("session present");
        assert_eq!(master_key_to_hex(&loaded.key), master_key_to_hex(&key));
        clear(&data).unwrap();
        assert!(load(&data, POLICY).unwrap().is_none());
        let _ = fs::remove_dir_all(data.root());
    }

    #[test]
    fn sliding_never_passes_hard_limit() {
        let data = tmp_data("limit");
        let key = generate_master_key();
        let now = now_secs().unwrap();

        // Unlocked 850s ago with max 900: touching may only extend to the 900s deadline.
        let session = Session { key, unlocked_at: now - 850 };
        touch(&data, &session, POLICY).unwrap();
        let left = remaining_secs(&data).unwrap().expect("still unlocked");
        assert!(left <= 50, "expiry extended past hard limit: {left}s left");

        // Past the hard limit: the session is gone, whatever its expiry says.
        let body = format!("v2\n{}\n{}\n{}\n", now + 60, now - 901, "00".repeat(32));
        fs::write(data.session_file(), body).unwrap();
        assert!(load(&data, POLICY).unwrap().is_none());
        assert!(!data.session_file().exists());
        let _ = fs::remove_dir_all(data.root());
    }
}
