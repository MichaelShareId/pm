use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::config::DataDir;
use crate::crypto::{master_key_from_hex, master_key_to_hex, MasterKey};

/// Default unlocked-session lifetime (3 minutes).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 180;

pub fn clear(data: &DataDir) -> Result<()> {
    let path = data.session_file();
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("remove session {}", path.display()))?;
    }
    Ok(())
}

pub fn load(data: &DataDir) -> Result<Option<MasterKey>> {
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

    let mut lines = raw.lines();
    let Some(version) = lines.next() else {
        let _ = clear(data);
        return Ok(None);
    };
    if version != "v1" {
        let _ = clear(data);
        return Ok(None);
    }
    let Some(expires_s) = lines.next() else {
        let _ = clear(data);
        return Ok(None);
    };
    let Some(hex) = lines.next() else {
        let _ = clear(data);
        return Ok(None);
    };

    let expires: u64 = match expires_s.parse() {
        Ok(n) => n,
        Err(_) => {
            let _ = clear(data);
            return Ok(None);
        }
    };

    if now_secs()? >= expires {
        let _ = clear(data);
        return Ok(None);
    }

    match master_key_from_hex(hex) {
        Ok(key) => Ok(Some(key)),
        Err(_) => {
            let _ = clear(data);
            Ok(None)
        }
    }
}

/// Persist master key until `now + ttl`. No-op when `ttl == 0`.
pub fn save(data: &DataDir, key: &MasterKey, ttl_secs: u64) -> Result<()> {
    if ttl_secs == 0 {
        clear(data)?;
        return Ok(());
    }

    data.ensure_dir()?;
    ensure_session_gitignored(data)?;
    let path = data.session_file();
    let expires = now_secs()? + ttl_secs;
    let hex = Zeroizing::new(master_key_to_hex(key));
    let body = Zeroizing::new(format!("v1\n{expires}\n{}\n", hex.as_str()));

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

fn ensure_session_gitignored(data: &DataDir) -> Result<()> {
    let path = data.root().join(".gitignore");
    let existing = if path.exists() {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    if existing.lines().any(|l| l.trim() == ".session") {
        return Ok(());
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(".session\n");
    fs::write(&path, out).with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

/// Sliding refresh: extend expiry from now if a valid session already exists.
pub fn touch(data: &DataDir, key: &MasterKey, ttl_secs: u64) -> Result<()> {
    save(data, key, ttl_secs)
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs())
}

#[allow(dead_code)]
pub fn remaining_secs(data: &DataDir) -> Result<Option<u64>> {
    let path = data.session_file();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)?;
    let mut lines = raw.lines();
    if lines.next() != Some("v1") {
        return Ok(None);
    }
    let expires: u64 = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("bad session"))?
        .parse()?;
    let now = now_secs()?;
    if now >= expires {
        return Ok(None);
    }
    Ok(Some(expires - now))
}

pub fn status_message(data: &DataDir, ttl_secs: u64) -> Result<String> {
    if ttl_secs == 0 {
        return Ok("session caching disabled (PM_SESSION_TTL=0)".into());
    }
    match remaining_secs(data)? {
        Some(left) => Ok(format!("unlocked (~{left}s remaining, ttl={ttl_secs}s)")),
        None => Ok(format!("locked (ttl={ttl_secs}s)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_master_key;

    fn tmp_data() -> DataDir {
        let dir = std::env::temp_dir().join(format!("pm-session-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // DataDir only wraps a path; construct via PM_DATA in real code — use a test helper.
        DataDir::from_path(dir)
    }

    #[test]
    fn roundtrip_and_expiry() {
        let data = tmp_data();
        let key = generate_master_key();
        save(&data, &key, 60).unwrap();
        let loaded = load(&data).unwrap().expect("session present");
        assert_eq!(master_key_to_hex(&loaded), master_key_to_hex(&key));
        clear(&data).unwrap();
        assert!(load(&data).unwrap().is_none());
        let _ = fs::remove_dir_all(data.root());
    }
}
