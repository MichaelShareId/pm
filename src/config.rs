use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct DataDir {
    /// Canonical path (absolute, symlinks resolved) once the directory exists.
    root: PathBuf,
    /// `PM_DATA` exactly as given; older builds keyed the Keychain item by this spelling.
    as_given: PathBuf,
}

impl DataDir {
    pub fn resolve() -> Result<Self> {
        let as_given = match env::var_os("PM_DATA") {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => bail!("PM_DATA is not set (path to the data directory)"),
        };
        Self::from_given(as_given)
    }

    fn from_given(as_given: PathBuf) -> Result<Self> {
        // One vault, one identity: `./vault`, `vault/` and a symlink to it all resolve to
        // the same root (and so the same Keychain item). Before the directory exists
        // (`init`), fall back to the absolute path; `init` resolves again after creating it.
        let root = match fs::canonicalize(&as_given) {
            Ok(path) => path,
            Err(_) => std::path::absolute(&as_given)
                .with_context(|| format!("resolve PM_DATA {}", as_given.display()))?,
        };
        Ok(Self { root, as_given })
    }

    #[cfg(test)]
    pub fn from_path(root: PathBuf) -> Self {
        Self {
            as_given: root.clone(),
            root,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn as_given(&self) -> &Path {
        &self.as_given
    }

    pub fn keys_db(&self) -> PathBuf {
        self.root.join("keys.db")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.root.join(".lock")
    }

    pub fn session_file(&self) -> PathBuf {
        self.root.join(".session")
    }

    /// Create the vault dir owner-only (`0700`), and tighten an existing one that is looser:
    /// keys.db and .git hold every path name and all ciphertext.
    pub fn ensure_dir(&self) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .with_context(|| format!("create data dir {}", self.root.display()))?;
        let mode = fs::metadata(&self.root)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restrict data dir {} to 0700", self.root.display()))?;
        }
        Ok(())
    }

    pub fn require_initialized(&self) -> Result<()> {
        if !self.keys_db().exists() {
            bail!(
                "not initialized: {} (run `pm init` with PM_DATA set)",
                self.root.display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_of_one_dir_share_a_root() {
        let base = fs::canonicalize(env::temp_dir())
            .unwrap()
            .join(format!("pm-config-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let vault = base.join("vault");
        fs::create_dir_all(&vault).unwrap();
        std::os::unix::fs::symlink(&vault, base.join("link")).unwrap();

        for given in [
            vault.clone(),
            base.join("vault/"),
            base.join("./vault"),
            base.join("x/../vault"),
            base.join("link"),
        ] {
            fs::create_dir_all(base.join("x")).unwrap();
            let root = DataDir::from_given(given.clone()).unwrap().root;
            assert_eq!(root, vault, "PM_DATA={}", given.display());
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ensure_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = env::temp_dir().join(format!("pm-config-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let data = DataDir::from_path(dir.join("new"));
        data.ensure_dir().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(data.root()), 0o700);

        fs::set_permissions(data.root(), fs::Permissions::from_mode(0o755)).unwrap();
        data.ensure_dir().unwrap();
        assert_eq!(mode(data.root()), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }
}
