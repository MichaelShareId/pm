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

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("create data dir {}", self.root.display()))?;
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
}
