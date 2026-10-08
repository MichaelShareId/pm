use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    pub fn resolve() -> Result<Self> {
        let root = match env::var_os("PM_DATA") {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => bail!("PM_DATA is not set (path to the data directory)"),
        };
        Ok(Self { root })
    }

    #[cfg(test)]
    pub fn from_path(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
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
