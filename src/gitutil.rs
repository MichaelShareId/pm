use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::config::DataDir;

pub fn init_repo(data: &DataDir) -> Result<()> {
    if data.root().join(".git").exists() {
        return Ok(());
    }
    run_git(data, &["init"])?;
    ensure_gitignore(data)
}

/// Files that must never be committed: write lock, unlocked session, SQLite side files.
const IGNORED: &[&str] = &[".lock", ".session", "keys.db-journal", "keys.db-wal", "keys.db-shm"];

/// Append any missing entries from [`IGNORED`] to `.gitignore` (also upgrades older vaults).
pub fn ensure_gitignore(data: &DataDir) -> Result<()> {
    let path = data.root().join(".gitignore");
    let mut out = std::fs::read_to_string(&path).unwrap_or_default();
    let missing: Vec<&str> = IGNORED
        .iter()
        .copied()
        .filter(|entry| !out.lines().any(|l| l.trim() == *entry))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for entry in missing {
        out.push_str(entry);
        out.push('\n');
    }
    std::fs::write(&path, out).with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

pub fn commit_db(data: &DataDir, message: &str) -> Result<()> {
    init_repo(data)?;
    ensure_gitignore(data)?;
    run_git(data, &["add", "keys.db", ".gitignore"])?;
    // Exit 0 means no staged diff.
    let status = Command::new("git")
        .args(["-C"])
        .arg(data.root())
        .args(["diff", "--cached", "--quiet"])
        .status()
        .context("git diff --cached")?;
    if status.success() {
        return Ok(());
    }
    // Fixed identity, and no signing or hooks: global settings like commit.gpgsign or
    // core.hooksPath must not prompt, run code, or fail vault commits.
    run_git(
        data,
        &[
            "-c",
            "user.name=pm",
            "-c",
            "user.email=pm@local",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-m",
            message,
        ],
    )?;
    Ok(())
}

fn run_git(data: &DataDir, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(data.root())
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {stderr}", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_ignores_hooks_and_signing() {
        let dir = std::env::temp_dir().join(format!("pm-git-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = DataDir::from_path(dir);
        init_repo(&data).unwrap();
        run_git(&data, &["config", "commit.gpgsign", "true"]).unwrap();
        run_git(&data, &["config", "gpg.program", "false"]).unwrap();
        let hook = data.root().join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        let mode = std::os::unix::fs::PermissionsExt::from_mode(0o755);
        std::fs::set_permissions(&hook, mode).unwrap();
        std::fs::write(data.keys_db(), b"x").unwrap();

        commit_db(&data, "set /a").unwrap();
        let _ = std::fs::remove_dir_all(data.root());
    }
}
