use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::config::DataDir;

pub fn init_repo(data: &DataDir) -> Result<()> {
    if data.root().join(".git").exists() {
        return Ok(());
    }
    run_git(data, &["init"])?;
    // Keep lock + unlocked session out of history.
    std::fs::write(data.root().join(".gitignore"), ".lock\n.session\n")?;
    Ok(())
}

pub fn commit_db(data: &DataDir, message: &str) -> Result<()> {
    init_repo(data)?;
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
    run_git(data, &["-c", "user.name=pm", "-c", "user.email=pm@local", "commit", "-m", message])?;
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
