mod auth;
mod config;
mod crypto;
mod gitutil;
mod pathutil;
mod session;
mod store;

use std::io::{self, IsTerminal, Read, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::auth::{ensure_touch_id, load_or_create_master_key, store_master_key};
use crate::config::DataDir;
use crate::crypto::{decrypt, encrypt, generate_master_key, MasterKey};
use crate::gitutil::commit_db;
use crate::pathutil::{normalize_path, path_to_env_name, prefix_env_mask};
use crate::store::Store;

#[derive(Debug, Parser)]
#[command(name = "pm", about = "Touch ID–gated path-keyed password manager")]
struct Cli {
    /// Session cache TTL in seconds (0 disables; env: PM_SESSION_TTL)
    #[arg(
        long = "session-ttl",
        global = true,
        env = "PM_SESSION_TTL",
        default_value_t = session::DEFAULT_SESSION_TTL_SECS
    )]
    session_ttl: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize PM_DATA (DB, git repo, master key)
    Init,
    /// Set a secret (value from stdin, or hidden prompt on a TTY)
    Set {
        /// Path key, e.g. /env/dev/url
        path: String,
    },
    /// Get a secret
    Get {
        /// Path key, e.g. /env/dev/url
        path: String,
        #[arg(short = 'o', long = "output", value_enum, default_value_t = Output::Stdout)]
        output: Output,
    },
    /// Inject matching secrets as env vars and run a command
    Inject {
        /// Path prefix to match; env names keep the last prefix segment
        /// (`--prefix /a/b` maps `/a/b/c` → `B_C`)
        #[arg(long = "prefix")]
        prefix: Option<String>,
        /// Strip this prefix before building env names (overrides `--prefix` naming)
        #[arg(long = "mask")]
        mask: Option<String>,
        /// Command and args after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Decrypt matching secrets and print `NAME=value` lines (dotenv format)
    Dump {
        /// Path prefix to match; env names keep the last prefix segment
        /// (`--prefix /a/b` maps `/a/b/c` → `B_C`)
        #[arg(long = "prefix")]
        prefix: Option<String>,
        /// Strip this prefix before building env names (overrides `--prefix` naming)
        #[arg(long = "mask")]
        mask: Option<String>,
    },
    /// List stored paths, or env names that `--prefix` would inject
    List {
        /// Path prefix; print env names as `inject --prefix` would set them
        #[arg(long = "prefix")]
        prefix: Option<String>,
        /// Optional path filter (paths only; ignored when `--prefix` is set)
        #[arg(value_name = "PATH")]
        path: Option<String>,
    },
    /// Remove a secret
    Rm {
        path: String,
    },
    /// Unlock vault into session cache (Touch ID)
    Unlock,
    /// Clear the unlocked session cache
    Lock,
    /// Show session lock/unlock status
    Status,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Stdout,
    Clipboard,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let ttl = cli.session_ttl;
    match cli.command {
        Commands::Init => cmd_init(ttl),
        Commands::Set { path } => cmd_set(&path, ttl),
        Commands::Get { path, output } => cmd_get(&path, output, ttl),
        Commands::Inject {
            prefix,
            mask,
            command,
        } => cmd_inject(prefix.as_deref(), mask.as_deref(), &command, ttl),
        Commands::Dump { prefix, mask } => cmd_dump(prefix.as_deref(), mask.as_deref(), ttl),
        Commands::List { prefix, path } => cmd_list(prefix.as_deref(), path.as_deref()),
        Commands::Rm { path } => cmd_rm(&path, ttl),
        Commands::Unlock => cmd_unlock(ttl),
        Commands::Lock => cmd_lock(),
        Commands::Status => cmd_status(ttl),
    }
}

fn cmd_init(ttl: u64) -> Result<()> {
    let data = DataDir::resolve()?;
    if data.keys_db().exists() {
        bail!("already initialized: {}", data.root().display());
    }

    data.ensure_dir()?;
    let store = Store::open(&data)?;
    drop(store);

    ensure_touch_id("pm: confirm Touch ID for new vault")?;
    let key = generate_master_key();
    store_master_key(&data, &key)?;
    let loaded = load_or_create_master_key(&data, false)?;
    session::save(&data, &loaded, ttl)?;

    gitutil::init_repo(&data)?;
    commit_db(&data, "init")?;

    println!("initialized {}", data.root().display());
    Ok(())
}

fn unlock_key(data: &DataDir, reason: &str, ttl: u64) -> Result<MasterKey> {
    if let Some(key) = session::load(data)? {
        session::touch(data, &key, ttl)?;
        return Ok(key);
    }

    ensure_touch_id(reason)?;
    let key = load_or_create_master_key(data, false)?;
    session::save(data, &key, ttl)?;
    Ok(key)
}

fn cmd_unlock(ttl: u64) -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    if ttl == 0 {
        bail!("session caching disabled (set PM_SESSION_TTL or --session-ttl > 0)");
    }
    ensure_touch_id("pm: unlock")?;
    let key = load_or_create_master_key(&data, false)?;
    session::save(&data, &key, ttl)?;
    println!("{}", session::status_message(&data, ttl)?);
    Ok(())
}

fn cmd_lock() -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    session::clear(&data)?;
    println!("locked");
    Ok(())
}

fn cmd_status(ttl: u64) -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    println!("{}", session::status_message(&data, ttl)?);
    Ok(())
}

fn cmd_set(path: &str, ttl: u64) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let value = read_secret_value()?;
    let key = unlock_key(&data, &format!("pm: set {path}"), ttl)?;
    let (nonce, ciphertext) = encrypt(&key, path.as_bytes(), value.as_bytes())?;

    let store = Store::open(&data)?;
    let _lock = store.write_lock()?;
    store.upsert(&path, &nonce, &ciphertext)?;
    drop(_lock);

    commit_db(&data, &format!("set {path}"))?;
    Ok(())
}

fn cmd_get(path: &str, output: Output, ttl: u64) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let store = Store::open(&data)?;
    let row = store
        .get(&path)?
        .with_context(|| format!("key not found: {path}"))?;

    let key = unlock_key(&data, &format!("pm: get {path}"), ttl)?;
    let plaintext = decrypt(&key, path.as_bytes(), &row.nonce, &row.ciphertext)?;
    let text = String::from_utf8(plaintext.to_vec()).context("secret is not valid UTF-8")?;
    let text = Zeroizing::new(strip_surrounding_quotes(&text).to_string());

    match output {
        Output::Stdout => {
            print!("{}", text.as_str());
            if !text.ends_with('\n') && io::stdout().is_terminal() {
                println!();
            }
            io::stdout().flush()?;
        }
        Output::Clipboard => {
            let mut clipboard = arboard::Clipboard::new().context("open clipboard")?;
            clipboard
                .set_text(text.as_str())
                .context("copy to clipboard")?;
            eprintln!("copied {path} to clipboard");
        }
    }
    Ok(())
}

fn resolve_env_mask(prefix: Option<&str>, mask: Option<&str>) -> Result<Option<String>> {
    if let Some(mask) = mask {
        return Ok(Some(normalize_path(mask)?));
    }
    match prefix {
        Some(prefix) => prefix_env_mask(prefix),
        None => Ok(None),
    }
}

fn load_env_pairs(
    prefix: Option<&str>,
    mask: Option<&str>,
    reason_verb: &str,
    ttl: u64,
) -> Result<Vec<(String, Zeroizing<String>)>> {
    let prefix = prefix.map(normalize_path).transpose()?;
    let env_mask = resolve_env_mask(prefix.as_deref(), mask)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let store = Store::open(&data)?;
    let rows = match prefix.as_deref() {
        Some(prefix) => store.list_prefix(prefix)?,
        None => store.list_all()?,
    };
    if rows.is_empty() {
        match prefix.as_deref() {
            Some(prefix) => bail!("no keys matching prefix {prefix}"),
            None => bail!("no keys stored"),
        }
    }

    let reason = match prefix.as_deref() {
        Some(prefix) => format!("pm: {reason_verb} {prefix}"),
        None => format!("pm: {reason_verb}"),
    };
    let key = unlock_key(&data, &reason, ttl)?;
    let mut envs: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(rows.len());

    for row in rows {
        let name = path_to_env_name(&row.path, env_mask.as_deref())?;
        let plaintext = decrypt(&key, row.path.as_bytes(), &row.nonce, &row.ciphertext)?;
        let text = String::from_utf8(plaintext.to_vec())
            .with_context(|| format!("secret {} is not valid UTF-8", row.path))?;
        let value = Zeroizing::new(strip_surrounding_quotes(&text).to_string());
        envs.push((name, value));
    }
    Ok(envs)
}

fn cmd_inject(prefix: Option<&str>, mask: Option<&str>, command: &[String], ttl: u64) -> Result<()> {
    if command.is_empty() {
        bail!("missing command; usage: pm inject [--prefix <prefix>] [--mask <prefix>] -- <cmd> [args...]");
    }

    let (prog, args) = if command[0] == "--" {
        if command.len() < 2 {
            bail!("missing command after `--`");
        }
        (&command[1], &command[2..])
    } else {
        (&command[0], &command[1..])
    };

    let envs = load_env_pairs(prefix, mask, "inject", ttl)?;

    let mut child = Command::new(prog);
    child
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("_PM_INJECT", "1");
    for (name, value) in &envs {
        child.env(name, value.as_str());
    }

    let status = child
        .status()
        .with_context(|| format!("failed to run `{prog}`"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn cmd_dump(prefix: Option<&str>, mask: Option<&str>, ttl: u64) -> Result<()> {
    let envs = load_env_pairs(prefix, mask, "dump", ttl)?;
    let mut out = io::stdout().lock();
    for (name, value) in &envs {
        writeln!(out, "{}={}", name, value.as_str())?;
    }
    out.flush()?;
    Ok(())
}

fn cmd_list(prefix: Option<&str>, path: Option<&str>) -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    let store = Store::open(&data)?;

    if let Some(prefix) = prefix {
        let prefix = normalize_path(prefix)?;
        let env_mask = prefix_env_mask(&prefix)?;
        for path in store.list_paths(Some(&prefix))? {
            let name = path_to_env_name(&path, env_mask.as_deref())?;
            println!("${name}");
        }
        return Ok(());
    }

    let path = match path {
        Some(p) => normalize_path(p)?,
        None => String::new(),
    };
    for p in store.list_paths(if path.is_empty() {
        None
    } else {
        Some(&path)
    })? {
        println!("{p}");
    }
    Ok(())
}

fn cmd_rm(path: &str, ttl: u64) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let _key = unlock_key(&data, &format!("pm: rm {path}"), ttl)?;

    let store = Store::open(&data)?;
    let _lock = store.write_lock()?;
    let removed = store.delete(&path)?;
    drop(_lock);
    if !removed {
        bail!("key not found: {path}");
    }
    commit_db(&data, &format!("rm {path}"))?;
    Ok(())
}

/// Drop a single matching pair of surrounding `'` or `"` (common when pasting .env values).
fn strip_surrounding_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn read_secret_value() -> Result<Zeroizing<String>> {
    let stdin = io::stdin();
    let raw = if stdin.is_terminal() {
        let value = rpassword::prompt_password("value: ").context("read hidden prompt")?;
        if value.is_empty() {
            bail!("empty value");
        }
        value
    } else {
        let mut buf = String::new();
        stdin.lock().read_to_string(&mut buf)?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            bail!("empty value on stdin");
        }
        buf
    };
    let value = strip_surrounding_quotes(&raw);
    if value.is_empty() {
        bail!("empty value");
    }
    Ok(Zeroizing::new(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::strip_surrounding_quotes;

    #[test]
    fn strips_matching_quotes() {
        assert_eq!(strip_surrounding_quotes(r#""hello""#), "hello");
        assert_eq!(strip_surrounding_quotes("'hello'"), "hello");
        assert_eq!(strip_surrounding_quotes("hello"), "hello");
        assert_eq!(strip_surrounding_quotes(r#""hello'"#), r#""hello'"#);
        assert_eq!(strip_surrounding_quotes(r#""""#), "");
        assert_eq!(strip_surrounding_quotes("'"), "'");
    }
}
