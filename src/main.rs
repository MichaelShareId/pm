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

use crate::auth::{ensure_touch_id, load_existing_master_key, load_master_key, store_master_key};
use crate::config::DataDir;
use crate::crypto::{decrypt, encrypt, generate_master_key, MasterKey};
use crate::gitutil::commit_db;
use crate::pathutil::{check_env_names, normalize_path, path_to_env_name, prefix_env_mask};
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

    /// Hard session limit in seconds from the Touch ID unlock; use can't extend past it
    /// (0 = no limit; env: PM_SESSION_MAX)
    #[arg(
        long = "session-max",
        global = true,
        env = "PM_SESSION_MAX",
        default_value_t = session::DEFAULT_SESSION_MAX_SECS
    )]
    session_max: u64,

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
        /// Store the value exactly as given (don't strip one pair of surrounding quotes)
        #[arg(long)]
        raw: bool,
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
        /// Allow env names like PATH, DYLD_*, NODE_OPTIONS that change how programs load code
        #[arg(long)]
        allow_reserved: bool,
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
        /// Allow env names like PATH, DYLD_*, NODE_OPTIONS that change how programs load code
        #[arg(long)]
        allow_reserved: bool,
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
    let policy = session::Policy {
        ttl: cli.session_ttl,
        max: cli.session_max,
    };
    match cli.command {
        Commands::Init => cmd_init(policy),
        Commands::Set { path, raw } => cmd_set(&path, raw, policy),
        Commands::Get { path, output } => cmd_get(&path, output, policy),
        Commands::Inject {
            prefix,
            mask,
            allow_reserved,
            command,
        } => cmd_inject(prefix.as_deref(), mask.as_deref(), allow_reserved, &command, policy),
        Commands::Dump {
            prefix,
            mask,
            allow_reserved,
        } => cmd_dump(prefix.as_deref(), mask.as_deref(), allow_reserved, policy),
        Commands::List { prefix, path } => cmd_list(prefix.as_deref(), path.as_deref()),
        Commands::Rm { path } => cmd_rm(&path, policy),
        Commands::Unlock => cmd_unlock(policy),
        Commands::Lock => cmd_lock(),
        Commands::Status => cmd_status(policy),
    }
}

fn cmd_init(policy: session::Policy) -> Result<()> {
    let data = DataDir::resolve()?;
    if data.keys_db().exists() {
        bail!("already initialized: {}", data.root().display());
    }

    data.ensure_dir()?;
    // Now that the directory exists, resolve again to get its canonical path.
    let data = DataDir::resolve()?;

    // keys.db marks the vault as initialized, so create it only after auth and the
    // master key succeed; otherwise a cancelled Touch ID leaves a vault with no key.
    ensure_touch_id("pm: confirm Touch ID for new vault")?;
    let key = match load_existing_master_key(&data)? {
        // Left by an earlier init of this PM_DATA: reuse it so old git history stays decryptable.
        Some(key) => {
            eprintln!("reusing existing master key from Keychain");
            key
        }
        None => {
            let key = generate_master_key();
            store_master_key(&data, &key)?;
            key
        }
    };
    session::save(&data, &key, policy)?;

    drop(Store::open(&data)?);
    gitutil::init_repo(&data)?;
    commit_or_warn(&data, "init");

    println!("initialized {}", data.root().display());
    Ok(())
}

fn unlock_key(data: &DataDir, reason: &str, policy: session::Policy) -> Result<MasterKey> {
    if let Some(session) = session::load(data, policy)? {
        session::touch(data, &session, policy)?;
        return Ok(session.key);
    }

    ensure_touch_id(reason)?;
    let key = load_master_key(data)?;
    session::save(data, &key, policy)?;
    Ok(key)
}

fn cmd_unlock(policy: session::Policy) -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    if policy.ttl == 0 {
        bail!("session caching disabled (set PM_SESSION_TTL or --session-ttl > 0)");
    }
    ensure_touch_id("pm: unlock")?;
    let key = load_master_key(&data)?;
    session::save(&data, &key, policy)?;
    println!("{}", session::status_message(&data, policy)?);
    Ok(())
}

fn cmd_lock() -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    session::clear(&data)?;
    println!("locked");
    Ok(())
}

fn cmd_status(policy: session::Policy) -> Result<()> {
    let data = DataDir::resolve()?;
    data.require_initialized()?;
    println!("{}", session::status_message(&data, policy)?);
    Ok(())
}

fn cmd_set(path: &str, raw: bool, policy: session::Policy) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let value = read_secret_value(raw)?;
    let key = unlock_key(&data, &format!("pm: set {path}"), policy)?;
    let (nonce, ciphertext) = encrypt(&key, path.as_bytes(), value.as_bytes())?;

    let store = Store::open(&data)?;
    // Hold the lock through the commit so concurrent writers can't race on git.
    let _lock = store.write_lock()?;
    store.upsert(&path, &nonce, &ciphertext)?;
    commit_or_warn(&data, &format!("set {path}"));
    Ok(())
}

fn cmd_get(path: &str, output: Output, policy: session::Policy) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let store = Store::open(&data)?;
    let row = store
        .get(&path)?
        .with_context(|| format!("key not found: {path}"))?;

    let key = unlock_key(&data, &format!("pm: get {path}"), policy)?;
    let plaintext = decrypt(&key, path.as_bytes(), &row.nonce, &row.ciphertext)?;
    // Output exactly what was stored; quotes were already handled by `set`.
    let text = Zeroizing::new(
        String::from_utf8(plaintext.to_vec()).context("secret is not valid UTF-8")?,
    );

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
    allow_reserved: bool,
    reason_verb: &str,
    policy: session::Policy,
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

    // Check names before Touch ID: a bad mapping fails without prompting or decrypting.
    let names = rows
        .iter()
        .map(|row| path_to_env_name(&row.path, env_mask.as_deref()))
        .collect::<Result<Vec<_>>>()?;
    let pairs: Vec<(&str, &str)> = rows
        .iter()
        .zip(&names)
        .map(|(row, name)| (row.path.as_str(), name.as_str()))
        .collect();
    check_env_names(&pairs, allow_reserved)?;

    let reason = match prefix.as_deref() {
        Some(prefix) => format!("pm: {reason_verb} {prefix}"),
        None => format!("pm: {reason_verb}"),
    };
    let key = unlock_key(&data, &reason, policy)?;
    let mut envs: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(rows.len());

    for (row, name) in rows.iter().zip(names) {
        let plaintext = decrypt(&key, row.path.as_bytes(), &row.nonce, &row.ciphertext)?;
        let value = Zeroizing::new(
            String::from_utf8(plaintext.to_vec())
                .with_context(|| format!("secret {} is not valid UTF-8", row.path))?,
        );
        envs.push((name, value));
    }
    Ok(envs)
}

fn cmd_inject(
    prefix: Option<&str>,
    mask: Option<&str>,
    allow_reserved: bool,
    command: &[String],
    policy: session::Policy,
) -> Result<()> {
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

    let envs = load_env_pairs(prefix, mask, allow_reserved, "inject", policy)?;

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

fn cmd_dump(
    prefix: Option<&str>,
    mask: Option<&str>,
    allow_reserved: bool,
    policy: session::Policy,
) -> Result<()> {
    let envs = load_env_pairs(prefix, mask, allow_reserved, "dump", policy)?;
    let mut out = io::stdout().lock();
    // Quote everything first so a bad value fails before any secret is printed.
    let mut lines = Vec::with_capacity(envs.len());
    for (name, value) in &envs {
        lines.push(Zeroizing::new(format!("{name}={}", dotenv_quote(name, value)?)));
    }
    for line in &lines {
        writeln!(out, "{}", line.as_str())?;
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

fn cmd_rm(path: &str, policy: session::Policy) -> Result<()> {
    let path = normalize_path(path)?;
    let data = DataDir::resolve()?;
    data.require_initialized()?;

    let _key = unlock_key(&data, &format!("pm: rm {path}"), policy)?;

    let store = Store::open(&data)?;
    let _lock = store.write_lock()?;
    if !store.delete(&path)? {
        bail!("key not found: {path}");
    }
    commit_or_warn(&data, &format!("rm {path}"));
    Ok(())
}

/// The change is already saved in keys.db; a failed commit only loses history, so warn
/// instead of reporting the command as failed. The next successful commit includes it.
fn commit_or_warn(data: &DataDir, message: &str) {
    if let Err(err) = commit_db(data, message) {
        eprintln!("warning: change saved, but git commit failed (included in the next commit): {err:#}");
    }
}

/// Single-quote a value for dotenv files and `set -a; . file` in shells: inside `'...'`
/// nothing is expanded, so `$`, `#`, spaces and `"` are kept as is. A `'` or line break
/// can't be written there without parser-specific escapes, so such values are refused.
fn dotenv_quote(name: &str, value: &str) -> Result<String> {
    if value.contains(['\'', '\n', '\r']) {
        bail!("{name}: value contains a `'` or line break and can't be written safely as dotenv; use `pm inject` or `pm get`");
    }
    Ok(format!("'{value}'"))
}

/// Drop a single matching pair of surrounding `'` or `"` (common when pasting .env values).
/// Applied once, on input only, so stored values are returned unchanged.
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

fn read_secret_value(raw_value: bool) -> Result<Zeroizing<String>> {
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
    prepare_value(&raw, raw_value)
}

fn prepare_value(input: &str, raw_value: bool) -> Result<Zeroizing<String>> {
    let value = if raw_value {
        input
    } else {
        strip_surrounding_quotes(input)
    };
    if value.is_empty() {
        bail!("empty value");
    }
    Ok(Zeroizing::new(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{dotenv_quote, prepare_value, strip_surrounding_quotes};

    #[test]
    fn strips_matching_quotes() {
        assert_eq!(strip_surrounding_quotes(r#""hello""#), "hello");
        assert_eq!(strip_surrounding_quotes("'hello'"), "hello");
        assert_eq!(strip_surrounding_quotes("hello"), "hello");
        assert_eq!(strip_surrounding_quotes(r#""hello'"#), r#""hello'"#);
        assert_eq!(strip_surrounding_quotes(r#""""#), "");
        assert_eq!(strip_surrounding_quotes("'"), "'");
    }

    #[test]
    fn set_strips_quotes_once_and_raw_keeps_them() {
        assert_eq!(prepare_value(r#""'abc'""#, false).unwrap().as_str(), "'abc'");
        assert_eq!(prepare_value(r#""abc""#, true).unwrap().as_str(), r#""abc""#);
        assert!(prepare_value(r#""""#, false).is_err());
    }

    #[test]
    fn dotenv_values_are_single_quoted() {
        assert_eq!(dotenv_quote("A", "p@ss word#$HOME\"x").unwrap(), "'p@ss word#$HOME\"x'");
        assert!(dotenv_quote("A", "it's").is_err());
        assert!(dotenv_quote("A", "x\nOTHER=y").is_err());
        assert!(dotenv_quote("A", "x\r").is_err());
    }
}
