use anyhow::{bail, Result};

/// Normalize a path key: must be absolute-style (`/a/b`), no `..`, no empty segments.
pub fn normalize_path(input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        bail!("path must not be empty");
    }
    if !input.starts_with('/') {
        bail!("path must start with `/` (got {input})");
    }
    let mut parts = Vec::new();
    for part in input.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            bail!("path must not contain `.` or `..` segments");
        }
        // Includes NUL, newlines, tabs, ESC: paths end up in commit messages and terminal output.
        if part.chars().any(char::is_control) {
            bail!("path must not contain control characters");
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("path must have at least one segment");
    }
    Ok(format!("/{}", parts.join("/")))
}

/// For `--prefix /a/b`, strip all but the last prefix segment from env names
/// (`/a/b/c` → `B_C`). Returns the mask to pass to [`path_to_env_name`], or
/// `None` when the prefix is a single segment (nothing to strip).
pub fn prefix_env_mask(prefix: &str) -> Result<Option<String>> {
    let prefix = normalize_path(prefix)?;
    let parts: Vec<_> = prefix
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() <= 1 {
        return Ok(None);
    }
    Ok(Some(format!("/{}", parts[..parts.len() - 1].join("/"))))
}

/// Map `/env/dev/url` → `ENV_DEV_URL`, or with mask `/env` → `DEV_URL`.
pub fn path_to_env_name(path: &str, mask: Option<&str>) -> Result<String> {
    let path = normalize_path(path)?;
    let remainder = if let Some(mask) = mask {
        let mask = normalize_path(mask)?;
        if path == mask {
            bail!("path {path} equals mask {mask}; nothing left for env name");
        }
        let prefix = format!("{mask}/");
        if let Some(rest) = path.strip_prefix(&prefix) {
            rest
        } else if path.starts_with(&mask) {
            bail!("path {path} does not sit under mask {mask}");
        } else {
            bail!("path {path} does not start with mask {mask}");
        }
    } else {
        path.trim_start_matches('/')
    };

    if remainder.is_empty() {
        bail!("empty env name after applying mask");
    }

    let name = remainder
        .split('/')
        .map(|s| {
            s.chars()
                .map(|c| match c {
                    '-' | '.' => '_',
                    c => c.to_ascii_uppercase(),
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("_");

    if !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
        bail!("env name `{name}` must start with A–Z or `_`");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!("env name `{name}` contains invalid characters");
    }
    Ok(name)
}

/// Env vars that change how a process or its children find and load code, or that pm uses
/// itself. A stored secret silently overriding one of these is almost never intended.
const RESERVED_ENV_NAMES: &[&str] = &[
    "PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR", "IFS", "ENV", "BASH_ENV", "PS4",
    "PROMPT_COMMAND", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME",
    "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];
const RESERVED_ENV_PREFIXES: &[&str] = &["DYLD_", "LD_", "PM_", "_PM_"];

fn is_reserved_env_name(name: &str) -> bool {
    RESERVED_ENV_NAMES.contains(&name) || RESERVED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Refuse `(path, env name)` mappings that would silently lose or misuse a secret:
/// two paths mapping to the same name, or (unless allowed) a reserved name.
pub fn check_env_names(pairs: &[(&str, &str)], allow_reserved: bool) -> Result<()> {
    let mut seen = std::collections::HashMap::new();
    for &(path, name) in pairs {
        if let Some(other) = seen.insert(name, path) {
            bail!("{other} and {path} both map to env name {name}; rename one or use --mask");
        }
        if !allow_reserved && is_reserved_env_name(name) {
            bail!("{path} maps to reserved env name {name}; pass --allow-reserved if intended");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ok() {
        assert_eq!(normalize_path("/env/dev/url").unwrap(), "/env/dev/url");
        assert_eq!(normalize_path("/env//dev/").unwrap(), "/env/dev");
        for bad in ["/a\nb", "/a\0b", "/a\tb", "/a\x1b[31mb", "/a\u{85}b"] {
            assert!(normalize_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn env_mapping() {
        assert_eq!(
            path_to_env_name("/env/dev/url", None).unwrap(),
            "ENV_DEV_URL"
        );
        assert_eq!(
            path_to_env_name("/env/dev/url", Some("/env")).unwrap(),
            "DEV_URL"
        );
        assert_eq!(
            path_to_env_name("/gather/bot-ox/secret", Some("/gather")).unwrap(),
            "BOT_OX_SECRET"
        );
        assert_eq!(
            path_to_env_name("/svc/api.v2/token", None).unwrap(),
            "SVC_API_V2_TOKEN"
        );
    }

    #[test]
    fn prefix_keeps_last_segment() {
        assert_eq!(prefix_env_mask("/a/b").unwrap(), Some("/a".into()));
        assert_eq!(prefix_env_mask("/env").unwrap(), None);
        assert_eq!(
            path_to_env_name("/a/b/c", prefix_env_mask("/a/b").unwrap().as_deref()).unwrap(),
            "B_C"
        );
        assert_eq!(
            path_to_env_name("/a/b/d", prefix_env_mask("/a/b").unwrap().as_deref()).unwrap(),
            "B_D"
        );
    }

    #[test]
    fn env_name_checks() {
        assert!(check_env_names(&[("/a/x", "A_X"), ("/a/y", "A_Y")], false).is_ok());
        let err = check_env_names(&[("/a/b-c", "A_B_C"), ("/a/b/c", "A_B_C")], true).unwrap_err();
        assert!(err.to_string().contains("/a/b-c and /a/b/c"));
        assert!(check_env_names(&[("/env/path", "PATH")], false).is_err());
        assert!(check_env_names(&[("/env/dyld_x", "DYLD_X")], false).is_err());
        assert!(check_env_names(&[("/env/path", "PATH")], true).is_ok());
    }
}
