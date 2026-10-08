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
        if part.contains('\0') {
            bail!("path must not contain NUL");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ok() {
        assert_eq!(normalize_path("/env/dev/url").unwrap(), "/env/dev/url");
        assert_eq!(normalize_path("/env//dev/").unwrap(), "/env/dev");
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
}
