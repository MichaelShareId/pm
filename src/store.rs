use std::fs::{File, OpenOptions};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use rusqlite::{params, Connection, OptionalExtension};

use crate::config::DataDir;

/// Segment-exact, case-sensitive prefix match: `/env/dev` (?1) matches `/env/dev` and
/// `/env/dev/...` (?2 = `/env/dev/`). Not `LIKE`: it treats `_`/`%` as wildcards and
/// ignores ASCII case, so `/env/my_app` would also match `/env/myXapp/...`.
const PREFIX_MATCH: &str = "path = ?1 OR substr(path, 1, length(?2)) = ?2";

pub struct Store {
    conn: Connection,
    lock_path: std::path::PathBuf,
}

pub struct SecretRow {
    pub path: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct WriteLock {
    _file: File,
}

impl Store {
    pub fn open(data: &DataDir) -> Result<Self> {
        data.ensure_dir()?;
        let db_path = data.keys_db();
        let conn = Connection::open(&db_path)
            .with_context(|| format!("open db {}", db_path.display()))?;
        conn.execute_batch(
            "
            -- Rollback journal: commits land in keys.db itself, so git sees them.
            -- (WAL would leave changes in keys.db-wal until the connection closes.)
            PRAGMA journal_mode=DELETE;
            -- Zero deleted/overwritten content instead of leaving old ciphertext in free
            -- pages of keys.db (and so in every later git snapshot).
            PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS secrets (
                path TEXT PRIMARY KEY NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self {
            conn,
            lock_path: data.lock_file(),
        })
    }

    pub fn write_lock(&self) -> Result<WriteLock> {
        if let Some(parent) = self.lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open lock {}", self.lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("acquire write lock {}", self.lock_path.display()))?;
        Ok(WriteLock { _file: file })
    }

    pub fn upsert(&self, path: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<()> {
        let now = now_secs()?;
        self.conn.execute(
            "
            INSERT INTO secrets (path, nonce, ciphertext, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(path) DO UPDATE SET
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                updated_at = excluded.updated_at
            ",
            params![path, nonce, ciphertext, now],
        )?;
        Ok(())
    }

    pub fn get(&self, path: &str) -> Result<Option<SecretRow>> {
        self.conn
            .query_row(
                "SELECT path, nonce, ciphertext FROM secrets WHERE path = ?1",
                params![path],
                |row| {
                    Ok(SecretRow {
                        path: row.get(0)?,
                        nonce: row.get(1)?,
                        ciphertext: row.get(2)?,
                    })
                },
            )
            .optional()
            .context("query secret")
    }

    pub fn delete(&self, path: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM secrets WHERE path = ?1", params![path])?;
        Ok(n > 0)
    }

    pub fn list_all(&self) -> Result<Vec<SecretRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, nonce, ciphertext FROM secrets ORDER BY path",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SecretRow {
                    path: row.get(0)?,
                    nonce: row.get(1)?,
                    ciphertext: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_prefix(&self, prefix: &str) -> Result<Vec<SecretRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT path, nonce, ciphertext FROM secrets WHERE {PREFIX_MATCH} ORDER BY path"
        ))?;
        let rows = stmt
            .query_map(params![prefix, format!("{prefix}/")], |row| {
                Ok(SecretRow {
                    path: row.get(0)?,
                    nonce: row.get(1)?,
                    ciphertext: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_paths(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        match prefix {
            None => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT path FROM secrets ORDER BY path")?;
                let rows = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
            Some(prefix) => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT path FROM secrets WHERE {PREFIX_MATCH} ORDER BY path"
                ))?;
                let rows = stmt
                    .query_map(params![prefix, format!("{prefix}/")], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
        }
    }
}

fn now_secs() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_data(name: &str) -> DataDir {
        let dir = std::env::temp_dir().join(format!("pm-store-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        DataDir::from_path(dir)
    }

    #[test]
    fn write_reaches_keys_db_while_store_open() {
        let data = tmp_data("journal");
        // Simulate a vault created by an older build that used WAL.
        let legacy = Connection::open(data.keys_db()).unwrap();
        legacy.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
        drop(legacy);

        let store = Store::open(&data).unwrap();
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");

        store.upsert("/a", b"n", b"c").unwrap();
        // Store still open (as when commit_db runs): the change must already be in keys.db.
        assert!(!data.root().join("keys.db-wal").exists());
        let other = Connection::open(data.keys_db()).unwrap();
        let n: i64 = other
            .query_row("SELECT count(*) FROM secrets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let _ = std::fs::remove_dir_all(data.root());
    }

    #[test]
    fn commit_while_store_open_captures_change() {
        let data = tmp_data("git");
        crate::gitutil::init_repo(&data).unwrap();
        let store = Store::open(&data).unwrap();
        crate::gitutil::commit_db(&data, "init").unwrap();

        store.upsert("/a", b"n", b"c").unwrap();
        crate::gitutil::commit_db(&data, "set /a").unwrap();

        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(data.root())
                .args(args)
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(git(&["log", "--format=%s"]), "set /a\ninit\n");
        assert_eq!(git(&["status", "--porcelain"]), "");
        let _ = std::fs::remove_dir_all(data.root());
    }

    #[test]
    fn prefix_match_is_exact() {
        let data = tmp_data("prefix");
        let store = Store::open(&data).unwrap();
        for path in [
            "/env/my_app",
            "/env/my_app/key",
            "/env/myXapp/key",
            "/env/MY_APP/key",
            "/env/my_apps/key",
            "/env/100%/key",
            "/env/100x/key",
        ] {
            store.upsert(path, b"n", b"c").unwrap();
        }

        assert_eq!(
            store.list_paths(Some("/env/my_app")).unwrap(),
            vec!["/env/my_app", "/env/my_app/key"]
        );
        let rows: Vec<String> = store
            .list_prefix("/env/my_app")
            .unwrap()
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(rows, vec!["/env/my_app", "/env/my_app/key"]);
        assert_eq!(store.list_paths(Some("/env/100%")).unwrap(), vec!["/env/100%/key"]);
        let _ = std::fs::remove_dir_all(data.root());
    }

    #[test]
    fn removed_and_overwritten_values_leave_no_trace_in_file() {
        let data = tmp_data("secure-delete");
        let store = Store::open(&data).unwrap();
        store.upsert("/a", b"n", b"OLD-CIPHERTEXT-AAAA").unwrap();
        store.upsert("/a", b"n", b"NEW-CIPHERTEXT-BBBB").unwrap();
        store.upsert("/b", b"n", b"GONE-CIPHERTEXT-CCC").unwrap();
        assert!(store.delete("/b").unwrap());
        drop(store);

        let bytes = std::fs::read(data.keys_db()).unwrap();
        let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b"NEW-CIPHERTEXT-BBBB"));
        assert!(!contains(b"OLD-CIPHERTEXT-AAAA"));
        assert!(!contains(b"GONE-CIPHERTEXT-CCC"));
        let _ = std::fs::remove_dir_all(data.root());
    }
}
