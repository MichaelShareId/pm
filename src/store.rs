use std::fs::{File, OpenOptions};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use rusqlite::{params, Connection, OptionalExtension};

use crate::config::DataDir;

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
            PRAGMA journal_mode=WAL;
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
        // Exact prefix match on path segments: `/env/dev` matches `/env/dev` and `/env/dev/...`
        let like = format!("{prefix}/%");
        let mut stmt = self.conn.prepare(
            "SELECT path, nonce, ciphertext FROM secrets
             WHERE path = ?1 OR path LIKE ?2 ESCAPE '\\'
             ORDER BY path",
        )?;
        let rows = stmt
            .query_map(params![prefix, like], |row| {
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
                let like = format!("{prefix}/%");
                let mut stmt = self.conn.prepare(
                    "SELECT path FROM secrets
                     WHERE path = ?1 OR path LIKE ?2
                     ORDER BY path",
                )?;
                let rows = stmt
                    .query_map(params![prefix, like], |row| row.get(0))?
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
