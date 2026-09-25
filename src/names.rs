//! Persistent world-key -> name mapping, so a world keeps its address forever.
//!
//! Only the `word-word` label is stored; the base domain is appended at routing time,
//! so moving the relay to a different base domain keeps every world's label.

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Names(Mutex<Connection>);

impl Names {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS names (
                key_hash  TEXT PRIMARY KEY,
                label     TEXT NOT NULL UNIQUE,
                last_seen INTEGER NOT NULL
            )",
        )?;
        Ok(Self(Mutex::new(conn)))
    }

    pub fn label_for(&self, key_hash: &str) -> rusqlite::Result<Option<String>> {
        self.0
            .lock()
            .query_row(
                "SELECT label FROM names WHERE key_hash = ?1",
                [key_hash],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn is_taken(&self, label: &str) -> rusqlite::Result<bool> {
        self.0
            .lock()
            .query_row("SELECT 1 FROM names WHERE label = ?1", [label], |_| Ok(()))
            .optional()
            .map(|row| row.is_some())
    }

    pub fn insert(&self, key_hash: &str, label: &str) -> rusqlite::Result<()> {
        self.0.lock().execute(
            "INSERT INTO names (key_hash, label, last_seen) VALUES (?1, ?2, ?3)",
            params![key_hash, label, now()],
        )?;
        Ok(())
    }

    pub fn touch(&self, label: &str) -> rusqlite::Result<()> {
        self.0.lock().execute(
            "UPDATE names SET last_seen = ?1 WHERE label = ?2",
            params![now(), label],
        )?;
        Ok(())
    }
}

/// World keys are secrets; only their hash is stored.
pub fn hash_key(key: &str) -> String {
    Sha256::digest(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
