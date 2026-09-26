//! Persistent world-key -> name mapping, so a world keeps its address forever.
//!
//! Only the `word-word` label is stored; the base domain is appended at routing time,
//! so moving the relay to a different base domain keeps every world's label.

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix seconds. Injectable so tests can move time forward.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    })
}

/// A name unused for this long is freed.
pub const EXPIRY_SECS: i64 = 90 * 24 * 60 * 60;

pub struct Names {
    conn: Mutex<Connection>,
    clock: Clock,
}

impl Names {
    pub fn open(path: &Path, clock: Clock) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS names (
                key_hash  TEXT PRIMARY KEY,
                label     TEXT NOT NULL UNIQUE,
                last_seen INTEGER NOT NULL
            )",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            clock,
        })
    }

    pub fn label_for(&self, key_hash: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .lock()
            .query_row(
                "SELECT label FROM names WHERE key_hash = ?1",
                [key_hash],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn is_taken(&self, label: &str) -> rusqlite::Result<bool> {
        self.conn
            .lock()
            .query_row("SELECT 1 FROM names WHERE label = ?1", [label], |_| Ok(()))
            .optional()
            .map(|row| row.is_some())
    }

    pub fn insert(&self, key_hash: &str, label: &str) -> rusqlite::Result<()> {
        self.conn.lock().execute(
            "INSERT INTO names (key_hash, label, last_seen) VALUES (?1, ?2, ?3)",
            params![key_hash, label, (self.clock)()],
        )?;
        Ok(())
    }

    pub fn touch(&self, label: &str) -> rusqlite::Result<()> {
        self.conn.lock().execute(
            "UPDATE names SET last_seen = ?1 WHERE label = ?2",
            params![(self.clock)(), label],
        )?;
        Ok(())
    }

    /// Frees names unused for `EXPIRY_SECS`, except those `is_live` (a world online
    /// for months hasn't been re-registered, but is in use).
    pub fn expire(&self, is_live: impl Fn(&str) -> bool) -> rusqlite::Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT label FROM names WHERE last_seen < ?1")?;
        let stale = stmt
            .query_map([(self.clock)() - EXPIRY_SECS], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for label in stale.iter().filter(|label| !is_live(label)) {
            conn.execute("DELETE FROM names WHERE label = ?1", [label])?;
        }
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
