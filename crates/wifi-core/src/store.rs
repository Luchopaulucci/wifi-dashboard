use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::error::{CoreError, Result};
use crate::types::{now_ms, HistoryPoint, HistoryRange, ProbeInstant};

const RETENTION_MS: u64 = 8 * 24 * 60 * 60 * 1000;
const STATS_WINDOW: usize = 20;

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CoreError::Storage(e.to_string()))?;
        }
        let conn = Connection::open(&path).map_err(|e| CoreError::Storage(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS ping_samples (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts INTEGER NOT NULL,
               target TEXT NOT NULL,
               latency_ms REAL,
               lost INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_ping_ts ON ping_samples(ts);
             CREATE INDEX IF NOT EXISTS idx_ping_target_ts ON ping_samples(target, ts);",
        )
        .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(Self { conn, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn insert_sample(
        &self,
        ts_ms: u64,
        target: &str,
        latency_ms: Option<f64>,
        lost: bool,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO ping_samples (ts, target, latency_ms, lost) VALUES (?1, ?2, ?3, ?4)",
                params![ts_ms as i64, target, latency_ms, if lost { 1 } else { 0 }],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ping_samples", [], |r| r.get(0))
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(n as u64)
    }

    pub fn prune(&self) -> Result<usize> {
        let cutoff = now_ms().saturating_sub(RETENTION_MS) as i64;
        let n = self
            .conn
            .execute("DELETE FROM ping_samples WHERE ts < ?1", params![cutoff])
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(n)
    }

    pub fn history(&self, target: &str, range: HistoryRange) -> Result<Vec<HistoryPoint>> {
        let now = now_ms();
        let from = now.saturating_sub(range.window_ms()) as i64;
        let bucket = range.bucket_ms() as i64;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT (ts / ?1) * ?1 AS bucket,
                        AVG(latency_ms),
                        AVG(lost) * 100.0,
                        COUNT(*)
                 FROM ping_samples
                 WHERE target = ?2 AND ts >= ?3
                 GROUP BY bucket
                 ORDER BY bucket",
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(params![bucket, target, from], |row| {
                let ts: i64 = row.get(0)?;
                let latency: Option<f64> = row.get(1)?;
                let loss: f64 = row.get(2)?;
                Ok(HistoryPoint {
                    ts_ms: ts as u64,
                    latency_ms: latency,
                    loss_pct: loss,
                    jitter_ms: None,
                })
            })
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| CoreError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn instant_stats(&self, target: &str, label: &str) -> Result<ProbeInstant> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT latency_ms, lost FROM ping_samples
                 WHERE target = ?1 ORDER BY ts DESC LIMIT ?2",
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(params![target, STATS_WINDOW as i64], |row| {
                let lat: Option<f64> = row.get(0)?;
                let lost: i64 = row.get(1)?;
                Ok((lat, lost != 0))
            })
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let mut samples = Vec::new();
        for row in rows {
            samples.push(row.map_err(|e| CoreError::Storage(e.to_string()))?);
        }
        let last = samples.first().cloned();
        let lost_count = samples.iter().filter(|(_, lost)| *lost).count();
        let loss_pct = if samples.is_empty() {
            None
        } else {
            Some((lost_count as f64) * 100.0 / samples.len() as f64)
        };
        let lats: Vec<f64> = samples
            .iter()
            .filter_map(|(l, lost)| if *lost { None } else { *l })
            .collect();
        let jitter = jitter_ms(&lats);
        Ok(ProbeInstant {
            target: target.to_string(),
            label: label.to_string(),
            latency_ms: last.and_then(|(l, lost)| if lost { None } else { l }),
            lost: last.map(|(_, lost)| lost).unwrap_or(true),
            jitter_ms: jitter,
            loss_pct,
        })
    }
}

fn jitter_ms(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() as f64 - 1.0);
    Some(var.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_aggregates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("t.db")).unwrap();
        let now = 1_700_000_000_000u64;
        store
            .insert_sample(now, "1.1.1.1", Some(20.0), false)
            .unwrap();
        store
            .insert_sample(now + 1000, "1.1.1.1", None, true)
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
        let stats = store.instant_stats("1.1.1.1", "Internet").unwrap();
        assert!(stats.loss_pct.unwrap() > 0.0);
    }
}
