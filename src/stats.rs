//! Append-only redaction-count log. Powers the TUI activity panel.
//!
//! One JSONL line per non-zero trigger: `{"ts":"<rfc3339>","count":N}`. No
//! text, no spans, no pattern names - just a counter so the user can see "X
//! redactions in the last 24h" without us storing anything sensitive.
//!
//! On Unix the file is created 0o600. Rotation halves the log once it crosses
//! 1 MiB (~20k entries; decades of normal use) so a long-running install
//! cannot accumulate an unbounded log.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::config::{atomic_write, base_dir};

const STATS_FILENAME: &str = "stats.jsonl";
const ROTATE_AT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StatBuckets {
    pub last_24h: u64,
    pub last_7d: u64,
    pub last_30d: u64,
    pub last_90d: u64,
    pub total: u64,
    pub file_exists: bool,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    ts: String,
    count: u64,
}

pub fn stats_path() -> PathBuf {
    let mut p = base_dir();
    p.push(STATS_FILENAME);
    p
}

fn now_rfc3339() -> String {
    let dt: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    dt.to_rfc3339()
}

/// Append `count` to the stats log. No-op when `count == 0`. Best-effort:
/// failures are logged but never propagated, so a stats write never breaks
/// the user-visible redaction flow.
pub fn append(count: u64) {
    if count == 0 {
        return;
    }
    if let Err(e) = append_inner(count) {
        log::warn!("stats append failed: {e}");
    }
}

fn append_inner(count: u64) -> anyhow::Result<()> {
    let path = stats_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let entry = Entry {
        ts: now_rfc3339(),
        count,
    };
    let mut line = serde_json::to_string(&entry).context("encode stats entry")?;
    line.push('\n');

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).context("open stats.jsonl")?;
    f.write_all(line.as_bytes()).context("write stats entry")?;
    drop(f);

    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > ROTATE_AT_BYTES {
            let _ = rotate(&path);
        }
    }
    Ok(())
}

fn rotate(path: &Path) -> anyhow::Result<()> {
    let f = File::open(path)?;
    let lines: Vec<String> = BufReader::new(f).lines().map_while(Result::ok).collect();
    let drop_n = lines.len() / 2;
    let kept = &lines[drop_n..];
    let mut buf = String::with_capacity(kept.len() * 64);
    for l in kept {
        buf.push_str(l);
        buf.push('\n');
    }
    atomic_write(path, buf.as_bytes())?;
    Ok(())
}

pub fn read_buckets() -> StatBuckets {
    read_buckets_at(SystemTime::now())
}

pub fn read_buckets_at(now: SystemTime) -> StatBuckets {
    let path = stats_path();
    let f = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return StatBuckets::default(),
    };
    let mut buckets = StatBuckets {
        file_exists: true,
        ..StatBuckets::default()
    };
    let now_dt: chrono::DateTime<chrono::Utc> = now.into();
    let h24 = chrono::Duration::hours(24);
    let d7 = chrono::Duration::days(7);
    let d30 = chrono::Duration::days(30);
    let d90 = chrono::Duration::days(90);

    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let Ok(entry) = serde_json::from_str::<Entry>(&line) else {
            continue;
        };
        let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&entry.ts) else {
            continue;
        };
        let dt = parsed.with_timezone(&chrono::Utc);
        let age = now_dt.signed_duration_since(dt);
        if age < chrono::Duration::zero() {
            // Future timestamp (clock skew) - count toward total only.
            buckets.total = buckets.total.saturating_add(entry.count);
            continue;
        }
        buckets.total = buckets.total.saturating_add(entry.count);
        if age < h24 {
            buckets.last_24h = buckets.last_24h.saturating_add(entry.count);
        }
        if age < d7 {
            buckets.last_7d = buckets.last_7d.saturating_add(entry.count);
        }
        if age < d30 {
            buckets.last_30d = buckets.last_30d.saturating_add(entry.count);
        }
        if age < d90 {
            buckets.last_90d = buckets.last_90d.saturating_add(entry.count);
        }
    }
    buckets
}
