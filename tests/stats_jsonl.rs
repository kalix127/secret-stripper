use secret_stripper::stats;
use serial_test::serial;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

/// Same isolation helper as tests/config_fs.rs: point the config base dir at a
/// tempdir for the duration of the closure. Tests are serialized on the
/// `config_env` key because the env var is process-global.
fn with_isolated_home<R>(f: impl FnOnce(&Path) -> R) -> R {
    let tmp = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("SECRET_STRIPPER_CONFIG_HOME");
    std::env::set_var("SECRET_STRIPPER_CONFIG_HOME", tmp.path());
    let out = f(tmp.path());
    match prev {
        Some(v) => std::env::set_var("SECRET_STRIPPER_CONFIG_HOME", v),
        None => std::env::remove_var("SECRET_STRIPPER_CONFIG_HOME"),
    }
    out
}

#[test]
#[serial(config_env)]
fn append_creates_jsonl_with_count_and_timestamp() {
    with_isolated_home(|home| {
        stats::append(3);
        let path = home.join("secret-stripper").join("stats.jsonl");
        assert!(path.exists(), "stats.jsonl should exist after append");
        let text = std::fs::read_to_string(&path).unwrap();
        let line = text.lines().next().expect("at least one line");
        assert!(line.contains("\"count\":3"), "count present: {line}");
        assert!(line.contains("\"ts\":\""), "ts present: {line}");
        // RFC3339 sanity check.
        assert!(line.contains('T') && (line.contains('Z') || line.contains('+')));
    });
}

#[test]
#[serial(config_env)]
fn zero_count_is_a_no_op() {
    with_isolated_home(|home| {
        stats::append(0);
        let path = home.join("secret-stripper").join("stats.jsonl");
        assert!(!path.exists(), "zero count must not create the file");
    });
}

#[test]
#[serial(config_env)]
fn multiple_appends_produce_one_line_each() {
    with_isolated_home(|home| {
        stats::append(1);
        stats::append(2);
        stats::append(4);
        let path = home.join("secret-stripper").join("stats.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        let total_count: u64 = lines
            .iter()
            .filter_map(|l| {
                let key = "\"count\":";
                let i = l.find(key)? + key.len();
                let rest = &l[i..];
                let end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                rest[..end].parse::<u64>().ok()
            })
            .sum();
        assert_eq!(total_count, 7);
    });
}

#[test]
#[serial(config_env)]
fn read_buckets_reports_empty_when_missing() {
    with_isolated_home(|_| {
        let b = stats::read_buckets();
        assert!(!b.file_exists);
        assert_eq!(b.total, 0);
        assert_eq!(b.last_24h, 0);
        assert_eq!(b.last_7d, 0);
        assert_eq!(b.last_30d, 0);
        assert_eq!(b.last_90d, 0);
    });
}

#[test]
#[serial(config_env)]
fn read_buckets_partitions_by_age() {
    with_isolated_home(|home| {
        let path = home.join("secret-stripper");
        std::fs::create_dir_all(&path).unwrap();
        let stats_file = path.join("stats.jsonl");

        // Hand-craft a file with known timestamps at three buckets:
        // - 1 hour ago: count 5  -> hits 24h, 7d, 30d, 90d
        // - 3 days ago: count 7  -> hits      7d, 30d, 90d
        // - 60 days ago: count 9 -> hits             90d
        // - 200 days ago: count 11 -> total only
        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        let mut text = String::new();
        for (offset_seconds, count) in [
            (3600u64, 5u64),
            (3 * 86400, 7),
            (60 * 86400, 9),
            (200 * 86400, 11),
        ] {
            let then = now - chrono::Duration::seconds(offset_seconds as i64);
            text.push_str(&format!(
                "{{\"ts\":\"{}\",\"count\":{}}}\n",
                then.to_rfc3339(),
                count
            ));
        }
        std::fs::write(&stats_file, text).unwrap();

        let b = stats::read_buckets();
        assert!(b.file_exists);
        assert_eq!(b.last_24h, 5);
        assert_eq!(b.last_7d, 5 + 7);
        assert_eq!(b.last_30d, 5 + 7);
        assert_eq!(b.last_90d, 5 + 7 + 9);
        assert_eq!(b.total, 5 + 7 + 9 + 11);
    });
}

#[test]
#[serial(config_env)]
fn read_buckets_at_injected_now() {
    with_isolated_home(|home| {
        let path = home.join("secret-stripper");
        std::fs::create_dir_all(&path).unwrap();
        let stats_file = path.join("stats.jsonl");

        // Anchor at a fixed moment so the test does not race the wall clock.
        let anchor: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::parse_from_rfc3339("2026-05-01T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc);

        let entries = [
            ("2026-04-30T12:00:00Z", 1u64), // 24h ago exactly -> NOT < 24h
            ("2026-04-30T13:00:00Z", 2),    // 23h ago -> in 24h
            ("2026-04-24T12:00:00Z", 3),    // 7d ago exactly -> NOT < 7d
            ("2026-04-25T12:00:00Z", 4),    // 6d ago -> in 7d
        ];
        let mut text = String::new();
        for (ts, count) in entries {
            text.push_str(&format!("{{\"ts\":\"{}\",\"count\":{}}}\n", ts, count));
        }
        std::fs::write(&stats_file, text).unwrap();

        let anchor_st: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_secs(anchor.timestamp() as u64);
        let b = stats::read_buckets_at(anchor_st);
        // The 24h-ago entry is NOT < 24h (boundary excluded) but IS < 7d.
        // The 7d-ago entry is NOT < 7d (boundary excluded) but IS < 30d.
        assert_eq!(b.last_24h, 2);
        assert_eq!(b.last_7d, 1 + 2 + 4);
        assert_eq!(b.total, 1 + 2 + 3 + 4);
    });
}

#[test]
#[serial(config_env)]
fn malformed_lines_are_skipped() {
    with_isolated_home(|home| {
        let path = home.join("secret-stripper");
        std::fs::create_dir_all(&path).unwrap();
        let stats_file = path.join("stats.jsonl");

        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        let valid = format!("{{\"ts\":\"{}\",\"count\":42}}\n", now.to_rfc3339());
        let text = format!(
            "{valid}\n\
             garbage line\n\
             {{\"ts\":\"not-a-date\",\"count\":1}}\n\
             {{\"count\":2}}\n\
             {valid}"
        );
        std::fs::write(&stats_file, text).unwrap();

        let b = stats::read_buckets();
        assert_eq!(b.total, 84, "only the two valid lines count");
    });
}

#[cfg(unix)]
#[test]
#[serial(config_env)]
fn append_creates_file_0o600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    with_isolated_home(|home| {
        stats::append(1);
        let path = home.join("secret-stripper").join("stats.jsonl");
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "stats.jsonl must be 0o600, got {mode:o}");
    });
}
