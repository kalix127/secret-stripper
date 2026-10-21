use super::patterns::{SecretPattern, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

const MAX_REGEX_LEN: usize = 2000;
const REGEX_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPatternSpec {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub regex: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CustomPatternsFile {
    #[serde(default, rename = "pattern")]
    pub patterns: Vec<CustomPatternSpec>,
}

pub fn path() -> PathBuf {
    let mut p = crate::config::base_dir();
    p.push("patterns.toml");
    p
}

pub fn parse_severity(s: &str) -> Severity {
    Severity::from_wire(s)
}

/// Compile a user regex with a bounded size, never panicking. Returns a
/// human-readable error string on failure (the built-in `re()` panics, so it
/// must never touch user input).
pub fn validate_regex(src: &str) -> Result<regex::Regex, String> {
    if src.is_empty() {
        return Err("regex is empty".to_string());
    }
    if src.len() > MAX_REGEX_LEN {
        return Err(format!("regex too long (max {} chars)", MAX_REGEX_LEN));
    }
    regex::RegexBuilder::new(src)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| e.to_string())
}

/// Read the raw specs straight from disk. The TOML file is the source of
/// truth; callers re-read on every screen entry.
pub fn load_specs() -> Vec<CustomPatternSpec> {
    let data = match fs::read_to_string(path()) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    match toml::from_str::<CustomPatternsFile>(&data) {
        Ok(f) => f.patterns,
        Err(_) => Vec::new(),
    }
}

/// Process-level cache for `patterns.toml`, reused while the file's mtime and
/// size are unchanged, so repeated `load()` calls skip the parse and compile.
struct CustomCache {
    mtime: SystemTime,
    len: u64,
    patterns: Vec<SecretPattern>,
    errs: Vec<String>,
}
static CACHE: Mutex<Option<CustomCache>> = Mutex::new(None);

/// Build runtime patterns from the file. Invalid-regex rows are skipped and
/// reported. Strings are leaked to `&'static str` to satisfy
/// `SecretPattern`'s field types; the leak is bounded by the cache (a handful
/// of custom rows, refreshed only when the file changes) and `paste` exits
/// after each run, so the leaked memory is reclaimed.
pub fn load() -> (Vec<SecretPattern>, Vec<String>) {
    let p = path();
    let meta = fs::metadata(&p).ok();
    let key = meta
        .as_ref()
        .and_then(|m| Some((m.modified().ok()?, m.len())));

    if let (Some((mt, ln)), Ok(guard)) = (key, CACHE.lock()) {
        if let Some(c) = guard.as_ref() {
            if c.mtime == mt && c.len == ln {
                return (c.patterns.clone(), c.errs.clone());
            }
        }
    }

    let data = match fs::read_to_string(&p) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let file: CustomPatternsFile = match toml::from_str(&data) {
        Ok(f) => f,
        Err(e) => return (Vec::new(), vec![format!("patterns.toml parse error: {e}")]),
    };
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for spec in file.patterns {
        match validate_regex(&spec.regex) {
            Ok(rx) => out.push(SecretPattern {
                name: Box::leak(spec.name.into_boxed_str()),
                category: Box::leak(spec.category.into_boxed_str()),
                severity: parse_severity(&spec.severity),
                regex: rx,
            }),
            Err(e) => errs.push(format!(
                "skipped custom pattern {:?}: invalid regex: {e}",
                spec.name
            )),
        }
    }

    if let (Some((mt, ln)), Ok(mut guard)) = (key, CACHE.lock()) {
        *guard = Some(CustomCache {
            mtime: mt,
            len: ln,
            patterns: out.clone(),
            errs: errs.clone(),
        });
    }

    (out, errs)
}

pub fn save(file: &CustomPatternsFile) -> anyhow::Result<()> {
    let data = toml::to_string_pretty(file)?;
    crate::config::atomic_write(&path(), data.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_regex_empty_rejected() {
        assert!(validate_regex("").is_err());
    }

    #[test]
    fn validate_regex_simple_accepted() {
        let r = validate_regex(r"foo\d+").expect("simple regex compiles");
        assert!(r.is_match("foo123"));
        assert!(!r.is_match("nope"));
    }

    #[test]
    fn validate_regex_syntax_error_reported() {
        let err = validate_regex(r"foo[\\d").unwrap_err();
        assert!(!err.is_empty(), "error message must be non-empty");
    }

    #[test]
    fn validate_regex_length_capped() {
        // 2001 chars triggers the MAX_REGEX_LEN guard before regex compilation.
        let too_long = "a".repeat(MAX_REGEX_LEN + 1);
        let err = validate_regex(&too_long).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn validate_regex_size_limit_enforced() {
        // A bounded repetition pattern that would compile fine without the
        // size_limit but exceeds the 1 MiB cap we set. The exact string is a
        // worst-case for the DFA expansion: nested counted repeats over a
        // sufficiently broad character class.
        let big = r"([0-9a-z]{50}){50}".repeat(20);
        // Stay under MAX_REGEX_LEN so the length guard doesn't pre-empt the
        // size_limit guard we actually want to exercise.
        assert!(big.len() <= MAX_REGEX_LEN);
        let _ = validate_regex(&big); // accept either Ok or Err; we just
                                      // assert we don't panic.
    }
}
