use std::env;
use std::path::PathBuf;

/// One AI TUI tool secret-stripper knows how to wrap with `paste-guard`.
/// `binary` is the executable name to look up on PATH; `label` is the
/// human-readable name shown in the init prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiTui {
    pub binary: &'static str,
    pub label: &'static str,
}

/// Add a new entry here to teach `init` about another AI TUI. The matching
/// binary name must be what users actually invoke from a shell prompt.
pub const KNOWN: &[AiTui] = &[
    AiTui {
        binary: "claude",
        label: "Claude Code",
    },
    AiTui {
        binary: "codex",
        label: "OpenAI Codex CLI",
    },
    AiTui {
        binary: "aider",
        label: "aider",
    },
    AiTui {
        binary: "gemini",
        label: "Google Gemini CLI",
    },
    AiTui {
        binary: "continue",
        label: "Continue CLI",
    },
    AiTui {
        binary: "opencode",
        label: "opencode",
    },
];

/// Return the subset of `KNOWN` whose binary is reachable on the current
/// process's PATH. Order matches `KNOWN`.
pub fn detect() -> Vec<AiTui> {
    KNOWN
        .iter()
        .filter(|t| which_on_path(t.binary).is_some())
        .copied()
        .collect()
}

/// Minimal `which` reimplementation - we already shell out for OS integration
/// but adding a `which` crate just to walk PATH is not worth it.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(target_os = "windows")]
        {
            for ext in ["exe", "cmd", "bat", "ps1"] {
                let mut p = candidate.clone();
                p.set_extension(ext);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_catalog_has_unique_binaries() {
        let mut bins: Vec<&str> = KNOWN.iter().map(|t| t.binary).collect();
        let n = bins.len();
        bins.sort();
        bins.dedup();
        assert_eq!(bins.len(), n, "duplicate binary in KNOWN catalog");
    }

    #[test]
    fn detect_finds_stub_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("claude");
        std::fs::write(&bin_path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin_path, perms).unwrap();
        }
        let saved = env::var_os("PATH");
        env::set_var("PATH", dir.path());
        let found = detect();
        if let Some(p) = saved {
            env::set_var("PATH", p);
        }
        assert!(found.iter().any(|t| t.binary == "claude"));
    }
}
