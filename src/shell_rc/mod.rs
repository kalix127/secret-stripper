use std::path::{Path, PathBuf};

use crate::config::atomic_write;

pub const BLOCK_BEGIN: &str = "# ---- secret-stripper paste-guard ----";
pub const BLOCK_END: &str = "# ---- secret-stripper paste-guard ----";

/// Substring that uniquely identifies a paste-guard alias line in the user's
/// rc file. `uninstall` falls back to this when the fence comments have
/// been stripped or edited.
pub const ALIAS_MARKER: &str = "secret-stripper paste-guard --";

const ENV_NO_OS: &str = "SECRET_STRIPPER_NO_OS_SIDE_EFFECTS";

fn os_side_effects_allowed() -> bool {
    std::env::var_os(ENV_NO_OS).is_none()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    /// Pick the shell from `$SHELL`. `None` on Windows, an unknown shell, or
    /// when the variable is missing - the caller falls back to printing
    /// generic instructions in those cases.
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("SHELL").ok()?;
        let name = Path::new(&raw).file_name()?.to_string_lossy().to_string();
        match name.as_str() {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            _ => None,
        }
    }

    pub fn rc_path(&self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        Some(match self {
            Shell::Bash => home.join(".bashrc"),
            Shell::Zsh => home.join(".zshrc"),
            Shell::Fish => home.join(".config/fish/config.fish"),
        })
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
        }
    }

    /// Fish uses `alias name 'target'` instead of POSIX `alias name='target'`.
    fn alias_line(&self, name: &str, target: &str) -> String {
        match self {
            Shell::Fish => format!("alias {} '{}'", name, target),
            _ => format!("alias {}='{}'", name, target),
        }
    }
}

/// Render the alias snippet a user would paste into their shell rc. Each
/// alias routes one detected AI TUI through `paste-guard`. Fenced with
/// sentinel comments so the user (or a future script) can find / remove the
/// block later.
pub fn render_alias_snippet(shell: Shell, binaries: &[&str]) -> String {
    let mut out = String::new();
    out.push_str(BLOCK_BEGIN);
    out.push('\n');
    for b in binaries {
        let target = format!("secret-stripper paste-guard -- {}", b);
        out.push_str(&shell.alias_line(b, &target));
        out.push('\n');
    }
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// Remove a previously-pasted paste-guard alias block from `rc_path`.
///
/// Returns `Ok(true)` if a block was found and removed, `Ok(false)` if no
/// block was present (file missing, empty, or no paste-guard markers).
/// Atomic write via tempfile + rename so a torn rc is impossible.
///
/// Honors `SECRET_STRIPPER_NO_OS_SIDE_EFFECTS`: returns `Ok(false)` without
/// touching the file when set, so tests can exercise `run_uninstall`
/// without writing to the developer's real shell rc.
///
/// Detection strategy, in order:
/// 1. Two adjacent lines both equal to `BLOCK_BEGIN` (the labelled fence) -
///    everything between them is removed, fences included.
/// 2. Fallback: any line containing `ALIAS_MARKER` is removed individually.
///    Catches the case where the user kept the alias line but deleted the
///    fence comments.
pub fn uninstall_aliases(rc_path: &Path) -> anyhow::Result<bool> {
    if !os_side_effects_allowed() {
        return Ok(false);
    }
    let existing = match std::fs::read_to_string(rc_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let (new_contents, changed) = strip_paste_guard_block(&existing);
    if !changed {
        return Ok(false);
    }
    atomic_write(rc_path, new_contents.as_bytes())?;
    Ok(true)
}

/// Pure string transform behind `uninstall_aliases`. Lets the tests exercise
/// the parser without hitting the filesystem.
pub fn strip_paste_guard_block(contents: &str) -> (String, bool) {
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut changed = false;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_end() == BLOCK_BEGIN {
            // Find the matching closing fence at the same trimmed value.
            // `BLOCK_BEGIN` and `BLOCK_END` are identical strings so the
            // pair is just the next occurrence.
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_end() != BLOCK_END {
                j += 1;
            }
            if j < lines.len() {
                // Skip lines [i, j] inclusive.
                changed = true;
                i = j + 1;
                continue;
            }
            // Unterminated fence - leave the file alone rather than chew
            // an arbitrary tail; user can clean by hand.
        }
        if lines[i].contains(ALIAS_MARKER) {
            changed = true;
            i += 1;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    // Collapse a run of consecutive blank lines that the removal may have
    // produced. Conservative: keep at most one blank between non-blank
    // lines.
    let joined: String = out.into_iter().collect();
    let collapsed = collapse_blank_runs(&joined);
    (collapsed, changed)
}

fn collapse_blank_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank_run = 0;
    for line in s.split_inclusive('\n') {
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run <= 1 {
                out.push_str(line);
            }
        } else {
            blank_run = 0;
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_bash_format() {
        let s = render_alias_snippet(Shell::Bash, &["claude", "codex"]);
        assert!(s.contains("alias claude='secret-stripper paste-guard -- claude'"));
        assert!(s.contains("alias codex='secret-stripper paste-guard -- codex'"));
        assert!(s.contains(BLOCK_BEGIN));
        assert!(s.contains(BLOCK_END));
    }

    #[test]
    fn snippet_fish_format_differs() {
        let s = render_alias_snippet(Shell::Fish, &["claude"]);
        assert!(s.contains("alias claude 'secret-stripper paste-guard -- claude'"));
    }

    #[test]
    fn display_name_round_trip() {
        assert_eq!(Shell::Bash.display_name(), "bash");
        assert_eq!(Shell::Zsh.display_name(), "zsh");
        assert_eq!(Shell::Fish.display_name(), "fish");
    }

    #[test]
    fn strip_removes_fenced_block() {
        let input = "export FOO=1\n\
                     # ---- secret-stripper paste-guard ----\n\
                     alias claude='secret-stripper paste-guard -- claude'\n\
                     alias codex='secret-stripper paste-guard -- codex'\n\
                     # ---- secret-stripper paste-guard ----\n\
                     export BAR=2\n";
        let (out, changed) = strip_paste_guard_block(input);
        assert!(changed);
        assert!(!out.contains("secret-stripper paste-guard"));
        assert!(out.contains("export FOO=1"));
        assert!(out.contains("export BAR=2"));
    }

    #[test]
    fn strip_removes_orphan_alias_without_fence() {
        let input = "export FOO=1\n\
                     alias claude='secret-stripper paste-guard -- claude'\n\
                     export BAR=2\n";
        let (out, changed) = strip_paste_guard_block(input);
        assert!(changed);
        assert!(!out.contains("secret-stripper paste-guard"));
        assert!(out.contains("export FOO=1"));
        assert!(out.contains("export BAR=2"));
    }

    #[test]
    fn strip_no_op_when_clean() {
        let input = "export FOO=1\nexport BAR=2\n";
        let (out, changed) = strip_paste_guard_block(input);
        assert!(!changed);
        assert_eq!(out, input);
    }

    #[test]
    fn strip_collapses_blank_runs() {
        let input = "export FOO=1\n\n\n\n# ---- secret-stripper paste-guard ----\n\
                     alias x='secret-stripper paste-guard -- x'\n\
                     # ---- secret-stripper paste-guard ----\n\n\n\nexport BAR=2\n";
        let (out, changed) = strip_paste_guard_block(input);
        assert!(changed);
        // No more than one consecutive blank line remains.
        assert!(!out.contains("\n\n\n"));
    }

    #[test]
    fn uninstall_aliases_round_trip_with_real_file() {
        let saved = std::env::var_os(ENV_NO_OS);
        std::env::remove_var(ENV_NO_OS);

        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        let original = "export FOO=1\nexport BAR=2\n";
        let with_block = format!(
            "{}# ---- secret-stripper paste-guard ----\n\
             alias claude='secret-stripper paste-guard -- claude'\n\
             # ---- secret-stripper paste-guard ----\n",
            original
        );
        std::fs::write(&rc, &with_block).unwrap();

        let removed = uninstall_aliases(&rc).unwrap();
        assert!(removed);
        let after = std::fs::read_to_string(&rc).unwrap();
        assert!(!after.contains("secret-stripper paste-guard"));
        assert!(after.contains("export FOO=1"));

        if let Some(v) = saved {
            std::env::set_var(ENV_NO_OS, v);
        }
    }

    #[test]
    fn uninstall_no_op_when_env_set() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        std::fs::write(&rc, "alias x='secret-stripper paste-guard -- x'\n").unwrap();
        std::env::set_var(ENV_NO_OS, "1");
        let removed = uninstall_aliases(&rc).unwrap();
        std::env::remove_var(ENV_NO_OS);
        assert!(!removed);
        // File untouched.
        assert!(std::fs::read_to_string(&rc)
            .unwrap()
            .contains("secret-stripper paste-guard"));
    }
}
