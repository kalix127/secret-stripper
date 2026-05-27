# Changelog

All notable changes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-05-27

### Added

- `secret-stripper redact` subcommand: read stdin, print the redacted text to stdout. Designed for shell pipelines and used internally by `paste-guard`.
- `secret-stripper paste-guard -- <cmd>` subcommand: run a child process inside a PTY and rewrite any bracketed-paste payload sent on stdin, redacting secrets in flight. Targets AI terminal UIs like Claude Code, Codex CLI, aider, Gemini CLI, Continue, and opencode.
- `init` walks `PATH` for a catalog of AI TUIs and prints a ready-to-copy shell alias snippet that routes each through `paste-guard`. Snippet is tailored to the detected shell (bash, zsh, fish) and names the exact rc file to paste into; on Windows or an unknown shell it falls back to generic instructions. The user copies it manually.

### Fixed

- gate patterns_doc behind feature flag; drop flaky CI badge

### Documentation

- Update README
- replace static banner with animated demo gif

### Other

- drop cross-platform environment approval gate
- replace makefile with justfile


## [1.0.0] - 2026-05-24

### Added

- Initial public release.

[Unreleased]: https://github.com/kalix127/secret-stripper/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/kalix127/secret-stripper/releases/tag/v1.1.0
[1.0.0]: https://github.com/kalix127/secret-stripper/releases/tag/v1.0.0
