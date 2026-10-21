# Contributing

Thanks for your interest in Secret Stripper. This file covers the day-to-day mechanics: how to build, test, lint, and shape your commits so they land cleanly.

## Local development

The repo uses [`just`](https://github.com/casey/just) as the task runner. Install it once:

```bash
cargo install just
```

The single most useful recipe is:

```bash
just ci
```

That runs `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets`. For every pull request CI runs `just ci` plus the secret corpus on Ubuntu. A green local `just ci` is the cheapest way to know your PR will pass the per-PR gates.

Other recipes:

| Recipe | What it does |
|--------|--------------|
| `just build` | `cargo build` |
| `just build-release` | `cargo build --release` |
| `just test` | `cargo test --all-targets` |
| `just lint` | `cargo clippy --all-targets --all-features -- -D warnings` |
| `just fmt` | `cargo fmt --all` |
| `just fmt-check` | `cargo fmt --all -- --check` |
| `just release` | Interactive version bump + commit + tag |
| `just patterns-doc` | Regenerate `DETECTION_COVERAGE.md` from the live catalog |
| `just clean` | `cargo clean` |
| `just` (no args) | List every recipe |

The repo treats `clippy` warnings as bugs. `just lint` must pass before a PR is reviewable.

The build needs only a Rust toolchain (1.89 or newer): the X11, Wayland and D-Bus crates are pure Rust, so no system `-dev` packages are required.

After changing detection patterns, run `just patterns-doc` and commit the regenerated `DETECTION_COVERAGE.md`.

### Tests and the real desktop

With `SECRET_STRIPPER_NO_OS_SIDE_EFFECTS` set, the code that touches your desktop (shortcuts, the update timer, shell rc files, uinput setup) does nothing; tests rely on it. `SECRET_STRIPPER_CONFIG_HOME` moves the config directory. Together they let you try `init` without changing your own setup:

```bash
export SECRET_STRIPPER_NO_OS_SIDE_EFFECTS=1
export SECRET_STRIPPER_CONFIG_HOME="$(mktemp -d)"
cargo run -- init
```

### Manual paste testing

The paste flow depends on the desktop, so test it by hand on what you changed, on X11 and on Wayland when you can:

1. `cargo build --release`, then point the shortcuts at the new binary with `./target/release/secret-stripper register-shortcut`.
2. Copy text with a fake secret, such as `aws=AKIAIOSFODNN7EXAMPLE`, and press the hotkey in a text editor and the terminal hotkey in a terminal.
3. Check that the redacted copy is pasted and that `Ctrl+V` afterwards pastes the original.
4. Run `./target/release/secret-stripper paste --terminal --log-level debug` in a terminal to see each step.

Run `secret-stripper register-shortcut` with your installed binary afterwards to point the shortcuts back at it.

## Commit and PR conventions

All commits follow [Conventional Commits](https://www.conventionalcommits.org/):

- Subject line: `<type>(<optional-scope>): <imperative summary>`, lowercase, under 72 characters, no trailing period.
- Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Use a scope when it sharpens the message: `detect`, `redact`, `image`, `tui`, `paste-guard`, `shortcut`, `config`, `readme`, `deps`, `release`. Skip the scope when the change spans the whole repo.
- Body (optional): blank line, then bullets that explain the *why* and the user-visible impact, not a file-by-file replay. Wrap at ~80 chars.
- Footer (optional): `BREAKING CHANGE: <description>` for breaks; `Closes #<n>` / `Refs #<n>` for issue links.

Branch names follow the same prefix: `feat/...`, `fix/...`, `chore/...`, `docs/...`.

PR titles use the same Conventional Commit format. PR bodies should lead with a one-paragraph summary, then a `## Test plan` checklist of how you verified the change.

The version-bump rules for cutting a release are derived from the commit log since the last tag:

- A `feat!:` or any `BREAKING CHANGE:` footer = major bump.
- A `feat:` commit = minor bump.
- A `fix:`, `perf:`, or `refactor:` commit = patch bump.
- `chore:`, `docs:`, `style:`, `test:`, `ci:` alone do not warrant a release.

## Filing issues

Bugs, feature requests, and missing-pattern reports each have a dedicated GitHub Issue form. For a bug, include the version (`secret-stripper --version`), distribution, desktop environment, session type (X11 or Wayland), reproduction steps, and expected vs actual behavior; the bug form has a block that collects these. For a feature, lead with the problem you are trying to solve before proposing a solution. To report a secret/PII format that should be redacted but isn't, use the "Missing pattern" form and provide a synthetic example - never a real secret.
