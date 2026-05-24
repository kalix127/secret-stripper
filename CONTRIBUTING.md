# Contributing

Thanks for your interest in Secret Stripper. This file covers the day-to-day mechanics: how to build, test, lint, and shape your commits so they land cleanly.

## Local development

The repo ships a `Makefile` that wraps the cargo commands CI runs. The single most useful target is:

```bash
make ci
```

That runs `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets`. For every pull request CI runs `make ci` plus the secret corpus on Linux, and a Windows cross-compile check via mingw. The full 3-OS build + filesystem integration matrix (`make build` + `make test-fs` on Ubuntu / macOS / Windows) runs on `pull_request_review: approved`, post-merge to `main`, or manual `workflow_dispatch`. A green local `make ci` is the cheapest way to know your PR will pass the per-PR gates.

Other targets:

| Target | What it does |
|--------|--------------|
| `make build` | `cargo build` |
| `make build-release` | `cargo build --release` |
| `make test` | `cargo test --all-targets` |
| `make test-fs` | `cargo test --test config_fs` (filesystem seam integration; what CI runs on macOS/Windows) |
| `make lint` | `cargo clippy --all-targets --all-features -- -D warnings` |
| `make fmt` | `cargo fmt --all` |
| `make fmt-check` | `cargo fmt --all -- --check` |
| `make clean` | `cargo clean` |
| `make help` | Print the target list |

Linux contributors need a few system packages so `arboard` and `notify-rust` link:

```bash
sudo apt-get install -y \
    libxcb1-dev libxcb-shape0-dev libxcb-xfixes0-dev \
    libxkbcommon-dev libdbus-1-dev
```

macOS and Windows need no extra system packages. Windows contributors need `make` on `PATH` (`choco install make`) to use the Makefile targets; otherwise invoke the underlying `cargo` commands directly.

The repo treats `clippy` warnings as bugs. `make lint` must pass before a PR is reviewable.

## Commit and PR conventions

All commits follow [Conventional Commits](https://www.conventionalcommits.org/):

- Subject line: `<type>(<optional-scope>): <imperative summary>`, lowercase, under 72 characters, no trailing period.
- Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Use a scope when it sharpens the message: `fix(shortcut):`, `feat(detect):`. Skip the scope when the change spans the whole repo.
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

Bugs, feature requests, and missing-pattern reports each have a dedicated GitHub Issue form. For a bug, include the OS, version (`secret-stripper --version`), reproduction steps, expected vs actual behavior. For a feature, lead with the problem you are trying to solve before proposing a solution. To report a secret/PII format that should be redacted but isn't, use the "Missing pattern" form and provide a synthetic example - never a real secret.
