<p align="center">
  <a href="https://github.com/kalix127/secret-stripper"><img src="https://shieldcn.dev/group/badge/platform-Linux-blue+crates/secret-stripper+github/license/kalix127/secret-stripper.svg?variant=secondary" alt="status"></a>
</p>

<img src="https://raw.githubusercontent.com/kalix127/secret-stripper/main/.github/assets/banner.gif" width="100%">

**A small Rust CLI that strips secrets from your clipboard on demand. Bind a hotkey, highlight text, press the chord - the clipboard holds a redacted version. Normal Ctrl+C / Ctrl+V is never intercepted.**

## Contents

- [Quick Start](#quick-start)
- [Supported desktops](#supported-desktops)
- [What It Detects](#what-it-detects)
- [Redact screenshots](#redact-screenshots)
- [Auto-redact paste into AI TUIs](#auto-redact-paste-into-ai-tuis)
- [Contributing](#contributing)
- [Star history](#star-history)
- [License](#license)

---

## Quick Start

One command, no extra setup:

```bash
curl -sSf https://secretstripper.download/install.sh | bash
```

Default chord: `Ctrl+Alt+V`.

**From [crates.io](https://crates.io/crates/secret-stripper) (Rust):**

```bash
cargo install secret-stripper && secret-stripper init
```

**From source (git):**

```bash
cargo install --git https://github.com/kalix127/secret-stripper.git --locked && secret-stripper init
```

After install, copy text as usual. `Ctrl+V` pastes the original; your chord pastes a redacted copy and then restores the original clipboard.

Run `secret-stripper menu` to tune settings, or `secret-stripper --help` for all commands.

---

## Supported desktops

Secret Stripper supports Linux only, on both X11 and Wayland. Version 1.5.x was the last release for macOS and Windows; users on those platforms should stay on it.

| Desktop | Hotkey backend |
|---------|----------------|
| GNOME / Cinnamon / Unity / Budgie / Pantheon | gsettings |
| MATE | gsettings (MATE schema) |
| XFCE | xfconf-query |
| KDE Plasma 5/6 | kwriteconfig + qdbus |

---

## What It Detects

| Category | Examples |
|----------|---------|
| **🔴 Cloud Secrets** | AWS keys, Google API keys, Azure credentials, OpenAI tokens, Stripe keys, Heroku API keys |
| **🔴 Auth Tokens** | GitHub tokens, GitLab tokens, Slack tokens, Discord tokens, JWTs, bearer tokens, NPM tokens |
| **🔴 Cryptographic Keys** | RSA/EC/OpenSSH private keys, PGP private keys, SSH public keys |
| **🔴 PII** | Credit card numbers, SSNs, phone numbers, email addresses, passport numbers |
| **🟠 Connection Strings** | PostgreSQL, MongoDB, Redis, MySQL, JDBC URLs with credentials |
| **🟡 Heuristic** | Unusual strings, env files with secrets, JSON with password fields, base64-encoded content |
| **🟢 Safe** | Normal text, emails, documents - no false alerts |

For the full list of buckets, severity tiers, and patterns, see [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md).

---

## Redaction styles

Pick how detected secrets are replaced from `secret-stripper menu` -> **Redaction Style**:

| Style | Output for `aws=AKIAIOSFODNN7EXAMPLE` |
|-------|----------------------------------------|
| **Marker** (default) | `aws=[REDACTED]` - uses a configurable marker string (eight presets + custom) |
| **Drop** | `aws=` - removes the matched bytes entirely |
| **Typed** | `aws=[AWS_ACCESS_KEY_ID]` - replaces each span with a tag derived from the matched pattern name |
| **Placeholder** | `aws=AKIAIOSFODNN7EXAMPLE` - swaps in a realistic but fake sample value for the matched pattern (an email becomes `user@example.com`, a Stripe key `sk_test_4eC39HqLyjWDarjtT1zdp7dc`) |

The same setting applies to the paste chord, the `redact` pipeline subcommand, and the `paste-guard` AI-TUI wrapper.

---

## Redact screenshots

Secrets often live in screenshots, not just text - a terminal grab, a config pane, an API dashboard. When you press the paste chord and the clipboard holds an image instead of text, Secret Stripper OCRs the image, runs the same detector it uses for text, and paints a solid black box over only the words that contain a secret. The redacted image is what gets pasted. Clean parts of the image are left untouched - the whole screenshot is never blacked out.

Works on both X11 and Wayland.

It needs the [`tesseract`](https://github.com/tesseract-ocr/tesseract) OCR CLI on your `PATH`. It is an optional runtime dependency: everything else works without it.

```bash
sudo pacman -S tesseract tesseract-data-eng    # Arch
sudo apt install tesseract-ocr                  # Debian / Ubuntu
sudo dnf install tesseract                      # Fedora
```

It fails closed: if `tesseract` is missing, the image cannot be read, or a detected secret cannot be located, nothing is pasted and you get a notification - the original image is never silently passed through. OCR makes this path slower than the instant text path (roughly half a second to a couple of seconds for a full screenshot) before the paste happens.

Image redaction is off by default. Turn it on from `secret-stripper menu` -> **Detection Settings** -> **Screenshot redaction**, or set `enable_image_scan = true` in `config.toml`.

---

## Auto-redact paste into AI TUIs

`secret-stripper init` looks for installed AI terminal tools (Claude Code, Codex CLI, aider, Gemini CLI, Continue, opencode) and prints a ready-to-copy shell alias block. Each alias routes the tool through `paste-guard`, a PTY wrapper that intercepts clipboard pastes and redacts secrets before they reach the AI's prompt - typing and normal output are untouched. Copy the snippet into your shell config (`~/.zshrc`, `~/.bashrc`, or `~/.config/fish/config.fish`) and open a new shell:

```bash
# ----------------------------------
alias claude='secret-stripper paste-guard -- claude'
alias codex='secret-stripper paste-guard -- codex'
# ----------------------------------
```

Secret Stripper never writes to your shell rc on its own. To stop routing through `paste-guard`, delete the block between the dashed comment lines.

**Scope.** `paste-guard` is a per-process wrapper - it only filters pastes into the *one* command you ran it on. Daily use of `ssh`, `psql`, `vim`, `kubectl`, the bare shell prompt, GUI apps, the system clipboard - all completely untouched. You can also add aliases for non-AI tools by hand (live demos against `psql` / `mysql`, screen-recordings) - wrapping leaf commands is fine, wrapping a whole shell usually is not.

You can also pipe arbitrary text through the same engine:

```bash
cat secrets.log | secret-stripper redact > clean.log
```

**Limitations.** Bracketed paste must be supported by your terminal (every modern emulator does, including the VSCode integrated terminal and tmux passthrough); typed secrets are never modified, only pasted ones; paste payloads above 1 MiB fall through unredacted.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, lint, and commit conventions.

## Star history

<a href="https://star-history.com/#kalix127/secret-stripper&Date">
  <img src="https://api.star-history.com/svg?repos=kalix127/secret-stripper&type=Date" alt="Star history chart" width="100%">
</a>

## License

[MIT](LICENSE)
