<p align="center">
  <a href="https://github.com/kalix127/secret-stripper"><img src="https://shieldcn.dev/group/badge/platform-Linux-blue+crates/secret-stripper+github/license/kalix127/secret-stripper.svg?variant=secondary" alt="status"></a>
</p>

<img src="https://raw.githubusercontent.com/kalix127/secret-stripper/main/.github/assets/banner.gif" width="100%">

**Paste a redacted copy of your clipboard with one hotkey. Copy as usual, press `Ctrl+Alt+V`, and API keys, tokens, private keys and PII come out as `[REDACTED]`. Your clipboard keeps the original, and plain `Ctrl+V` is never touched. Linux only, X11 and Wayland, everything stays on your machine.**

## Contents

- [Quick Start](#quick-start)
- [How it works](#how-it-works)
- [Supported desktops](#supported-desktops)
- [What it detects](#what-it-detects)
- [Redaction styles](#redaction-styles)
- [Redact screenshots](#redact-screenshots)
- [Auto-redact paste into AI TUIs](#auto-redact-paste-into-ai-tuis)
- [Commands](#commands)
- [Configuration](#configuration)
- [Notifications](#notifications)
- [Updates](#updates)
- [Upgrading from 1.x](#upgrading-from-1x)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [Privacy and security](#privacy-and-security)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```bash
curl -sSf https://secretstripper.download/install.sh | bash
```

The installer downloads the release binary for your CPU (x86_64 or aarch64), checks it against the release's `SHA256SUMS`, and installs it to `/usr/local/bin` (sudo asks for your password) or to `~/.local/bin` if that fails. It then runs `secret-stripper init`, which:

- writes `~/.config/secret-stripper/config.toml`,
- binds two shortcuts in your desktop: `Ctrl+Alt+V` and, for terminals, `Ctrl+Alt+Shift+V`,
- installs a systemd user timer that checks for updates,
- on Wayland, asks before running sudo once to let your session use `/dev/uinput` (see [Wayland setup](#wayland-setup)).

Then copy something with a secret in it and press `Ctrl+Alt+V` in any text field.

**From [crates.io](https://crates.io/crates/secret-stripper)** (Rust 1.89 or newer):

```bash
cargo install secret-stripper
secret-stripper init
```

**From source:**

```bash
cargo install --git https://github.com/kalix127/secret-stripper.git --locked
secret-stripper init
```

The shortcuts run the binary by its absolute path. If you move the binary, run `secret-stripper init` again.

Run `secret-stripper menu` to change the hotkey, detection and notifications, or `secret-stripper status` to see what is set up.

---

## How it works

The hotkey runs `secret-stripper paste`, which:

1. reads the clipboard and scans it locally, with no network access;
2. with nothing to redact, sends the normal paste keys, so the app pastes the clipboard unchanged;
3. otherwise puts a redacted copy on the clipboard, sends the paste keys, waits for the app to read it, then puts the original back.

The paste keys are `Ctrl+V`, or `Ctrl+Shift+V` for the terminal hotkey. On X11 they are typed through XTest, and a focused terminal is detected by its window class, so the main hotkey works there too. On Wayland they are typed through a virtual keyboard on `/dev/uinput`, which works on every compositor and with any keyboard layout.

If the app has not read the clipboard within 3 seconds, the redacted copy stays on the clipboard instead of the original, so a slow app can never paste the secret.

### Wayland setup

Wayland does not let programs type into other windows, so `paste` creates a virtual keyboard through `/dev/uinput`. That device is root-only by default. `init` shows these commands and asks before running them with sudo:

```bash
echo 'uinput' | sudo tee /etc/modules-load.d/secret-stripper-uinput.conf
echo 'KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/60-secret-stripper-uinput.rules
sudo modprobe uinput
sudo udevadm control --reload-rules
sudo udevadm trigger --settle --action=change --sysname-match=uinput
```

The `uaccess` tag gives `/dev/uinput` to the user of the active local session only, not to a group. If the paste still fails right after setup, log out and back in. To revoke the access:

```bash
sudo rm -f /etc/modules-load.d/secret-stripper-uinput.conf
sudo rm -f /etc/udev/rules.d/60-secret-stripper-uinput.rules
```

### Terminal hotkey

Terminals paste with `Ctrl+Shift+V`, because `Ctrl+V` means something else there. The terminal hotkey is your hotkey plus Shift (`Ctrl+Alt+Shift+V` by default) and runs `secret-stripper paste --terminal`. On X11 the main hotkey also works in common terminals.

---

## Supported desktops

Secret Stripper supports Linux only, on X11 and Wayland. 1.5.x was the last release for macOS and Windows; see [Upgrading from 1.x](#upgrading-from-1x).

| Desktop | How the shortcuts are bound |
|---------|-----------------------------|
| GNOME, Unity, Budgie, Pantheon | gsettings custom keybindings |
| Cinnamon | gsettings (Cinnamon schema) |
| MATE | gsettings (MATE schema) |
| XFCE | xfconf-query |
| KDE Plasma 5/6 | kglobalshortcutsrc + kglobalaccel |
| Hyprland | `~/.config/hypr/secret-stripper.conf`, sourced from `hyprland.conf` |
| sway, i3 and others | printed lines to add to your config yourself |

On a desktop it cannot configure, `init` prints the two commands and ready-made lines, for example:

```
bindsym Ctrl+Mod1+v exec '/usr/local/bin/secret-stripper' paste
bindsym Ctrl+Mod1+Shift+v exec '/usr/local/bin/secret-stripper' paste --terminal
```

On GNOME, which has no clipboard protocol for background programs on Wayland, the redacted copy is served through XWayland. Wayland apps see it as usual.

---

## What it detects

| Category | Examples |
|----------|----------|
| Cloud secrets | AWS keys, Google API keys, Azure credentials, Heroku and other PaaS tokens |
| Auth and API tokens | GitHub, GitLab, Slack, Discord, OpenAI, Anthropic, Stripe and NPM tokens, JWTs, bearer tokens |
| Private keys | RSA, EC, OpenSSH and PGP private key blocks |
| Connection strings | PostgreSQL, MongoDB, Redis and MySQL URLs with credentials |
| PII | Email addresses, phone numbers, credit cards (Luhn-checked), IBANs, IP addresses |
| Optional | Government IDs, password hashes, crypto wallets and other niche buckets (Full preset) |
| Optional, off by default | High-entropy strings (`enable_entropy`) and deep-scan heuristics such as `.env` files and JSON password fields (`enable_deep_scan`) |

New installs use the Balanced preset. Switch presets or toggle single buckets in `secret-stripper menu` -> **Detection Settings**. The full list of 850+ patterns is in [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md).

You can add your own patterns in `~/.config/secret-stripper/patterns.toml`:

```toml
[[patterns]]
name = "internal_token"
category = "custom"
severity = "high"
regex = "itk_[A-Za-z0-9]{32}"
```

---

## Redaction styles

Pick how secrets are replaced in `secret-stripper menu` -> **Redaction Style**:

| Style | Output for `aws=AKIAIOSFODNN7EXAMPLE` |
|-------|----------------------------------------|
| **Marker** (default) | `aws=[REDACTED]`, with a configurable marker |
| **Drop** | `aws=`, the secret is removed |
| **Typed** | `aws=[AWS_ACCESS_KEY_ID]`, a tag named after the pattern |
| **Placeholder** | a realistic fake value of the same kind, for example `user@example.com` for an email |

The same setting applies to the hotkey, the `redact` command and `paste-guard`.

---

## Redact screenshots

With screenshot redaction on, an image on the clipboard is read with OCR, scanned with the same detector, and pasted with a black box over each word that holds a secret. The rest of the image is left as is.

It is off by default: until you turn it on, images paste unredacted. Turn it on in `secret-stripper menu` -> **Screenshot redaction**, or set `enable_image_scan = true`. It needs the [`tesseract`](https://github.com/tesseract-ocr/tesseract) CLI:

```bash
sudo pacman -S tesseract tesseract-data-eng    # Arch
sudo apt install tesseract-ocr                  # Debian / Ubuntu
sudo dnf install tesseract                      # Fedora
```

It fails closed: if `tesseract` is missing, the image cannot be read, or a secret cannot be located in it, nothing is pasted and a notification says why. OCR adds about half a second to a couple of seconds before the paste.

---

## Auto-redact paste into AI TUIs

`secret-stripper init` looks for AI terminal tools (Claude Code, Codex CLI, aider, Gemini CLI, Continue, opencode) and prints an alias block for your shell config. Each alias runs the tool through `paste-guard`, a PTY wrapper that redacts bracketed pastes before they reach the prompt. Typing and output are untouched.

```bash
# ---- secret-stripper paste-guard ----
alias claude='secret-stripper paste-guard -- claude'
alias codex='secret-stripper paste-guard -- codex'
# ---- secret-stripper paste-guard ----
```

Add the block to `~/.zshrc`, `~/.bashrc` or `~/.config/fish/config.fish` yourself and open a new shell. `init` never edits your shell config; `uninstall` removes the block if it finds it.

`paste-guard` only filters pastes into the one command it wraps. It needs a terminal with bracketed paste (all modern ones, including tmux and the VS Code terminal), never changes typed text, and passes pastes over 1 MiB through unredacted.

The same engine works in pipelines:

```bash
cat app.log | secret-stripper redact > clean.log
```

---

## Commands

| Command | What it does |
|---------|--------------|
| `init` | Set up config, shortcuts, update timer and uinput access. Safe to run again. |
| `paste [--terminal]` | Paste a redacted copy. Run by the hotkeys. |
| `menu` | Settings menu. |
| `status` | Hotkeys, desktop, session, uinput access and main settings. |
| `register-shortcut` / `unregister-shortcut` | Bind or remove both shortcuts. |
| `upgrade` | Download, verify and install the latest release. |
| `redact` | Redact stdin to stdout. |
| `paste-guard -- <cmd>` | Run `<cmd>` with pastes redacted. |
| `uninstall` | Remove shortcuts, timer, config and the alias block. |

Add `--log-level debug` to any command for details on stderr.

---

## Configuration

Settings live in `~/.config/secret-stripper/config.toml` (or `$SECRET_STRIPPER_CONFIG_HOME/secret-stripper/config.toml`). The menu covers most of them; these are the keys you may want to edit by hand:

| Key | Default | Meaning |
|-----|---------|---------|
| `hotkey` | `"Ctrl+Alt+V"` | The paste hotkey. Change it in the menu so the shortcuts are rebound. |
| `paste_keys` | `"Ctrl+V"` | Keys sent to paste. |
| `terminal_paste_keys` | `"Ctrl+Shift+V"` | Keys sent by `paste --terminal`. |
| `redact_pattern` | `"[REDACTED]"` | Marker text for the Marker style. |
| `silent` | `false` | Turn off redaction and update notifications. |
| `enable_image_scan` | `false` | Screenshot redaction. |
| `enable_entropy` | `false` | Redact random-looking strings with no known format. |
| `enable_deep_scan` | `false` | Heuristic scanners for `.env`, JSON, YAML and similar. |
| `allowlist_regex` | `[]` | Regexes for values that must never be redacted. |
| `check_for_updates` | `true` | Daily update check. |
| `auto_install` | `false` | Install updates automatically when the binary is writable. |

---

## Notifications

A desktop notification tells you how many secrets were redacted and when an update is available or was installed. `silent = true` (or the menu toggle) turns those off. A paste that did not happen always notifies, with the reason, since the hotkey has no terminal to print to.

---

## Updates

A systemd user timer runs `secret-stripper upgrade-check` 2 minutes after login and once a day. It shows at most one update notice per day and stays quiet on network errors.

Install an update with `secret-stripper upgrade`, or `sudo secret-stripper upgrade` if the binary is in `/usr/local/bin`. Downloads are checked against the release's `SHA256SUMS`. With `auto_install = true`, the timer installs updates itself, but only when it can write to the binary's directory (for example `~/.local/bin`).

---

## Upgrading from 1.x

2.0 replaces the 1.x flow, where the hotkey rewrote the clipboard in place, with a paste: the hotkey now types the redacted copy into the focused app and keeps your clipboard intact.

On Linux, `secret-stripper upgrade` (or the 1.x auto-install) brings you to 2.0. The first time you press your old hotkey or run `init`, `menu` or `status`, it migrates once:

- the old default hotkey `Ctrl+Alt+X` moves to `Ctrl+Alt+V`; a hotkey you chose yourself is kept,
- the terminal hotkey is added and both shortcuts are rebound,
- notifications are turned on (1.x was silent by default),
- the update timer is rewritten.

On Wayland, run `secret-stripper init` once more to set up uinput access.

**macOS and Windows:** 2.0 is Linux only. Stay on 1.5.2, the last release for those systems. Older 1.x versions will show notices about 2.0 that they cannot install; to stop them, install 1.5.2 from the [release page](https://github.com/kalix127/secret-stripper/releases/tag/v1.5.2) or with `cargo install secret-stripper --version 1.5.2`, or turn off update checks in the menu.

---

## Uninstall

```bash
secret-stripper uninstall
```

This removes both shortcuts, the update timer, the config directory and the `paste-guard` alias block. It then prints the two commands it cannot run for you: the `sudo rm -f` for the uinput rule, and the path of the binary to delete.

---

## Troubleshooting

To see each step, run `secret-stripper paste --terminal --log-level debug` in a terminal: it pastes into that terminal and logs to stderr.

- **Nothing is pasted on Wayland:** check that `secret-stripper status` shows `uinput access: yes`. If not, run `secret-stripper init`, then log out and back in.
- **"The shortcut keys were still held":** release the keys right after pressing. A hotkey that does not include `Ctrl+V` (for example `Super+Alt+V`) waits a moment for you to let go.
- **Wrong character pasted, or nothing, with a non-US layout:** run with `--log-level debug` and open an issue with the output and your layout.
- **The original comes back too early or not at all:** the original is restored after the app reads the paste. An app that takes longer than 3 seconds keeps the redacted copy on the clipboard.
- **Rich formatting lost:** after a redacted paste the original is restored as plain text (or PNG). Copy again if you need the formatting.
- **No notifications:** a notification daemon must be running; most desktops have one.
- **Screenshot not redacted:** check that `tesseract` is installed and screenshot redaction is on.

---

## Privacy and security

- Scanning happens on your machine. The only network request is the update check to the GitHub API.
- During a redacted paste a small `serve-clipboard` process owns the clipboard. It keeps the content in memory until another program takes the clipboard, like any clipboard owner.
- Everything Secret Stripper puts on the clipboard carries KDE's password-manager hint, which Klipper and managers that honor it skip. Other clipboard managers may still record the redacted copy and the restored original.
- On Wayland, uinput access lets any program running as you create a virtual keyboard while you are logged in at the machine.
- Release binaries are checked against `SHA256SUMS` from the same release. This catches corrupted or tampered downloads, but it is not a signature.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, lint and commit conventions.

## License

[MIT](LICENSE)
