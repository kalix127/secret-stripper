<img src="https://raw.githubusercontent.com/kalix127/secret-stripper/main/.github/assets/secret-stripper.png" width="100%">

<p align="center">
  <a href="https://github.com/kalix127/secret-stripper"><img src="https://shieldcn.dev/group/badge/platform-Linux_%7C_macOS_%7C_Windows-blue+crates/secret-stripper+github/license/kalix127/secret-stripper.svg?variant=secondary" alt="status"></a>
</p>

**A small Rust CLI that strips secrets from your clipboard on demand. Bind a hotkey, highlight text, press the chord - the clipboard holds a redacted version. Normal Ctrl+C / Ctrl+V is never intercepted.**

---

## Quick Start

**Linux:**

```bash
curl -sSf https://secretstripper.download/install.sh | bash
```

**macOS:**

```bash
curl -sSf https://secretstripper.download/install.sh | bash
```

**Windows (PowerShell):**

```powershell
iwr -useb https://secretstripper.download/install.ps1 | iex
```

**From [crates.io](https://crates.io/crates/secret-stripper) (Rust):**

```bash
cargo install secret-stripper && secret-stripper init
```

**From source (git clone):**

```bash
git clone https://github.com/kalix127/secret-stripper.git
cd secret-stripper
cargo build --release
sudo cp target/release/secret-stripper /usr/local/bin/
secret-stripper init
```

Highlight text and press your default chord (Linux `Ctrl+Alt+X` / macOS `Cmd+Shift+C` / Windows `Ctrl+Alt+C`). The clipboard now holds a redacted version - paste with `Ctrl+V` (`Cmd+V` on macOS). On Linux the PRIMARY selection is read directly, so you can skip the `Ctrl+C`.

Run `secret-stripper menu` to tune settings, or `secret-stripper --help` for all commands.

---

## Supported OS

| OS | Status | Hotkey backend |
|----|--------|----------------|
| Linux | ✅ Supported | gsettings (GNOME / Cinnamon / Unity / Budgie / Pantheon), gsettings (MATE schema), xfconf-query (XFCE), kwriteconfig + qdbus (KDE Plasma 5/6) |
| macOS | ✅ Supported | skhd (`~/.skhdrc`) or Hammerspoon (`~/.hammerspoon/init.lua`); manual instructions if neither is installed |
| Windows | ✅ Supported | AutoHotkey v2 (`%APPDATA%\secret-stripper\secret-stripper.ahk`) - install via `winget install AutoHotkey.AutoHotkey` |

## Platform setup

<details>
<summary><strong>macOS setup</strong></summary>

There is no zero-install way to register a true global hotkey on macOS without a resident process. Secret Stripper itself stays one-shot, so it delegates hotkey capture to one of two well-known helpers: [skhd](https://github.com/koekeishiya/skhd) (lightweight, recommended) or [Hammerspoon](https://www.hammerspoon.org/) (heavier, scriptable). If neither is installed, `init` falls back to printing manual binding instructions.

1. **Install skhd via Homebrew:**

   ```bash
   brew install koekeishiya/formulae/skhd
   ```

2. **Run `secret-stripper init`.** It writes `~/.skhdrc`, the launchd LaunchAgent for the daily update check, and the config file. Output includes a "DE binding" line: `OK` if skhd / Hammerspoon was detected, `FAILED` with install hints if not.

3. **Grant skhd Accessibility permission.** skhd needs this to intercept global hotkeys, otherwise it silently captures nothing. Open **System Settings -> Privacy & Security -> Accessibility**, click `+`, add `/usr/local/bin/skhd`, and toggle it on. If skhd was already running, restart it so the new permission takes effect:

   ```bash
   skhd --restart-service
   ```

4. **Test the chord:**

   ```bash
   echo "test@example.com" | pbcopy
   # Press your chord (default: Cmd+Shift+C)
   pbpaste     # expect: [REDACTED]
   ```

*Hammerspoon alternative:* `brew install --cask hammerspoon`, open it once to grant Accessibility, then run `secret-stripper init` - it writes the binding into `~/.hammerspoon/init.lua` instead of `~/.skhdrc`.

*Default chord:* `Cmd+Shift+C`. macOS apps often claim Cmd-modifier chords, so if it conflicts with something you use (browser DevTools, Finder "Copy Path", etc.), rebind from `secret-stripper menu -> Rebind Hotkey`. Two safer options if you want to plan ahead: `Cmd+Option+X` or `Cmd+Ctrl+X`.

</details>

<details>
<summary><strong>Windows setup</strong></summary>

Windows has no zero-install way to register a true global hotkey. Same constraint as macOS - Secret Stripper delegates hotkey capture to [AutoHotkey](https://www.autohotkey.com/) v2 (the Windows analogue of skhd). AutoHotkey uses the Win32 `RegisterHotKey` API under the hood and is the only mechanism that delivers the chord reliably across focused windows, full-screen apps, and elevated processes. AutoHotkey is required - `init` aborts with an install hint if it cannot find it.

1. **Install AutoHotkey via winget:**

   ```powershell
   winget install AutoHotkey.AutoHotkey
   ```

   The package installs AutoHotkey v2 to `C:\Program Files\AutoHotkey\v2\`.

2. **Run `secret-stripper init`.** It writes `%APPDATA%\secret-stripper\secret-stripper.ahk`, drops a startup `.lnk` so AHK re-launches the script at every login, and starts the AHK process immediately so the chord is live without a logout.

3. **Test the chord:**

   ```powershell
   Set-Clipboard "test@example.com"
   # Press your chord (default: Ctrl+Alt+C)
   Get-Clipboard    # expect: [REDACTED]
   ```

- The hotkey is limited to `Ctrl+Alt+<key>` (optionally with `Shift`); other chords are rejected.
- No PRIMARY selection: the flow is two steps (`Ctrl+C`, then your chord).
- The AHK script runs the redaction with a hidden console, so no window flashes on each trigger.
- The daily update check runs as a `schtasks` daily task at 11:00.
- *Uninstall* kills the AHK process bound to our script and removes the `.ahk` file and the startup `.lnk`. Other AHK scripts you have running are untouched.

</details>

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, lint, and commit conventions.

## Star history

<a href="https://star-history.com/#kalix127/secret-stripper&Date">
  <img src="https://api.star-history.com/svg?repos=kalix127/secret-stripper&type=Date" alt="Star history chart" width="100%">
</a>

## License

[MIT](LICENSE)
