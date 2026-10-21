# Security Policy

Secret Stripper handles secrets and PII from your clipboard. A vulnerability
here can leak exactly the data the tool exists to protect, so please report
issues privately and give us a chance to fix them before public disclosure.

## Supported versions

Only the latest 2.x release is supported, on Linux. Fixes ship in a new
release; older versions do not receive backports. 1.5.x, the last release for
macOS and Windows, receives no further fixes.

## Threat model

Secret Stripper runs as your user and never sends clipboard content anywhere.
Things worth knowing when you assess a report:

- On Wayland, `init` grants the active session's user write access to
  `/dev/uinput`, so any program running as that user can create a virtual
  keyboard.
- During a redacted paste a `serve-clipboard` child process holds the redacted
  copy, and afterwards the original, in memory until another program takes the
  clipboard.
- Downloads by `upgrade` and the installer are checked against the release's
  `SHA256SUMS`. That detects corrupted or tampered downloads, but it is not a
  signature: whoever can publish a release can publish matching checksums.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report the issue privately, either:

- Through GitHub's private vulnerability reporting: go to the repository's **Security** tab and click **Report a vulnerability** (once Private Vulnerability Reporting is enabled on this repo), or
- By email to <info@gianlucaiavicoli.dev>

Please include:

- Affected version (`secret-stripper --version`), distribution, desktop
  environment and session type (X11 or Wayland)
- A description of the issue and its impact
- Minimal reproduction steps

Do not paste real secrets in the report. Describe the format of any value
(e.g. "an AWS access key") rather than the value itself.

## What to expect

We aim to acknowledge a report within a few days and to keep you updated on the
fix and disclosure timeline. We will credit reporters who want it once a fix is
released.