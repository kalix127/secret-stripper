# Security Policy

Secret Stripper handles secrets and PII from your clipboard. A vulnerability
here can leak exactly the data the tool exists to protect, so please report
issues privately and give us a chance to fix them before public disclosure.

## Supported versions

Only the latest published release is supported. Fixes ship in a new release;
older versions do not receive backports.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report the issue privately, either:

- Through GitHub's private vulnerability reporting: go to the repository's **Security** tab and click **Report a vulnerability** (once Private Vulnerability Reporting is enabled on this repo), or
- By email to <info@gianlucaiavicoli.dev>

Please include:

- Affected version (`secret-stripper --version`) and OS / desktop environment
- A description of the issue and its impact
- Minimal reproduction steps

Do not paste real secrets in the report. Describe the format of any value
(e.g. "an AWS access key") rather than the value itself.

## What to expect

We aim to acknowledge a report within a few days and to keep you updated on the
fix and disclosure timeline. We will credit reporters who want it once a fix is
released.