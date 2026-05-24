# systemd update-check timer

`secret-stripper init` installs and enables this timer automatically on Linux when `check_for_updates = true` (the default). The unit files in this directory are reference templates for users who want to install the timer manually or audit what will be deployed.

The equivalent on macOS is a launchd LaunchAgent at `~/Library/LaunchAgents/com.kalix127.secret-stripper-update-check.plist`, and on Windows a daily `schtasks` task named `com.kalix127.secret-stripper-update-check` - both created and removed by `init` / `uninstall`. This directory documents only the Linux (systemd) path.

## What it does

A oneshot service that runs `secret-stripper upgrade-check` and a daily timer that triggers it. The check fetches the latest GitHub release; if a newer version exists it posts a desktop notification (and, when `auto_install = true` in config, swaps the binary in place).

`Persistent=true` runs the check on boot if the machine was off when it would have fired, and `RandomizedDelaySec=1h` spreads the GitHub API load across users so we do not stampede the API at 00:00 UTC.

## Manual install

If you prefer not to let `secret-stripper init` write into `~/.config/systemd/user/`:

```bash
# Adjust ExecStart in the .service file if your binary lives somewhere other
# than /usr/local/bin/secret-stripper.
mkdir -p ~/.config/systemd/user
cp secret-stripper-update-check.service ~/.config/systemd/user/
cp secret-stripper-update-check.timer   ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now secret-stripper-update-check.timer
```

Verify:

```bash
systemctl --user list-timers | grep secret-stripper
```

Disable:

```bash
systemctl --user disable --now secret-stripper-update-check.timer
rm ~/.config/systemd/user/secret-stripper-update-check.{service,timer}
systemctl --user daemon-reload
```
