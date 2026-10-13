# systemd update-check timer

`secret-stripper init` installs and enables this timer automatically when `check_for_updates = true` (the default). The unit files in this directory are reference templates for users who want to install the timer manually or audit what will be deployed.

## What it does

A oneshot service that runs `secret-stripper upgrade-check` and a timer that triggers it once per login session. The check fetches the latest GitHub release; if a newer version exists it posts a desktop notification (and, when `auto_install = true` in config, swaps the binary in place).

`OnStartupSec=2min` counts from the start of your systemd user manager, which starts at login, so the check runs once, two minutes into each session. The notification itself is also limited to once per 24 hours and never shown when notifications are off.

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
