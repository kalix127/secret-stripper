# systemd update-check timer

`secret-stripper init` installs and enables this timer when `check_for_updates = true` (the default). Turn it off or on in `secret-stripper menu` -> **Manage Installation**. The unit files in this directory are reference copies for auditing or installing the timer by hand.

## What it does

A oneshot service runs `secret-stripper upgrade-check`, and the timer starts it 2 minutes after login (`OnStartupSec=2min`) and then once a day while the session stays open (`OnUnitActiveSec=1d`). The check fetches the latest GitHub release and, if it is newer, shows a desktop notification at most once every 24 hours, and never when notifications are off.

With `auto_install = true` it also replaces the binary in place. That only works when your user can write to the binary's directory (for example `~/.local/bin`); a binary in `/usr/local/bin` needs `sudo secret-stripper upgrade` instead.

`init` writes the units with the absolute path of the binary it runs from. Run `init` again after moving the binary.

## Manual install

If you prefer not to let `secret-stripper init` write into `~/.config/systemd/user/`:

```bash
# Edit ExecStart in the .service file if your binary is not
# /usr/local/bin/secret-stripper.
mkdir -p ~/.config/systemd/user
cp secret-stripper-update-check.service ~/.config/systemd/user/
cp secret-stripper-update-check.timer ~/.config/systemd/user/
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
rm ~/.config/systemd/user/secret-stripper-update-check.service
rm ~/.config/systemd/user/secret-stripper-update-check.timer
systemctl --user daemon-reload
```
