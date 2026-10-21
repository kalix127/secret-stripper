use crate::config::Config;

// Notifies on a redaction, a paste that did not happen, an available or
// installed update and a hotkey moved by the 1.x upgrade. With `silent` set, nothing does.

pub fn redacted(count: usize, config: &Config) {
    if config.silent {
        return;
    }
    show(make_notification(
        &config.lang.notify_redacted(count),
        config.lang.notify_pasted(),
        config.notification_timeout_secs,
    ));
}

/// The hotkey runs in the background, so stderr is invisible: this is the only
/// way the user learns why nothing was pasted.
pub fn not_pasted(config: &Config, reason: &str) {
    if config.silent {
        return;
    }
    show(make_notification(
        config.lang.notify_not_pasted(),
        reason,
        config.notification_timeout_secs,
    ));
}

pub fn hotkey_moved(config: &Config, old: &str) {
    if config.silent {
        return;
    }
    show(make_notification(
        crate::APP_NAME,
        &config.lang.notify_hotkey_moved(old, &config.hotkey),
        config.notification_timeout_secs,
    ));
}

pub fn update_available(config: &Config, current: &str, latest: &str) {
    if config.silent {
        return;
    }
    show(make_notification(
        config.lang.update_available_title(),
        &config.lang.update_available_body(current, latest),
        config.notification_timeout_secs,
    ));
}

pub fn update_installed(config: &Config, version: &str) {
    if config.silent {
        return;
    }
    show(make_notification(
        config.lang.update_installed_title(),
        &config.lang.update_installed_body(version),
        config.notification_timeout_secs,
    ));
}

/// Display a notification, logging (not swallowing) any backend failure.
/// A missing/!running notification daemon is the usual cause and is
/// otherwise invisible to the user.
fn show(n: notify_rust::Notification) {
    if let Err(e) = n.show() {
        log::warn!("desktop notification failed (is a notification daemon running?): {e}");
    }
}

fn make_notification(summary: &str, body: &str, timeout: u64) -> notify_rust::Notification {
    let mut n = notify_rust::Notification::new();
    n.summary(summary)
        .body(body)
        .icon("dialog-warning")
        .appname(crate::APP_NAME)
        .timeout(notify_rust::Timeout::Milliseconds((timeout * 1000) as u32));
    n
}
