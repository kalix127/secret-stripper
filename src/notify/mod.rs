use crate::config::Config;

// Only two events ever notify: a redaction and an available update. With
// `silent` set, nothing does.

pub fn redacted(count: usize, config: &Config) {
    if config.silent {
        return;
    }
    show(make_notification(
        &config.lang.notify_redacted(count),
        config.lang.notify_cleaned(),
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
