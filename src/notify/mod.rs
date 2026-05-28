use crate::lang::Lang;

pub fn redacted_notification(count: usize, timeout: u64, lang: Lang) {
    show(make_notification(
        &lang.notify_redacted(count),
        lang.notify_cleaned(),
        timeout,
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

pub fn write_failed_notification(timeout: u64, lang: Lang, cleared: bool) {
    show(make_notification(
        lang.notify_write_failed(),
        lang.notify_write_failed_body(cleared),
        timeout,
    ));
}

/// Fires when Drop style triggers the deep-scan-no-span fallback: a secret was
/// detected but no byte range was known, so the clipboard was cleared rather
/// than left intact. Bypasses `Config.silent` because an emptied clipboard
/// otherwise looks like silent breakage.
pub fn drop_fallback_notification(timeout: u64, lang: Lang) {
    show(make_notification(
        lang.notify_drop_fallback_title(),
        lang.notify_drop_fallback_body(),
        timeout,
    ));
}

pub fn update_available_notification(timeout: u64, lang: Lang, current: &str, latest: &str) {
    let body = lang.update_available_body(current, latest);
    show(make_notification(
        lang.update_available_title(),
        &body,
        timeout,
    ));
}

pub fn update_installed_notification(timeout: u64, lang: Lang, version: &str) {
    let body = lang.update_installed_body(version);
    show(make_notification(
        lang.update_installed_title(),
        &body,
        timeout,
    ));
}

pub fn uninstalled_notification(timeout: u64, lang: Lang) {
    show(make_notification(
        lang.notify_uninstalled_title(),
        lang.notify_uninstalled_body(),
        timeout,
    ));
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
