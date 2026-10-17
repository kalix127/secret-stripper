use crate::config::Config;
use crate::{notify, shortcut, updater};

/// One-time upgrade of a config written by 1.x. Its shortcut runs `trigger`
/// on the old default chord and its timer fires daily, so re-register both
/// with the migrated settings. The version is saved first so a desktop that
/// rejects the shortcut is not retried on every paste.
pub fn run() {
    let mut config = Config::load();
    if !config.needs_migration() {
        return;
    }
    let old_hotkey = config.hotkey.clone();
    let moved = config.migrate_from_v1();
    if let Err(e) = config.save() {
        log::warn!("saving the migrated config failed: {e:#}");
        return;
    }

    if !config.hotkey.is_empty() {
        if let Err(e) = shortcut::register(&config.hotkey) {
            log::warn!("re-registering the shortcut failed: {e:#}");
        }
    }
    if config.check_for_updates {
        if let Err(e) = updater::install_update_check_timer() {
            log::warn!("rewriting the update timer failed: {e:#}");
        }
    }
    if moved {
        eprintln!(
            "{}",
            config.lang.notify_hotkey_moved(&old_hotkey, &config.hotkey)
        );
        notify::hotkey_moved(&config, &old_hotkey);
    }
}
