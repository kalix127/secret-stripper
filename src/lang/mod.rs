use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::detector::patterns::Severity;
use crate::detector::presets::Preset;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Lang {
    EN,
    FR,
    IT,
    ES,
}

/// Which desktop-environment backend accepted a shortcut binding. Returned by
/// `shortcut::register` so the user-facing confirmation can be localized at
/// the call site instead of baked into the (binary-only) shortcut module.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShortcutBackend {
    Gnome,
    Cinnamon,
    Mate,
    Xfce,
    Kde,
    Skhd,
    Hammerspoon,
    WindowsAhk,
}

// Return type for a generated string method: no args => &'static str,
// any args => String (the arms are format!(...)).
macro_rules! lang_ret {
    () => { &'static str };
    ($($t:tt)+) => { String };
}

// Generates one method per user-facing string. Each entry must list EN, FR,
// IT and ES. The generated `match self { ... }` has no wildcard arm and Lang
// has exactly four variants, so a missing language is a non-exhaustive-match
// compile error. That is the i18n drift guard: there is no default-EN
// fallback anywhere. Parameterized entries declare args (each with a trailing
// comma) and their arms are `format!(...)` returning String.
macro_rules! lang_strings {
    (
        $(
            $name:ident
            $( ( $( $arg:ident : $argty:ty , )+ ) )?
            {
                EN => $en:expr,
                FR => $fr:expr,
                IT => $it:expr,
                ES => $es:expr,
            }
        )*
    ) => {
        impl Lang {
            $(
                pub fn $name(
                    &self
                    $( $( , $arg : $argty )+ )?
                ) -> lang_ret!( $( $( $arg )+ )? ) {
                    match self {
                        Lang::EN => $en,
                        Lang::FR => $fr,
                        Lang::IT => $it,
                        Lang::ES => $es,
                    }
                }
            )*
        }
    };
}

impl Lang {
    pub fn detect_from_env() -> Lang {
        let raw = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default();
        let prefix = raw
            .split(['.', '_', '@'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match prefix.as_str() {
            "fr" => Lang::FR,
            "it" => Lang::IT,
            "es" => Lang::ES,
            _ => Lang::EN,
        }
    }

    /// The language to render output in, usable before/without a loaded
    /// Config. A persisted choice wins (this is what makes a manual menu
    /// choice beat OS detection on later runs); only a brand-new install with
    /// no config falls back to environment detection.
    pub fn active() -> Lang {
        if Config::path_exists() {
            Config::load().lang
        } else {
            Lang::detect_from_env()
        }
    }

    /// Native name of the language itself, identical regardless of the active
    /// UI language (used by the menu language picker).
    pub fn endonym(&self) -> &'static str {
        match self {
            Lang::EN => "English",
            Lang::FR => "Français",
            Lang::IT => "Italiano",
            Lang::ES => "Español",
        }
    }

    pub fn all() -> [Lang; 4] {
        [Lang::EN, Lang::FR, Lang::IT, Lang::ES]
    }

    /// Display label for a detection severity. Exhaustive over (Lang,
    /// Severity) with no wildcard, so adding a variant on either enum is a
    /// compile error here too.
    pub fn severity_label(&self, sev: &Severity) -> &'static str {
        match (self, sev) {
            (Lang::EN, Severity::Critical) => "Critical",
            (Lang::EN, Severity::High) => "High",
            (Lang::EN, Severity::Medium) => "Medium",
            (Lang::EN, Severity::Low) => "Low",
            (Lang::FR, Severity::Critical) => "Critique",
            (Lang::FR, Severity::High) => "Élevé",
            (Lang::FR, Severity::Medium) => "Moyen",
            (Lang::FR, Severity::Low) => "Faible",
            (Lang::IT, Severity::Critical) => "Critico",
            (Lang::IT, Severity::High) => "Alto",
            (Lang::IT, Severity::Medium) => "Medio",
            (Lang::IT, Severity::Low) => "Basso",
            (Lang::ES, Severity::Critical) => "Crítico",
            (Lang::ES, Severity::High) => "Alto",
            (Lang::ES, Severity::Medium) => "Medio",
            (Lang::ES, Severity::Low) => "Bajo",
        }
    }

    /// Localized (name, one-line description) for a detection preset.
    /// Exhaustive over (Lang, Preset) with no wildcard, so adding a variant on
    /// either enum is a compile error here too.
    pub fn preset_label(&self, p: &Preset) -> (&'static str, &'static str) {
        match (self, p) {
            (Lang::EN, Preset::Minimal) => (
                "Minimal",
                "Popular PII only: emails, phones, cards, IPs - lowest noise",
            ),
            (Lang::EN, Preset::Balanced) => ("Balanced", "Broad credential + common PII (default)"),
            (Lang::EN, Preset::Full) => ("Full", "Every bucket, including regional & niche"),
            (Lang::FR, Preset::Minimal) => (
                "Minimal",
                "PII courantes : e-mails, téléphones, cartes, IP - bruit minimal",
            ),
            (Lang::FR, Preset::Balanced) => (
                "Équilibré",
                "Large couverture identifiants + PII courantes (défaut)",
            ),
            (Lang::FR, Preset::Full) => (
                "Complet",
                "Tous les groupes, y compris régionaux et de niche",
            ),
            (Lang::IT, Preset::Minimal) => (
                "Minimo",
                "Solo PII comuni: email, telefoni, carte, IP - rumore minimo",
            ),
            (Lang::IT, Preset::Balanced) => (
                "Bilanciato",
                "Ampia copertura credenziali + PII comuni (predefinito)",
            ),
            (Lang::IT, Preset::Full) => {
                ("Completo", "Tutti i gruppi, inclusi regionali e di nicchia")
            }
            (Lang::ES, Preset::Minimal) => (
                "Mínimo",
                "Solo PII comunes: correos, teléfonos, tarjetas, IP - menos ruido",
            ),
            (Lang::ES, Preset::Balanced) => (
                "Equilibrado",
                "Amplia cobertura de credenciales + PII comunes (predeterminado)",
            ),
            (Lang::ES, Preset::Full) => (
                "Completo",
                "Todos los grupos, incluidos regionales y de nicho",
            ),
        }
    }

    pub fn notify_write_failed_body(&self, cleared: bool) -> &'static str {
        match (self, cleared) {
            (Lang::EN, true) => "Original content was cleared from the clipboard.",
            (Lang::EN, false) => "Original content may still be in the clipboard.",
            (Lang::FR, true) => "Le contenu original a été effacé du presse-papiers.",
            (Lang::FR, false) => "Le contenu original peut encore être dans le presse-papiers.",
            (Lang::IT, true) => "Il contenuto originale è stato rimosso dagli appunti.",
            (Lang::IT, false) => "Il contenuto originale potrebbe essere ancora negli appunti.",
            (Lang::ES, true) => "El contenido original fue eliminado del portapapeles.",
            (Lang::ES, false) => "El contenido original puede seguir en el portapapeles.",
        }
    }

    /// Localized confirmation that a hotkey was bound via a given DE backend.
    /// Exhaustive over (Lang, ShortcutBackend) with no wildcard.
    pub fn shortcut_bound(&self, backend: &ShortcutBackend, chord: &str) -> String {
        match (self, backend) {
            (Lang::EN, ShortcutBackend::Gnome) => {
                format!("Custom shortcut bound to '{}' via GNOME schema (gsettings).", chord)
            }
            (Lang::EN, ShortcutBackend::Cinnamon) => {
                format!("Custom shortcut bound to '{}' via Cinnamon schema (gsettings).", chord)
            }
            (Lang::EN, ShortcutBackend::Mate) => {
                format!("Custom shortcut bound to '{}' via MATE schema (gsettings).", chord)
            }
            (Lang::EN, ShortcutBackend::Xfce) => {
                format!("Custom shortcut bound to '{}' via xfconf-query.", chord)
            }
            (Lang::EN, ShortcutBackend::Kde) => format!(
                "Custom shortcut bound to '{}' via kglobalshortcutsrc. You may need to log out and back in for the binding to take effect.",
                chord
            ),
            (Lang::EN, ShortcutBackend::Skhd) => {
                format!("Custom shortcut bound to '{}' via skhd (~/.skhdrc).", chord)
            }
            (Lang::EN, ShortcutBackend::Hammerspoon) => {
                format!("Custom shortcut bound to '{}' via Hammerspoon (~/.hammerspoon/init.lua).", chord)
            }
            (Lang::EN, ShortcutBackend::WindowsAhk) => format!(
                "Custom shortcut bound to '{}' via AutoHotkey (secret-stripper.ahk). Press it from any app to redact.",
                chord
            ),
            (Lang::FR, ShortcutBackend::Gnome) => {
                format!("Raccourci personnalisé lié à '{}' via le schéma GNOME (gsettings).", chord)
            }            (Lang::FR, ShortcutBackend::Cinnamon) => {
                format!("Raccourci personnalisé lié à '{}' via le schéma Cinnamon (gsettings).", chord)
            }            (Lang::FR, ShortcutBackend::Mate) => {
                format!("Raccourci personnalisé lié à '{}' via le schéma MATE (gsettings).", chord)
            }            (Lang::FR, ShortcutBackend::Xfce) => {
                format!("Raccourci personnalisé lié à '{}' via xfconf-query.", chord)
            }            (Lang::FR, ShortcutBackend::Kde) => format!(
                "Raccourci personnalisé lié à '{}' via kglobalshortcutsrc. Vous devrez peut-être vous déconnecter et vous reconnecter pour que la liaison prenne effet.",
                chord
            ),
            (Lang::FR, ShortcutBackend::Skhd) => {
                format!("Raccourci personnalisé lié à '{}' via skhd (~/.skhdrc).", chord)
            }
            (Lang::FR, ShortcutBackend::Hammerspoon) => {
                format!("Raccourci personnalisé lié à '{}' via Hammerspoon (~/.hammerspoon/init.lua).", chord)
            }
            (Lang::FR, ShortcutBackend::WindowsAhk) => format!(
                "Raccourci personnalisé lié à '{}' via AutoHotkey (secret-stripper.ahk). Appuyez dessus depuis n'importe quelle application pour masquer.",
                chord
            ),
            (Lang::IT, ShortcutBackend::Gnome) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite schema GNOME (gsettings).", chord)
            }            (Lang::IT, ShortcutBackend::Cinnamon) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite schema Cinnamon (gsettings).", chord)
            }            (Lang::IT, ShortcutBackend::Mate) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite schema MATE (gsettings).", chord)
            }            (Lang::IT, ShortcutBackend::Xfce) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite xfconf-query.", chord)
            }            (Lang::IT, ShortcutBackend::Kde) => format!(
                "Scorciatoia personalizzata associata a '{}' tramite kglobalshortcutsrc. Potrebbe essere necessario disconnettersi e riconnettersi affinché l'associazione abbia effetto.",
                chord
            ),
            (Lang::IT, ShortcutBackend::Skhd) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite skhd (~/.skhdrc).", chord)
            }
            (Lang::IT, ShortcutBackend::Hammerspoon) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite Hammerspoon (~/.hammerspoon/init.lua).", chord)
            }
            (Lang::IT, ShortcutBackend::WindowsAhk) => format!(
                "Scorciatoia personalizzata associata a '{}' tramite AutoHotkey (secret-stripper.ahk). Premila da qualsiasi app per oscurare.",
                chord
            ),
            (Lang::ES, ShortcutBackend::Gnome) => {
                format!("Atajo personalizado vinculado a '{}' mediante el esquema GNOME (gsettings).", chord)
            }            (Lang::ES, ShortcutBackend::Cinnamon) => {
                format!("Atajo personalizado vinculado a '{}' mediante el esquema Cinnamon (gsettings).", chord)
            }            (Lang::ES, ShortcutBackend::Mate) => {
                format!("Atajo personalizado vinculado a '{}' mediante el esquema MATE (gsettings).", chord)
            }            (Lang::ES, ShortcutBackend::Xfce) => {
                format!("Atajo personalizado vinculado a '{}' mediante xfconf-query.", chord)
            }            (Lang::ES, ShortcutBackend::Kde) => format!(
                "Atajo personalizado vinculado a '{}' mediante kglobalshortcutsrc. Es posible que tengas que cerrar sesión y volver a entrar para que el vínculo surta efecto.",
                chord
            ),
            (Lang::ES, ShortcutBackend::Skhd) => {
                format!("Atajo personalizado vinculado a '{}' mediante skhd (~/.skhdrc).", chord)
            }
            (Lang::ES, ShortcutBackend::Hammerspoon) => {
                format!("Atajo personalizado vinculado a '{}' mediante Hammerspoon (~/.hammerspoon/init.lua).", chord)
            }
            (Lang::ES, ShortcutBackend::WindowsAhk) => format!(
                "Atajo personalizado vinculado a '{}' mediante AutoHotkey (secret-stripper.ahk). Púlsalo desde cualquier app para ocultar.",
                chord
            ),
        }
    }
}

lang_strings! {
    // ---- Notifications (migrated, human translations kept) ----
    notify_redacted(n: usize,) {
        EN => if n == 1 { "Redacted 1 item".to_string() } else { format!("Redacted {} items", n) },
        FR => if n == 1 { "1 élément masqué".to_string() } else { format!("{} éléments masqués", n) },
        IT => if n == 1 { "1 elemento oscurato".to_string() } else { format!("{} elementi oscurati", n) },
        ES => if n == 1 { "1 elemento redactado".to_string() } else { format!("{} elementos redactados", n) },
    }


    notify_cleaned {
        EN => "Clipboard has been cleaned",
        FR => "Le presse-papiers a été nettoyé",
        IT => "Gli appunti sono stati puliti",
        ES => "El portapapeles ha sido limpiado",
    }

    notify_write_failed {
        EN => "Clipboard write failed",
        FR => "Échec d'écriture du presse-papiers",
        IT => "Scrittura negli appunti fallita",
        ES => "Fallo al escribir en el portapapeles",
    }

    update_available_title {
        EN => "Secret Stripper update available",
        FR => "Mise à jour de Secret Stripper disponible",
        IT => "Aggiornamento di Secret Stripper disponibile",
        ES => "Actualización de Secret Stripper disponible",
    }

    update_available_body(current: &str, latest: &str,) {
        EN => format!("Version {} is out (you have {}). Run 'secret-stripper upgrade' to install.", latest, current),
        FR => format!("La version {} est sortie (vous avez {}). Lancez 'secret-stripper upgrade' pour l'installer.", latest, current),
        IT => format!("È disponibile la versione {} (la tua è {}). Esegui 'secret-stripper upgrade' per installarla.", latest, current),
        ES => format!("La versión {} está disponible (tu versión es {}). Ejecuta 'secret-stripper upgrade' para instalarla.", latest, current),
    }

    update_installed_title {
        EN => "Secret Stripper updated",
        FR => "Secret Stripper mis à jour",
        IT => "Secret Stripper aggiornato",
        ES => "Secret Stripper actualizado",
    }

    update_installed_body(version: &str,) {
        EN => format!("Successfully installed {}.", version),
        FR => format!("Version {} installée avec succès.", version),
        IT => format!("Versione {} installata con successo.", version),
        ES => format!("Versión {} instalada correctamente.", version),
    }

    // ---- Shared field labels (init / menu) ----
    lbl_config {
        EN => "Config",
        FR => "Configuration",
        IT => "Configurazione",
        ES => "Configuración",
    }
    lbl_language {
        EN => "Language",
        FR => "Langue",
        IT => "Lingua",
        ES => "Idioma",
    }
    lbl_hotkey {
        EN => "Hotkey",
        FR => "Raccourci",
        IT => "Scorciatoia",
        ES => "Atajo",
    }
    lbl_de_binding {
        EN => "DE binding",
        FR => "Liaison DE",
        IT => "Associazione DE",
        ES => "Vínculo DE",
    }
    lbl_sensitivity {
        EN => "Sensitivity",
        FR => "Sensibilité",
        IT => "Sensibilità",
        ES => "Sensibilidad",
    }
    lbl_redact_as {
        EN => "Redact as",
        FR => "Masquer par",
        IT => "Oscura come",
        ES => "Redactar como",
    }
    lbl_deep_scan {
        EN => "Deep scan",
        FR => "Analyse approfondie",
        IT => "Scansione profonda",
        ES => "Análisis profundo",
    }
    lbl_entropy {
        EN => "Entropy scan",
        FR => "Analyse d'entropie",
        IT => "Scansione entropia",
        ES => "Análisis de entropía",
    }
    lbl_notifications {
        EN => "Notifications",
        FR => "Notifications",
        IT => "Notifiche",
        ES => "Notificaciones",
    }
    lbl_notif_timeout {
        EN => "Notif timeout",
        FR => "Délai de notification",
        IT => "Durata notifica",
        ES => "Tiempo de notificación",
    }
    lbl_silent {
        EN => "Silent",
        FR => "Silencieux",
        IT => "Silenzioso",
        ES => "Silencioso",
    }
    lbl_onboarding_done {
        EN => "Onboarding done",
        FR => "Configuration initiale faite",
        IT => "Configurazione iniziale completata",
        ES => "Configuración inicial hecha",
    }
    lbl_config_path {
        EN => "Config path",
        FR => "Chemin de configuration",
        IT => "Percorso configurazione",
        ES => "Ruta de configuración",
    }
    status_title {
        EN => "Secret Stripper Status",
        FR => "État de Secret Stripper",
        IT => "Stato di Secret Stripper",
        ES => "Estado de Secret Stripper",
    }
    de_status_failed(err: &str,) {
        EN => format!("FAILED ({})", err),
        FR => format!("ÉCHEC ({})", err),
        IT => format!("FALLITO ({})", err),
        ES => format!("FALLÓ ({})", err),
    }

    // ---- CLI: menu / generic ----
    cli_no_config {
        EN => "No configuration found. Run 'secret-stripper init' first.",
        FR => "Aucune configuration trouvée. Lancez d'abord 'secret-stripper init'.",
        IT => "Nessuna configurazione trovata. Esegui prima 'secret-stripper init'.",
        ES => "No se encontró configuración. Ejecuta primero 'secret-stripper init'.",
    }
    cli_run_init_first {
        EN => "Run 'secret-stripper init' first.",
        FR => "Lancez d'abord 'secret-stripper init'.",
        IT => "Esegui prima 'secret-stripper init'.",
        ES => "Ejecuta primero 'secret-stripper init'.",
    }
    cli_run_init_again {
        EN => "Run 'secret-stripper init' to set up again.",
        FR => "Lancez 'secret-stripper init' pour reconfigurer.",
        IT => "Esegui 'secret-stripper init' per riconfigurare.",
        ES => "Ejecuta 'secret-stripper init' para configurar de nuevo.",
    }
    cli_clipboard_access_failed(err: &str,) {
        EN => format!("Failed to access clipboard: {}", err),
        FR => format!("Échec d'accès au presse-papiers : {}", err),
        IT => format!("Accesso agli appunti non riuscito: {}", err),
        ES => format!("Error al acceder al portapapeles: {}", err),
    }

    // ---- CLI: uninstall ----
    cli_uninstall_done {
        EN => "Secret Stripper fully removed.",
        FR => "Secret Stripper entièrement supprimé.",
        IT => "Secret Stripper rimosso completamente.",
        ES => "Secret Stripper eliminado por completo.",
    }
    cli_uninstall_de_cleared {
        EN => "  - DE shortcut binding: cleared",
        FR => "  - Liaison du raccourci DE : supprimée",
        IT => "  - Associazione scorciatoia DE: rimossa",
        ES => "  - Vínculo de atajo DE: eliminado",
    }
    cli_uninstall_nothing {
        EN => "  - Config dir: nothing to clean",
        FR => "  - Dossier de configuration : rien à nettoyer",
        IT => "  - Cartella configurazione: niente da pulire",
        ES => "  - Carpeta de configuración: nada que limpiar",
    }
    cli_uninstall_files(list: &str,) {
        EN => format!("  - Config files: {}", list),
        FR => format!("  - Fichiers de configuration : {}", list),
        IT => format!("  - File di configurazione: {}", list),
        ES => format!("  - Archivos de configuración: {}", list),
    }

    // ---- CLI: register / unregister shortcut ----
    cli_no_hotkey {
        EN => "No hotkey configured. Run 'secret-stripper init' first.",
        FR => "Aucun raccourci configuré. Lancez d'abord 'secret-stripper init'.",
        IT => "Nessuna scorciatoia configurata. Esegui prima 'secret-stripper init'.",
        ES => "No hay atajo configurado. Ejecuta primero 'secret-stripper init'.",
    }
    cli_press_to_redact(hotkey: &str,) {
        EN => format!("Press {} on selected text after copying it (Ctrl+C) to redact in place.", hotkey),
        FR => format!("Appuyez sur {} sur le texte sélectionné après l'avoir copié (Ctrl+C) pour le masquer sur place.", hotkey),
        IT => format!("Premi {} sul testo selezionato dopo averlo copiato (Ctrl+C) per oscurarlo sul posto.", hotkey),
        ES => format!("Pulsa {} sobre el texto seleccionado tras copiarlo (Ctrl+C) para redactarlo en el sitio.", hotkey),
    }
    cli_register_failed(err: &str,) {
        EN => format!("Could not auto-register the shortcut: {}", err),
        FR => format!("Impossible d'enregistrer automatiquement le raccourci : {}", err),
        IT => format!("Impossibile registrare automaticamente la scorciatoia: {}", err),
        ES => format!("No se pudo registrar automáticamente el atajo: {}", err),
    }
    cli_register_workaround(exe: &str, hotkey: &str,) {
        EN => format!("Workaround: bind '{} trigger' manually to {} in your desktop's keyboard settings.", exe, hotkey),
        FR => format!("Solution : liez '{} trigger' manuellement à {} dans les paramètres clavier de votre bureau.", exe, hotkey),
        IT => format!("Soluzione: associa manualmente '{} trigger' a {} nelle impostazioni della tastiera del desktop.", exe, hotkey),
        ES => format!("Solución: vincula '{} trigger' manualmente a {} en la configuración de teclado de tu escritorio.", exe, hotkey),
    }
    cli_unregister_failed(err: &str,) {
        EN => format!("Could not auto-unregister the shortcut: {}", err),
        FR => format!("Impossible de désenregistrer automatiquement le raccourci : {}", err),
        IT => format!("Impossibile annullare automaticamente la registrazione della scorciatoia: {}", err),
        ES => format!("No se pudo anular automáticamente el registro del atajo: {}", err),
    }
    cli_unregister_done {
        EN => "Custom shortcut removed.",
        FR => "Raccourci personnalisé supprimé.",
        IT => "Scorciatoia personalizzata rimossa.",
        ES => "Atajo personalizado eliminado.",
    }

    // ---- CLI: trigger ----
    cli_nothing_to_redact {
        EN => "Nothing to redact: no selection and clipboard is empty.",
        FR => "Rien à masquer : aucune sélection et le presse-papiers est vide.",
        IT => "Niente da oscurare: nessuna selezione e appunti vuoti.",
        ES => "Nada que redactar: sin selección y el portapapeles está vacío.",
    }
    cli_clipboard_too_large(len: usize, cap: usize,) {
        EN => format!("Clipboard too large to scan: {} bytes (cap {} bytes). Skipping.", len, cap),
        FR => format!("Presse-papiers trop volumineux à analyser : {} octets (limite {} octets). Ignoré.", len, cap),
        IT => format!("Appunti troppo grandi da analizzare: {} byte (limite {} byte). Saltato.", len, cap),
        ES => format!("Portapapeles demasiado grande para analizar: {} bytes (límite {} bytes). Omitido.", len, cap),
    }
    cli_no_secrets {
        EN => "No secrets detected in clipboard.",
        FR => "Aucun secret détecté dans le presse-papiers.",
        IT => "Nessun segreto rilevato negli appunti.",
        ES => "No se detectaron secretos en el portapapeles.",
    }
    cli_clipboard_write_failed(cleared: bool, err: &str,) {
        EN => format!("Clipboard write failed{}: {}", if cleared { " (clipboard cleared)" } else { " (and clipboard could NOT be cleared)" }, err),
        FR => format!("Échec d'écriture du presse-papiers{} : {}", if cleared { " (presse-papiers vidé)" } else { " (et le presse-papiers n'a PAS pu être vidé)" }, err),
        IT => format!("Scrittura negli appunti fallita{}: {}", if cleared { " (appunti svuotati)" } else { " (e gli appunti NON sono stati svuotati)" }, err),
        ES => format!("Fallo al escribir en el portapapeles{}: {}", if cleared { " (portapapeles vaciado)" } else { " (y el portapapeles NO se pudo vaciar)" }, err),
    }
    cli_redacted(n: usize,) {
        EN => if n == 1 { "Redacted 1 item.".to_string() } else { format!("Redacted {} items.", n) },
        FR => if n == 1 { "1 élément masqué.".to_string() } else { format!("{} éléments masqués.", n) },
        IT => if n == 1 { "1 elemento oscurato.".to_string() } else { format!("{} elementi oscurati.", n) },
        ES => if n == 1 { "1 elemento redactado.".to_string() } else { format!("{} elementos redactados.", n) },
    }

    // ---- CLI: init ----
    cli_already_configured(path: &str,) {
        EN => format!("Secret Stripper is already configured at {}", path),
        FR => format!("Secret Stripper est déjà configuré dans {}", path),
        IT => format!("Secret Stripper è già configurato in {}", path),
        ES => format!("Secret Stripper ya está configurado en {}", path),
    }
    cli_init_done_hint {
        EN => "Run 'secret-stripper menu' to change settings, or 'secret-stripper uninstall' to start over.",
        FR => "Lancez 'secret-stripper menu' pour changer les réglages, ou 'secret-stripper uninstall' pour tout recommencer.",
        IT => "Esegui 'secret-stripper menu' per cambiare le impostazioni, o 'secret-stripper uninstall' per ricominciare.",
        ES => "Ejecuta 'secret-stripper menu' para cambiar la configuración, o 'secret-stripper uninstall' para empezar de nuevo.",
    }
    cli_init_header {
        EN => "Secret Stripper initialized with defaults:",
        FR => "Secret Stripper initialisé avec les valeurs par défaut :",
        IT => "Secret Stripper inizializzato con i valori predefiniti:",
        ES => "Secret Stripper inicializado con valores predeterminados:",
    }
    suffix_autodetected {
        EN => "auto-detected",
        FR => "détecté automatiquement",
        IT => "rilevato automaticamente",
        ES => "detectado automáticamente",
    }
    sensitivity_balanced {
        EN => "Balanced",
        FR => "Équilibré",
        IT => "Bilanciato",
        ES => "Equilibrado",
    }
    deep_scan_on_desc {
        EN => "on (8 heuristic scanners)",
        FR => "activé (8 scanners heuristiques)",
        IT => "attivo (8 scanner euristici)",
        ES => "activado (8 escáneres heurísticos)",
    }
    entropy_state_desc(on: bool,) {
        EN => format!(
            "{} (Shannon-entropy catch-all; edit config.toml)",
            if on { "on" } else { "off" }
        ),
        FR => format!(
            "{} (filet de sécurité par entropie ; modifier config.toml)",
            if on { "activé" } else { "désactivé" }
        ),
        IT => format!(
            "{} (rete di sicurezza a entropia; modifica config.toml)",
            if on { "attivo" } else { "disattivo" }
        ),
        ES => format!(
            "{} (red de seguridad por entropía; editar config.toml)",
            if on { "activado" } else { "desactivado" }
        ),
    }
    notif_silent_hint {
        EN => "silent (toggle via 'secret-stripper menu')",
        FR => "silencieux (basculer via 'secret-stripper menu')",
        IT => "silenzioso (commuta tramite 'secret-stripper menu')",
        ES => "silencioso (alternar con 'secret-stripper menu')",
    }
    cli_init_usage(hotkey: &str,) {
        EN => format!("Normal Ctrl+C / Ctrl+V are untouched. Press {} to copy a redacted version of the current selection.", hotkey),
        FR => format!("Ctrl+C / Ctrl+V normaux ne sont pas modifiés. Appuyez sur {} pour copier une version masquée de la sélection actuelle.", hotkey),
        IT => format!("I normali Ctrl+C / Ctrl+V non sono modificati. Premi {} per copiare una versione oscurata della selezione corrente.", hotkey),
        ES => format!("Ctrl+C / Ctrl+V normales no se modifican. Pulsa {} para copiar una versión redactada de la selección actual.", hotkey),
    }
    cli_warn_no_hotkey {
        EN => "Warning: no hotkey could be registered. Run 'secret-stripper menu' and rebind the hotkey to capture a working chord.",
        FR => "Attention : aucun raccourci n'a pu être enregistré. Lancez 'secret-stripper menu' et redéfinissez le raccourci pour capturer une combinaison fonctionnelle.",
        IT => "Attenzione: nessuna scorciatoia registrata. Esegui 'secret-stripper menu' e riassegna la scorciatoia per catturare una combinazione valida.",
        ES => "Aviso: no se pudo registrar ningún atajo. Ejecuta 'secret-stripper menu' y reasigna el atajo para capturar una combinación válida.",
    }
    cli_last_error(err: &str,) {
        EN => format!("Last error: {}", err),
        FR => format!("Dernière erreur : {}", err),
        IT => format!("Ultimo errore: {}", err),
        ES => format!("Último error: {}", err),
    }
    cli_tweak_later {
        EN => "Tweak any setting later with 'secret-stripper menu'.",
        FR => "Ajustez n'importe quel réglage plus tard avec 'secret-stripper menu'.",
        IT => "Modifica qualsiasi impostazione in seguito con 'secret-stripper menu'.",
        ES => "Ajusta cualquier opción más tarde con 'secret-stripper menu'.",
    }
    hk_available(key: &str,) {
        EN => format!("{} (available)", key),
        FR => format!("{} (disponible)", key),
        IT => format!("{} (disponibile)", key),
        ES => format!("{} (disponible)", key),
    }
    hk_fallback(active: &str, preferred: &str,) {
        EN => format!("{} (fallback: {} was unavailable)", active, preferred),
        FR => format!("{} (repli : {} était indisponible)", active, preferred),
        IT => format!("{} (ripiego: {} non disponibile)", active, preferred),
        ES => format!("{} (alternativa: {} no estaba disponible)", active, preferred),
    }
    hk_none(tried: &str,) {
        EN => format!("none available (tried {})", tried),
        FR => format!("aucun disponible (essayé {})", tried),
        IT => format!("nessuno disponibile (provato {})", tried),
        ES => format!("ninguno disponible (probado {})", tried),
    }
    err_rebind_failed(hotkey: &str,) {
        EN => format!("re-binding '{}' failed: no desktop-environment backend accepted the binding. Fix the DE state and rerun 'secret-stripper init', or pick another chord via 'secret-stripper menu'.", hotkey),
        FR => format!("la reliaison de '{}' a échoué : aucun backend d'environnement de bureau n'a accepté la liaison. Corrigez l'état du DE et relancez 'secret-stripper init', ou choisissez une autre combinaison via 'secret-stripper menu'.", hotkey),
        IT => format!("la riassociazione di '{}' è fallita: nessun backend dell'ambiente desktop ha accettato l'associazione. Correggi lo stato del DE e riesegui 'secret-stripper init', o scegli un'altra combinazione tramite 'secret-stripper menu'.", hotkey),
        ES => format!("la revinculación de '{}' falló: ningún backend del entorno de escritorio aceptó el vínculo. Corrige el estado del DE y vuelve a ejecutar 'secret-stripper init', o elige otra combinación con 'secret-stripper menu'.", hotkey),
    }
    err_autobind_failed(hotkey: &str,) {
        EN => format!("auto-binding '{}' failed: no desktop-environment backend accepted the binding. Config has been saved; fix the DE state and rerun 'secret-stripper init', or pick another chord via 'secret-stripper menu'.", hotkey),
        FR => format!("la liaison automatique de '{}' a échoué : aucun backend d'environnement de bureau n'a accepté la liaison. La configuration a été enregistrée ; corrigez l'état du DE et relancez 'secret-stripper init', ou choisissez une autre combinaison via 'secret-stripper menu'.", hotkey),
        IT => format!("l'associazione automatica di '{}' è fallita: nessun backend dell'ambiente desktop ha accettato l'associazione. La configurazione è stata salvata; correggi lo stato del DE e riesegui 'secret-stripper init', o scegli un'altra combinazione tramite 'secret-stripper menu'.", hotkey),
        ES => format!("el vínculo automático de '{}' falló: ningún backend del entorno de escritorio aceptó el vínculo. La configuración se guardó; corrige el estado del DE y vuelve a ejecutar 'secret-stripper init', o elige otra combinación con 'secret-stripper menu'.", hotkey),
    }

    // ---- updater: run_upgrade progress ----
    up_checking {
        EN => "Checking for updates...",
        FR => "Recherche de mises à jour...",
        IT => "Ricerca di aggiornamenti...",
        ES => "Buscando actualizaciones...",
    }
    up_latest(tag: &str,) {
        EN => format!("  Latest version: {}", tag),
        FR => format!("  Dernière version : {}", tag),
        IT => format!("  Ultima versione: {}", tag),
        ES => format!("  Última versión: {}", tag),
    }
    up_current_binary(path: &str,) {
        EN => format!("\n  Current binary: {}", path),
        FR => format!("\n  Binaire actuel : {}", path),
        IT => format!("\n  Binario attuale: {}", path),
        ES => format!("\n  Binario actual: {}", path),
    }
    up_no_binary(os: &str, arch: &str,) {
        EN => format!("  No pre-built binary for {}-{}", os, arch),
        FR => format!("  Aucun binaire précompilé pour {}-{}", os, arch),
        IT => format!("  Nessun binario precompilato per {}-{}", os, arch),
        ES => format!("  No hay binario precompilado para {}-{}", os, arch),
    }
    up_downloading(name: &str,) {
        EN => format!("  Downloading {}...", name),
        FR => format!("  Téléchargement de {}...", name),
        IT => format!("  Scaricamento di {}...", name),
        ES => format!("  Descargando {}...", name),
    }
    up_updated(tag: &str,) {
        EN => format!("Updated to {}.", tag),
        FR => format!("Mis à jour vers {}.", tag),
        IT => format!("Aggiornato a {}.", tag),
        ES => format!("Actualizado a {}.", tag),
    }
    up_up_to_date(current: &str,) {
        EN => format!("Already on the latest version ({}).", current),
        FR => format!("Déjà sur la dernière version ({}).", current),
        IT => format!("Già all'ultima versione ({}).", current),
        ES => format!("Ya tienes la última versión ({}).", current),
    }
    svc_update_desc {
        EN => "Secret Stripper daily update check",
        FR => "Vérification quotidienne des mises à jour de Secret Stripper",
        IT => "Controllo giornaliero degli aggiornamenti di Secret Stripper",
        ES => "Comprobación diaria de actualizaciones de Secret Stripper",
    }
    svc_timer_desc {
        EN => "Daily Secret Stripper update check",
        FR => "Vérification quotidienne de Secret Stripper",
        IT => "Controllo giornaliero di Secret Stripper",
        ES => "Comprobación diaria de Secret Stripper",
    }

    // ---- TUI: menu ----
    menu_exit {
        EN => "Exit",
        FR => "Quitter",
        IT => "Esci",
        ES => "Salir",
    }

    // ---- TUI: status + activity panel ----
    status_panel_title {
        EN => "Status",
        FR => "Statut",
        IT => "Stato",
        ES => "Estado",
    }
    status_hotkey {
        EN => "Hotkey",
        FR => "Raccourci",
        IT => "Scorciatoia",
        ES => "Atajo",
    }
    status_lang {
        EN => "Lang",
        FR => "Langue",
        IT => "Lingua",
        ES => "Idioma",
    }
    status_sens {
        EN => "Sens.",
        FR => "Sens.",
        IT => "Sens.",
        ES => "Sens.",
    }
    status_notif {
        EN => "Notif.",
        FR => "Notif.",
        IT => "Notif.",
        ES => "Notif.",
    }
    status_deep {
        EN => "Deep",
        FR => "Approf.",
        IT => "Approf.",
        ES => "Profundo",
    }
    status_style {
        EN => "Style",
        FR => "Style",
        IT => "Stile",
        ES => "Estilo",
    }
    status_buckets {
        EN => "Buckets",
        FR => "Groupes",
        IT => "Gruppi",
        ES => "Grupos",
    }
    status_update {
        EN => "Update",
        FR => "Maj",
        IT => "Aggior.",
        ES => "Actualiz.",
    }
    status_on {
        EN => "on",
        FR => "activé",
        IT => "attivo",
        ES => "activo",
    }
    status_off {
        EN => "off",
        FR => "désactivé",
        IT => "spento",
        ES => "apagado",
    }
    status_silent {
        EN => "silent",
        FR => "silencieux",
        IT => "silenzioso",
        ES => "silencioso",
    }
    stats_24h {
        EN => "24h",
        FR => "24h",
        IT => "24h",
        ES => "24h",
    }
    stats_7d {
        EN => "7d",
        FR => "7j",
        IT => "7g",
        ES => "7d",
    }
    stats_30d {
        EN => "30d",
        FR => "30j",
        IT => "30g",
        ES => "30d",
    }
    stats_total {
        EN => "total",
        FR => "total",
        IT => "totale",
        ES => "total",
    }
    preset_custom_short {
        EN => "Custom",
        FR => "Personnalisé",
        IT => "Personalizzato",
        ES => "Personalizado",
    }
    section_main_menu {
        EN => "Main Menu",
        FR => "Menu principal",
        IT => "Menu principale",
        ES => "Menú principal",
    }
    lbl_menu_notifications {
        EN => "Notifications",
        FR => "Notifications",
        IT => "Notifiche",
        ES => "Notificaciones",
    }
    lbl_rebind_hotkey(hotkey: &str,) {
        EN => format!("Rebind Hotkey ({})", hotkey),
        FR => format!("Redéfinir le raccourci ({})", hotkey),
        IT => format!("Riassegna scorciatoia ({})", hotkey),
        ES => format!("Reasignar atajo ({})", hotkey),
    }
    lbl_menu_language(name: &str,) {
        EN => format!("Language ({})", name),
        FR => format!("Langue ({})", name),
        IT => format!("Lingua ({})", name),
        ES => format!("Idioma ({})", name),
    }
    lbl_manage_installation {
        EN => "Manage Installation",
        FR => "Gérer l'installation",
        IT => "Gestisci installazione",
        ES => "Gestionar instalación",
    }
    lbl_exit {
        EN => "Exit",
        FR => "Quitter",
        IT => "Esci",
        ES => "Salir",
    }
    lbl_star_github {
        EN => "Like Secret Stripper? Star us on GitHub",
        FR => "Vous aimez Secret Stripper ? Mettez une étoile sur GitHub",
        IT => "Ti piace Secret Stripper? Lascia una stella su GitHub",
        ES => "¿Te gusta Secret Stripper? Danos una estrella en GitHub",
    }
    help_notifications {
        EN => "Turn desktop notifications on or off when a secret is redacted",
        FR => "Activer ou désactiver les notifications lors d'une expurgation",
        IT => "Attiva o disattiva le notifiche quando un segreto viene oscurato",
        ES => "Activa o desactiva las notificaciones al redactar un secreto",
    }
    help_rebind_hotkey {
        EN => "Change the keyboard shortcut that triggers a clipboard scan",
        FR => "Modifier le raccourci clavier qui déclenche une analyse",
        IT => "Cambia la scorciatoia che avvia una scansione degli appunti",
        ES => "Cambia el atajo que inicia un escaneo del portapapeles",
    }
    help_language {
        EN => "Choose the interface language",
        FR => "Choisir la langue de l'interface",
        IT => "Scegli la lingua dell'interfaccia",
        ES => "Elige el idioma de la interfaz",
    }
    help_manage_installation {
        EN => "Check for updates or uninstall Secret Stripper",
        FR => "Rechercher des mises à jour ou désinstaller Secret Stripper",
        IT => "Controlla aggiornamenti o disinstalla Secret Stripper",
        ES => "Buscar actualizaciones o desinstalar Secret Stripper",
    }
    help_exit {
        EN => "Close the configuration menu",
        FR => "Fermer le menu de configuration",
        IT => "Chiudi il menu di configurazione",
        ES => "Cerrar el menú de configuración",
    }
    help_star_github {
        EN => "Open the Secret Stripper repository on GitHub",
        FR => "Ouvrir le dépôt Secret Stripper sur GitHub",
        IT => "Apri il repository di Secret Stripper su GitHub",
        ES => "Abrir el repositorio de Secret Stripper en GitHub",
    }
    confirm_yes {
        EN => "Yes",
        FR => "Oui",
        IT => "Sì",
        ES => "Sí",
    }
    confirm_no {
        EN => "No",
        FR => "Non",
        IT => "No",
        ES => "No",
    }
    star_title {
        EN => "Star us on GitHub",
        FR => "Une étoile sur GitHub",
        IT => "Stella su GitHub",
        ES => "Estrella en GitHub",
    }
    star_question {
        EN => "Open the Secret Stripper GitHub repository in your browser?",
        FR => "Ouvrir le dépôt GitHub de Secret Stripper dans votre navigateur ?",
        IT => "Aprire il repository GitHub di Secret Stripper nel browser?",
        ES => "¿Abrir el repositorio de GitHub de Secret Stripper en tu navegador?",
    }
    star_hint {
        EN => "  up/down  Choose  |  Enter  Confirm  |  Esc  Cancel  ",
        FR => "  haut/bas  Choisir  |  Entrée  Confirmer  |  Échap  Annuler  ",
        IT => "  su/giù  Scegli  |  Invio  Conferma  |  Esc  Annulla  ",
        ES => "  arriba/abajo  Elegir  |  Intro  Confirmar  |  Esc  Cancelar  ",
    }
    star_opened {
        EN => "Opened in your browser.",
        FR => "Ouvert dans votre navigateur.",
        IT => "Aperto nel browser.",
        ES => "Abierto en tu navegador.",
    }
    star_open_failed {
        EN => "Could not open the browser. Visit github.com/kalix127/secret-stripper",
        FR => "Impossible d'ouvrir le navigateur. Visitez github.com/kalix127/secret-stripper",
        IT => "Impossibile aprire il browser. Visita github.com/kalix127/secret-stripper",
        ES => "No se pudo abrir el navegador. Visita github.com/kalix127/secret-stripper",
    }
    mi_title {
        EN => "Manage Installation",
        FR => "Gérer l'installation",
        IT => "Gestisci installazione",
        ES => "Gestionar instalación",
    }
    mi_current(desktop: &str, hotkey: &str,) {
        EN => format!("Current: hotkey {} on {}", hotkey, desktop),
        FR => format!("Actuel : raccourci {} sur {}", hotkey, desktop),
        IT => format!("Attuale: scorciatoia {} su {}", hotkey, desktop),
        ES => format!("Actual: atajo {} en {}", hotkey, desktop),
    }
    mi_path(path: &str,) {
        EN => format!("Binary: {}", path),
        FR => format!("Binaire : {}", path),
        IT => format!("Binario: {}", path),
        ES => format!("Binario: {}", path),
    }
    lbl_check_updates {
        EN => "Check for Updates",
        FR => "Rechercher des mises à jour",
        IT => "Controlla aggiornamenti",
        ES => "Buscar actualizaciones",
    }
    lbl_uninstall {
        EN => "Uninstall (remove all)",
        FR => "Désinstaller (tout supprimer)",
        IT => "Disinstalla (rimuovi tutto)",
        ES => "Desinstalar (eliminar todo)",
    }
    lbl_back {
        EN => "Back",
        FR => "Retour",
        IT => "Indietro",
        ES => "Atrás",
    }
    help_check_updates {
        EN => "Download and install the latest Secret Stripper release",
        FR => "Télécharger et installer la dernière version de Secret Stripper",
        IT => "Scarica e installa l'ultima versione di Secret Stripper",
        ES => "Descargar e instalar la última versión de Secret Stripper",
    }
    help_uninstall {
        EN => "Remove the shortcut, config files, and Secret Stripper data",
        FR => "Supprimer le raccourci, les fichiers de configuration et les données",
        IT => "Rimuovi la scorciatoia, i file di configurazione e i dati",
        ES => "Eliminar el atajo, los archivos de configuración y los datos",
    }
    help_back {
        EN => "Return to the main menu",
        FR => "Revenir au menu principal",
        IT => "Torna al menu principale",
        ES => "Volver al menú principal",
    }

    // ---- TUI: detection settings (Phase 2) ----
    lbl_detection_settings {
        EN => "Detection Settings",
        FR => "Paramètres de détection",
        IT => "Impostazioni di rilevamento",
        ES => "Ajustes de detección",
    }
    help_detection_settings {
        EN => "Enable/disable categories, custom redaction patterns, allowlist",
        FR => "Activer/désactiver des catégories, motifs personnalisés, liste blanche",
        IT => "Attiva/disattiva categorie, modelli personalizzati, lista consentiti",
        ES => "Activar/desactivar categorías, patrones personalizados, lista blanca",
    }
    dm_title {
        EN => "Detection Settings",
        FR => "Paramètres de détection",
        IT => "Impostazioni di rilevamento",
        ES => "Ajustes de detección",
    }
    dm_categories {
        EN => "Categories (enable/disable buckets)",
        FR => "Catégories (activer/désactiver)",
        IT => "Categorie (attiva/disattiva)",
        ES => "Categorías (activar/desactivar)",
    }
    dm_add_custom {
        EN => "Add Custom Pattern",
        FR => "Ajouter un motif personnalisé",
        IT => "Aggiungi modello personalizzato",
        ES => "Añadir patrón personalizado",
    }
    dm_manage_custom {
        EN => "Manage Custom Patterns",
        FR => "Gérer les motifs personnalisés",
        IT => "Gestisci modelli personalizzati",
        ES => "Gestionar patrones personalizados",
    }
    dm_manage_allowlist {
        EN => "Manage Allowlist",
        FR => "Gérer la liste blanche",
        IT => "Gestisci lista consentiti",
        ES => "Gestionar lista blanca",
    }
    dm_back {
        EN => "Back",
        FR => "Retour",
        IT => "Indietro",
        ES => "Atrás",
    }
    help_dm_categories {
        EN => "Turn whole detection buckets on or off",
        FR => "Activer ou désactiver des groupes entiers de détection",
        IT => "Attiva o disattiva interi gruppi di rilevamento",
        ES => "Activa o desactiva grupos enteros de detección",
    }
    help_dm_add_custom {
        EN => "Define a new custom redaction regex",
        FR => "Définir un nouveau motif d'expurgation personnalisé",
        IT => "Definisci una nuova regex di oscuramento personalizzata",
        ES => "Define una nueva expresión regular de redacción",
    }
    help_dm_manage_custom {
        EN => "Edit or delete your custom redaction patterns",
        FR => "Modifier ou supprimer vos motifs personnalisés",
        IT => "Modifica o elimina i tuoi modelli personalizzati",
        ES => "Edita o elimina tus patrones personalizados",
    }
    help_dm_manage_allowlist {
        EN => "Mute known-safe values without disabling a category",
        FR => "Ignorer des valeurs sûres sans désactiver une catégorie",
        IT => "Ignora valori sicuri senza disattivare una categoria",
        ES => "Silencia valores seguros sin desactivar una categoría",
    }
    help_dm_back {
        EN => "Return to the main menu",
        FR => "Revenir au menu principal",
        IT => "Torna al menu principale",
        ES => "Volver al menú principal",
    }
    dm_presets {
        EN => "Presets",
        FR => "Préréglages",
        IT => "Preset",
        ES => "Preajustes",
    }
    help_dm_presets {
        EN => "Pick a coverage level: Minimal, Balanced, Full",
        FR => "Choisir un niveau de couverture : Minimal, Équilibré, Complet",
        IT => "Scegli un livello di copertura: Minimo, Bilanciato, Completo",
        ES => "Elige un nivel de cobertura: Mínimo, Equilibrado, Completo",
    }
    preset_title {
        EN => "Detection Presets",
        FR => "Préréglages de détection",
        IT => "Preset di rilevamento",
        ES => "Preajustes de detección",
    }
    help_preset_pick {
        EN => "Apply this detection preset",
        FR => "Appliquer ce préréglage de détection",
        IT => "Applica questo preset di rilevamento",
        ES => "Aplica este preajuste de detección",
    }
    preset_current {
        EN => "current",
        FR => "actuel",
        IT => "attuale",
        ES => "actual",
    }
    preset_custom {
        EN => "Custom (manual selection)",
        FR => "Personnalisé (sélection manuelle)",
        IT => "Personalizzato (selezione manuale)",
        ES => "Personalizado (selección manual)",
    }
    dm_redact_style {
        EN => "Redaction Style",
        FR => "Style d'expurgation",
        IT => "Stile di oscuramento",
        ES => "Estilo de redacción",
    }
    help_dm_redact_style {
        EN => "Choose the text that replaces a detected secret",
        FR => "Choisir le texte qui remplace un secret détecté",
        IT => "Scegli il testo che sostituisce un segreto rilevato",
        ES => "Elige el texto que reemplaza un secreto detectado",
    }
    rs_title {
        EN => "Redaction Style",
        FR => "Style d'expurgation",
        IT => "Stile di oscuramento",
        ES => "Estilo de redacción",
    }
    help_rs_preset {
        EN => "Use this marker to redact detected secrets",
        FR => "Utiliser ce marqueur pour expurger les secrets détectés",
        IT => "Usa questo marcatore per oscurare i segreti rilevati",
        ES => "Usa este marcador para redactar los secretos detectados",
    }
    help_rs_custom {
        EN => "Type your own redaction marker",
        FR => "Saisir votre propre marqueur d'expurgation",
        IT => "Scrivi il tuo marcatore di oscuramento",
        ES => "Escribe tu propio marcador de redacción",
    }
    rs_current {
        EN => "current",
        FR => "actuel",
        IT => "attuale",
        ES => "actual",
    }
    rs_custom {
        EN => "Type your own",
        FR => "Saisir le vôtre",
        IT => "Scrivi il tuo",
        ES => "Escribe el tuyo",
    }
    rs_custom_field {
        EN => "Custom redaction text",
        FR => "Texte d'expurgation personnalisé",
        IT => "Testo di oscuramento personalizzato",
        ES => "Texto de redacción personalizado",
    }
    rs_custom_hint {
        EN => "Enter  Save   |   Esc  Cancel",
        FR => "Entrée  Enregistrer   |   Échap  Annuler",
        IT => "Invio  Salva   |   Esc  Annulla",
        ES => "Intro  Guardar   |   Esc  Cancelar",
    }
    rs_empty_err {
        EN => "Redaction text cannot be empty.",
        FR => "Le texte d'expurgation ne peut pas être vide.",
        IT => "Il testo di oscuramento non può essere vuoto.",
        ES => "El texto de redacción no puede estar vacío.",
    }
    cat_title {
        EN => "Categories",
        FR => "Catégories",
        IT => "Categorie",
        ES => "Categorías",
    }
    cat_empty {
        EN => "No categories found.",
        FR => "Aucune catégorie trouvée.",
        IT => "Nessuna categoria trovata.",
        ES => "No se encontraron categorías.",
    }
    cat_hint {
        EN => "up/down  Move   |   Space  Toggle   |   Esc  Back",
        FR => "haut/bas  Déplacer   |   Espace  Basculer   |   Échap  Retour",
        IT => "su/giù  Sposta   |   Spazio  Attiva/disattiva   |   Esc  Indietro",
        ES => "arriba/abajo  Mover   |   Espacio  Alternar   |   Esc  Atrás",
    }
    cp_title_list {
        EN => "Custom Patterns",
        FR => "Motifs personnalisés",
        IT => "Modelli personalizzati",
        ES => "Patrones personalizados",
    }
    cp_title_add {
        EN => "Add Custom Pattern",
        FR => "Ajouter un motif",
        IT => "Aggiungi modello",
        ES => "Añadir patrón",
    }
    cp_title_edit {
        EN => "Edit Custom Pattern",
        FR => "Modifier le motif",
        IT => "Modifica modello",
        ES => "Editar patrón",
    }
    cp_empty {
        EN => "No custom patterns yet. Press 'a' to add one.",
        FR => "Aucun motif personnalisé. Appuyez sur 'a' pour en ajouter.",
        IT => "Nessun modello personalizzato. Premi 'a' per aggiungerne uno.",
        ES => "Aún no hay patrones. Pulsa 'a' para añadir uno.",
    }
    cp_list_hint {
        EN => "up/down  Move   |   Enter  Edit   |   a  Add   |   d  Delete   |   Esc  Back",
        FR => "haut/bas  Déplacer   |   Entrée  Modifier   |   a  Ajouter   |   d  Supprimer   |   Échap  Retour",
        IT => "su/giù  Sposta   |   Invio  Modifica   |   a  Aggiungi   |   d  Elimina   |   Esc  Indietro",
        ES => "arriba/abajo  Mover   |   Intro  Editar   |   a  Añadir   |   d  Eliminar   |   Esc  Atrás",
    }
    cp_form_hint {
        EN => "Tab  Next field   |   Enter  Save   |   Esc  Cancel",
        FR => "Tab  Champ suivant   |   Entrée  Enregistrer   |   Échap  Annuler",
        IT => "Tab  Campo successivo   |   Invio  Salva   |   Esc  Annulla",
        ES => "Tab  Campo siguiente   |   Intro  Guardar   |   Esc  Cancelar",
    }
    cp_field_name {
        EN => "Name",
        FR => "Nom",
        IT => "Nome",
        ES => "Nombre",
    }
    cp_field_category {
        EN => "Category (bucket)",
        FR => "Catégorie (groupe)",
        IT => "Categoria (gruppo)",
        ES => "Categoría (grupo)",
    }
    cp_field_severity {
        EN => "Severity",
        FR => "Gravité",
        IT => "Gravità",
        ES => "Gravedad",
    }
    cp_severity_help {
        EN => "label only - every match is redacted; affects line-wrap rejoin only",
        FR => "étiquette seule - tout est masqué ; n'agit que sur le regroupement des lignes coupées",
        IT => "solo etichetta - tutto viene oscurato; incide solo sul riunire le righe spezzate",
        ES => "solo etiqueta - todo se redacta; solo afecta la reunión de líneas cortadas",
    }
    cp_field_regex {
        EN => "Regex",
        FR => "Regex",
        IT => "Regex",
        ES => "Regex",
    }
    cp_field_sample {
        EN => "Sample (test string)",
        FR => "Échantillon (chaîne de test)",
        IT => "Campione (stringa di test)",
        ES => "Muestra (cadena de prueba)",
    }
    cp_regex_invalid(e: &str,) {
        EN => format!("Invalid regex: {}", e),
        FR => format!("Regex invalide : {}", e),
        IT => format!("Regex non valida: {}", e),
        ES => format!("Regex no válida: {}", e),
    }
    cp_preview_match(m: &str,) {
        EN => format!("Match: {}", m),
        FR => format!("Correspondance : {}", m),
        IT => format!("Corrispondenza: {}", m),
        ES => format!("Coincidencia: {}", m),
    }
    cp_preview_nomatch {
        EN => "No match in sample.",
        FR => "Aucune correspondance dans l'échantillon.",
        IT => "Nessuna corrispondenza nel campione.",
        ES => "Sin coincidencias en la muestra.",
    }
    cp_preview_na {
        EN => "(fix the regex to preview)",
        FR => "(corrigez la regex pour l'aperçu)",
        IT => "(correggi la regex per l'anteprima)",
        ES => "(corrige la regex para la vista previa)",
    }
    cp_err_name_empty {
        EN => "Name cannot be empty.",
        FR => "Le nom ne peut pas être vide.",
        IT => "Il nome non può essere vuoto.",
        ES => "El nombre no puede estar vacío.",
    }
    cp_confirm_delete(n: &str,) {
        EN => format!("Delete custom pattern '{}'?", n),
        FR => format!("Supprimer le motif « {} » ?", n),
        IT => format!("Eliminare il modello '{}'?", n),
        ES => format!("¿Eliminar el patrón '{}'?", n),
    }
    al_title {
        EN => "Allowlist",
        FR => "Liste blanche",
        IT => "Lista consentiti",
        ES => "Lista blanca",
    }
    al_empty {
        EN => "Allowlist is empty. Press 'a' to add a regex.",
        FR => "Liste blanche vide. Appuyez sur 'a' pour ajouter une regex.",
        IT => "Lista vuota. Premi 'a' per aggiungere una regex.",
        ES => "Lista vacía. Pulsa 'a' para añadir una regex.",
    }
    al_list_hint {
        EN => "up/down  Move   |   Enter  Edit   |   a  Add   |   d  Delete",
        FR => "haut/bas  Déplacer   |   Entrée  Modifier   |   a  Ajouter   |   d  Supprimer",
        IT => "su/giù  Sposta   |   Invio  Modifica   |   a  Aggiungi   |   d  Elimina",
        ES => "arriba/abajo  Mover   |   Intro  Editar   |   a  Añadir   |   d  Eliminar",
    }
    al_form_hint {
        EN => "Enter  Save   |   Esc  Cancel",
        FR => "Entrée  Enregistrer   |   Échap  Annuler",
        IT => "Invio  Salva   |   Esc  Annulla",
        ES => "Intro  Guardar   |   Esc  Cancelar",
    }
    al_field_regex {
        EN => "Allowlist regex",
        FR => "Regex de la liste blanche",
        IT => "Regex lista consentiti",
        ES => "Regex de la lista blanca",
    }
    al_valid {
        EN => "Valid regex.",
        FR => "Regex valide.",
        IT => "Regex valida.",
        ES => "Regex válida.",
    }
    al_confirm_delete(n: &str,) {
        EN => format!("Delete allowlist entry '{}'?", n),
        FR => format!("Supprimer l'entrée « {} » ?", n),
        IT => format!("Eliminare la voce '{}'?", n),
        ES => format!("¿Eliminar la entrada '{}'?", n),
    }

    // ---- TUI: manage installation (updates) ----
    state_on {
        EN => "on",
        FR => "activé",
        IT => "attivo",
        ES => "activado",
    }
    state_off {
        EN => "off",
        FR => "désactivé",
        IT => "disattivato",
        ES => "desactivado",
    }
    lbl_auto_check(state: &str,) {
        EN => format!("Automatic update check ({})", state),
        FR => format!("Vérification auto des mises à jour ({})", state),
        IT => format!("Controllo automatico aggiornamenti ({})", state),
        ES => format!("Comprobación automática de actualizaciones ({})", state),
    }
    lbl_auto_upgrade(state: &str,) {
        EN => format!("Automatic upgrade ({})", state),
        FR => format!("Mise à niveau automatique ({})", state),
        IT => format!("Aggiornamento automatico ({})", state),
        ES => format!("Actualización automática ({})", state),
    }
    help_auto_check {
        EN => "Check once a day and notify when a new version is available",
        FR => "Vérifier une fois par jour et notifier si une version est disponible",
        IT => "Controlla una volta al giorno e notifica se c'è una nuova versione",
        ES => "Comprobar una vez al día y notificar si hay una versión nueva",
    }
    help_auto_upgrade {
        EN => "Also download and install new versions automatically, then notify",
        FR => "Télécharger et installer aussi les nouvelles versions, puis notifier",
        IT => "Scarica e installa anche le nuove versioni, poi notifica",
        ES => "Descargar e instalar también las versiones nuevas y notificar",
    }
    mi_checking {
        EN => "Checking for updates...",
        FR => "Recherche de mises à jour...",
        IT => "Ricerca aggiornamenti...",
        ES => "Buscando actualizaciones...",
    }
    mi_up_to_date(cur: &str,) {
        EN => format!("You are on the latest version ({}).", cur),
        FR => format!("Vous avez la dernière version ({}).", cur),
        IT => format!("Hai l'ultima versione ({}).", cur),
        ES => format!("Tienes la última versión ({}).", cur),
    }
    mi_update_available(cur: &str, latest: &str,) {
        EN => format!("Update available: {} -> {}", cur, latest),
        FR => format!("Mise à jour disponible : {} -> {}", cur, latest),
        IT => format!("Aggiornamento disponibile: {} -> {}", cur, latest),
        ES => format!("Actualización disponible: {} -> {}", cur, latest),
    }
    mi_check_failed {
        EN => "Could not check for updates (network error).",
        FR => "Impossible de vérifier les mises à jour (erreur réseau).",
        IT => "Impossibile verificare gli aggiornamenti (errore di rete).",
        ES => "No se pudo comprobar actualizaciones (error de red).",
    }
    mi_upgrade_now_q(latest: &str,) {
        EN => format!("Version {} is available. Upgrade now?", latest),
        FR => format!("La version {} est disponible. Mettre à jour maintenant ?", latest),
        IT => format!("È disponibile la versione {}. Aggiornare ora?", latest),
        ES => format!("La versión {} está disponible. ¿Actualizar ahora?", latest),
    }
    notify_uninstalled_title {
        EN => "Secret Stripper removed",
        FR => "Secret Stripper supprimé",
        IT => "Secret Stripper rimosso",
        ES => "Secret Stripper eliminado",
    }
    notify_uninstalled_body {
        EN => "Everything about Secret Stripper has been removed from your system.",
        FR => "Tout ce qui concerne Secret Stripper a été supprimé de votre système.",
        IT => "Tutto ciò che riguarda Secret Stripper è stato rimosso dal sistema.",
        ES => "Todo lo relacionado con Secret Stripper se ha eliminado del sistema.",
    }

    // ---- TUI: hotkey capture ----
    hk_placeholder {
        EN => "(press a combination)",
        FR => "(appuyez sur une combinaison)",
        IT => "(premi una combinazione)",
        ES => "(pulsa una combinación)",
    }
    hk_instr1 {
        EN => "  Press the key combination you want to use.",
        FR => "  Appuyez sur la combinaison de touches que vous voulez utiliser.",
        IT => "  Premi la combinazione di tasti che vuoi usare.",
        ES => "  Pulsa la combinación de teclas que quieres usar.",
    }
    hk_instr2 {
        EN => "  Hold one or more modifiers (Ctrl, Alt, Shift, Super) and tap a key.",
        FR => "  Maintenez un ou plusieurs modificateurs (Ctrl, Alt, Shift, Super) et appuyez sur une touche.",
        IT => "  Tieni premuti uno o più modificatori (Ctrl, Alt, Shift, Super) e premi un tasto.",
        ES => "  Mantén uno o más modificadores (Ctrl, Alt, Shift, Super) y pulsa una tecla.",
    }
    hk_current(value: &str,) {
        EN => format!("  Current: {}", value),
        FR => format!("  Actuel : {}", value),
        IT => format!("  Attuale: {}", value),
        ES => format!("  Actual: {}", value),
    }
    hk_new(value: &str,) {
        EN => format!("  New:     {}", value),
        FR => format!("  Nouveau : {}", value),
        IT => format!("  Nuovo:   {}", value),
        ES => format!("  Nuevo:   {}", value),
    }
    hk_title {
        EN => " Rebind Hotkey ",
        FR => " Redéfinir le raccourci ",
        IT => " Riassegna scorciatoia ",
        ES => " Reasignar atajo ",
    }
    hk_hint {
        EN => "  Enter Save  |  Esc Cancel  |  Backspace Clear  ",
        FR => "  Entrée Enregistrer  |  Échap Annuler  |  Retour arrière Effacer  ",
        IT => "  Invio Salva  |  Esc Annulla  |  Backspace Cancella  ",
        ES => "  Intro Guardar  |  Esc Cancelar  |  Retroceso Borrar  ",
    }
    hk_err_rebind(err: &str,) {
        EN => format!("Saved to config but DE re-bind failed: {}. Run 'secret-stripper register-shortcut' to retry.", err),
        FR => format!("Enregistré dans la configuration mais la reliaison DE a échoué : {}. Lancez 'secret-stripper register-shortcut' pour réessayer.", err),
        IT => format!("Salvato nella configurazione ma la riassociazione DE è fallita: {}. Esegui 'secret-stripper register-shortcut' per riprovare.", err),
        ES => format!("Guardado en la configuración pero la revinculación DE falló: {}. Ejecuta 'secret-stripper register-shortcut' para reintentar.", err),
    }
    hk_err_invalid(err: &str,) {
        EN => format!("Invalid chord: {}", err),
        FR => format!("Combinaison invalide : {}", err),
        IT => format!("Combinazione non valida: {}", err),
        ES => format!("Combinación no válida: {}", err),
    }
    hk_err_press_first {
        EN => "Press a combination first.",
        FR => "Appuyez d'abord sur une combinaison.",
        IT => "Premi prima una combinazione.",
        ES => "Pulsa primero una combinación.",
    }
    hk_err_unsupported(err: &str,) {
        EN => format!("Unsupported: {}", err),
        FR => format!("Non pris en charge : {}", err),
        IT => format!("Non supportato: {}", err),
        ES => format!("No compatible: {}", err),
    }

    // ---- TUI: language picker ----
    lang_title {
        EN => " Select Language ",
        FR => " Choisir la langue ",
        IT => " Seleziona lingua ",
        ES => " Seleccionar idioma ",
    }
    help_lang_pick {
        EN => "Switch the interface language",
        FR => "Changer la langue de l'interface",
        IT => "Cambia la lingua dell'interfaccia",
        ES => "Cambia el idioma de la interfaz",
    }

    ai_tui_detected_title {
        EN => "Detected AI TUIs on this system:",
        FR => "Outils TUI d'IA détectés sur ce système :",
        IT => "TUI di IA rilevate su questo sistema:",
        ES => "TUI de IA detectadas en este sistema:",
    }
    ai_tui_why {
        EN => "Add the snippet below to your shell config so each tool runs through 'paste-guard'. The wrapper sits between your terminal and the AI TUI, intercepting clipboard pastes and redacting any secrets or PII before they reach the prompt. Typing and normal output stay untouched.",
        FR => "Ajoutez le bloc ci-dessous à la configuration de votre shell pour que chaque outil passe par 'paste-guard'. Ce wrapper se place entre votre terminal et l'outil d'IA, intercepte les collages du presse-papiers et masque les secrets ou les données personnelles avant qu'ils n'atteignent l'invite. La frappe et la sortie normale ne sont pas modifiées.",
        IT => "Aggiungi il blocco qui sotto alla configurazione della shell così ogni strumento passa attraverso 'paste-guard'. Il wrapper si frappone tra il terminale e la TUI di IA, intercetta gli incolla dagli appunti e oscura segreti o dati personali prima che raggiungano il prompt. La digitazione e l'output normale restano invariati.",
        ES => "Añade el bloque siguiente a la configuración de tu shell para que cada herramienta pase por 'paste-guard'. El envoltorio se sitúa entre tu terminal y la TUI de IA, intercepta los pegados del portapapeles y redacta los secretos o datos personales antes de que lleguen al prompt. La escritura y la salida normal no se ven afectadas.",
    }
    ai_tui_add_to_file(path: &str,) {
        EN => format!("Add the lines below to {} (then open a new shell or run 'source {}'):", path, path),
        FR => format!("Ajoutez les lignes ci-dessous à {} (puis ouvrez un nouveau shell ou exécutez 'source {}') :", path, path),
        IT => format!("Aggiungi le righe sottostanti a {} (poi apri una nuova shell o esegui 'source {}'):", path, path),
        ES => format!("Añade las líneas siguientes a {} (después abre un nuevo shell o ejecuta 'source {}'):", path, path),
    }
    ai_tui_add_to_unknown_shell {
        EN => "Could not detect your shell from $SHELL. Add the lines below to your shell's startup file (e.g. ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, or the PowerShell profile on Windows):",
        FR => "Impossible de détecter votre shell via $SHELL. Ajoutez les lignes ci-dessous au fichier de démarrage de votre shell (par ex. ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, ou le profil PowerShell sous Windows) :",
        IT => "Impossibile rilevare la shell da $SHELL. Aggiungi le righe sottostanti al file di avvio della tua shell (ad es. ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, oppure il profilo PowerShell su Windows):",
        ES => "No se pudo detectar tu shell desde $SHELL. Añade las líneas siguientes al archivo de inicio de tu shell (por ejemplo ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, o el perfil de PowerShell en Windows):",
    }
    ai_tui_none_detected {
        EN => "No supported AI TUIs detected on PATH. If you install one later, re-run 'secret-stripper init' to see the alias snippet.",
        FR => "Aucun outil TUI d'IA pris en charge détecté dans le PATH. Si vous en installez un plus tard, relancez 'secret-stripper init' pour obtenir le bloc d'alias.",
        IT => "Nessuna TUI di IA supportata rilevata nel PATH. Se ne installi una in seguito, rilancia 'secret-stripper init' per vedere lo snippet di alias.",
        ES => "No se detectó ninguna TUI de IA compatible en el PATH. Si instalas una más adelante, vuelve a ejecutar 'secret-stripper init' para ver el bloque de alias.",
    }
    ai_tui_remove_hint {
        EN => "To stop routing through paste-guard, delete the block above (between the dashed comment lines) from your shell config, or run 'secret-stripper uninstall' to clean up everything at once.",
        FR => "Pour cesser d'utiliser paste-guard, supprimez le bloc ci-dessus (entre les lignes de commentaire en tirets) de la configuration de votre shell, ou exécutez 'secret-stripper uninstall' pour tout nettoyer en une fois.",
        IT => "Per non far più passare il pasting da paste-guard, elimina il blocco qui sopra (tra le righe di commento tratteggiate) dalla configurazione della tua shell, oppure esegui 'secret-stripper uninstall' per ripulire tutto in una volta.",
        ES => "Para dejar de pasar por paste-guard, elimina el bloque de arriba (entre las líneas de comentario con guiones) de la configuración de tu shell, o ejecuta 'secret-stripper uninstall' para limpiar todo de una vez.",
    }
    ai_tui_alias_removed(path: &str,) {
        EN => format!("Removed paste-guard alias block from {}", path),
        FR => format!("Bloc d'alias paste-guard supprimé de {}", path),
        IT => format!("Blocco di alias paste-guard rimosso da {}", path),
        ES => format!("Bloque de alias paste-guard eliminado de {}", path),
    }
    pg_no_child {
        EN => "paste-guard: no child command provided. Usage: secret-stripper paste-guard -- <cmd> [args...]",
        FR => "paste-guard : aucune commande enfant fournie. Usage : secret-stripper paste-guard -- <cmd> [args...]",
        IT => "paste-guard: nessun comando figlio fornito. Uso: secret-stripper paste-guard -- <cmd> [args...]",
        ES => "paste-guard: no se proporcionó ningún comando hijo. Uso: secret-stripper paste-guard -- <cmd> [args...]",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_returns_non_empty() {
        for l in Lang::all() {
            assert!(!l.notify_cleaned().is_empty());
            assert!(!l.notify_redacted(2).is_empty());
            assert!(!l.cli_no_config().is_empty());
            assert!(!l.cli_redacted(1).is_empty());
            assert!(!l.lang_title().is_empty());
            assert!(!l.hk_title().is_empty());
            assert!(!l.up_checking().is_empty());
            assert!(!l.svc_update_desc().is_empty());
            assert!(!l.endonym().is_empty());
            assert!(!l.notify_write_failed_body(true).is_empty());
            assert!(!l.notify_write_failed_body(false).is_empty());
        }
    }

    #[test]
    fn severity_label_covers_all_pairs() {
        let sevs = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ];
        for l in Lang::all() {
            for s in &sevs {
                assert!(!l.severity_label(s).is_empty());
            }
        }
        assert_eq!(Lang::EN.severity_label(&Severity::Critical), "Critical");
    }

    #[test]
    fn preset_label_covers_all_pairs() {
        for l in Lang::all() {
            for p in Preset::all() {
                let (name, desc) = l.preset_label(&p);
                assert!(!name.is_empty());
                assert!(!desc.is_empty());
            }
        }
        assert_eq!(Lang::EN.preset_label(&Preset::Balanced).0, "Balanced");
    }

    #[test]
    fn shortcut_bound_covers_all_pairs() {
        let backends = [
            ShortcutBackend::Gnome,
            ShortcutBackend::Cinnamon,
            ShortcutBackend::Mate,
            ShortcutBackend::Xfce,
            ShortcutBackend::Kde,
            ShortcutBackend::Skhd,
            ShortcutBackend::Hammerspoon,
            ShortcutBackend::WindowsAhk,
        ];
        for l in Lang::all() {
            for b in &backends {
                let s = l.shortcut_bound(b, "Ctrl+Alt+X");
                assert!(s.contains("Ctrl+Alt+X"));
            }
        }
    }

    #[test]
    fn endonyms_are_distinct() {
        let names: Vec<&str> = Lang::all().iter().map(|l| l.endonym()).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len());
    }
}
