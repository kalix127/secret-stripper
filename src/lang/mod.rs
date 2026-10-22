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
    Hyprland,
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
            (Lang::EN, ShortcutBackend::Hyprland) => {
                format!("Custom shortcut bound to '{}' via hyprland.conf.", chord)
            }
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
            (Lang::FR, ShortcutBackend::Hyprland) => {
                format!("Raccourci personnalisé lié à '{}' via hyprland.conf.", chord)
            }
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
            (Lang::IT, ShortcutBackend::Hyprland) => {
                format!("Scorciatoia personalizzata associata a '{}' tramite hyprland.conf.", chord)
            }
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
            (Lang::ES, ShortcutBackend::Hyprland) => {
                format!("Atajo personalizado vinculado a '{}' mediante hyprland.conf.", chord)
            }
        }
    }
}

lang_strings! {
    notify_redacted(n: usize,) {
        EN => if n == 1 { "Redacted 1 item".to_string() } else { format!("Redacted {} items", n) },
        FR => if n == 1 { "1 élément masqué".to_string() } else { format!("{} éléments masqués", n) },
        IT => if n == 1 { "1 elemento oscurato".to_string() } else { format!("{} elementi oscurati", n) },
        ES => if n == 1 { "1 elemento redactado".to_string() } else { format!("{} elementos redactados", n) },
    }

    notify_pasted {
        EN => "Pasted a redacted copy",
        FR => "Copie masquée collée",
        IT => "Copia oscurata incollata",
        ES => "Copia redactada pegada",
    }

    notify_not_pasted {
        EN => "Nothing was pasted",
        FR => "Rien n'a été collé",
        IT => "Non è stato incollato nulla",
        ES => "No se pegó nada",
    }

    notify_hotkey_moved(old: &str, new: &str,) {
        EN => format!("Updated to 2.0: the hotkey moved from {} to {}. Change it with 'secret-stripper menu'.", old, new),
        FR => format!("Mise à jour vers 2.0 : le raccourci passe de {} à {}. Modifiez-le avec 'secret-stripper menu'.", old, new),
        IT => format!("Aggiornato alla 2.0: la scorciatoia è passata da {} a {}. Cambiala con 'secret-stripper menu'.", old, new),
        ES => format!("Actualizado a 2.0: el atajo pasó de {} a {}. Cámbialo con 'secret-stripper menu'.", old, new),
    }

    cli_secret_without_location {
        EN => "A secret was detected without an exact location. Nothing was pasted to avoid leaking it.",
        FR => "Un secret a été détecté sans emplacement exact. Rien n'a été collé pour éviter toute fuite.",
        IT => "È stato rilevato un segreto senza una posizione esatta. Non è stato incollato nulla per evitare fughe.",
        ES => "Se detectó un secreto sin una ubicación exacta. No se pegó nada para evitar filtraciones.",
    }

    update_available_title {
        EN => "Secret Stripper update available",
        FR => "Mise à jour de Secret Stripper disponible",
        IT => "Aggiornamento di Secret Stripper disponibile",
        ES => "Actualización de Secret Stripper disponible",
    }

    update_available_body(current: &str, latest: &str,) {
        EN => format!("Version {} is out (you have {}). Run 'secret-stripper upgrade' to install, with sudo if it is in /usr/local/bin.", latest, current),
        FR => format!("La version {} est sortie (vous avez {}). Lancez 'secret-stripper upgrade' pour l'installer, avec sudo s'il est dans /usr/local/bin.", latest, current),
        IT => format!("È disponibile la versione {} (la tua è {}). Esegui 'secret-stripper upgrade' per installarla, con sudo se è in /usr/local/bin.", latest, current),
        ES => format!("La versión {} está disponible (tu versión es {}). Ejecuta 'secret-stripper upgrade' para instalarla, con sudo si está en /usr/local/bin.", latest, current),
    }

    update_installed_title {
        EN => "Secret Stripper updated",
        FR => "Secret Stripper mis à jour",
        IT => "Secret Stripper aggiornato",
        ES => "Secret Stripper actualizado",
    }

    update_installed_body(version: &str,) {
        EN => format!("Version {} is installed and used from the next paste.", version),
        FR => format!("La version {} est installée et servira dès le prochain collage.", version),
        IT => format!("La versione {} è installata e verrà usata dal prossimo incolla.", version),
        ES => format!("La versión {} está instalada y se usará desde el próximo pegado.", version),
    }

    lbl_config {
        EN => "Config",
        FR => "Configuration",
        IT => "Configurazione",
        ES => "Configuración",
    }
    lbl_hotkey {
        EN => "Hotkey",
        FR => "Raccourci",
        IT => "Scorciatoia",
        ES => "Atajo",
    }
    lbl_de_binding {
        EN => "Desktop shortcut",
        FR => "Raccourci du bureau",
        IT => "Scorciatoia desktop",
        ES => "Atajo del escritorio",
    }
    lbl_sensitivity {
        EN => "Sensitivity",
        FR => "Sensibilité",
        IT => "Sensibilità",
        ES => "Sensibilidad",
    }
    lbl_silent {
        EN => "Silent",
        FR => "Silencieux",
        IT => "Silenzioso",
        ES => "Silencioso",
    }
    lbl_config_path {
        EN => "Config path",
        FR => "Chemin de configuration",
        IT => "Percorso configurazione",
        ES => "Ruta de configuración",
    }
    lbl_terminal_chord {
        EN => "Terminal hotkey",
        FR => "Raccourci terminal",
        IT => "Scorciatoia terminale",
        ES => "Atajo de terminal",
    }
    lbl_desktop {
        EN => "Desktop",
        FR => "Bureau",
        IT => "Desktop",
        ES => "Escritorio",
    }
    lbl_session {
        EN => "Session",
        FR => "Session",
        IT => "Sessione",
        ES => "Sesión",
    }
    lbl_uinput_access {
        EN => "uinput access",
        FR => "Accès uinput",
        IT => "Accesso uinput",
        ES => "Acceso a uinput",
    }
    uinput_state(ok: bool,) {
        EN => if ok { "yes".to_string() } else { "no, run 'secret-stripper init'".to_string() },
        FR => if ok { "oui".to_string() } else { "non, lancez 'secret-stripper init'".to_string() },
        IT => if ok { "sì".to_string() } else { "no, esegui 'secret-stripper init'".to_string() },
        ES => if ok { "sí".to_string() } else { "no, ejecuta 'secret-stripper init'".to_string() },
    }
    status_not_set_up {
        EN => "Not set up. Run 'secret-stripper init'.",
        FR => "Non configuré. Lancez 'secret-stripper init'.",
        IT => "Non configurato. Esegui 'secret-stripper init'.",
        ES => "No configurado. Ejecuta 'secret-stripper init'.",
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

    cli_uninstall_done {
        EN => "Secret Stripper settings removed.",
        FR => "Paramètres de Secret Stripper supprimés.",
        IT => "Impostazioni di Secret Stripper rimosse.",
        ES => "Configuración de Secret Stripper eliminada.",
    }
    cli_uninstall_de_cleared {
        EN => "  - Keyboard shortcut: removed",
        FR => "  - Raccourci clavier : supprimé",
        IT => "  - Scorciatoia da tastiera: rimossa",
        ES => "  - Atajo de teclado: eliminado",
    }
    cli_uninstall_de_failed(err: &str,) {
        EN => format!("  - Keyboard shortcut: not removed ({}); delete it in your desktop's keyboard settings", err),
        FR => format!("  - Raccourci clavier : non supprimé ({}) ; supprimez-le dans les paramètres clavier du bureau", err),
        IT => format!("  - Scorciatoia da tastiera: non rimossa ({}); eliminala nelle impostazioni tastiera del desktop", err),
        ES => format!("  - Atajo de teclado: no eliminado ({}); bórralo en la configuración de teclado del escritorio", err),
    }
    cli_uninstall_timer_removed {
        EN => "  - Update check timer: removed",
        FR => "  - Minuteur de vérification des mises à jour : supprimé",
        IT => "  - Timer di controllo aggiornamenti: rimosso",
        ES => "  - Temporizador de comprobación de actualizaciones: eliminado",
    }
    cli_uninstall_timer_failed(err: &str,) {
        EN => format!("  - Update check timer: not removed ({})", err),
        FR => format!("  - Minuteur de vérification des mises à jour : non supprimé ({})", err),
        IT => format!("  - Timer di controllo aggiornamenti: non rimosso ({})", err),
        ES => format!("  - Temporizador de comprobación de actualizaciones: no eliminado ({})", err),
    }
    cli_uninstall_binary_left(exe: &str,) {
        EN => format!("The program itself stays at {}; delete it to finish.", exe),
        FR => format!("Le programme reste dans {} ; supprimez-le pour terminer.", exe),
        IT => format!("Il programma resta in {}; eliminalo per completare.", exe),
        ES => format!("El programa sigue en {}; bórralo para terminar.", exe),
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

    cli_no_hotkey {
        EN => "No hotkey configured. Run 'secret-stripper init' first.",
        FR => "Aucun raccourci configuré. Lancez d'abord 'secret-stripper init'.",
        IT => "Nessuna scorciatoia configurata. Esegui prima 'secret-stripper init'.",
        ES => "No hay atajo configurado. Ejecuta primero 'secret-stripper init'.",
    }
    cli_press_to_paste(hotkey: &str,) {
        EN => format!("Copy text as usual, then press {} to paste a redacted copy.", hotkey),
        FR => format!("Copiez du texte comme d'habitude, puis appuyez sur {} pour coller une copie masquée.", hotkey),
        IT => format!("Copia il testo come al solito, poi premi {} per incollarne una copia oscurata.", hotkey),
        ES => format!("Copia texto como siempre y luego pulsa {} para pegar una copia redactada.", hotkey),
    }
    cli_register_failed(err: &str,) {
        EN => format!("Could not auto-register the shortcut: {}", err),
        FR => format!("Impossible d'enregistrer automatiquement le raccourci : {}", err),
        IT => format!("Impossibile registrare automaticamente la scorciatoia: {}", err),
        ES => format!("No se pudo registrar automáticamente el atajo: {}", err),
    }
    cli_register_workaround(exe: &str, hotkey: &str,) {
        EN => format!("Workaround: bind '{} paste' manually to {} in your desktop's keyboard settings.", exe, hotkey),
        FR => format!("Solution : liez '{} paste' manuellement à {} dans les paramètres clavier de votre bureau.", exe, hotkey),
        IT => format!("Soluzione: associa manualmente '{} paste' a {} nelle impostazioni della tastiera del desktop.", exe, hotkey),
        ES => format!("Solución: vincula '{} paste' manualmente a {} en la configuración de teclado de tu escritorio.", exe, hotkey),
    }
    cli_register_workaround_terminal(exe: &str, chord: &str,) {
        EN => format!("For terminals, also bind '{} paste --terminal' to {}.", exe, chord),
        FR => format!("Pour les terminaux, liez aussi '{} paste --terminal' à {}.", exe, chord),
        IT => format!("Per i terminali, associa anche '{} paste --terminal' a {}.", exe, chord),
        ES => format!("Para terminales, vincula también '{} paste --terminal' a {}.", exe, chord),
    }
    cli_bind_examples {
        EN => "Example config lines:",
        FR => "Exemples de lignes de configuration :",
        IT => "Esempi di righe di configurazione:",
        ES => "Ejemplos de líneas de configuración:",
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

    cli_clipboard_too_large(len: usize, cap: usize,) {
        EN => format!("Clipboard too large to scan: {} bytes (cap {} bytes). Nothing was pasted.", len, cap),
        FR => format!("Presse-papiers trop volumineux à analyser : {} octets (limite {} octets). Rien n'a été collé.", len, cap),
        IT => format!("Appunti troppo grandi da analizzare: {} byte (limite {} byte). Non è stato incollato nulla.", len, cap),
        ES => format!("Portapapeles demasiado grande para analizar: {} bytes (límite {} bytes). No se pegó nada.", len, cap),
    }
    cli_no_secrets {
        EN => "No secrets detected; pasted the clipboard as is.",
        FR => "Aucun secret détecté ; presse-papiers collé tel quel.",
        IT => "Nessun segreto rilevato; appunti incollati così come sono.",
        ES => "No se detectaron secretos; se pegó el portapapeles tal cual.",
    }

    cli_image_scan_failed {
        EN => "Could not scan the clipboard image. Nothing was pasted.",
        FR => "Impossible d'analyser l'image du presse-papiers. Rien n'a été collé.",
        IT => "Impossibile analizzare l'immagine degli appunti. Non è stato incollato nulla.",
        ES => "No se pudo analizar la imagen del portapapeles. No se pegó nada.",
    }
    cli_ocr_missing {
        EN => "tesseract is not installed. Install it, or turn off screenshot redaction in 'secret-stripper menu'.",
        FR => "tesseract n'est pas installé. Installez-le ou désactivez l'expurgation des captures dans 'secret-stripper menu'.",
        IT => "tesseract non è installato. Installalo o disattiva l'oscuramento degli screenshot in 'secret-stripper menu'.",
        ES => "tesseract no está instalado. Instálalo o desactiva la redacción de capturas en 'secret-stripper menu'.",
    }

    cli_image_detected_unmappable {
        EN => "Detected a secret in the image but could not locate it to redact. Nothing was pasted.",
        FR => "Secret détecté dans l'image mais impossible de le localiser pour le masquer. Rien n'a été collé.",
        IT => "Segreto rilevato nell'immagine ma impossibile localizzarlo per oscurarlo. Non è stato incollato nulla.",
        ES => "Se detectó un secreto en la imagen pero no se pudo localizar para redactarlo. No se pegó nada.",
    }

    cli_paste_failed(err: &str,) {
        EN => format!("Redacted paste failed: {}", err),
        FR => format!("Échec du collage masqué : {}", err),
        IT => format!("Incolla oscurato non riuscito: {}", err),
        ES => format!("Falló el pegado redactado: {}", err),
    }
    cli_input_unavailable(err: &str,) {
        EN => format!("Cannot simulate the paste keys: {}. On Wayland, run 'secret-stripper init' to set up /dev/uinput access.", err),
        FR => format!("Impossible de simuler les touches de collage : {}. Sous Wayland, lancez 'secret-stripper init' pour configurer l'accès à /dev/uinput.", err),
        IT => format!("Impossibile simulare i tasti di incolla: {}. Su Wayland, esegui 'secret-stripper init' per configurare l'accesso a /dev/uinput.", err),
        ES => format!("No se pueden simular las teclas de pegado: {}. En Wayland, ejecuta 'secret-stripper init' para configurar el acceso a /dev/uinput.", err),
    }
    cli_lock_failed(err: &str,) {
        EN => format!("Cannot create the paste lock file: {}", err),
        FR => format!("Impossible de créer le fichier de verrou de collage : {}", err),
        IT => format!("Impossibile creare il file di blocco per l'incolla: {}", err),
        ES => format!("No se puede crear el archivo de bloqueo de pegado: {}", err),
    }
    cli_chord_held {
        EN => "The shortcut keys were still held, so the paste kept triggering the shortcut again. Release them right after pressing.",
        FR => "Les touches du raccourci étaient encore enfoncées, le collage relançait donc le raccourci. Relâchez-les juste après l'appui.",
        IT => "I tasti della scorciatoia erano ancora premuti, quindi l'incolla riattivava la scorciatoia. Rilasciali subito dopo averli premuti.",
        ES => "Las teclas del atajo seguían pulsadas, así que el pegado volvía a activar el atajo. Suéltalas justo después de pulsarlas.",
    }
    cli_restore_skipped {
        EN => "No app read the redacted copy within 3s, so it stays on the clipboard.",
        FR => "Aucune application n'a lu la copie masquée en 3 s ; elle reste dans le presse-papiers.",
        IT => "Nessuna app ha letto la copia oscurata entro 3 s; resta negli appunti.",
        ES => "Ninguna app leyó la copia redactada en 3 s; permanece en el portapapeles.",
    }
    cli_redacted(n: usize,) {
        EN => if n == 1 { "Redacted 1 item.".to_string() } else { format!("Redacted {} items.", n) },
        FR => if n == 1 { "1 élément masqué.".to_string() } else { format!("{} éléments masqués.", n) },
        IT => if n == 1 { "1 elemento oscurato.".to_string() } else { format!("{} elementi oscurati.", n) },
        ES => if n == 1 { "1 elemento redactado.".to_string() } else { format!("{} elementos redactados.", n) },
    }

    uinput_intro {
        EN => "Pasting on Wayland needs access to /dev/uinput. These commands grant it once, with sudo:",
        FR => "Coller sous Wayland nécessite l'accès à /dev/uinput. Ces commandes l'accordent une fois, avec sudo :",
        IT => "Incollare su Wayland richiede l'accesso a /dev/uinput. Questi comandi lo concedono una volta, con sudo:",
        ES => "Pegar en Wayland requiere acceso a /dev/uinput. Estos comandos lo conceden una vez, con sudo:",
    }
    cli_uinput_denied {
        EN => "No access to /dev/uinput. Run 'secret-stripper init'.",
        FR => "Pas d'accès à /dev/uinput. Lancez 'secret-stripper init'.",
        IT => "Nessun accesso a /dev/uinput. Esegui 'secret-stripper init'.",
        ES => "Sin acceso a /dev/uinput. Ejecuta 'secret-stripper init'.",
    }
    uinput_confirm {
        EN => "Run them now? [Y/n] ",
        FR => "Les exécuter maintenant ? [O/n] ",
        IT => "Eseguirli ora? [S/n] ",
        ES => "¿Ejecutarlos ahora? [S/n] ",
    }
    uinput_done {
        EN => "Virtual keyboard access granted.",
        FR => "Accès au clavier virtuel accordé.",
        IT => "Accesso alla tastiera virtuale concesso.",
        ES => "Acceso al teclado virtual concedido.",
    }
    uinput_relogin {
        EN => "Setup finished, but /dev/uinput is not writable yet. Log out and back in, then try the shortcut.",
        FR => "Configuration terminée, mais /dev/uinput n'est pas encore accessible en écriture. Déconnectez-vous puis reconnectez-vous, puis essayez le raccourci.",
        IT => "Configurazione completata, ma /dev/uinput non è ancora scrivibile. Esci e rientra nella sessione, poi prova la scorciatoia.",
        ES => "Configuración terminada, pero /dev/uinput aún no tiene permiso de escritura. Cierra sesión y vuelve a entrar, luego prueba el atajo.",
    }
    uinput_failed(err: &str,) {
        EN => format!("Virtual keyboard setup failed ({}). Run the commands above yourself, then rerun 'secret-stripper init'.", err),
        FR => format!("Échec de la configuration du clavier virtuel ({}). Exécutez vous-même les commandes ci-dessus, puis relancez 'secret-stripper init'.", err),
        IT => format!("Configurazione della tastiera virtuale non riuscita ({}). Esegui tu i comandi qui sopra, poi riesegui 'secret-stripper init'.", err),
        ES => format!("Falló la configuración del teclado virtual ({}). Ejecuta tú los comandos de arriba y vuelve a ejecutar 'secret-stripper init'.", err),
    }
    uinput_declined {
        EN => "Skipped. Pasting on Wayland will not work until you run the commands above or rerun 'secret-stripper init'.",
        FR => "Ignoré. Le collage sous Wayland ne fonctionnera pas tant que vous n'aurez pas exécuté les commandes ci-dessus ou relancé 'secret-stripper init'.",
        IT => "Saltato. L'incolla su Wayland non funzionerà finché non esegui i comandi qui sopra o riesegui 'secret-stripper init'.",
        ES => "Omitido. El pegado en Wayland no funcionará hasta que ejecutes los comandos de arriba o vuelvas a ejecutar 'secret-stripper init'.",
    }
    uinput_no_tty {
        EN => "Not running in a terminal, so nothing was run. Run the commands above yourself, or rerun 'secret-stripper init' in a terminal.",
        FR => "Pas de terminal, rien n'a été exécuté. Exécutez vous-même les commandes ci-dessus, ou relancez 'secret-stripper init' dans un terminal.",
        IT => "Nessun terminale, quindi non è stato eseguito nulla. Esegui tu i comandi qui sopra, o riesegui 'secret-stripper init' in un terminale.",
        ES => "No hay terminal, así que no se ejecutó nada. Ejecuta tú los comandos de arriba, o vuelve a ejecutar 'secret-stripper init' en una terminal.",
    }
    uinput_uninstall_hint(cmd: &str,) {
        EN => format!("Your session still has virtual keyboard access. To revoke it, run: {}", cmd),
        FR => format!("Votre session a toujours accès au clavier virtuel. Pour le révoquer, lancez : {}", cmd),
        IT => format!("La tua sessione ha ancora accesso alla tastiera virtuale. Per revocarlo, esegui: {}", cmd),
        ES => format!("Tu sesión aún tiene acceso al teclado virtual. Para revocarlo, ejecuta: {}", cmd),
    }
    cli_already_configured {
        EN => "Secret Stripper is already set up.",
        FR => "Secret Stripper est déjà configuré.",
        IT => "Secret Stripper è già configurato.",
        ES => "Secret Stripper ya está configurado.",
    }
    cli_init_done_hint {
        EN => "Run 'secret-stripper menu' to change settings, or 'secret-stripper uninstall' to start over.",
        FR => "Lancez 'secret-stripper menu' pour changer les réglages, ou 'secret-stripper uninstall' pour tout recommencer.",
        IT => "Esegui 'secret-stripper menu' per cambiare le impostazioni, o 'secret-stripper uninstall' per ricominciare.",
        ES => "Ejecuta 'secret-stripper menu' para cambiar la configuración, o 'secret-stripper uninstall' para empezar de nuevo.",
    }
    cli_init_header {
        EN => "Secret Stripper is set up.",
        FR => "Secret Stripper est configuré.",
        IT => "Secret Stripper è configurato.",
        ES => "Secret Stripper está configurado.",
    }
    cli_init_header_unbound {
        EN => "Secret Stripper is installed, but the hotkey is not bound yet.",
        FR => "Secret Stripper est installé, mais le raccourci n'est pas encore lié.",
        IT => "Secret Stripper è installato, ma la scorciatoia non è ancora assegnata.",
        ES => "Secret Stripper está instalado, pero el atajo aún no está asignado.",
    }
    cli_terminal_hint(chord: &str, keys: &str,) {
        EN => format!("In a terminal, press {} instead (it sends {}).", chord, keys),
        FR => format!("Dans un terminal, appuyez plutôt sur {} (il envoie {}).", chord, keys),
        IT => format!("In un terminale, premi invece {} (invia {}).", chord, keys),
        ES => format!("En una terminal, pulsa {} en su lugar (envía {}).", chord, keys),
    }
    cli_init_usage(hotkey: &str,) {
        EN => format!("Copy text as usual, then press {} to paste a redacted copy.", hotkey),
        FR => format!("Copiez comme d'habitude, puis appuyez sur {} pour coller une copie masquée.", hotkey),
        IT => format!("Copia come al solito, poi premi {} per incollare una copia oscurata.", hotkey),
        ES => format!("Copia como siempre y luego pulsa {} para pegar una copia redactada.", hotkey),
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
        EN => "Change settings with 'secret-stripper menu'.",
        FR => "Modifiez les réglages avec 'secret-stripper menu'.",
        IT => "Cambia le impostazioni con 'secret-stripper menu'.",
        ES => "Cambia la configuración con 'secret-stripper menu'.",
    }
    hk_fallback(active: &str, preferred: &str,) {
        EN => format!("{} (fallback: {} was invalid)", active, preferred),
        FR => format!("{} (repli : {} était invalide)", active, preferred),
        IT => format!("{} (ripiego: {} non valida)", active, preferred),
        ES => format!("{} (alternativa: {} no era válida)", active, preferred),
    }
    hk_none(tried: &str,) {
        EN => format!("none available (tried {})", tried),
        FR => format!("aucun disponible (essayé {})", tried),
        IT => format!("nessuno disponibile (provato {})", tried),
        ES => format!("ninguno disponible (probado {})", tried),
    }

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
        EN => "Secret Stripper update check",
        FR => "Vérification des mises à jour de Secret Stripper",
        IT => "Controllo degli aggiornamenti di Secret Stripper",
        ES => "Comprobación de actualizaciones de Secret Stripper",
    }
    svc_timer_desc {
        EN => "Secret Stripper update check at login and daily",
        FR => "Vérification de Secret Stripper à la connexion et chaque jour",
        IT => "Controllo di Secret Stripper all'accesso e ogni giorno",
        ES => "Comprobación de Secret Stripper al iniciar sesión y cada día",
    }

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
        EN => "Turn desktop notifications on or off: redactions and updates (failed pastes always notify)",
        FR => "Activer ou désactiver les notifications : expurgations et mises à jour (les collages échoués notifient toujours)",
        IT => "Attiva o disattiva le notifiche: oscuramenti e aggiornamenti (gli incolla non riusciti notificano sempre)",
        ES => "Activa o desactiva las notificaciones: redacciones y actualizaciones (los pegados fallidos siempre notifican)",
    }
    help_rebind_hotkey {
        EN => "Change the keyboard shortcut that pastes a redacted copy",
        FR => "Modifier le raccourci clavier qui colle une copie masquée",
        IT => "Cambia la scorciatoia che incolla una copia oscurata",
        ES => "Cambia el atajo que pega una copia redactada",
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
        EN => "Uninstall",
        FR => "Désinstaller",
        IT => "Disinstalla",
        ES => "Desinstalar",
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
        EN => "Remove the shortcut, update timer, config and data; the program file stays",
        FR => "Supprimer le raccourci, le minuteur, la configuration et les données ; le programme reste",
        IT => "Rimuovi scorciatoia, timer, configurazione e dati; il programma resta",
        ES => "Eliminar el atajo, el temporizador, la configuración y los datos; el programa se queda",
    }
    help_back {
        EN => "Return to the main menu",
        FR => "Revenir au menu principal",
        IT => "Torna al menu principale",
        ES => "Volver al menú principal",
    }

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
    menu_image_scan(on: bool,) {
        EN => format!("Screenshot redaction: {}", if on { "on" } else { "off" }),
        FR => format!(
            "Expurgation des captures d'écran : {}",
            if on { "activée" } else { "désactivée" }
        ),
        IT => format!(
            "Oscuramento screenshot: {}",
            if on { "attivo" } else { "disattivo" }
        ),
        ES => format!(
            "Redacción de capturas: {}",
            if on { "activada" } else { "desactivada" }
        ),
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
    flash_tesseract_missing {
        EN => "tesseract is not installed: screenshots will not paste.",
        FR => "tesseract n'est pas installé : les captures ne seront pas collées.",
        IT => "tesseract non è installato: gli screenshot non verranno incollati.",
        ES => "tesseract no está instalado: las capturas no se pegarán.",
    }
    help_menu_image_scan {
        EN => "Redact secrets in clipboard screenshots (needs tesseract)",
        FR => "Expurger les secrets des captures du presse-papiers (requiert tesseract)",
        IT => "Oscura i segreti negli screenshot degli appunti (richiede tesseract)",
        ES => "Redacta secretos en capturas del portapapeles (requiere tesseract)",
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
    menu_redact_style {
        EN => "Redaction Style",
        FR => "Style d'expurgation",
        IT => "Stile di oscuramento",
        ES => "Estilo de redacción",
    }
    help_menu_redact_style {
        EN => "Choose how detected secrets are replaced",
        FR => "Choisir comment les secrets détectés sont remplacés",
        IT => "Scegli come sostituire i segreti rilevati",
        ES => "Elige cómo se reemplazan los secretos detectados",
    }
    rs_title {
        EN => "Redaction Style",
        FR => "Style d'expurgation",
        IT => "Stile di oscuramento",
        ES => "Estilo de redacción",
    }
    rs_style_marker {
        EN => "Marker",
        FR => "Marqueur",
        IT => "Marcatore",
        ES => "Marcador",
    }
    rs_style_drop {
        EN => "Drop",
        FR => "Supprimer",
        IT => "Rimuovi",
        ES => "Eliminar",
    }
    rs_style_typed {
        EN => "Type tag",
        FR => "Étiquette typée",
        IT => "Etichetta tipizzata",
        ES => "Etiqueta tipada",
    }
    rs_style_placeholder {
        EN => "Placeholder",
        FR => "Valeur fictive",
        IT => "Valore fittizio",
        ES => "Valor ficticio",
    }
    help_rs_style_marker {
        EN => "Replace each secret with a configurable marker (e.g. [REDACTED])",
        FR => "Remplacer chaque secret par un marqueur configurable (ex : [REDACTED])",
        IT => "Sostituisci ogni segreto con un marcatore configurabile (es. [REDACTED])",
        ES => "Reemplaza cada secreto con un marcador configurable (p. ej. [REDACTED])",
    }
    help_rs_style_drop {
        EN => "Remove the secret entirely; surrounding text stays unchanged",
        FR => "Supprimer entièrement le secret ; le texte autour reste inchangé",
        IT => "Rimuovi del tutto il segreto; il testo circostante resta invariato",
        ES => "Elimina el secreto por completo; el texto alrededor no cambia",
    }
    help_rs_style_typed {
        EN => "Replace each secret with a typed tag (e.g. [EMAIL_ADDRESS], [AWS_ACCESS_KEY_ID])",
        FR => "Remplacer chaque secret par une étiquette typée (ex : [EMAIL_ADDRESS], [AWS_ACCESS_KEY_ID])",
        IT => "Sostituisci ogni segreto con un'etichetta tipizzata (es. [EMAIL_ADDRESS], [AWS_ACCESS_KEY_ID])",
        ES => "Reemplaza cada secreto con una etiqueta tipada (p. ej. [EMAIL_ADDRESS], [AWS_ACCESS_KEY_ID])",
    }
    help_rs_style_placeholder {
        EN => "Replace each secret with a realistic but fake sample value (e.g. user@example.com, AKIAIOSFODNN7EXAMPLE)",
        FR => "Remplacer chaque secret par une valeur d'exemple réaliste mais fictive (ex : user@example.com, AKIAIOSFODNN7EXAMPLE)",
        IT => "Sostituisci ogni segreto con un valore di esempio realistico ma falso (es. user@example.com, AKIAIOSFODNN7EXAMPLE)",
        ES => "Reemplaza cada secreto con un valor de ejemplo realista pero falso (p. ej. user@example.com, AKIAIOSFODNN7EXAMPLE)",
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
        EN => "Check at each login and notify, at most once a day, when a new version is out",
        FR => "Vérifier à chaque connexion et notifier, au plus une fois par jour, si une version sort",
        IT => "Controlla a ogni accesso e notifica, al massimo una volta al giorno, se c'è una nuova versione",
        ES => "Comprobar en cada inicio de sesión y avisar, como mucho una vez al día, si hay una versión nueva",
    }
    help_auto_upgrade {
        EN => "Also install new versions automatically; needs a binary your user can write",
        FR => "Installer aussi les nouvelles versions ; le binaire doit être modifiable par votre utilisateur",
        IT => "Installa anche le nuove versioni; il binario deve essere scrivibile dal tuo utente",
        ES => "Instalar también las versiones nuevas; el binario debe poder escribirlo tu usuario",
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
    hk_warn_slow_paste(keys: &str,) {
        EN => format!("  On Wayland, chords that do not include {} paste after a short delay, so you can release the keys.", keys),
        FR => format!("  Sous Wayland, les combinaisons qui ne contiennent pas {} collent après un court délai, le temps de relâcher les touches.", keys),
        IT => format!("  Su Wayland, le combinazioni che non contengono {} incollano dopo una breve attesa, per darti il tempo di rilasciare i tasti.", keys),
        ES => format!("  En Wayland, las combinaciones que no contienen {} pegan tras una breve espera, para que puedas soltar las teclas.", keys),
    }
    hk_terminal(chord: &str,) {
        EN => format!("  Terminals: {} (added automatically)", chord),
        FR => format!("  Terminaux : {} (ajouté automatiquement)", chord),
        IT => format!("  Terminali: {} (aggiunta automaticamente)", chord),
        ES => format!("  Terminales: {} (añadido automáticamente)", chord),
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
    hk_err_paste_keys(chord: &str,) {
        EN => format!("{} is also a paste shortcut, so every paste would trigger it again. Pick another hotkey in 'secret-stripper menu'.", chord),
        FR => format!("{} est aussi un raccourci de collage : chaque collage le relancerait. Choisissez un autre raccourci dans 'secret-stripper menu'.", chord),
        IT => format!("{} è anche una scorciatoia di incolla, quindi ogni incolla la riattiverebbe. Scegli un'altra scorciatoia in 'secret-stripper menu'.", chord),
        ES => format!("{} también es un atajo de pegado, así que cada pegado lo volvería a activar. Elige otro atajo en 'secret-stripper menu'.", chord),
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

    ai_tui_detected(tools: &str,) {
        EN => format!("AI tools found: {}.", tools),
        FR => format!("Outils d'IA trouvés : {}.", tools),
        IT => format!("Strumenti di IA trovati: {}.", tools),
        ES => format!("Herramientas de IA encontradas: {}.", tools),
    }
    ai_tui_add_to_file(path: &str,) {
        EN => format!("To redact pastes into them, add these lines to {} and open a new shell:", path),
        FR => format!("Pour masquer les collages dans ces outils, ajoutez ces lignes à {} et ouvrez un nouveau shell :", path),
        IT => format!("Per oscurare gli incolla in questi strumenti, aggiungi queste righe a {} e apri una nuova shell:", path),
        ES => format!("Para redactar lo que pegas en ellas, añade estas líneas a {} y abre un nuevo shell:", path),
    }
    ai_tui_add_to_unknown_shell {
        EN => "To redact pastes into them, add these lines to your shell config (~/.bashrc, ~/.zshrc or ~/.config/fish/config.fish) and open a new shell:",
        FR => "Pour masquer les collages dans ces outils, ajoutez ces lignes à la configuration de votre shell (~/.bashrc, ~/.zshrc ou ~/.config/fish/config.fish) et ouvrez un nouveau shell :",
        IT => "Per oscurare gli incolla in questi strumenti, aggiungi queste righe alla configurazione della shell (~/.bashrc, ~/.zshrc o ~/.config/fish/config.fish) e apri una nuova shell:",
        ES => "Para redactar lo que pegas en ellas, añade estas líneas a la configuración de tu shell (~/.bashrc, ~/.zshrc o ~/.config/fish/config.fish) y abre un nuevo shell:",
    }
    ai_tui_none_detected {
        EN => "No supported AI tools found on PATH. Wrap any command with 'secret-stripper paste-guard -- <cmd>'.",
        FR => "Aucun outil d'IA pris en charge trouvé dans le PATH. Enveloppez n'importe quelle commande avec 'secret-stripper paste-guard -- <cmd>'.",
        IT => "Nessuno strumento di IA supportato trovato nel PATH. Avvolgi qualsiasi comando con 'secret-stripper paste-guard -- <cmd>'.",
        ES => "No se encontró ninguna herramienta de IA compatible en el PATH. Envuelve cualquier comando con 'secret-stripper paste-guard -- <cmd>'.",
    }
    ai_tui_alias_removed(path: &str,) {
        EN => format!("Removed paste-guard alias block from {}", path),
        FR => format!("Bloc d'alias paste-guard supprimé de {}", path),
        IT => format!("Blocco di alias paste-guard rimosso da {}", path),
        ES => format!("Bloque de alias paste-guard eliminado de {}", path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_returns_non_empty() {
        for l in Lang::all() {
            assert!(!l.notify_pasted().is_empty());
            assert!(!l.notify_redacted(2).is_empty());
            assert!(!l.cli_no_config().is_empty());
            assert!(!l.cli_redacted(1).is_empty());
            assert!(!l.lang_title().is_empty());
            assert!(!l.hk_title().is_empty());
            assert!(!l.up_checking().is_empty());
            assert!(!l.svc_update_desc().is_empty());
            assert!(!l.endonym().is_empty());
        }
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
            ShortcutBackend::Hyprland,
        ];
        for l in Lang::all() {
            for b in &backends {
                let s = l.shortcut_bound(b, "Ctrl+Alt+V");
                assert!(s.contains("Ctrl+Alt+V"));
            }
        }
    }
}
