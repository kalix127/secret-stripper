use secret_stripper::config::{self, Config};
use secret_stripper::detector::custom::{self, CustomPatternSpec, CustomPatternsFile};
use secret_stripper::lang::Lang;
use serial_test::serial;
use std::path::Path;
use tempfile::TempDir;

/// Point the config seam at a fresh tempdir for the duration of `f`, then
/// restore the previous env value. Tests are `#[serial(config_env)]` because
/// the env var is process-global.
fn with_isolated_home<R>(f: impl FnOnce(&Path) -> R) -> R {
    let tmp = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("SECRET_STRIPPER_CONFIG_HOME");
    std::env::set_var("SECRET_STRIPPER_CONFIG_HOME", tmp.path());
    let out = f(tmp.path());
    match prev {
        Some(v) => std::env::set_var("SECRET_STRIPPER_CONFIG_HOME", v),
        None => std::env::remove_var("SECRET_STRIPPER_CONFIG_HOME"),
    }
    out
}

#[test]
#[serial(config_env)]
fn base_dir_honors_env_and_does_not_create() {
    with_isolated_home(|home| {
        let expected = home.join("secret-stripper");
        assert_eq!(config::base_dir(), expected);
        // The resolver must not create the directory as a side effect.
        assert!(!expected.exists());
    });
}

#[test]
#[serial(config_env)]
fn config_save_load_round_trip() {
    with_isolated_home(|home| {
        let cfg = Config {
            sensitivity: 5,
            onboarding_done: true,
            disabled_categories: vec!["payments".to_string()],
            ..Config::default()
        };
        cfg.save().expect("save");

        let cfg_path = home.join("secret-stripper").join("config.toml");
        assert!(cfg_path.exists());
        assert!(!home
            .join("secret-stripper")
            .join("config.toml.tmp")
            .exists());

        let text = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(text.contains("onboarding_done = true"));
        assert!(text.contains("sensitivity = 5"));

        let loaded = Config::load();
        assert_eq!(loaded.sensitivity, 5);
        assert!(loaded.onboarding_done);
        assert_eq!(loaded.disabled_categories, vec!["payments".to_string()]);
    });
}

#[test]
#[serial(config_env)]
fn init_first_run_writes_config_with_onboarding_done() {
    with_isolated_home(|home| {
        assert!(!Config::path_exists());
        assert!(!home.join("secret-stripper").exists());

        Config::first_run(Lang::EN).save().expect("save");

        let cfg_path = home.join("secret-stripper").join("config.toml");
        assert_eq!(Config::path(), cfg_path);
        assert!(cfg_path.exists());

        let loaded = Config::load();
        assert!(loaded.onboarding_done);
        assert_eq!(
            secret_stripper::detector::presets::detect(&loaded),
            Some(secret_stripper::detector::presets::Preset::Balanced)
        );
        let text = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(text.contains("onboarding_done = true"));
    });
}

#[test]
#[serial(config_env)]
fn uninstall_purges_files_and_dir() {
    with_isolated_home(|home| {
        let dir = home.join("secret-stripper");
        Config::first_run(Lang::EN).save().expect("save");
        custom::save(&CustomPatternsFile::default()).expect("patterns save");
        std::fs::write(dir.join("last_detection.json"), "{}").unwrap();
        std::fs::write(dir.join("last_update_check.json"), "{}").unwrap();

        let removed = config::purge_config_dir();
        assert!(removed.contains(&"config.toml".to_string()));
        assert!(removed.contains(&"patterns.toml".to_string()));

        assert!(!dir.exists());
        assert!(!Config::path_exists());
    });
}

#[test]
#[serial(config_env)]
fn category_add_then_remove_persists() {
    with_isolated_home(|_| {
        // default() (not first_run) so disabled_categories starts empty -
        // this test exercises the add/remove persistence seam, not the
        // Balanced preset that first_run now seeds.
        Config::default().save().expect("save");

        let mut c = Config::load();
        c.disabled_categories.push("cloud_aws".to_string());
        c.save().expect("save add");
        let reloaded = Config::load();
        assert_eq!(reloaded.disabled_categories, vec!["cloud_aws".to_string()]);
        let text = std::fs::read_to_string(Config::path()).unwrap();
        assert!(text.contains("disabled_categories"));

        let mut c = Config::load();
        let pos = c
            .disabled_categories
            .iter()
            .position(|d| d == "cloud_aws")
            .unwrap();
        c.disabled_categories.remove(pos);
        c.save().expect("save remove");
        let reloaded = Config::load();
        assert!(reloaded.disabled_categories.is_empty());
        // skip_serializing_if = "Vec::is_empty" must drop the key entirely.
        let text = std::fs::read_to_string(Config::path()).unwrap();
        assert!(!text.contains("disabled_categories"));
    });
}

#[test]
#[serial(config_env)]
fn load_migrates_legacy_redact_char_and_missing_lang() {
    with_isolated_home(|home| {
        // Write a valid config, then rewrite it as an "old" one: no
        // redact_pattern, no lang, a legacy `redact_char` line. That fails to
        // parse and must hit the migration path. (No `toml` use here - it is
        // not a dev-dependency of the integration test crate.)
        Config::default().save().expect("seed save");
        let _ = home;
        let base = std::fs::read_to_string(Config::path()).unwrap();
        let mut old: String = base
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("redact_pattern") && !t.starts_with("lang")
            })
            .map(|l| format!("{l}\n"))
            .collect();
        old.push_str("redact_char = '#'\n");

        std::fs::write(Config::path(), old).unwrap();

        let loaded = Config::load();
        assert_eq!(loaded.redact_pattern, "#");
        assert_eq!(loaded.lang, Lang::EN);

        // The file is rewritten in the new shape so a second load is clean.
        let rewritten = std::fs::read_to_string(Config::path()).unwrap();
        assert!(rewritten.contains("redact_pattern = \"#\""));
        assert!(!rewritten.contains("redact_char"));
        assert_eq!(Config::load().redact_pattern, "#");
    });
}

#[test]
#[serial(config_env)]
fn custom_load_skips_bad_regex_and_keeps_good_one() {
    with_isolated_home(|_| {
        custom::save(&CustomPatternsFile {
            patterns: vec![
                CustomPatternSpec {
                    name: "good".to_string(),
                    category: "c".to_string(),
                    severity: "high".to_string(),
                    regex: "abc[0-9]+".to_string(),
                },
                CustomPatternSpec {
                    name: "bad".to_string(),
                    category: "c".to_string(),
                    severity: "high".to_string(),
                    regex: "abc(".to_string(),
                },
            ],
        })
        .expect("save");

        let (patterns, errs) = custom::load();
        assert_eq!(patterns.len(), 1);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("bad"));
    });
}

#[test]
#[serial(config_env)]
fn patterns_save_creates_dir_when_absent() {
    with_isolated_home(|home| {
        assert!(!home.join("secret-stripper").exists());
        let file = CustomPatternsFile {
            patterns: vec![CustomPatternSpec {
                name: "x".to_string(),
                category: "c".to_string(),
                severity: "high".to_string(),
                regex: "abc".to_string(),
            }],
        };
        custom::save(&file).expect("patterns save");
        assert!(home.join("secret-stripper").join("patterns.toml").exists());
    });
}
