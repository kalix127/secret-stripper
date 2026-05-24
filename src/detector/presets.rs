use crate::config::Config;
use crate::detector::patterns::BUCKETS;
use std::collections::BTreeSet;

/// Buckets enabled by the Minimal preset: popular PII only, lowest noise.
/// `pii_contact` = emails/phones/DOB, `pii_financial` = credit cards/IBAN,
/// `networking` = IPs and host/device addresses.
pub const MINIMAL: &[&str] = &["pii_contact", "pii_financial", "networking"];

/// Buckets enabled by the Balanced preset (the new-install default): broad
/// credential + common PII, excluding regional gov-ID, threat-intel, banking,
/// healthcare, and niche/high-false-positive buckets. Password-hash artifacts
/// (`hashes`) and crypto wallet/exchange/RPC buckets (`wallets`, `exchanges`,
/// `rpc_chain`) are Full-only: niche for a typical user and the source of the
/// loosest shape-patterns. Every bucket not listed here becomes a
/// `disabled_categories` entry.
pub const BALANCED: &[&str] = &[
    "legacy",
    "cloud_aws",
    "cloud_gcp",
    "cloud_azure",
    "cloud_other",
    "infra",
    "networking",
    "payments",
    "messaging",
    "vcs_ci",
    "ai",
    "monitoring",
    "databases",
    "edge",
    "crypto_keys",
    "auth_tokens",
    "packages",
    "pii_contact",
    "pii_financial",
    "structured",
    "mobile",
    "saas_iam",
    "saas_collab",
    "saas_crm_marketing",
    "saas_hr_finance",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Minimal,
    Balanced,
    Full,
}

impl Preset {
    pub fn all() -> [Preset; 3] {
        [Preset::Minimal, Preset::Balanced, Preset::Full]
    }

    /// Stable stem of every built-in bucket. Single source of truth = BUCKETS,
    /// so Full never drifts when a bucket is added.
    fn all_stems() -> Vec<&'static str> {
        BUCKETS.iter().map(|&(s, _)| s).collect()
    }

    /// Bucket stems this preset enables.
    pub fn enabled_stems(&self) -> Vec<&'static str> {
        match self {
            Preset::Minimal => MINIMAL.to_vec(),
            Preset::Balanced => BALANCED.to_vec(),
            Preset::Full => Self::all_stems(),
        }
    }

    /// Bucket stems this preset disables = BUCKETS minus enabled, kept in
    /// BUCKETS order so the persisted `disabled_categories` is deterministic.
    pub fn disabled_stems(&self) -> Vec<String> {
        let on: BTreeSet<&str> = self.enabled_stems().into_iter().collect();
        Self::all_stems()
            .into_iter()
            .filter(|s| !on.contains(s))
            .map(|s| s.to_string())
            .collect()
    }

    /// Rewrite `cfg.disabled_categories` to match this preset.
    pub fn apply(&self, cfg: &mut Config) {
        cfg.disabled_categories = self.disabled_stems();
    }
}

/// Which preset the config currently matches, or `None` for a hand-edited
/// ("Custom") selection. Compared as sets so config order does not matter.
pub fn detect(cfg: &Config) -> Option<Preset> {
    let cur: BTreeSet<&str> = cfg.disabled_categories.iter().map(|s| s.as_str()).collect();
    Preset::all().into_iter().find(|p| {
        let want: BTreeSet<String> = p.disabled_stems().into_iter().collect();
        let want: BTreeSet<&str> = want.iter().map(|s| s.as_str()).collect();
        cur == want
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket_set() -> BTreeSet<&'static str> {
        BUCKETS.iter().map(|&(s, _)| s).collect()
    }

    #[test]
    fn every_preset_stem_exists_in_buckets() {
        let buckets = bucket_set();
        for stem in MINIMAL.iter().chain(BALANCED.iter()) {
            assert!(buckets.contains(stem), "unknown bucket stem: {stem}");
        }
    }

    #[test]
    fn full_equals_all_buckets() {
        let enabled: BTreeSet<&str> = Preset::Full.enabled_stems().into_iter().collect();
        assert_eq!(enabled, bucket_set());
        assert!(Preset::Full.disabled_stems().is_empty());
    }

    #[test]
    fn detect_round_trips_apply() {
        for p in Preset::all() {
            let mut cfg = Config::default();
            p.apply(&mut cfg);
            assert_eq!(detect(&cfg), Some(p));
        }
    }

    #[test]
    fn manual_edit_is_custom() {
        let mut cfg = Config::default();
        Preset::Balanced.apply(&mut cfg);
        cfg.disabled_categories.push("legacy".to_string());
        assert_eq!(detect(&cfg), None);
    }

    #[test]
    fn presets_are_distinct() {
        let m: BTreeSet<String> = Preset::Minimal.disabled_stems().into_iter().collect();
        let b: BTreeSet<String> = Preset::Balanced.disabled_stems().into_iter().collect();
        let f: BTreeSet<String> = Preset::Full.disabled_stems().into_iter().collect();
        assert_ne!(m, b);
        assert_ne!(b, f);
        assert_ne!(m, f);
    }
}
