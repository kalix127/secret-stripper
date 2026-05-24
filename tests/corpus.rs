// Corpus-driven detection + redaction round-trip tests. Each bucket has a
// fixture under tests/fixtures/corpus/<bucket>.txt. See tests/fixtures/README.md.

mod common;

macro_rules! bucket_tests {
    ($($detect:ident / $roundtrip:ident => $file:literal),+ $(,)?) => {
        $(
            #[test]
            fn $detect() {
                common::run_bucket($file);
            }

            #[test]
            fn $roundtrip() {
                common::run_bucket_roundtrip($file);
            }
        )+
    };
}

bucket_tests! {
    corpus_cloud_aws_detects_all / corpus_cloud_aws_redaction_round_trip_clean => "cloud_aws.txt",
    corpus_cloud_gcp_detects_all / corpus_cloud_gcp_redaction_round_trip_clean => "cloud_gcp.txt",
    corpus_cloud_azure_detects_all / corpus_cloud_azure_redaction_round_trip_clean => "cloud_azure.txt",
    corpus_cloud_other_detects_all / corpus_cloud_other_redaction_round_trip_clean => "cloud_other.txt",
    corpus_infra_detects_all / corpus_infra_redaction_round_trip_clean => "infra.txt",
    corpus_networking_detects_all / corpus_networking_redaction_round_trip_clean => "networking.txt",
    corpus_vcs_ci_detects_all / corpus_vcs_ci_redaction_round_trip_clean => "vcs_ci.txt",
    corpus_ai_detects_all / corpus_ai_redaction_round_trip_clean => "ai.txt",
    corpus_payments_detects_all / corpus_payments_redaction_round_trip_clean => "payments.txt",
    corpus_messaging_detects_all / corpus_messaging_redaction_round_trip_clean => "messaging.txt",
    corpus_monitoring_detects_all / corpus_monitoring_redaction_round_trip_clean => "monitoring.txt",
    corpus_databases_detects_all / corpus_databases_redaction_round_trip_clean => "databases.txt",
    corpus_edge_detects_all / corpus_edge_redaction_round_trip_clean => "edge.txt",
    corpus_crypto_keys_detects_all / corpus_crypto_keys_redaction_round_trip_clean => "crypto_keys.txt",
    corpus_auth_tokens_detects_all / corpus_auth_tokens_redaction_round_trip_clean => "auth_tokens.txt",
    corpus_packages_detects_all / corpus_packages_redaction_round_trip_clean => "packages.txt",
    corpus_pii_contact_detects_all / corpus_pii_contact_redaction_round_trip_clean => "pii_contact.txt",
    corpus_pii_network_detects_all / corpus_pii_network_redaction_round_trip_clean => "pii_network.txt",
    corpus_pii_financial_detects_all / corpus_pii_financial_redaction_round_trip_clean => "pii_financial.txt",
    corpus_pii_govid_us_detects_all / corpus_pii_govid_us_redaction_round_trip_clean => "pii_govid_us.txt",
    corpus_pii_govid_eu_detects_all / corpus_pii_govid_eu_redaction_round_trip_clean => "pii_govid_eu.txt",
    corpus_pii_govid_intl_detects_all / corpus_pii_govid_intl_redaction_round_trip_clean => "pii_govid_intl.txt",
    corpus_pii_geo_detects_all / corpus_pii_geo_redaction_round_trip_clean => "pii_geo.txt",
    corpus_pii_biometric_detects_all / corpus_pii_biometric_redaction_round_trip_clean => "pii_biometric.txt",
    corpus_extra_ids_detects_all / corpus_extra_ids_redaction_round_trip_clean => "extra_ids.txt",
    corpus_healthcare_detects_all / corpus_healthcare_redaction_round_trip_clean => "healthcare.txt",
    corpus_hashes_detects_all / corpus_hashes_redaction_round_trip_clean => "hashes.txt",
    corpus_structured_detects_all / corpus_structured_redaction_round_trip_clean => "structured.txt",
    corpus_wallets_detects_all / corpus_wallets_redaction_round_trip_clean => "wallets.txt",
    corpus_exchanges_detects_all / corpus_exchanges_redaction_round_trip_clean => "exchanges.txt",
    corpus_rpc_chain_detects_all / corpus_rpc_chain_redaction_round_trip_clean => "rpc_chain.txt",
    corpus_mobile_detects_all / corpus_mobile_redaction_round_trip_clean => "mobile.txt",
    corpus_gaming_detects_all / corpus_gaming_redaction_round_trip_clean => "gaming.txt",
    corpus_iot_detects_all / corpus_iot_redaction_round_trip_clean => "iot.txt",
    corpus_saas_iam_detects_all / corpus_saas_iam_redaction_round_trip_clean => "saas_iam.txt",
    corpus_saas_collab_detects_all / corpus_saas_collab_redaction_round_trip_clean => "saas_collab.txt",
    corpus_saas_crm_marketing_detects_all / corpus_saas_crm_marketing_redaction_round_trip_clean => "saas_crm_marketing.txt",
    corpus_saas_hr_finance_detects_all / corpus_saas_hr_finance_redaction_round_trip_clean => "saas_hr_finance.txt",
    corpus_ad_tech_detects_all / corpus_ad_tech_redaction_round_trip_clean => "ad_tech.txt",
    corpus_banking_detects_all / corpus_banking_redaction_round_trip_clean => "banking.txt",
    corpus_threat_intel_detects_all / corpus_threat_intel_redaction_round_trip_clean => "threat_intel.txt",
    corpus_industry_other_detects_all / corpus_industry_other_redaction_round_trip_clean => "industry_other.txt",
    // BIP39 mnemonics carry a real byte span (the wordlist run), so they
    // round-trip like pattern matches. Vendor-host findings span the token.
    corpus_mnemonic_detects_all / corpus_mnemonic_redaction_round_trip_clean => "mnemonic.txt",
    corpus_vendor_host_detects_all / corpus_vendor_host_redaction_round_trip_clean => "vendor_host.txt",
    // Secrets a human soft-wrapped across one newline: the additive
    // soft-wrap pass must detect them and the redactor must keep the
    // line break ("[R]\n[R]") so the round-trip re-scan is clean.
    corpus_softwrap_detects_all / corpus_softwrap_redaction_round_trip_clean => "softwrap.txt",
}

#[test]
fn corpus_negatives_zero_detections() {
    common::run_negatives("negatives.txt");
}
