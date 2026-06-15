//! Platform-adapter tests against the REAL committed T03 fixture.
//!
//! `fixtures/demo_dataset_users_v1.gdcpc.signed` is the actual signed bundle
//! emitted by T03's demo compiler. These tests prove the adapter reads that real
//! artefact and maps it to the engine's policy. (The fixture's public key is not
//! published with it, so signature *verification* is exercised separately by the
//! self-signed round-trip unit test in `src/platform/bundle.rs`.)
#![cfg(feature = "platform")]

use griot::contract_source::Caller;
use griot::platform::{map_bundle_to_policy, SignedBundleFile};
use griot::policy::MaskAction;

fn load_fixture() -> SignedBundleFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/demo_dataset_users_v1.gdcpc.signed"
    );
    let bytes = std::fs::read(path).expect("fixture present");
    SignedBundleFile::from_json(&bytes).expect("fixture parses")
}

#[test]
fn real_fixture_parses() {
    let file = load_fixture();
    assert_eq!(file.bundle.manifest.contract_id, "demo_dataset_users_v1");
    assert_eq!(file.owner_tenant(), Some("demo-tenant-a"));
    assert!(!file.bundle.sql_templates.is_empty());
}

#[test]
fn real_fixture_non_owner_email_is_hashed() {
    let file = load_fixture();
    let policy = map_bundle_to_policy(&file, &Caller::new("svc:x", "analytics", "globex"));
    assert!(policy.is_allowed());
    assert_eq!(
        policy.column_masks.get("email"),
        Some(&MaskAction::HashSha256),
        "non-owner email must be hashed per the T03 bundle's non-owner SQL template"
    );
}

#[test]
fn real_fixture_owner_sees_raw() {
    let file = load_fixture();
    let policy = map_bundle_to_policy(&file, &Caller::new("svc:x", "analytics", "demo-tenant-a"));
    assert!(policy.is_allowed());
    assert!(policy.column_masks.is_empty(), "owner sees raw data");
}

#[test]
fn real_fixture_denies_unlisted_purpose() {
    let file = load_fixture();
    // The demo purpose gate allows marketplace-listing / analytics only.
    let policy = map_bundle_to_policy(&file, &Caller::new("svc:x", "model-training", "globex"));
    assert!(!policy.is_allowed(), "unlisted purpose must be denied");
}
