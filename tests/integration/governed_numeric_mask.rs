//! End-to-end integration test for Task #26 — governed masking of a NUMERIC PII
//! column through the full DataFusion logical→physical planner.
//!
//! # Why this test exists
//!
//! The physical `MaskingExec` unit tests (tests/unit/wave9/physical_masking.rs)
//! build the physical plan directly and bypass DataFusion's logical planner and
//! its `ProjectionPushdown` physical-optimizer rule. That rule validates that a
//! `TableProvider`'s declared logical schema matches the schema of the physical
//! plan its `scan()` returns. When a string-producing mask (hash_sha256) is
//! applied to an `Int64` column, `MaskingExec` retypes it to `Utf8` — so the
//! `ContractTableProvider`'s `schema()` MUST also report `Utf8`, or
//! `ProjectionPushdown` rejects the whole plan with:
//!
//!   PhysicalOptimizer rule 'ProjectionPushdown' failed. Schema mismatch.
//!   Expected ... national_id: Utf8 ... got ... national_id: Int64 ...
//!
//! This is exactly the failure the live E2E hit on 2026-07-05. These tests drive
//! a real `SessionContext::sql()` query against a `ContractTableProvider` and
//! assert the masked column comes back as sha256 hex strings — the same path the
//! K04D server uses.

use std::sync::Arc;

use datafusion::arrow::array::{Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::prelude::SessionConfig;
use griot::contract_table_provider::ContractTableProvider;
use griot::engine::governed_session_context;
use griot::policy::{MaskAction, ResolvedPolicy};
use sha2::{Digest, Sha256};

/// SHA-256 hex of a value's canonical string form — what the engine must emit.
fn expected_hash(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build a raw MemTable: policy_id(Utf8), national_id(Int64 PII), region(Utf8),
/// risk_score(Int64) — mirrors the live `claims/policy-scores` upload. Row 1 and
/// row 4 share national_id 8801015555 to prove deterministic hashing.
fn raw_table() -> Arc<MemTable> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("policy_id", DataType::Utf8, false),
        Field::new("national_id", DataType::Int64, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("risk_score", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec![
                "P1001", "P1002", "P1003", "P1004", "P1005",
            ])),
            Arc::new(Int64Array::from(vec![
                8801015555i64,
                7702021234,
                9003037777,
                8801015555, // duplicate → same hash as row 1
                6504048888,
            ])),
            Arc::new(StringArray::from(vec![
                "Nairobi", "Mombasa", "Kisumu", "Nairobi", "Nakuru",
            ])),
            Arc::new(Int64Array::from(vec![72i64, 55, 88, 64, 41])),
        ],
    )
    .unwrap();
    Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
}

/// A non-owner policy that masks the numeric `national_id` with hash_sha256.
fn policy_hash_national_id() -> ResolvedPolicy {
    let mut policy = ResolvedPolicy::allow_all("claims/policy-scores", "1", "griot");
    policy
        .column_masks
        .insert("national_id".into(), MaskAction::HashSha256);
    policy
}

/// Register the governed provider under `claims_policy_scores` and query it,
/// through the SAME planning path the engine uses (`governed_session_context`,
/// which drops `ProjectionPushdown`).
fn ctx_with_governed_table() -> SessionContext {
    let provider = Arc::new(ContractTableProvider::new(
        raw_table(),
        &policy_hash_national_id(),
    ));
    let ctx = governed_session_context(SessionConfig::new());
    ctx.register_table("claims_policy_scores", provider)
        .unwrap();
    ctx
}

/// GNM-01: `SELECT policy_id, national_id, region, risk_score` — the exact
/// projected shape the live query used. Before Task #26 this failed with
/// "ProjectionPushdown ... Schema mismatch" (Utf8 vs Int64). It must now succeed
/// and return national_id as sha256 hex strings, other columns clear.
#[tokio::test]
async fn gnm_01_projected_numeric_mask_end_to_end() {
    let ctx = ctx_with_governed_table();

    let df = ctx
        .sql("SELECT policy_id, national_id, region, risk_score FROM claims_policy_scores ORDER BY policy_id")
        .await
        .expect("planning must succeed (no ProjectionPushdown schema mismatch)");
    let batches = df.collect().await.expect("execution must succeed");

    let b = &batches[0];
    // national_id column must now be Utf8 (hashed), not Int64.
    assert_eq!(
        b.schema().field(1).data_type(),
        &DataType::Utf8,
        "masked numeric national_id must be Utf8 in the result"
    );

    let nid = b
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("national_id must be a StringArray");
    // Rows ordered by policy_id: P1001, P1002, P1003, P1004, P1005.
    assert_eq!(nid.value(0), expected_hash("8801015555")); // P1001
    assert_eq!(nid.value(1), expected_hash("7702021234")); // P1002
    assert_eq!(nid.value(2), expected_hash("9003037777")); // P1003
    assert_eq!(
        nid.value(0),
        nid.value(3),
        "P1001 and P1004 share national_id 8801015555 → identical hashes (deterministic)"
    );
    assert_eq!(nid.value(4), expected_hash("6504048888")); // P1005

    // policy_id + region clear; risk_score clear Int64.
    let pid = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
    assert_eq!(pid.value(0), "P1001");
    let risk = b.column(3).as_any().downcast_ref::<Int64Array>().unwrap();
    assert_eq!(risk.value(0), 72);
}

/// GNM-02: `SELECT *` — star projection through the planner also must succeed
/// and mask the numeric column.
#[tokio::test]
async fn gnm_02_star_projection_numeric_mask() {
    let ctx = ctx_with_governed_table();

    let df = ctx
        .sql("SELECT * FROM claims_policy_scores ORDER BY policy_id")
        .await
        .expect("SELECT * planning must succeed");
    let batches = df.collect().await.expect("execution must succeed");

    let b = &batches[0];
    let nid = b
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("national_id must be masked to a StringArray under SELECT *");
    assert_eq!(nid.value(0), expected_hash("8801015555"));
}

/// GNM-03: selecting ONLY the masked numeric column (tightest projection —
/// most likely to trip ProjectionPushdown).
#[tokio::test]
async fn gnm_03_select_only_masked_numeric_column() {
    let ctx = ctx_with_governed_table();

    let df = ctx
        .sql("SELECT national_id FROM claims_policy_scores")
        .await
        .expect("single-masked-column planning must succeed");
    let batches = df.collect().await.expect("execution must succeed");

    let b = &batches[0];
    assert_eq!(b.schema().field(0).data_type(), &DataType::Utf8);
    let nid = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
    // 5 rows, each a 64-char hex digest.
    assert_eq!(nid.len(), 5);
    for i in 0..nid.len() {
        assert_eq!(
            nid.value(i).len(),
            64,
            "each masked value is a sha256 hex digest"
        );
    }
}

/// GNM-04: the provider's declared logical schema retypes only the masked
/// column — this is what keeps ProjectionPushdown happy.
#[test]
fn gnm_04_provider_schema_retypes_only_masked_column() {
    use datafusion::datasource::TableProvider;

    let provider = ContractTableProvider::new(raw_table(), &policy_hash_national_id());
    let schema = provider.schema();
    assert_eq!(schema.field(0).data_type(), &DataType::Utf8); // policy_id
    assert_eq!(
        schema.field(1).data_type(),
        &DataType::Utf8,
        "national_id (masked numeric) retyped to Utf8"
    );
    assert_eq!(schema.field(2).data_type(), &DataType::Utf8); // region
    assert_eq!(
        schema.field(3).data_type(),
        &DataType::Int64,
        "risk_score (unmasked) stays Int64"
    );
}

/// GNM-05: an owner (allow_all, no masks) sees the raw Int64 column — the
/// provider schema stays Int64 and rows are clear. Proves we don't over-mask.
#[tokio::test]
async fn gnm_05_owner_allow_all_sees_raw_numeric() {
    let policy = ResolvedPolicy::allow_all("claims/policy-scores", "1", "griot"); // no masks
    let provider = Arc::new(ContractTableProvider::new(raw_table(), &policy));
    let ctx = governed_session_context(SessionConfig::new());
    ctx.register_table("t", provider).unwrap();

    let df = ctx
        .sql("SELECT national_id FROM t ORDER BY national_id")
        .await
        .expect("owner query must plan");
    let batches = df.collect().await.expect("owner query must run");

    let b = &batches[0];
    assert_eq!(
        b.schema().field(0).data_type(),
        &DataType::Int64,
        "owner (no mask) sees raw Int64 national_id"
    );
    let nid = b.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
    assert_eq!(nid.value(0), 6504048888);
}
