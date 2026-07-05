//! Unit tests for `MaskingExec` — Wave 9 / ADR-0002.
//!
//! Testing agent authored (2026-05-05).
//!
//! # TDD state
//!
//! All `#[test]` and `#[tokio::test]` functions are `#[ignore]`'d.
//! `cargo test` must report 0 run, N ignored.
//!
//! # Coverage
//!
//! * MSK-01: Schema preserved — output schema == input schema (masking is type-preserving).
//! * MSK-02: Single-batch execution applies masking policy per column (redact → `"***"`).
//! * MSK-03: Multi-batch streaming applies masking to each batch independently.
//! * MSK-04: Constructor without ContractApprovedExec upstream → Err(ContractNotApproved).
//! * MSK-STRUCT: Public API exists and compiles (GREEN).
//!
//! # Spec anchors
//!
//! ADR-0002 §Physical operators — MaskingExec.
//! INV-2: no read without satisfaction (column-level masking).

#![allow(unused_imports, dead_code)]

use bytes::Bytes;
use datafusion::arrow::array::{Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::ExecutionPlan;
use griot::optimizer_rules::masking::MaskPolicy;
use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::masking_exec::MaskingExec;
use griot::physical::PhysicalError;
use griot::ContractBundleHandle;
use std::sync::Arc;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Bundle with `email` column tagged as PII → Redact.
fn make_bundle_with_redact(contract_id: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "column_masking": {
                    "email": "redact"
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

/// Bundle with `name` column tagged as PII → HashSha256.
fn make_bundle_with_hash(contract_id: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "column_masking": {
                    "name": "hash_sha256"
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn id_email_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("email", DataType::Utf8, false),
    ]))
}

async fn make_approved_with_redact(
    rows: Vec<(i64, &str)>,
    bundle: ContractBundleHandle,
) -> Arc<dyn datafusion::physical_plan::ExecutionPlan> {
    let schema = id_email_schema();
    let ids: Vec<i64> = rows.iter().map(|(id, _)| *id).collect();
    let emails: Vec<&str> = rows.iter().map(|(_, e)| *e).collect();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(emails)),
        ],
    )
    .unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    let inner = ctx
        .table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();
    Arc::new(ContractApprovedExec::new(bundle, inner).unwrap())
}

// ─── MSK-01: Schema preserved ────────────────────────────────────────────────

/// MSK-01: `MaskingExec::schema()` MUST match the inner plan's schema.
/// Masking replaces column VALUES but does not change column TYPES.
///
/// Spec anchor: ADR-0002 §MaskingExec — type-preserving masking.
#[tokio::test]

async fn msk_01_schema_preserved() {
    let schema = id_email_schema();
    let bundle = make_bundle_with_redact("contract-msk-01");
    let approved = make_approved_with_redact(vec![(1, "alice@example.com")], bundle.clone()).await;

    let exec = MaskingExec::new(bundle, approved).unwrap();
    assert_eq!(
        exec.schema().as_ref(),
        schema.as_ref(),
        "MaskingExec must preserve schema (type-preserving)"
    );
}

// ─── MSK-02: Redact policy replaces values with "***" ────────────────────────

/// MSK-02: When the bundle tags `email` as `redact`, executing `MaskingExec`
/// MUST replace every email value with `"***"`.  The `id` column is unchanged.
///
/// Spec anchor: ADR-0002 §MaskingExec — Redact policy behaviour.
/// INV-2: column access restricted by masking policy from the contract.
#[tokio::test]

async fn msk_02_redact_policy_replaces_values() {
    use datafusion::physical_plan::collect;

    let bundle = make_bundle_with_redact("contract-msk-02");
    let approved = make_approved_with_redact(
        vec![(1, "alice@example.com"), (2, "bob@example.com")],
        bundle.clone(),
    )
    .await;

    let exec = MaskingExec::new(bundle, approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();

    let email_col = batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();

    for i in 0..email_col.len() {
        assert_eq!(
            email_col.value(i),
            "***",
            "redact policy must replace email with '***'"
        );
    }

    // id column must be unchanged.
    let id_col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    assert_eq!(id_col.value(0), 1);
    assert_eq!(id_col.value(1), 2);
}

// ─── MSK-03: Multi-batch masking applied independently ───────────────────────

/// MSK-03: When the inner plan produces multiple batches, `MaskingExec` MUST
/// apply the masking policy to each batch independently and preserve order.
///
/// Spec anchor: ADR-0002 §MaskingExec — streaming masking consistency.
#[tokio::test]

async fn msk_03_multi_batch_masking_applied_independently() {
    use datafusion::physical_plan::collect;

    let schema = id_email_schema();
    let bundle = make_bundle_with_redact("contract-msk-03");

    let batch1 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(StringArray::from(vec!["alice@example.com"])),
        ],
    )
    .unwrap();
    let batch2 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![2i64])),
            Arc::new(StringArray::from(vec!["bob@example.com"])),
        ],
    )
    .unwrap();

    let table = MemTable::try_new(schema, vec![vec![batch1], vec![batch2]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("multi", Arc::new(table)).unwrap();
    let inner = ctx
        .table("multi")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let approved = Arc::new(ContractApprovedExec::new(bundle.clone(), inner).unwrap());
    let exec = MaskingExec::new(bundle, approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 2, "total row count preserved across batches");

    // All email values must be redacted.
    for batch in &batches {
        let email_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for i in 0..email_col.len() {
            assert_eq!(email_col.value(i), "***", "every email must be redacted");
        }
    }
}

// ─── MSK-04: No ContractApprovedExec upstream → constructor error ─────────────

/// MSK-04: Constructing `MaskingExec` without `ContractApprovedExec` upstream
/// MUST return `Err(PhysicalError::ContractNotApproved)`.
///
/// Spec anchor: ADR-0002 verified-binary surface rule (c).
/// INV-2: masking cannot be bypassed by assembling an unapproved plan.
#[tokio::test]

async fn msk_04_no_approved_ancestor_constructor_error() {
    let schema = id_email_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(StringArray::from(vec!["alice@example.com"])),
        ],
    )
    .unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("raw", Arc::new(table)).unwrap();
    let raw_inner = ctx
        .table("raw")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let bundle = make_bundle_with_redact("contract-msk-04");
    let result = MaskingExec::new(bundle, raw_inner);

    assert!(
        result.is_err(),
        "MaskingExec must reject unapproved inner plan"
    );
    match result.unwrap_err() {
        PhysicalError::ContractNotApproved { operator } => {
            assert_eq!(operator, "MaskingExec");
        }
        other => panic!("expected ContractNotApproved(MaskingExec), got {:?}", other),
    }
}

// ─── MSK-STRUCT: Public API compile-time check (GREEN) ───────────────────────

/// MSK-STRUCT: Verify type names and method signatures compile.
#[test]
fn msk_struct_public_api_compiles() {
    let _ = std::any::type_name::<MaskingExec>();
    // MaskPolicy variants accessible:
    let _r = MaskPolicy::Redact;
    let _h = MaskPolicy::HashSha256;
    let _t = MaskPolicy::Tokenize;
    let _n = MaskPolicy::Noop;
}

// ═══════════════════════════════════════════════════════════════════════════
// Task #26 — non-string masked columns hash via a Utf8 cast (2026-07-05)
//
// A masked column whose Arrow type is numeric/temporal/bool with a
// string-producing policy (hash_sha256 / tokenize / partial) must WORK: cast to
// canonical Utf8, then apply the mask.  The output column type becomes Utf8.
// Nulls stay null.  The hash is deterministic on the string form.
// ═══════════════════════════════════════════════════════════════════════════

use datafusion::arrow::array::{
    BooleanArray, Date32Array, Float64Array, TimestampMicrosecondArray,
};
use datafusion::physical_plan::collect;
use sha2::{Digest, Sha256};

/// The exact hash the engine must produce for a value: SHA-256 hex of the
/// canonical string form (this is what `mask_string_value` does for HashSha256).
fn expected_hash(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build a single-column bundle tagging `col` with `policy`.
fn make_bundle_single_col(contract_id: &str, col: &str, policy: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "column_masking": { col: policy }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

/// Wrap a single-column batch in a ContractApprovedExec so the enforcement
/// invariant (ContractApprovedExec upstream) is satisfied for MaskingExec.
async fn approved_single_column(
    schema: Arc<Schema>,
    column: Arc<dyn Array>,
    inner_bundle: ContractBundleHandle,
) -> Arc<dyn ExecutionPlan> {
    let batch = RecordBatch::try_new(schema.clone(), vec![column]).unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    let inner = ctx
        .table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();
    Arc::new(ContractApprovedExec::new(inner_bundle, inner).unwrap())
}

/// Collect the single masked column as a `StringArray`.
async fn collect_masked_utf8(exec: MaskingExec) -> datafusion::arrow::array::StringArray {
    let out_schema = exec.schema();
    // Task #26: the masked column's output type MUST be Utf8.
    assert_eq!(
        out_schema.field(0).data_type(),
        &DataType::Utf8,
        "string-producing mask on a non-string column must retype the output field to Utf8"
    );
    let exec_arc: Arc<dyn ExecutionPlan> = Arc::new(exec);
    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    // Schema of the emitted batch must equal the declared output schema.
    assert_eq!(
        batches[0].schema().field(0).data_type(),
        &DataType::Utf8,
        "emitted batch column type must match declared Utf8 output schema"
    );
    batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::StringArray>()
        .expect("masked column must be a StringArray")
        .clone()
}

/// MSK-26-FLOAT: a Float64 PII column masked with hash_sha256 → hashed strings.
#[tokio::test]
async fn msk_26_float64_hash_sha256() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "policyholder_phone",
        DataType::Float64,
        true,
    )]));
    let col = Arc::new(Float64Array::from(vec![
        Some(2547000.0),
        Some(2547111.0),
        None,
    ])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-f64", "policyholder_phone", "hash_sha256");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-f64-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    // Float64 renders as "2547000.0" via Arrow's canonical cast.
    assert_eq!(out.value(0), expected_hash("2547000.0"));
    assert_eq!(out.value(1), expected_hash("2547111.0"));
    assert!(out.is_null(2), "null input must stay null");
    // Determinism: identical values hash identically.
    assert_ne!(out.value(0), out.value(1));
}

/// MSK-26-INT: an Int64 PII column masked with hash_sha256 → hashed strings.
/// Two equal Int64 values must hash identically (determinism).
#[tokio::test]
async fn msk_26_int64_hash_sha256() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "national_id",
        DataType::Int64,
        true,
    )]));
    let col = Arc::new(Int64Array::from(vec![
        Some(8801015555i64),
        Some(8801015555i64), // duplicate → must hash the same
        Some(7702021234i64),
        None,
    ])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-i64", "national_id", "hash_sha256");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-i64-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    assert_eq!(out.value(0), expected_hash("8801015555"));
    assert_eq!(
        out.value(0),
        out.value(1),
        "identical Int64 values must produce identical hashes"
    );
    assert_eq!(out.value(2), expected_hash("7702021234"));
    assert!(out.is_null(3), "null input must stay null");
}

/// MSK-26-DATE: a Date32 column masked with hash_sha256 → hashed strings.
#[tokio::test]
async fn msk_26_date32_hash_sha256() {
    let schema = Arc::new(Schema::new(vec![Field::new("dob", DataType::Date32, true)]));
    // Date32 = days since epoch. 0 = 1970-01-01; 19723 = 2024-01-01.
    let col = Arc::new(Date32Array::from(vec![Some(0), Some(19723), None])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-date", "dob", "hash_sha256");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-date-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    // Arrow casts Date32 to the ISO date string.
    assert_eq!(out.value(0), expected_hash("1970-01-01"));
    assert_eq!(out.value(1), expected_hash("2024-01-01"));
    assert!(out.is_null(2), "null date must stay null");
    // Ensure it's a 64-hex-char digest (no raw date leaked).
    assert_eq!(out.value(0).len(), 64);
}

/// MSK-26-TS: a Timestamp column masked with hash_sha256 → hashed strings.
#[tokio::test]
async fn msk_26_timestamp_hash_sha256() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "last_seen",
        DataType::Timestamp(datafusion::arrow::datatypes::TimeUnit::Microsecond, None),
        true,
    )]));
    // 1_700_000_000_000_000 µs = 2023-11-14T22:13:20.
    let col = Arc::new(TimestampMicrosecondArray::from(vec![
        Some(1_700_000_000_000_000i64),
        None,
    ])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-ts", "last_seen", "hash_sha256");
    let approved = approved_single_column(schema, col, make_bundle_with_redact("c-ts-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    // Non-null must be a 64-char hex digest; no raw timestamp leaked.
    assert_eq!(out.value(0).len(), 64);
    assert!(
        out.value(0).chars().all(|c| c.is_ascii_hexdigit()),
        "masked timestamp must be a hex digest"
    );
    assert!(out.is_null(1), "null timestamp must stay null");
}

/// MSK-26-BOOL: a Boolean column masked with hash_sha256 → hashed strings.
#[tokio::test]
async fn msk_26_boolean_hash_sha256() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "is_flagged",
        DataType::Boolean,
        true,
    )]));
    let col = Arc::new(BooleanArray::from(vec![
        Some(true),
        Some(false),
        Some(true),
        None,
    ])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-bool", "is_flagged", "hash_sha256");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-bool-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    // Arrow casts Boolean → "true"/"false".
    assert_eq!(out.value(0), expected_hash("true"));
    assert_eq!(out.value(1), expected_hash("false"));
    assert_eq!(
        out.value(0),
        out.value(2),
        "identical booleans must hash identically"
    );
    assert!(out.is_null(3), "null boolean must stay null");
}

/// MSK-26-TOKENIZE: tokenize (a string-producing alias of hash) on Int64 works.
#[tokio::test]
async fn msk_26_int64_tokenize() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "account_no",
        DataType::Int64,
        true,
    )]));
    let col = Arc::new(Int64Array::from(vec![Some(12345i64), None])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-tok", "account_no", "tokenize");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-tok-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    // tokenize maps to the same SHA-256 as hash_sha256.
    assert_eq!(out.value(0), expected_hash("12345"));
    assert!(out.is_null(1));
}

/// MSK-26-PARTIAL: partial mask on Int64 → "***" + last 4 chars of the string form.
#[tokio::test]
async fn msk_26_int64_partial() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "card_number",
        DataType::Int64,
        true,
    )]));
    let col =
        Arc::new(Int64Array::from(vec![Some(4111_1111_1111_1234i64), None])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-part", "card_number", "partial");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-part-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    let out = collect_masked_utf8(exec).await;
    assert_eq!(
        out.value(0),
        "***1234",
        "partial shows last 4 of the digits"
    );
    assert!(out.is_null(1));
}

/// MSK-26-STRING-UNCHANGED: a Utf8 column masked with hash_sha256 keeps its
/// prior behaviour exactly (hash of the raw string) — no regression from the
/// Task #26 change.  Output stays Utf8.
#[tokio::test]
async fn msk_26_string_column_unchanged_behaviour() {
    let schema = Arc::new(Schema::new(vec![Field::new("email", DataType::Utf8, true)]));
    let col = Arc::new(StringArray::from(vec![Some("alice@example.com"), None])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-str", "email", "hash_sha256");
    let approved =
        approved_single_column(schema.clone(), col, make_bundle_with_redact("c-str-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    // Output schema type must remain Utf8 (unchanged).
    assert_eq!(exec.schema().field(0).data_type(), &DataType::Utf8);
    let out = collect_masked_utf8(exec).await;
    assert_eq!(out.value(0), expected_hash("alice@example.com"));
    assert!(out.is_null(1), "null string must stay null");
}

/// MSK-26-REDACT-NUMERIC-PRESERVED: Redact on Int64 is NOT string-producing, so
/// it stays type-preserving (Int64 zeros) — the msk_c5 behaviour is unchanged.
#[tokio::test]
async fn msk_26_redact_int64_stays_int64() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "score",
        DataType::Int64,
        false,
    )]));
    let col = Arc::new(Int64Array::from(vec![100i64, 200, 300])) as Arc<dyn Array>;
    let bundle = make_bundle_single_col("c-redint", "score", "redact");
    let approved =
        approved_single_column(schema, col, make_bundle_with_redact("c-redint-inner")).await;
    let exec = MaskingExec::new(bundle, approved).unwrap();

    // Redact on Int64 must keep the Int64 type (NOT retyped to Utf8).
    assert_eq!(
        exec.schema().field(0).data_type(),
        &DataType::Int64,
        "Redact on Int64 must remain type-preserving (Int64), not become Utf8"
    );
    let exec_arc: Arc<dyn ExecutionPlan> = Arc::new(exec);
    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let score = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    for i in 0..score.len() {
        assert_eq!(score.value(i), 0, "redacted Int64 values must be zeroed");
    }
}

/// MSK-26-MIXED-SCHEMA: a multi-column batch where one numeric column is
/// hash-masked and a clear column is untouched — verifies the output schema
/// retypes only the masked column and clear columns pass through with their
/// original type + values.
#[tokio::test]
async fn msk_26_mixed_columns_only_masked_retyped() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("national_id", DataType::Int64, false),
        Field::new("city", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64, 2])),
            Arc::new(Int64Array::from(vec![5551234i64, 5555678])),
            Arc::new(StringArray::from(vec!["Nairobi", "Mombasa"])),
        ],
    )
    .unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    let inner = ctx
        .table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();
    let approved =
        Arc::new(ContractApprovedExec::new(make_bundle_with_redact("c-mix-inner"), inner).unwrap());

    let bundle = make_bundle_single_col("c-mix", "national_id", "hash_sha256");
    let exec = MaskingExec::new(bundle, approved).unwrap();

    // Output schema: id Int64, national_id RETYPED Utf8, city Utf8.
    let out_schema = exec.schema();
    assert_eq!(out_schema.field(0).data_type(), &DataType::Int64);
    assert_eq!(
        out_schema.field(1).data_type(),
        &DataType::Utf8,
        "masked numeric column retyped to Utf8"
    );
    assert_eq!(out_schema.field(2).data_type(), &DataType::Utf8);

    let exec_arc: Arc<dyn ExecutionPlan> = Arc::new(exec);
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let b = &batches[0];

    // id untouched.
    let id = b.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
    assert_eq!(id.value(0), 1);
    assert_eq!(id.value(1), 2);
    // national_id hashed.
    let nid = b
        .column(1)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::StringArray>()
        .unwrap();
    assert_eq!(nid.value(0), expected_hash("5551234"));
    assert_eq!(nid.value(1), expected_hash("5555678"));
    // city untouched clear text.
    let city = b
        .column(2)
        .as_any()
        .downcast_ref::<datafusion::arrow::array::StringArray>()
        .unwrap();
    assert_eq!(city.value(0), "Nairobi");
    assert_eq!(city.value(1), "Mombasa");
}

// ─── MSK-C2: Finding 2 — unknown masking policy → hard error ─────────────────

/// MSK-C2: Copilot finding 2 — when the contract bundle specifies an unrecognised
/// masking policy string (e.g. `"rainbow"`) the constructor MUST return
/// `Err(UnknownMaskPolicy)`.  Before the fix, unknown policies were silently
/// treated as `Noop`, meaning PII columns were returned unmasked.
///
/// Spec anchor: ADR-0002 §MaskingExec — policy validation.
/// INV-2: an unknown policy is not a satisfied contract.
#[tokio::test]
async fn msk_c2_unknown_masking_policy_returns_hard_error() {
    use datafusion::arrow::array::Int64Array;

    // Bundle with an unknown policy string.
    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-msk-c2",
        "test-tenant",
        bytes::Bytes::from(
            serde_json::json!({
                "contract_id": "contract-msk-c2",
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "column_masking": {
                    "email": "rainbow"
                }
            })
            .to_string()
            .into_bytes(),
        ),
    );

    let schema = id_email_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(StringArray::from(vec!["alice@example.com"])),
        ],
    )
    .unwrap();
    let table = datafusion::datasource::MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = datafusion::execution::context::SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    let inner = ctx
        .table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(
            make_bundle_with_redact("contract-msk-c2-inner"),
            inner,
        )
        .unwrap(),
    );

    let result = MaskingExec::new(bundle, approved);
    assert!(
        result.is_err(),
        "MaskingExec must reject unknown masking policy with a hard error"
    );
    match result.unwrap_err() {
        PhysicalError::UnknownMaskPolicy { policy, column } => {
            assert_eq!(policy, "rainbow");
            assert_eq!(column, "email");
        }
        other => panic!("expected UnknownMaskPolicy, got {:?}", other),
    }
}

// ─── MSK-C5: Finding 5 — non-Utf8 column type with incompatible policy → error ─

/// MSK-C5: Copilot finding 5 — when a masking policy that requires string
/// handling (e.g. `redact`) is applied to a non-Utf8, non-string column type
/// where redact is explicitly handled as a zero-equivalent, verify that the
/// implementation handles Int64 columns (returns zeros, not errors).
///
/// For columns of unsupported types that can't be masked in any meaningful way,
/// the operator MUST return `Err(MaskTypeUnsupported)` rather than silently
/// returning original values.
///
/// Spec anchor: ADR-0002 §MaskingExec — type-safe masking dispatch.
/// INV-2: per-type masking must be deterministic and spec-compliant.
#[tokio::test]
async fn msk_c5_int64_redact_returns_zeros() {
    use datafusion::arrow::array::Int64Array;
    use datafusion::physical_plan::collect;

    // Schema: an Int64 column tagged for redact.
    let schema = Arc::new(datafusion::arrow::datatypes::Schema::new(vec![
        datafusion::arrow::datatypes::Field::new(
            "score",
            datafusion::arrow::datatypes::DataType::Int64,
            false,
        ),
    ]));

    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-msk-c5",
        "test-tenant",
        bytes::Bytes::from(
            serde_json::json!({
                "contract_id": "contract-msk-c5",
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "column_masking": {
                    "score": "redact"
                }
            })
            .to_string()
            .into_bytes(),
        ),
    );

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![100i64, 200, 300]))],
    )
    .unwrap();
    let table = datafusion::datasource::MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = datafusion::execution::context::SessionContext::new();
    ctx.register_table("scores", Arc::new(table)).unwrap();
    let inner = ctx
        .table("scores")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(bundle.clone(), inner)
            .unwrap(),
    );

    // For Int64 columns with redact policy: must succeed at construction and
    // return 0-valued integers (redact for numeric = zero out).
    let exec_result = MaskingExec::new(bundle, approved);
    assert!(
        exec_result.is_ok(),
        "MaskingExec must succeed for Int64 redact policy (zeros out numerics)"
    );

    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> =
        Arc::new(exec_result.unwrap());
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();

    let score_col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    for i in 0..score_col.len() {
        assert_eq!(
            score_col.value(i),
            0,
            "redacted Int64 values must be zeroed out"
        );
    }
}
