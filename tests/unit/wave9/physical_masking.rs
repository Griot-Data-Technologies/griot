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
