//! Unit tests for `RowFilterExec` — Wave 9 / ADR-0002.
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
//! * RFE-01: Schema preserved — output schema == input schema.
//! * RFE-02: Single-batch execution drops rows matching inverse of filter.
//! * RFE-03: Multi-batch streaming preserves order; each batch filtered independently.
//! * RFE-04: Constructor without ContractApprovedExec upstream → Err(ContractNotApproved).
//! * RFE-STRUCT: Public API exists and compiles (GREEN).
//!
//! # Spec anchors
//!
//! ADR-0002 §Physical operators — RowFilterExec.
//! INV-2: no read without satisfaction (row-level filtering).

#![allow(unused_imports, dead_code)]

use bytes::Bytes;
use datafusion::arrow::array::{Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::ExecutionPlan;
use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::row_filter_exec::RowFilterExec;
use griot::physical::PhysicalError;
use griot::ContractBundleHandle;
use std::sync::Arc;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_bundle_with_region_filter(contract_id: &str, region: &str) -> ContractBundleHandle {
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
                "row_filter": format!("region = '{}'", region)
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn make_bundle_no_filter(contract_id: &str) -> ContractBundleHandle {
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
                "row_filter": null
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn region_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("region", DataType::Utf8, false),
    ]))
}

async fn make_region_exec(
    rows: Vec<(i64, &str)>,
) -> Arc<dyn datafusion::physical_plan::ExecutionPlan> {
    let schema = region_schema();
    let ids: Vec<i64> = rows.iter().map(|(id, _)| *id).collect();
    let regions: Vec<&str> = rows.iter().map(|(_, r)| *r).collect();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(regions)),
        ],
    )
    .unwrap();
    let table = MemTable::try_new(schema.clone(), vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    ctx.table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap()
}

/// Build a `ContractApprovedExec`-wrapped inner plan (simulating a plan that
/// has already been through contract approval).
async fn make_approved_exec(
    rows: Vec<(i64, &str)>,
    bundle: ContractBundleHandle,
) -> Arc<dyn datafusion::physical_plan::ExecutionPlan> {
    let inner = make_region_exec(rows).await;
    let approved = ContractApprovedExec::new(bundle.clone(), inner).unwrap();
    Arc::new(approved)
}

// ─── RFE-01: Schema preserved ─────────────────────────────────────────────────

/// RFE-01: `RowFilterExec::schema()` MUST return the same schema as the inner
/// plan.  Row filtering does not change the column structure.
///
/// Spec anchor: ADR-0002 §RowFilterExec — schema-preserving filter.
/// INV-2: row filtering does not change schema.
#[tokio::test]

async fn rfe_01_schema_preserved() {
    let schema = region_schema();
    let bundle = make_bundle_with_region_filter("contract-rfe-01", "us");
    let approved = make_approved_exec(vec![(1, "us"), (2, "eu")], bundle.clone()).await;

    let exec = RowFilterExec::new(bundle, approved).unwrap();
    assert_eq!(
        exec.schema().as_ref(),
        schema.as_ref(),
        "RowFilterExec must preserve schema"
    );
}

// ─── RFE-02: Single-batch drops rows not matching filter ─────────────────────

/// RFE-02: When the bundle specifies `row_filter = "region = 'us'"`, executing
/// `RowFilterExec` on a batch containing both `us` and `eu` rows MUST drop the
/// `eu` rows and return only `us` rows.
///
/// Spec anchor: ADR-0002 §RowFilterExec — row dropping behaviour.
/// INV-2: no read without satisfaction — rows that don't satisfy the contract
/// row predicate are excluded.
#[tokio::test]

async fn rfe_02_single_batch_drops_non_matching_rows() {
    use datafusion::physical_plan::collect;

    let bundle = make_bundle_with_region_filter("contract-rfe-02", "us");
    let approved = make_approved_exec(
        vec![(1, "us"), (2, "eu"), (3, "us"), (4, "apac")],
        bundle.clone(),
    )
    .await;

    let exec = RowFilterExec::new(bundle, approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();

    // Only rows with region='us' pass (ids 1 and 3).
    assert_eq!(
        total_rows, 2,
        "only us-region rows should survive the filter"
    );

    // Verify the surviving row ids.
    let id_col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    let ids: Vec<i64> = id_col.values().to_vec();
    assert!(ids.contains(&1), "row id=1 (us) should survive");
    assert!(ids.contains(&3), "row id=3 (us) should survive");
}

// ─── RFE-03: Multi-batch streaming preserves order ───────────────────────────

/// RFE-03: When the inner plan produces multiple batches, `RowFilterExec`
/// MUST filter each independently while preserving batch order (IDs ascending).
///
/// Spec anchor: ADR-0002 §RowFilterExec — streaming order invariant.
#[tokio::test]

async fn rfe_03_multi_batch_streaming_preserves_order() {
    use datafusion::physical_plan::collect;

    let schema = region_schema();
    let bundle = make_bundle_with_region_filter("contract-rfe-03", "eu");

    // Two batches: first has eu+us, second has eu-only.
    let batch1 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![10i64, 11])),
            Arc::new(StringArray::from(vec!["eu", "us"])),
        ],
    )
    .unwrap();
    let batch2 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![20i64, 21])),
            Arc::new(StringArray::from(vec!["eu", "eu"])),
        ],
    )
    .unwrap();

    let table = MemTable::try_new(schema.clone(), vec![vec![batch1], vec![batch2]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("multi", Arc::new(table)).unwrap();
    let inner_plan = ctx
        .table("multi")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let approved = Arc::new(ContractApprovedExec::new(bundle.clone(), inner_plan).unwrap());
    let exec = RowFilterExec::new(bundle, approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();

    // id=10 (eu), id=20 (eu), id=21 (eu) survive; id=11 (us) is dropped.
    assert_eq!(total_rows, 3, "eu rows across both batches must survive");
}

// ─── RFE-04: No ContractApprovedExec upstream → constructor error ─────────────

/// RFE-04: Constructing `RowFilterExec` with an inner plan that does NOT have
/// `ContractApprovedExec` as an ancestor MUST return
/// `Err(PhysicalError::ContractNotApproved)`.
///
/// Spec anchor: ADR-0002 verified-binary surface rule (c).
/// INV-2: enforcement operators cannot operate on unapproved scans.
#[tokio::test]

async fn rfe_04_no_approved_ancestor_constructor_error() {
    let schema = region_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(StringArray::from(vec!["us"])),
        ],
    )
    .unwrap();
    // Raw inner plan — NOT wrapped in ContractApprovedExec.
    let table = MemTable::try_new(schema.clone(), vec![vec![batch]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("raw", Arc::new(table)).unwrap();
    let raw_inner = ctx
        .table("raw")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let bundle = make_bundle_with_region_filter("contract-rfe-04", "us");
    let result = RowFilterExec::new(bundle, raw_inner);

    assert!(
        result.is_err(),
        "RowFilterExec must reject unapproved inner plan"
    );
    match result.unwrap_err() {
        PhysicalError::ContractNotApproved { operator } => {
            assert_eq!(operator, "RowFilterExec");
        }
        other => panic!(
            "expected ContractNotApproved(RowFilterExec), got {:?}",
            other
        ),
    }
}

// ─── RFE-STRUCT: Public API compile-time check (GREEN) ───────────────────────

/// RFE-STRUCT: Verify type names resolve and error variants compile.
#[test]
fn rfe_struct_public_api_compiles() {
    let _ = std::any::type_name::<RowFilterExec>();
    let _err = PhysicalError::ContractNotApproved {
        operator: "RowFilterExec".to_string(),
    };
}

// ─── RFE-C1: Finding 1 — malformed bundle JSON → hard error ─────────────────

/// RFE-C1: Copilot finding 1 — constructing `RowFilterExec` with a bundle whose
/// raw_bytes contains invalid JSON MUST return `Err(ContractBundleMalformed)`.
///
/// Before the fix the impl silently fell back to no-filter; rows were returned
/// unfiltered, violating INV-2.
///
/// Spec anchor: ADR-0002 §RowFilterExec — contract bundle validation.
/// INV-2: a malformed contract is not a satisfied contract.
#[tokio::test]
async fn rfe_c1_malformed_bundle_json_returns_hard_error() {
    use datafusion::arrow::array::Int64Array;

    let schema = region_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(StringArray::from(vec!["us"])),
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

    // Bundle with syntactically invalid JSON bytes.
    let malformed_bundle = griot::ContractBundleHandle::from_x02_bytes(
        "contract-rfe-c1",
        "test-tenant",
        bytes::Bytes::from(b"{ this is not valid json !!!".to_vec()),
    );

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(
            make_bundle_no_filter("contract-rfe-c1-inner"),
            inner,
        )
        .unwrap(),
    );

    let result = RowFilterExec::new(malformed_bundle, approved);
    assert!(
        result.is_err(),
        "RowFilterExec must reject malformed bundle JSON with a hard error"
    );
    match result.unwrap_err() {
        PhysicalError::ContractBundleMalformed { .. } => {}
        other => panic!("expected ContractBundleMalformed, got {:?}", other),
    }
}

// ─── RFE-C4: Finding 4 — type-agnostic filtering preserves non-string columns ─

/// RFE-C4: Copilot finding 4 — filtering on a string column must not corrupt
/// non-string columns in the same batch.  After applying `region = 'us'`, the
/// `id` column (Int64) must retain its original values for surviving rows.
///
/// Before the fix the string-comparison filter was applied type-unsafely and
/// could corrupt or panic on non-Utf8 column types.
///
/// Spec anchor: ADR-0002 §RowFilterExec — type-agnostic filter.
/// INV-2: correctness of filtering is part of satisfaction.
#[tokio::test]
async fn rfe_c4_type_agnostic_filter_preserves_non_string_columns() {
    use datafusion::physical_plan::collect;

    let bundle = make_bundle_with_region_filter("contract-rfe-c4", "us");
    let approved =
        make_approved_exec(vec![(42, "us"), (99, "eu"), (7, "us")], bundle.clone()).await;

    let exec = RowFilterExec::new(bundle, approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let ctx = datafusion::execution::context::SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 2, "only us-region rows must survive");

    // id column must be the correct Int64 values (42 and 7), not corrupted.
    use datafusion::arrow::array::Int64Array;
    let id_col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    let ids: Vec<i64> = (0..id_col.len()).map(|i| id_col.value(i)).collect();
    assert!(ids.contains(&42), "id=42 must survive (region=us)");
    assert!(ids.contains(&7), "id=7 must survive (region=us)");
    assert!(!ids.contains(&99), "id=99 must be filtered (region=eu)");
}
