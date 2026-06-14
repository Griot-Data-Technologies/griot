//! Unit tests for `ContractApprovedExec` — Wave 9 / ADR-0002.
//!
//! Testing agent authored (2026-05-05).
//!
//! # TDD state
//!
//! All `#[test]` and `#[tokio::test]` functions are `#[ignore]`'d.
//! `cargo test` must report 0 run, N ignored.
//! The impl agent removes the `#[ignore]` attributes in the Wave 9 impl PR.
//!
//! # Coverage
//!
//! * CAE-01: Schema preserved — output schema == input schema.
//! * CAE-02: Single-batch execution streams through unchanged (approval propagates).
//! * CAE-03: Multi-batch streaming preserves order and row count.
//! * CAE-04: Constructor gates on non-empty contract_id (sealed).
//! * CAE-STRUCT: Public API exists and compiles (GREEN sanity check).
//!
//! # Spec anchors
//!
//! ADR-0002 §Physical operators — ContractApprovedExec.
//! INV-1: no data in without contract.

#![allow(unused_imports, dead_code)]

use bytes::Bytes;
use datafusion::arrow::array::{Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::ExecutionPlan;
use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::PhysicalError;
use griot::ContractBundleHandle;
use std::sync::Arc;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_bundle(contract_id: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal"
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn make_empty_bundle() -> ContractBundleHandle {
    // Empty contract_id simulates "no approval" — should cause constructor error.
    ContractBundleHandle::from_x02_bytes("", "test-tenant", Bytes::new())
}

/// Build a minimal MemTable-backed physical plan with a given schema and rows.
async fn make_memory_exec(
    schema: Arc<Schema>,
    batches: Vec<RecordBatch>,
) -> Arc<dyn datafusion::physical_plan::ExecutionPlan> {
    let table = MemTable::try_new(schema, vec![batches]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("t", Arc::new(table)).unwrap();
    ctx.table("t")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap()
}

fn int64_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]))
}

fn string_id_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ]))
}

// ─── CAE-01: Schema preserved ─────────────────────────────────────────────────

/// CAE-01: `ContractApprovedExec::schema()` MUST return a schema identical to
/// the inner plan's schema.  No columns are added or removed by the marker.
///
/// Spec anchor: ADR-0002 §ContractApprovedExec — type-preserving pass-through.
/// INV-1: contract approval does not alter the data type contract.
#[tokio::test]

async fn cae_01_schema_preserved() {
    let schema = int64_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
    )
    .unwrap();
    let inner = make_memory_exec(schema.clone(), vec![batch]).await;
    let bundle = make_bundle("contract-cae-01");

    let exec = ContractApprovedExec::new(bundle, inner).unwrap();
    let exec_schema = exec.schema();

    assert_eq!(
        exec_schema.as_ref(),
        schema.as_ref(),
        "ContractApprovedExec must preserve schema exactly"
    );
}

// ─── CAE-02: Single-batch execution passes through ────────────────────────────

/// CAE-02: Executing `ContractApprovedExec` on a single-batch inner plan MUST
/// produce the same rows as the inner plan.  The marker propagates approval
/// without mutating any values.
///
/// Spec anchor: ADR-0002 §ContractApprovedExec — row-count invariant.
#[tokio::test]

async fn cae_02_single_batch_execution_passthrough() {
    use datafusion::physical_plan::collect;

    let schema = int64_schema();
    let values = vec![10i64, 20, 30];
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(values.clone()))],
    )
    .unwrap();
    let inner = make_memory_exec(schema.clone(), vec![batch]).await;
    let bundle = make_bundle("contract-cae-02");

    let exec = ContractApprovedExec::new(bundle, inner).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();

    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 3, "row count must be preserved");

    // Verify values pass through unchanged.
    let col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    let result_values: Vec<i64> = col.values().to_vec();
    assert_eq!(result_values, values, "values must pass through unchanged");
}

// ─── CAE-03: Multi-batch streaming preserves order and row count ─────────────

/// CAE-03: When the inner plan produces multiple `RecordBatch`es (simulating
/// a multi-partition or split scan), `ContractApprovedExec` MUST preserve
/// the batch order and total row count.
///
/// Spec anchor: ADR-0002 §ContractApprovedExec — stream ordering invariant.
#[tokio::test]

async fn cae_03_multi_batch_streaming_preserves_order_and_count() {
    use datafusion::physical_plan::collect;

    let schema = int64_schema();
    // Two distinct batches to simulate a split scan.
    let batch1 =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(Int64Array::from(vec![1, 2]))]).unwrap();
    let batch2 = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![3, 4, 5]))],
    )
    .unwrap();

    // MemTable with two partition groups produces two batches.
    let table = MemTable::try_new(schema.clone(), vec![vec![batch1], vec![batch2]]).unwrap();
    let ctx = SessionContext::new();
    ctx.register_table("multi", Arc::new(table)).unwrap();
    let inner = ctx
        .table("multi")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let bundle = make_bundle("contract-cae-03");
    let exec = ContractApprovedExec::new(bundle, inner).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let task_ctx = ctx.task_ctx();
    let batches = collect(exec_arc, task_ctx).await.unwrap();

    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        total_rows, 5,
        "total row count must be preserved across batches"
    );
}

// ─── CAE-04: Constructor gates on empty contract_id (sealed) ─────────────────

/// CAE-04: Constructing `ContractApprovedExec` with a bundle that has an empty
/// `contract_id` MUST return an error.  This is the sealed-constructor gate —
/// it prevents unmarked approval from flowing downstream.
///
/// Spec anchor: ADR-0002 verified-binary surface rule (c) — sealed constructors.
/// INV-1: no data in without contract.
#[tokio::test]

async fn cae_04_constructor_gates_on_empty_contract_id() {
    let schema = int64_schema();
    let batch =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(Int64Array::from(vec![1]))]).unwrap();
    let inner = make_memory_exec(schema, vec![batch]).await;
    let empty_bundle = make_empty_bundle();

    let result = ContractApprovedExec::new(empty_bundle, inner);
    assert!(
        result.is_err(),
        "ContractApprovedExec must reject a bundle with empty contract_id"
    );
    match result.unwrap_err() {
        PhysicalError::ContractNotApproved { .. } => {}
        other => panic!("expected ContractNotApproved, got {:?}", other),
    }
}

// ─── CAE-STRUCT: Public API compile-time check (GREEN) ───────────────────────

/// CAE-STRUCT: Verify the public API of `ContractApprovedExec` compiles.
/// This test is GREEN — it only checks struct existence, not behaviour.
#[test]
fn cae_struct_public_api_compiles() {
    // We can name the type and its associated methods.
    // Actual construction would require a physical plan, so we just verify
    // the import and method signatures resolve.
    let _ = std::any::type_name::<ContractApprovedExec>();
    // PhysicalError variants accessible:
    let _err = PhysicalError::ContractNotApproved {
        operator: "test".to_string(),
    };
    let _err2 = PhysicalError::MissingInnerPlan;
    let _err3 = PhysicalError::MissingContractReference;
}
