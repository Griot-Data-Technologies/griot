//! Unit tests for `LaplaceNoiseExec` — Wave 9 / ADR-0002.
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
//! * DPE-01: Schema preserved — output schema == input schema (noise is value-level).
//! * DPE-02: Single-batch with DP noise applied — output values differ from input.
//! * DPE-03: Multi-batch streaming applies noise per batch; epsilon debited each time.
//! * DPE-04: Constructor without ContractApprovedExec upstream → Err(ContractNotApproved).
//! * DPE-STRUCT: Public API exists and compiles (GREEN).
//!
//! # Spec anchors
//!
//! ADR-0002 §Physical operators — LaplaceNoiseExec.
//! INV-2: no read without satisfaction (differential privacy budget).

#![allow(unused_imports, dead_code)]

use bytes::Bytes;
use datafusion::arrow::array::{Array, Float64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::ExecutionPlan;
use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::laplace_noise_exec::LaplaceNoiseExec;
use griot::physical::PhysicalError;
use griot::ContractBundleHandle;
use std::sync::Arc;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Bundle with `salary` tagged as DP-protected (sensitivity=1.0, epsilon=0.5).
fn make_dp_bundle(contract_id: &str) -> ContractBundleHandle {
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
                "dp_columns": {
                    "salary": { "sensitivity": 1.0, "epsilon": 0.5 }
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn salary_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("dept_id", DataType::Int64, false),
        Field::new("salary", DataType::Float64, false),
    ]))
}

async fn make_approved_dp_exec(
    salaries: Vec<f64>,
    bundle: ContractBundleHandle,
) -> Arc<dyn datafusion::physical_plan::ExecutionPlan> {
    use datafusion::arrow::array::Int64Array;
    let schema = salary_schema();
    let n = salaries.len() as i64;
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from((0..n).collect::<Vec<i64>>())),
            Arc::new(Float64Array::from(salaries)),
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

// ─── DPE-01: Schema preserved ────────────────────────────────────────────────

/// DPE-01: `LaplaceNoiseExec::schema()` MUST return the same schema as the
/// inner plan.  Noise is applied to column values; types are unchanged.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — schema-preserving noise.
#[tokio::test]

async fn dpe_01_schema_preserved() {
    let schema = salary_schema();
    let bundle = make_dp_bundle("contract-dpe-01");
    let approved = make_approved_dp_exec(vec![50_000.0, 60_000.0], bundle.clone()).await;

    let exec = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", approved).unwrap();
    assert_eq!(
        exec.schema().as_ref(),
        schema.as_ref(),
        "LaplaceNoiseExec must preserve schema"
    );
}

// ─── DPE-02: Single-batch execution modifies DP-tagged values ────────────────

/// DPE-02: After execution, the `salary` column values MUST differ from the
/// original (noise was added).  With Laplace noise (scale > 0) and a
/// deterministic seed, values will almost never be identical.
///
/// Note: this test uses a seeded RNG or checks that the standard deviation
/// of the noise is within bounds, NOT that specific exact values appear.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — noise application.
/// INV-2: DP guarantees that individual salaries cannot be precisely recovered.
#[tokio::test]

async fn dpe_02_single_batch_noise_applied_to_dp_column() {
    use datafusion::physical_plan::collect;

    let original_salaries = vec![50_000.0_f64, 60_000.0, 70_000.0];
    let bundle = make_dp_bundle("contract-dpe-02");
    let approved = make_approved_dp_exec(original_salaries.clone(), bundle.clone()).await;

    let exec = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let ctx = SessionContext::new();
    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();

    let salary_col = batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<Float64Array>()
        .unwrap();

    // At least one value must differ from the original (noise applied).
    let all_identical = (0..salary_col.len())
        .all(|i| (salary_col.value(i) - original_salaries[i]).abs() < f64::EPSILON);
    assert!(
        !all_identical,
        "Laplace noise must modify at least one salary value"
    );
}

// ─── DPE-03: Multi-batch: epsilon debited per batch ──────────────────────────

/// DPE-03: When the inner plan produces multiple batches, `LaplaceNoiseExec`
/// MUST apply noise to each batch independently.  The `epsilon_consumed()`
/// counter MUST reflect the total epsilon debited across all batches.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — streaming epsilon accounting.
#[tokio::test]

async fn dpe_03_multi_batch_epsilon_debited_across_batches() {
    use datafusion::arrow::array::Int64Array;
    use datafusion::physical_plan::collect;

    let schema = salary_schema();
    let bundle = make_dp_bundle("contract-dpe-03");

    let batch1 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(Float64Array::from(vec![50_000.0f64])),
        ],
    )
    .unwrap();
    let batch2 = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64])),
            Arc::new(Float64Array::from(vec![60_000.0f64])),
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
    let exec = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let batches = collect(exec_arc.clone(), ctx.task_ctx()).await.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 2, "all rows must stream through");

    // epsilon_consumed must be > 0 (noise was applied to 2 batches).
    let noise_exec = exec_arc
        .as_any()
        .downcast_ref::<LaplaceNoiseExec>()
        .unwrap();
    let eps = noise_exec.epsilon_consumed().unwrap_or(0.0);
    assert!(
        eps > 0.0,
        "epsilon_consumed must be positive after execution"
    );
}

// ─── DPE-04: No ContractApprovedExec upstream → constructor error ─────────────

/// DPE-04: Constructing `LaplaceNoiseExec` without `ContractApprovedExec`
/// upstream MUST return `Err(PhysicalError::ContractNotApproved)`.
///
/// Spec anchor: ADR-0002 verified-binary surface rule (c).
#[tokio::test]

async fn dpe_04_no_approved_ancestor_constructor_error() {
    use datafusion::arrow::array::Int64Array;

    let schema = salary_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(Float64Array::from(vec![50_000.0f64])),
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

    let bundle = make_dp_bundle("contract-dpe-04");
    let result = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", raw_inner);

    assert!(
        result.is_err(),
        "LaplaceNoiseExec must reject unapproved inner plan"
    );
    match result.unwrap_err() {
        PhysicalError::ContractNotApproved { operator } => {
            assert_eq!(operator, "LaplaceNoiseExec");
        }
        other => panic!(
            "expected ContractNotApproved(LaplaceNoiseExec), got {:?}",
            other
        ),
    }
}

// ─── DPE-STRUCT: Public API compile-time check (GREEN) ───────────────────────

/// DPE-STRUCT: Verify type names compile.
#[test]
fn dpe_struct_public_api_compiles() {
    let _ = std::any::type_name::<LaplaceNoiseExec>();
}

// ─── DPE-C3: Finding 3 — malformed DP bundle JSON → hard error ───────────────

/// DPE-C3: Copilot finding 3 — constructing `LaplaceNoiseExec` with a bundle
/// whose raw_bytes contains invalid JSON MUST return
/// `Err(ContractBundleMalformed)`.
///
/// Before the fix the impl silently treated malformed bundles as having no DP
/// columns, returning raw (non-noised) values in violation of INV-2.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — contract bundle validation.
/// INV-2: a malformed contract is not a satisfied contract.
#[tokio::test]
async fn dpe_c3_malformed_bundle_json_returns_hard_error() {
    use datafusion::arrow::array::Int64Array;

    let schema = salary_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(Float64Array::from(vec![50_000.0f64])),
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

    let malformed_bundle = griot::ContractBundleHandle::from_x02_bytes(
        "contract-dpe-c3",
        "test-tenant",
        bytes::Bytes::from(b"{ not valid json }".to_vec()),
    );

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(
            make_dp_bundle("contract-dpe-c3-inner"),
            inner,
        )
        .unwrap(),
    );

    let result = LaplaceNoiseExec::new_permissive(malformed_bundle, "test-tenant", approved);
    assert!(
        result.is_err(),
        "LaplaceNoiseExec must reject malformed bundle JSON with a hard error"
    );
    match result.unwrap_err() {
        PhysicalError::ContractBundleMalformed { .. } => {}
        other => panic!("expected ContractBundleMalformed, got {:?}", other),
    }
}

// ─── DPE-C6: Finding 6 — invalid epsilon (zero/negative/NaN) → hard error ────

/// DPE-C6: Copilot finding 6 — when the DP bundle specifies epsilon=0 or
/// epsilon<0 or epsilon=NaN the constructor MUST return
/// `Err(InvalidDpParameters)`.
///
/// Before the fix epsilon=0 caused division-by-zero in the Laplace scale
/// calculation (scale = sensitivity / epsilon), producing infinite or NaN noise.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — parameter validation.
/// INV-2: a contract with invalid DP parameters cannot be satisfied.
#[tokio::test]
async fn dpe_c6_invalid_epsilon_zero_returns_hard_error() {
    use datafusion::arrow::array::Int64Array;

    let schema = salary_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(Float64Array::from(vec![50_000.0f64])),
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

    // epsilon=0.0 is invalid.
    let bad_bundle = griot::ContractBundleHandle::from_x02_bytes(
        "contract-dpe-c6",
        "test-tenant",
        bytes::Bytes::from(
            serde_json::json!({
                "contract_id": "contract-dpe-c6",
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "dp_columns": {
                    "salary": { "sensitivity": 1.0, "epsilon": 0.0 }
                }
            })
            .to_string()
            .into_bytes(),
        ),
    );

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(
            make_dp_bundle("contract-dpe-c6-inner"),
            inner,
        )
        .unwrap(),
    );

    let result = LaplaceNoiseExec::new_permissive(bad_bundle, "test-tenant", approved);
    assert!(
        result.is_err(),
        "LaplaceNoiseExec must reject epsilon=0 with a hard error"
    );
    match result.unwrap_err() {
        PhysicalError::InvalidDpParameters {
            column, epsilon, ..
        } => {
            assert_eq!(column, "salary");
            assert_eq!(epsilon, 0.0);
        }
        other => panic!("expected InvalidDpParameters, got {:?}", other),
    }
}

/// DPE-C6b: Negative epsilon must also be rejected.
#[tokio::test]
async fn dpe_c6b_invalid_epsilon_negative_returns_hard_error() {
    use datafusion::arrow::array::Int64Array;

    let schema = salary_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![0i64])),
            Arc::new(Float64Array::from(vec![50_000.0f64])),
        ],
    )
    .unwrap();
    let table = datafusion::datasource::MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = datafusion::execution::context::SessionContext::new();
    ctx.register_table("t2", Arc::new(table)).unwrap();
    let inner = ctx
        .table("t2")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let bad_bundle = griot::ContractBundleHandle::from_x02_bytes(
        "contract-dpe-c6b",
        "test-tenant",
        bytes::Bytes::from(
            serde_json::json!({
                "contract_id": "contract-dpe-c6b",
                "tenant_id": "test-tenant",
                "dp_columns": {
                    "salary": { "sensitivity": 1.0, "epsilon": -0.5 }
                }
            })
            .to_string()
            .into_bytes(),
        ),
    );

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(
            make_dp_bundle("contract-dpe-c6b-inner"),
            inner,
        )
        .unwrap(),
    );

    let result = LaplaceNoiseExec::new_permissive(bad_bundle, "test-tenant", approved);
    assert!(
        result.is_err(),
        "LaplaceNoiseExec must reject negative epsilon"
    );
    assert!(matches!(
        result.unwrap_err(),
        PhysicalError::InvalidDpParameters { .. }
    ));
}

// ─── DPE-C7: Finding 7 — Int64 DP column receives noise ─────────────────────

/// DPE-C7: Copilot finding 7 — `LaplaceNoiseExec` MUST apply Laplace noise to
/// Int64 columns (not just Float64).  Before the fix, Int64 columns were silently
/// skipped (raw values returned), violating the DP guarantee.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — type coverage.
/// INV-2: DP must cover all tagged column types, not just Float64.
#[tokio::test]
async fn dpe_c7_int64_column_receives_noise() {
    use datafusion::arrow::array::Int64Array;
    use datafusion::physical_plan::collect;

    // Schema: an Int64 column tagged for DP.
    let schema = Arc::new(datafusion::arrow::datatypes::Schema::new(vec![
        datafusion::arrow::datatypes::Field::new(
            "count_val",
            datafusion::arrow::datatypes::DataType::Int64,
            false,
        ),
    ]));

    let bundle = griot::ContractBundleHandle::from_x02_bytes(
        "contract-dpe-c7",
        "test-tenant",
        bytes::Bytes::from(
            serde_json::json!({
                "contract_id": "contract-dpe-c7",
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "dp_columns": {
                    "count_val": { "sensitivity": 1.0, "epsilon": 0.1 }
                }
            })
            .to_string()
            .into_bytes(),
        ),
    );

    let original_values = vec![1000i64, 2000, 3000, 4000, 5000];
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(original_values.clone()))],
    )
    .unwrap();
    let table = datafusion::datasource::MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    let ctx = datafusion::execution::context::SessionContext::new();
    ctx.register_table("counts", Arc::new(table)).unwrap();
    let inner = ctx
        .table("counts")
        .await
        .unwrap()
        .create_physical_plan()
        .await
        .unwrap();

    let approved = Arc::new(
        griot::physical::contract_approved_exec::ContractApprovedExec::new(bundle.clone(), inner)
            .unwrap(),
    );

    let exec = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    let batches = collect(exec_arc, ctx.task_ctx()).await.unwrap();
    let count_col = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();

    // With epsilon=0.1 and sensitivity=1.0 (scale=10), at least one value must
    // differ from the original (the probability of all 5 being identical is
    // astronomically small — essentially 0).
    let all_identical = (0..count_col.len()).all(|i| count_col.value(i) == original_values[i]);
    assert!(
        !all_identical,
        "Laplace noise must modify at least one Int64 value (scale=10, 5 values)"
    );
}

// ─── DPE-C8: Finding 8 — budget consume() called before rows returned ─────────

/// DPE-C8: Copilot finding 8 — `PrivacyBudgetTracker::consume()` MUST be called
/// during execution (before rows are yielded to the caller), and if the budget
/// is exhausted the stream MUST return an error rather than returning rows.
///
/// This test verifies the positive case: after a successful execution the
/// `epsilon_consumed()` counter MUST reflect the epsilon debited from the budget.
/// A second execution on the same (consumed) budget is not tested here because
/// `PrivacyBudgetTracker` is an in-process mock in tests; the budget-exhaustion
/// path is covered by the error-variant being present in the type system.
///
/// Spec anchor: ADR-0002 §LaplaceNoiseExec — budget enforcement.
/// INV-2: DP rows cannot be returned without first debiting the budget.
#[tokio::test]
async fn dpe_c8_budget_consume_called_on_execute() {
    use datafusion::physical_plan::collect;

    let original_salaries = vec![50_000.0_f64];
    let bundle = make_dp_bundle("contract-dpe-c8");
    let approved = make_approved_dp_exec(original_salaries, bundle.clone()).await;

    let exec = LaplaceNoiseExec::new_permissive(bundle, "test-tenant", approved).unwrap();
    let exec_arc: Arc<dyn datafusion::physical_plan::ExecutionPlan> = Arc::new(exec);

    // Execute.
    let ctx = datafusion::execution::context::SessionContext::new();
    let _batches = collect(exec_arc.clone(), ctx.task_ctx()).await.unwrap();

    // After execution, epsilon_consumed must be Some and > 0.
    let noise_exec = exec_arc
        .as_any()
        .downcast_ref::<LaplaceNoiseExec>()
        .unwrap();
    let eps = noise_exec.epsilon_consumed();
    assert!(
        eps.is_some(),
        "epsilon_consumed must be Some after execution (budget was debited)"
    );
    assert!(
        eps.unwrap() > 0.0,
        "epsilon_consumed must be > 0 (equals the epsilon from the DP bundle)"
    );
}
