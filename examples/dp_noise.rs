//! Example 4 — differential-privacy noise.
//!
//! When the contract tags a column as differentially private, the engine adds
//! calibrated Laplace noise to its values before returning them, so individual
//! records can't be read back precisely. Here `salary` is tagged with
//! sensitivity=1.0, epsilon=0.1 (scale = sensitivity/epsilon = 10), and the
//! engine debits a privacy budget as it does so.
//!
//! The output prints the raw value next to the noised value for each row so the
//! perturbation is visible. (Run it a few times — the noise changes each run.)
//!
//! Run with:
//!   cargo run --example dp_noise

use std::sync::Arc;

use bytes::Bytes;
use datafusion::arrow::array::{Float64Array, Int64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::{collect, ExecutionPlan};

use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::laplace_noise_exec::LaplaceNoiseExec;
use griot::ContractBundleHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = SessionContext::new();

    // ── Source data (in memory) ───────────────────────────────────────────
    let schema = Arc::new(Schema::new(vec![
        Field::new("dept_id", DataType::Int64, false),
        Field::new("salary", DataType::Float64, false),
    ]));
    let raw_salaries = vec![120_000.0_f64, 95_000.0, 80_000.0, 60_000.0, 135_000.0];
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
            Arc::new(Float64Array::from(raw_salaries.clone())),
        ],
    )?;
    ctx.register_table(
        "payroll",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]])?),
    )?;

    let inner = ctx.table("payroll").await?.create_physical_plan().await?;

    // ── The contract bundle: salary is differentially private ─────────────
    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-dp-demo",
        "demo-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": "contract-dp-demo",
                "tenant_id": "demo-tenant",
                "dp_columns": {
                    "salary": { "sensitivity": 1.0, "epsilon": 0.1 }
                }
            })
            .to_string(),
        ),
    );

    let approved: Arc<dyn ExecutionPlan> =
        Arc::new(ContractApprovedExec::new(bundle.clone(), inner)?);

    // ── Apply Laplace noise ───────────────────────────────────────────────
    let noised_exec: Arc<dyn ExecutionPlan> = Arc::new(LaplaceNoiseExec::new_permissive(
        bundle,
        "demo-tenant",
        approved,
    )?);
    let after = collect(noised_exec.clone(), ctx.task_ctx()).await?;

    // ── Print raw vs noised, side by side ─────────────────────────────────
    let noised_col = after[0]
        .column(1)
        .as_any()
        .downcast_ref::<Float64Array>()
        .expect("salary column is Float64");

    println!("== Differential-privacy noise on `salary` (sensitivity=1.0, epsilon=0.1) ==\n");
    println!(
        "{:>8}  {:>14}  {:>16}  {:>12}",
        "dept_id", "raw salary", "noised salary", "delta"
    );
    println!("{}", "-".repeat(56));
    for (i, raw) in raw_salaries.iter().enumerate() {
        let noised = noised_col.value(i);
        println!(
            "{:>8}  {:>14.2}  {:>16.2}  {:>+12.2}",
            i + 1,
            raw,
            noised,
            noised - raw
        );
    }

    if let Some(eps) = noised_exec
        .as_any()
        .downcast_ref::<LaplaceNoiseExec>()
        .and_then(|e| e.epsilon_consumed())
    {
        println!("\nprivacy budget consumed this query: epsilon = {eps}");
    }

    Ok(())
}
