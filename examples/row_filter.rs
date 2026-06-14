//! Example 3 — row filtering.
//!
//! The contract restricts which rows the requester is entitled to see. Here the
//! contract carries `row_filter: "region = 'EU'"`, so the engine drops every
//! non-EU row from the result — enforced inside the query plan, not by the
//! caller's WHERE clause.
//!
//! Run with:
//!   cargo run --example row_filter

use std::sync::Arc;

use bytes::Bytes;
use datafusion::arrow::array::{Float64Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::{collect, ExecutionPlan};

use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::row_filter_exec::RowFilterExec;
use griot::ContractBundleHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = SessionContext::new();

    // ── Source data (in memory) ───────────────────────────────────────────
    let schema = Arc::new(Schema::new(vec![
        Field::new("order_id", DataType::Int64, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("amount", DataType::Float64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
            Arc::new(StringArray::from(vec!["EU", "US", "EU", "APAC", "US"])),
            Arc::new(Float64Array::from(vec![100.0, 250.0, 75.0, 300.0, 180.0])),
        ],
    )?;
    ctx.register_table(
        "orders",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]])?),
    )?;

    let inner = ctx.table("orders").await?.create_physical_plan().await?;

    // ── The contract bundle: only EU rows are permitted ───────────────────
    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-rowfilter-demo",
        "demo-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": "contract-rowfilter-demo",
                "tenant_id": "demo-tenant",
                "row_filter": "region = 'EU'"
            })
            .to_string(),
        ),
    );

    let approved: Arc<dyn ExecutionPlan> =
        Arc::new(ContractApprovedExec::new(bundle.clone(), inner)?);

    // ── Before ────────────────────────────────────────────────────────────
    let before = collect(approved.clone(), ctx.task_ctx()).await?;
    println!("== Raw data (all regions) ==");
    println!("{}\n", pretty_format_batches(&before)?);

    // ── After: contract row filter applied ────────────────────────────────
    let filtered: Arc<dyn ExecutionPlan> = Arc::new(RowFilterExec::new(bundle, approved)?);
    let after = collect(filtered, ctx.task_ctx()).await?;
    println!("== Governed output (row_filter = \"region = 'EU'\") ==");
    println!("{}", pretty_format_batches(&after)?);
    println!("\nOnly EU rows were returned; US/APAC rows were removed by the engine.");

    Ok(())
}
