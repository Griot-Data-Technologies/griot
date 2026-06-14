//! Example 2 — column masking.
//!
//! GriotQL's distinctive behaviour: a contract attached to the query rewrites
//! the result so that sensitive columns come back masked. Here `email` is
//! redacted to `***` and `ssn` is replaced by its SHA-256 hash — at read time,
//! enforced inside the engine, with no application code doing the masking.
//!
//! This mirrors how the engine's own tests construct the enforcement pipeline
//! (`ContractApprovedExec` proves the query was contract-checked; `MaskingExec`
//! applies the contract's per-column policy). No Griot services are required.
//!
//! Run with:
//!   cargo run --example column_masking

use std::sync::Arc;

use bytes::Bytes;
use datafusion::arrow::array::{Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use datafusion::physical_plan::{collect, ExecutionPlan};

use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::masking_exec::MaskingExec;
use griot::ContractBundleHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = SessionContext::new();

    // ── Source data (in memory) ───────────────────────────────────────────
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("email", DataType::Utf8, false),
        Field::new("ssn", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["alice", "bob", "carol"])),
            Arc::new(StringArray::from(vec![
                "alice@example.com",
                "bob@example.com",
                "carol@example.com",
            ])),
            Arc::new(StringArray::from(vec![
                "123-45-6789",
                "987-65-4321",
                "555-00-1234",
            ])),
        ],
    )?;
    ctx.register_table(
        "people",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]])?),
    )?;

    // Physical plan for `SELECT * FROM people`.
    let inner = ctx.table("people").await?.create_physical_plan().await?;

    // ── The contract bundle ───────────────────────────────────────────────
    // `email` -> redact, `ssn` -> SHA-256 hash. `id`/`name` are untouched.
    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-masking-demo",
        "demo-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": "contract-masking-demo",
                "tenant_id": "demo-tenant",
                "column_masking": {
                    "email": "redact",
                    "ssn": "hash_sha256"
                }
            })
            .to_string(),
        ),
    );

    // `ContractApprovedExec` is the proof the query passed the contract check;
    // the enforcement operators refuse to run without it upstream.
    let approved: Arc<dyn ExecutionPlan> =
        Arc::new(ContractApprovedExec::new(bundle.clone(), inner)?);

    // ── Before ────────────────────────────────────────────────────────────
    let before = collect(approved.clone(), ctx.task_ctx()).await?;
    println!("== Raw data (no masking) ==");
    println!("{}\n", pretty_format_batches(&before)?);

    // ── After: masking applied by the engine ──────────────────────────────
    let masked: Arc<dyn ExecutionPlan> = Arc::new(MaskingExec::new(bundle, approved)?);
    let after = collect(masked, ctx.task_ctx()).await?;
    println!("== Governed output (contract masking applied) ==");
    println!("{}", pretty_format_batches(&after)?);
    println!("\nemail was redacted to '***'; ssn was replaced by its SHA-256 hash.");

    Ok(())
}
