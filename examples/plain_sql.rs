//! Example 1 — plain SQL over an in-memory table.
//!
//! Shows that GriotQL is, at its core, a real Apache DataFusion engine: you
//! register Arrow data in memory and run ordinary SQL against it. No Griot
//! services (T04/T05), no network, no files.
//!
//! It also demonstrates two engine-level guarantees that hold even before any
//! masking/filtering is configured:
//!   * INV-1 (no data without a contract): `query()` refuses to run until a
//!     contract bundle is injected.
//!   * The DDL guard rejects unsafe verbs (INSTALL/LOAD/ATTACH/COPY).
//!
//! Run with:
//!   cargo run --example plain_sql

use std::sync::Arc;

use bytes::Bytes;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;

use griot::{ContractBundleHandle, InitConfig, K04DEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Build the engine ──────────────────────────────────────────────────
    // In the Griot platform these endpoints point at the T04/T05 sockets. For
    // a standalone run they only need to be non-empty — no service is contacted
    // on the plain-SQL path. (See the masking/row_filter/dp_noise examples for
    // the enforcement path.)
    let mut engine = K04DEngine::new_with_config(InitConfig {
        tenant_id: "demo-tenant".to_string(),
        contract_bundle_endpoint: "inmemory://contract".to_string(),
        attestation_endpoint: "inmemory://attest".to_string(),
        max_result_rows: 10_000,
        storaged_socket: "inmemory://storaged".to_string(),
    })?;

    // ── Register an in-memory Arrow table ─────────────────────────────────
    let schema = Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("dept", DataType::Utf8, false),
        Field::new("salary", DataType::Float64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec![
                "alice", "bob", "carol", "dan", "erin",
            ])),
            Arc::new(StringArray::from(vec![
                "eng", "eng", "sales", "sales", "eng",
            ])),
            Arc::new(Float64Array::from(vec![
                120_000.0, 95_000.0, 80_000.0, 60_000.0, 135_000.0,
            ])),
        ],
    )?;
    engine
        .register_memory_table("employees", schema, vec![vec![batch]])
        .await?;

    // ── INV-1: a query without a contract bundle is refused ───────────────
    println!("== INV-1: query before any contract bundle is injected ==");
    match engine.query("SELECT * FROM employees").await {
        Ok(_) => println!("  (unexpected: query succeeded without a contract)"),
        Err(e) => println!("  refused as expected: {e}\n"),
    }

    // Inject a (here trivial) contract bundle to authorise reads.
    let bundle = ContractBundleHandle::from_x02_bytes(
        "contract-demo",
        "demo-tenant",
        Bytes::from_static(b"{}"),
    );
    engine.inject_contract_bundle(bundle);

    // ── Run ordinary SQL ──────────────────────────────────────────────────
    let sql = "SELECT dept, ROUND(AVG(salary), 0) AS avg_salary, COUNT(*) AS headcount \
               FROM employees \
               GROUP BY dept \
               ORDER BY avg_salary DESC";
    println!("== Plain SQL ==\n{sql}\n");
    let results = engine.query(sql).await?;
    println!("{}\n", pretty_format_batches(&results)?);

    // ── DDL guard: unsafe verbs are rejected ──────────────────────────────
    println!("== DDL guard: unsafe verbs are rejected ==");
    match engine.query("COPY employees TO '/tmp/leak.csv'").await {
        Ok(_) => println!("  (unexpected: COPY was allowed)"),
        Err(e) => println!("  rejected as expected: {e}"),
    }

    Ok(())
}
