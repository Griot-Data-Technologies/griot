//! Example 5 — query a contract-bound dataset end to end.
//!
//! This is the headline of the engine: you do not register tables and feed the
//! enforcement operators by hand (see the other examples) — you point SQL at a
//! **contract**, and the engine resolves the contract + the data location,
//! applies the contract's masking and row filtering inside the plan, and returns
//! governed rows. The same query run by the owner vs. an outside tenant returns
//! differently-shaped results.
//!
//! Everything is local: this example writes a small Parquet file + a JSON
//! contract into a temp dir, with zero external services.
//!
//! Run with:
//!   cargo run --example contract_query

use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;

use griot::contract_source::Caller;
use griot::engine::GriotEngine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Write a small Parquet dataset into a temp dir ─────────────────────
    let dir = tempfile::tempdir()?;
    let parquet_path = dir.path().join("orders.parquet");

    let schema = Arc::new(Schema::new(vec![
        Field::new("order_id", DataType::Int64, false),
        Field::new("email", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("amount", DataType::Float64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
            Arc::new(StringArray::from(vec![
                "alice@acme.com",
                "bob@globex.com",
                "carol@acme.com",
                "dan@initech.com",
                "erin@acme.com",
            ])),
            Arc::new(StringArray::from(vec!["EU", "US", "EU", "APAC", "US"])),
            Arc::new(Float64Array::from(vec![100.0, 250.0, 75.0, 300.0, 180.0])),
        ],
    )?;
    {
        let file = std::fs::File::create(&parquet_path)?;
        let mut writer = parquet::arrow::ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // ── The contract (the DPI surface) ────────────────────────────────────
    // Owned by `acme`. Outside callers get `email` hashed and only EU rows.
    let contract = serde_json::json!({
        "contract_id": "sales_orders_v1",
        "version": "1",
        "dataset": "sales/orders/v1",
        "binding": { "parquet": parquet_path.to_string_lossy() },
        "owner_tenant": "acme",
        "purposes": ["analytics"],
        "columns": [
            { "name": "order_id", "type": "int" },
            { "name": "email", "type": "text", "sensitivity": "pii", "mask": "hash_sha256" },
            { "name": "region", "type": "text" },
            { "name": "amount", "type": "float" }
        ],
        "row_filter": "region = 'EU'"
    })
    .to_string();

    let engine = GriotEngine::from_json_contracts([contract])?;

    let sql = r#"SELECT order_id, email, region, amount FROM "sales/orders/v1" ORDER BY order_id"#;

    // ── Outside tenant: governed (masked email, EU-only rows) ─────────────
    println!("== Caller: globex (outside tenant, purpose=analytics) ==");
    let governed = engine
        .query(sql, Caller::new("user:bob", "analytics", "globex"))
        .await?;
    println!("{}\n", pretty_format_batches(&governed)?);
    println!("email is SHA-256 hashed; only EU rows are visible (contract enforced).\n");

    // ── Owner: raw ────────────────────────────────────────────────────────
    println!("== Caller: acme (owner, purpose=analytics) ==");
    let raw = engine
        .query(sql, Caller::new("user:alice", "analytics", "acme"))
        .await?;
    println!("{}\n", pretty_format_batches(&raw)?);
    println!("owner sees all rows and raw email.\n");

    // ── Purpose gate: a disallowed purpose is refused ─────────────────────
    println!("== Caller: globex with purpose=marketing (not allowed) ==");
    match engine
        .query(sql, Caller::new("user:bob", "marketing", "globex"))
        .await
    {
        Ok(_) => println!("  (unexpected: query succeeded)"),
        Err(e) => println!("  refused as expected: {e}"),
    }

    Ok(())
}
