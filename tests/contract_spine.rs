//! End-to-end tests for the contract resolution spine.
//!
//! These mirror `examples/contract_query.rs`: write a local Parquet dataset + a
//! JSON contract, then query `SELECT ... FROM "<dataset>"` and assert the
//! governed output (masking, row filtering, purpose gate) with zero external
//! services.

use std::sync::Arc;

use datafusion::arrow::array::{Array, Float64Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;

use griot::contract_source::Caller;
use griot::engine::GriotEngine;

/// Write the sample `orders` dataset to `path` and return the JSON contract that
/// governs it (owned by `acme`; outsiders get `email` hashed + EU-only rows).
fn write_dataset_and_contract(path: &std::path::Path) -> String {
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
    )
    .unwrap();

    let file = std::fs::File::create(path).unwrap();
    let mut writer = parquet::arrow::ArrowWriter::try_new(file, schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();

    serde_json::json!({
        "contract_id": "sales_orders_v1",
        "version": "1",
        "dataset": "sales/orders/v1",
        "binding": { "parquet": path.to_string_lossy() },
        "owner_tenant": "acme",
        "purposes": ["analytics"],
        "columns": [
            { "name": "order_id", "type": "int" },
            { "name": "email", "type": "text", "mask": "hash_sha256" },
            { "name": "region", "type": "text" },
            { "name": "amount", "type": "float" }
        ],
        "row_filter": "region = 'EU'"
    })
    .to_string()
}

fn engine_with_dataset(dir: &tempfile::TempDir) -> GriotEngine {
    let path = dir.path().join("orders.parquet");
    let contract = write_dataset_and_contract(&path);
    GriotEngine::from_json_contracts([contract]).unwrap()
}

fn string_col(batch: &RecordBatch, name: &str) -> Vec<String> {
    let idx = batch.schema().index_of(name).unwrap();
    let arr = batch
        .column(idx)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    (0..arr.len()).map(|i| arr.value(i).to_string()).collect()
}

#[tokio::test]
async fn outsider_gets_masked_and_filtered() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with_dataset(&dir);

    let rows = engine
        .query(
            r#"SELECT order_id, email, region FROM "sales/orders/v1" ORDER BY order_id"#,
            Caller::new("user:bob", "analytics", "globex"),
        )
        .await
        .unwrap();

    let total: usize = rows.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 2, "row_filter region='EU' must keep only 2 rows");

    let emails = string_col(&rows[0], "email");
    for e in &emails {
        assert_eq!(e.len(), 64, "email must be a SHA-256 hex digest");
        assert!(!e.contains('@'), "raw email must not leak: {e}");
    }
    let regions = string_col(&rows[0], "region");
    assert!(regions.iter().all(|r| r == "EU"));
}

#[tokio::test]
async fn owner_sees_raw() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with_dataset(&dir);

    let rows = engine
        .query(
            r#"SELECT order_id, email FROM "sales/orders/v1" ORDER BY order_id"#,
            Caller::new("user:alice", "analytics", "acme"),
        )
        .await
        .unwrap();

    let total: usize = rows.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 5, "owner sees all rows");
    let emails = string_col(&rows[0], "email");
    assert!(
        emails.iter().any(|e| e.contains('@')),
        "owner sees raw email"
    );
}

/// The row-filter column (`region`) is NOT in the SELECT list — the engine must
/// still apply the filter (it scans the inner table in full, then projects).
#[tokio::test]
async fn row_filter_applies_even_when_filter_column_not_selected() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with_dataset(&dir);

    let rows = engine
        .query(
            r#"SELECT order_id FROM "sales/orders/v1""#,
            Caller::new("user:bob", "analytics", "globex"),
        )
        .await
        .unwrap();

    let total: usize = rows.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 2, "EU-only filter applies regardless of projection");
    // Output schema is exactly the projection.
    assert_eq!(rows[0].num_columns(), 1);
    assert_eq!(rows[0].schema().field(0).name(), "order_id");
}

#[tokio::test]
async fn disallowed_purpose_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with_dataset(&dir);

    let err = engine
        .query(
            r#"SELECT * FROM "sales/orders/v1""#,
            Caller::new("user:bob", "marketing", "globex"),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("denied"), "got: {err}");
}

#[tokio::test]
async fn unknown_dataset_errors_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with_dataset(&dir);

    let err = engine
        .query(
            r#"SELECT * FROM "no/such/dataset""#,
            Caller::new("user:bob", "analytics", "globex"),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no/such/dataset"), "got: {err}");
}
