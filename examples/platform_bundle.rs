//! Example 6 — drive governance from a real Griot Cloud (T03) signed bundle.
//!
//! This proves the *platform* path: instead of a JSON contract, the policy comes
//! from `fixtures/demo_dataset_users_v1.gdcpc.signed` — the actual compiled,
//! signed bundle T03 produces. We map it to a `ResolvedPolicy` and govern a
//! query with the very same engine operators the open-source path uses. No live
//! T03/T04/T02 services are needed.
//!
//! Run with:
//!   cargo run --example platform_bundle --features platform

use std::sync::Arc;

use datafusion::arrow::array::{Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;

use griot::contract_source::Caller;
use griot::contract_table_provider::ContractTableProvider;
use griot::platform::{map_bundle_to_policy, SignedBundleFile};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Load the REAL T03 signed bundle ───────────────────────────────────
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/demo_dataset_users_v1.gdcpc.signed"
    );
    let file = SignedBundleFile::from_json(&std::fs::read(path)?)?;
    println!(
        "loaded T03 bundle: contract={} owner={} ({} sql templates, {} rego policies)\n",
        file.bundle.manifest.contract_id,
        file.owner_tenant().unwrap_or("?"),
        file.bundle.sql_templates.len(),
        file.bundle.rego_bundles.len(),
    );

    // ── The demo dataset (would come from T02 in production) ──────────────
    let schema = Arc::new(Schema::new(vec![
        Field::new("user_id", DataType::Int64, false),
        Field::new("email", DataType::Utf8, false),
        Field::new("country", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec![
                "alice@demo.com",
                "bob@demo.com",
                "carol@demo.com",
            ])),
            Arc::new(StringArray::from(vec!["KE", "US", "GB"])),
        ],
    )?;
    let raw: Arc<dyn datafusion::datasource::TableProvider> =
        Arc::new(MemTable::try_new(schema, vec![vec![batch]])?);

    // ── Map the bundle for an outside tenant, then govern a query ─────────
    let caller = Caller::new("svc:partner", "analytics", "globex");
    let policy = map_bundle_to_policy(&file, &caller);
    println!(
        "mapped policy for caller tenant '{}': masks={:?}\n",
        caller.tenant, policy.column_masks
    );

    let ctx = SessionContext::new();
    ctx.register_table(
        "demo_dataset_users",
        Arc::new(ContractTableProvider::new(raw, &policy)),
    )?;

    let rows = ctx
        .sql("SELECT user_id, email, country FROM demo_dataset_users ORDER BY user_id")
        .await?
        .collect()
        .await?;

    println!("== Governed output (T03 contract bundle enforced) ==");
    println!("{}", pretty_format_batches(&rows)?);
    println!(
        "\nemail is SHA-256 hashed for the outside tenant, per the bundle's non-owner template."
    );

    Ok(())
}
