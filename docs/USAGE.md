# Using GriotQL

This walks through running governed queries end to end — first standalone (JSON
contracts + local Parquet), then against a Griot Cloud T03 signed bundle.

## Install

GriotQL is a Rust library crate. Add it to a project (path/git for now; crates.io
later):

```toml
[dependencies]
griot = { path = "../griotql" }            # or git = "…"
# optional platform adapter:
# griot = { path = "../griotql", features = ["platform"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Requirements: Rust stable ≥ 1.88. Nothing else for the default build (no
`protoc`, no database).

## 1. Standalone: a contract + a Parquet file

Write a contract (`contracts/orders.json`) — see
[CONTRACT-FORMAT.md](CONTRACT-FORMAT.md):

```json
{
  "contract_id": "sales_orders_v1",
  "version": "1",
  "dataset": "sales/orders/v1",
  "binding": { "parquet": "/data/orders.parquet" },
  "owner_tenant": "acme",
  "purposes": ["analytics"],
  "columns": [
    { "name": "order_id", "type": "int" },
    { "name": "email", "type": "text", "sensitivity": "pii", "mask": "hash_sha256" },
    { "name": "region", "type": "text" }
  ],
  "row_filter": "region = 'EU'"
}
```

Query it:

```rust
use std::sync::Arc;
use griot::engine::GriotEngine;
use griot::contract_source::Caller;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = GriotEngine::from_json_contracts_dir("./contracts")?;

    // Datasets are referenced by their (quoted) URI — note the double quotes.
    let sql = r#"SELECT order_id, email, region FROM "sales/orders/v1""#;

    // Outsider: email hashed, EU-only rows.
    let governed = engine
        .query(sql, Caller::new("user:bob", "analytics", "globex"))
        .await?;

    // Owner: raw.
    let raw = engine
        .query(sql, Caller::new("user:alice", "analytics", "acme"))
        .await?;
    Ok(())
}
```

Key points:

- **Quote the dataset name.** `FROM "sales/orders/v1"` — the slashes/colons make
  it a quoted identifier, which DataFusion passes through verbatim to the
  resolver. Unquoted names are lowercased and split on `.`.
- **The `Caller` drives visibility.** The owning tenant (matching
  `owner_tenant`) sees raw data; everyone else gets the contract's masks +
  `row_filter`. A `purpose` not in the contract's `purposes` is denied with a
  clear error.
- **The row-filter column need not be selected.** `SELECT order_id` still
  applies `region = 'EU'` — the engine scans the table in full, enforces, then
  projects to your column list.

Run the worked example: `cargo run --example contract_query`.

## 2. Platform: a Griot Cloud T03 signed bundle

With `--features platform`, swap `JsonContractSource` for `PlatformBundleSource`,
which fetches the signed bundle from T03, optionally verifies its ECDSA-P256
signature, and maps it to the same policy:

```rust
use std::sync::Arc;
use griot::engine::GriotEngine;
use griot::platform::PlatformBundleSource;

let source = PlatformBundleSource::new("https://t03.internal")
    .with_verifying_key(t03_public_key)        // optional but recommended
    .with_auth("Authorization", "Bearer …");

// `binding` is your T02-backed BindingResolver (e.g. the `lance` table provider).
let engine = GriotEngine::new(Arc::new(source), binding);
```

To see the mapping without any live service, the
`cargo run --example platform_bundle --features platform` example loads the real
committed bundle `fixtures/demo_dataset_users_v1.gdcpc.signed` and governs a query
from it.

## Mask actions

`mask` (JSON) / the masking operator understand:

| Token | Effect |
|---|---|
| `redact` | value → `<REDACTED>` |
| `hash_sha256` | value → SHA-256 hex digest |
| `tokenize` | deterministic token (SHA-256) |
| `partial` | keep last 4 chars (`***1234`) |
| `null` | typed NULL |
| `noop` | unchanged |

Unknown tokens are a hard error — a typo can never silently disable masking.

## Differential privacy (JSON contracts)

Add `dp_columns` to a contract to noise an aggregate column:

```json
"dp_columns": { "amount": { "sensitivity": 1.0, "epsilon": 0.1 } }
```

(DP is an engine capability; T03 platform bundles do not carry DP parameters.)

## Errors you'll see

- `contract denied access to '<ds>': purpose '<p>' is not permitted …` — purpose
  gate.
- `no contract for dataset '<ds>'` / `binding failed …` — unknown dataset or
  missing/unreadable Parquet file.
- `unsafe DDL rejected: … 'COPY'` — the DDL guard blocks
  `INSTALL`/`LOAD`/`ATTACH`/`COPY`.
