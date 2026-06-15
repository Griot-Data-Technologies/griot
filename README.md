# GriotQL

**A contract-resolving, privacy-enforcing SQL engine — point SQL at a *contract*, get *governed* rows.**

GriotQL is [Apache DataFusion](https://datafusion.apache.org/) 47 + [Arrow](https://arrow.apache.org/) 55 with data-contract enforcement compiled into the query plan. You don't hand it tables and trust the caller to behave — you name a **contract-bound dataset** in SQL, and the engine resolves the governing contract for the caller, locates the data, and applies the contract's masking, row filtering and differential-privacy noise **inside the plan** before any row is returned.

```sql
SELECT email, region FROM "sales/orders/v1"
```

Run by the data's owner, that returns raw rows. Run by an outside tenant, the same query returns `email` SHA-256-hashed and only the rows the contract permits — enforced by the engine, not the application.

GriotQL works two ways from the same core:

- **Open-source / standalone** — contracts are simple JSON; data is local Parquet. No services, no network, no `protoc`.
- **Platform** (`--features platform`) — contracts are Griot Cloud's signed T03 bundles (ECDSA-P256), consumed and verified, mapping to the exact same enforcement.

---

## Quickstart (60 seconds)

Only Rust (stable, ≥ 1.88) is required.

```bash
git clone <this-repo> griotql && cd griotql
cargo run --example contract_query
```

```text
== Caller: globex (outside tenant, purpose=analytics) ==
+----------+------------------------------------------------------------------+--------+--------+
| order_id | email                                                            | region | amount |
+----------+------------------------------------------------------------------+--------+--------+
| 1        | 0a0a58273565a8f3dcf779375d9debd0f685d94dc56651a16bff3bf901c0b127 | EU     | 100.0  |
| 3        | e42c3ecc57efa1b09b019571c3b847ec504ca0357882611869b5a1d53ac36f26 | EU     | 75.0   |
+----------+------------------------------------------------------------------+--------+--------+
== Caller: acme (owner, purpose=analytics) ==
+----------+-----------------+--------+--------+
| order_id | email           | region | amount |
| 1        | alice@acme.com  | EU     | 100.0  |
| 2        | bob@globex.com  | US     | 250.0  |
| ...      | ...             | ...    | ...    |
```

The 30-line program behind that output is in [`examples/contract_query.rs`](examples/contract_query.rs); see **[docs/USAGE.md](docs/USAGE.md)**.

---

## How it works

```
SELECT … FROM "sales/orders/v1"
        │
        ▼
ContractSource ──► ResolvedPolicy ──┐   (mask email, drop non-EU rows, …)
                                    │
BindingResolver ──► raw table ──────┤
                                    ▼
            ContractTableProvider.scan()
                                    │
   ContractApprovedExec → RowFilterExec → MaskingExec → (LaplaceNoiseExec)
                                    ▼
                           governed RecordBatches
```

- **`ContractSource`** turns *(contract, caller)* into a `ResolvedPolicy` — what to mask, which rows to drop, deny reasons. Implementations: `JsonContractSource` (open-source) and `PlatformBundleSource` (T03).
- **`BindingResolver`** locates the bytes (local Parquet today; T02 storage on the platform).
- **`ContractTableProvider`** is a DataFusion table whose every `scan()` is wrapped in the enforcement operators — there is no scan path that skips them.

The enforcement decision (`ResolvedPolicy`) is engine-agnostic; the contract *source* is pluggable. The same engine, the same operators, two front doors. See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## Build & test

```bash
cargo build --release                              # standalone: only Rust + cargo
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

cargo build --features platform                    # + T03 signed-bundle adapter
cargo test  --features platform
```

A clean checkout builds and tests with **only Rust + cargo** — no `protoc`, no database, no network.

### Feature flags

| Feature | Default | Adds |
|---|---|---|
| `platform` | off | Fetch + verify (ECDSA P-256) Griot Cloud T03 signed contract bundles; pulls in `reqwest` + `p256`. |
| `lance` | off | Register [Lance](https://lancedb.github.io/lance/) columnar datasets. Needs `protoc` at build time. |

> `cargo build --all-features` will fail without `protoc` (that's the `lance` build). Use the default set, or `--features platform`.

---

## Examples

| Example | Command | Shows |
|---|---|---|
| **Contract query** | `cargo run --example contract_query` | The headline: `SELECT … FROM "<dataset>"` resolves a JSON contract + local Parquet → governed rows; owner vs. outsider; purpose-gate deny. |
| **Platform bundle** | `cargo run --example platform_bundle --features platform` | Governance driven by a **real T03 signed bundle** (`fixtures/…gdcpc.signed`) — same engine, no live services. |
| Plain SQL | `cargo run --example plain_sql` | It's a real DataFusion engine; INV-1 gate + DDL guard. |
| Column masking | `cargo run --example column_masking` | The masking operator in isolation. |
| Row filter | `cargo run --example row_filter` | The row-filter operator in isolation. |
| DP noise | `cargo run --example dp_noise` | Laplace noise on an aggregate. |

---

## Public API (open-source path)

```rust
use griot::engine::GriotEngine;
use griot::contract_source::Caller;

// Contracts are JSON (see docs/CONTRACT-FORMAT.md); data is local Parquet.
let engine = GriotEngine::from_json_contracts_dir("./contracts")?;

let rows = engine
    .query(
        r#"SELECT email, region FROM "sales/orders/v1""#,
        Caller::new("user:bob", "analytics", "globex"),
    )
    .await?; // Vec<RecordBatch>, governed
```

For the platform path, swap the source:

```rust
use griot::platform::PlatformBundleSource;
use griot::engine::GriotEngine;

let source = PlatformBundleSource::new("https://t03.internal")
    .with_verifying_key(t03_pubkey)        // verify the ECDSA-P256 signature
    .with_auth("Authorization", bearer);
let engine = GriotEngine::new(Arc::new(source), binding /* T02-backed */);
```

The lower-level building blocks — `ResolvedPolicy`, the `ContractSource` / `BindingResolver` traits, `ContractTableProvider`, and the physical operators — are all public for embedding.

---

## Current limitations (honest notes)

- **Column visibility / hiding** is not yet enforced (masking protects sensitive columns; full column-hiding is a follow-up). Masking, row filtering and DP are fully wired.
- **Local binding loads the whole Parquet file into memory** (`MemTable`) — ideal for dev/demo; large-file streaming via `ListingTable` is a follow-up.
- **Platform mapping is heuristic.** T03's bundle expresses policy as Rego + SQL templates, not a structured mask list, so `PlatformBundleSource` *parses* the non-owner SQL template (e.g. `sha256_hex(email)`) and the Rego purpose gate. It's faithful for the bundles T03 emits today; a structured-policy field in the bundle (or a shared types crate) would make it exact. The canonical signature-hash logic mirrors T03's `bundle-signer` and must stay in sync.
- **Differential privacy is an engine capability** beyond the T03 contract model, so it is available via JSON contracts but never populated from a platform bundle.
- **Attestation** (`AttestationExec`) exists but is not yet auto-attached to results; signed result envelopes are a follow-up.

These are packaging/sequencing boundaries, not gaps in the enforcement logic.

## Provenance

GriotQL was developed inside the Griot Cloud platform and copied into this standalone repository; the contract-resolution spine and the platform adapter were then added here. The upstream engine + contract authority live in the Griot Cloud monorepo. The exact source commit is in [`CHANGELOG.md`](CHANGELOG.md).

## License

**To be determined** (intended for open-source release). All dependencies are MIT / Apache-2.0.
