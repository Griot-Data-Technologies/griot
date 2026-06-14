# GriotQL

**A privacy-and-contract-enforcing SQL engine — Apache DataFusion with governance compiled into the query plan.**

GriotQL is [Apache DataFusion](https://datafusion.apache.org/) 47 + [Arrow](https://arrow.apache.org/) 55, extended with **native contract enforcement** implemented as DataFusion optimizer rules and physical operators. Where DuckDB is "a fast embeddable OLAP engine," GriotQL is "an embeddable OLAP engine that enforces data contracts as part of the query plan."

Before results are returned, a query plan can be rewritten to inject:

| Stage | What it does |
|---|---|
| **Contract check** | The query only runs if a contract bundle authorises it. |
| **Row filter** | Rows the requester isn't entitled to are dropped. |
| **Column masking** | Masked columns are redacted, hashed, or tokenized at read time. |
| **Differential-privacy noise** | Calibrated Laplace noise is added to columns the contract tags as DP, debiting a privacy budget. |
| **Attestation** | An optional signed envelope is produced over the result. |

Because the enforcement lives **inside the engine** — as plan-time optimizer rules and physical operators — there is no data path that bypasses it. The masking, filtering and noise in the examples below are done by the engine, not by application code.

---

## Quickstart (60 seconds)

You only need Rust (stable, ≥ 1.88) — nothing else.

```bash
git clone <this-repo> griotql && cd griotql
cargo run --example column_masking
```

```text
== Raw data (no masking) ==
+----+-------+-------------------+-------------+
| id | name  | email             | ssn         |
+----+-------+-------------------+-------------+
| 1  | alice | alice@example.com | 123-45-6789 |
| 2  | bob   | bob@example.com   | 987-65-4321 |
+----+-------+-------------------+-------------+

== Governed output (contract masking applied) ==
+----+-------+-------+------------------------------------------------------------------+
| id | name  | email | ssn                                                              |
+----+-------+-------+------------------------------------------------------------------+
| 1  | alice | ***   | 01a54629efb952287e554eb23ef69c52097a75aecc0e3a93ca0855ab6d7a31a0 |
| 2  | bob   | ***   | ecdbc061a36dd6495e016ba4696dedbc4c0b822b4d6ec55b4fb57d17f1df5695 |
+----+-------+-------+------------------------------------------------------------------+
```

---

## Build & test

```bash
cargo build --release      # plain build (no protoc, no system deps)
cargo test                 # unit + integration + physical-operator + doctests
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

A clean checkout builds and tests with **only Rust + cargo installed** — no `protoc`, no database, no network.

### Feature flags

| Feature | Default | Notes |
|---|---|---|
| `lance` | **off** | Registers [Lance](https://lancedb.github.io/lance/) columnar datasets as queryable tables. Lance's build pulls `lance-encoding`, which **requires `protoc`** at build time. Keep it off for a zero-dependency build; enable with `cargo build --features lance` (and `brew install protobuf` / `apt install protobuf-compiler`). |

> Note: `cargo build --all-features` will fail without `protoc` installed — that is expected, because `--all-features` turns on `lance`. Use the default feature set unless you specifically need the columnar path.

---

## The examples

Each example runs with **zero external services** and prints input vs. governed output so the enforcement is visible.

| Example | Command | Shows |
|---|---|---|
| Plain SQL | `cargo run --example plain_sql` | It's a real DataFusion engine — register Arrow data, run `GROUP BY`/`AVG`. Also shows the INV-1 "no read without a contract" gate and the DDL guard rejecting `COPY`. |
| Column masking | `cargo run --example column_masking` | `email` → `***`, `ssn` → SHA-256 hash, enforced by the engine. |
| Row filter | `cargo run --example row_filter` | A contract `row_filter = "region = 'EU'"` drops non-EU rows. |
| DP noise | `cargo run --example dp_noise` | Laplace noise on a `salary` column (sensitivity=1.0, ε=0.1), printed raw-vs-noised, with the privacy budget debited. |

---

## Public API

### High-level engine (plain SQL path)

```rust
use griot::{K04DEngine, InitConfig, ContractBundleHandle};

let mut engine = K04DEngine::new_with_config(InitConfig {
    tenant_id: "demo-tenant".into(),
    contract_bundle_endpoint: "inmemory://contract".into(),
    attestation_endpoint: "inmemory://attest".into(),
    max_result_rows: 10_000,
    storaged_socket: "inmemory://storaged".into(),
})?;

engine.register_memory_table("t", schema, partitions).await?; // in-memory Arrow data
engine.inject_contract_bundle(ContractBundleHandle::from_x02_bytes(
    "contract-1", "demo-tenant", bytes::Bytes::from_static(b"{}"),
));
let batches = engine.query("SELECT * FROM t").await?;          // Vec<RecordBatch>
```

`engine.query()` enforces two guarantees on its own: it refuses to run before a contract bundle is injected (`EngineError::NoContractBundle`), and it rejects unsafe DDL verbs — `INSTALL`/`LOAD`/`ATTACH`/`COPY` (`EngineError::UnsafeDdlRejected`).

### Enforcement operators (governed output path)

Masking, row filtering and DP noise are DataFusion **physical operators**. They compose above a `ContractApprovedExec`, which is the proof the query passed the contract check — the enforcement operators refuse to run without it upstream:

```rust
use griot::physical::contract_approved_exec::ContractApprovedExec;
use griot::physical::masking_exec::MaskingExec;

let approved = Arc::new(ContractApprovedExec::new(bundle.clone(), inner_physical_plan)?);
let masked   = Arc::new(MaskingExec::new(bundle, approved)?);
let batches  = datafusion::physical_plan::collect(masked, ctx.task_ctx()).await?;
```

The four logical-plan optimizer rules and the canonical ordered pipeline
(`ContractCheckRule → RowFilterRule → MaskingRule → DPNoiseRule`) are also
public under `griot::optimizer_rules` (see `build_permissive_pipeline` /
`build_enforced_pipeline`).

### Contract bundles

A contract bundle is opaque signed bytes (`ContractBundleHandle::from_x02_bytes`). In these standalone examples the bundle is a small JSON document the enforcement operators read directly, e.g.:

```json
{ "column_masking": { "email": "redact", "ssn": "hash_sha256" } }
{ "row_filter": "region = 'EU'" }
{ "dp_columns": { "salary": { "sensitivity": 1.0, "epsilon": 0.1 } } }
```

---

## Current limitations (this is a snapshot)

This repository is a **standalone snapshot** of the engine, trimmed so it builds and runs on its own. A few things are deliberately different from the full platform:

- **Enforcement operators are applied explicitly** (as the examples do), rather than being auto-wired into `engine.query()`. In the platform, the four-rule pipeline is registered on the session and attestations are signed by a live notary; here those integration seams are out of scope.
- **No live T04/T05 services.** The byte-read socket client (`storaged_client`) and the attestation client (`t05_client`) are included for completeness but the examples never contact them — they construct the engine entirely in memory.
- **Attestation signatures are placeholders.** `AttestationExec` produces a deterministic envelope, not a real ES256/Sigstore signature.
- **`lance` is feature-gated off** because it needs `protoc`.

These are packaging boundaries, not bugs: the masking, filtering, and DP-noise logic is the real engine code, unchanged.

---

## Provenance

GriotQL was developed inside the Griot Cloud data platform and **copied** out into this standalone repository. The upstream engine lives in the Griot Cloud monorepo; this repo is a snapshot for building, running, and (eventually) open-sourcing the engine on its own. The exact source commit is recorded in [`CHANGELOG.md`](CHANGELOG.md).

## License

**To be determined.** All dependencies are MIT / Apache-2.0 (no copyleft, no private registries, no git pins), so a permissive license is intended for the eventual open-source release. A `LICENSE` file will be added before publication.
