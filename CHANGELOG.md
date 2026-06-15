# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — contract resolution spine + platform adapter

Turned the engine from "mask a hand-fed batch" into "query a contract": you now
name a contract-bound dataset in SQL and get governed rows.

- **Contract resolution spine.** `SELECT … FROM "<dataset-uri>"` resolves the
  governing contract for the caller and the physical data location, then applies
  the contract's masking, row filtering and DP noise inside the query plan.
  New modules: `policy` (`ResolvedPolicy` — the engine-agnostic enforcement
  primitive), `contract_source` (`ContractSource` + `JsonContractSource`),
  `binding` (`BindingResolver` + local Parquet loader), `contract_table_provider`
  (`ContractTableProvider`), `catalog` (lazy DataFusion `SchemaProvider`/
  `CatalogProvider`), and `engine` (`GriotEngine`).
- **Open-source path.** A simple JSON contract format + local Parquet — no
  services, no `protoc`. See `docs/CONTRACT-FORMAT.md`.
- **Platform adapter** (`--features platform`). `PlatformBundleSource` fetches a
  Griot Cloud T03 signed bundle over HTTP, verifies its ECDSA-P256 signature
  (canonical hashing mirrored from T03's `bundle-signer`), and maps it to the
  same `ResolvedPolicy`. Exercised offline against the real committed bundle
  fixture.
- New examples: `contract_query` (standalone) and `platform_bundle` (platform).
- Docs: `docs/USAGE.md`, `docs/CONTRACT-FORMAT.md`, `docs/ARCHITECTURE.md`.
- The pre-existing enforcement operators are reused unchanged.

## [0.1.0] — initial snapshot

Initial standalone snapshot of the GriotQL query engine, **copied** out of the
Griot Cloud platform monorepo.

- **Source:** `griot-cloud` @ commit `5b999ed0010aeb86ae703076798f035b9c0c9121`
  (path `zone-k/k04-workers/k04d-query-rs/`).
- Trimmed the cloud-only deployment glue (HTTP service wrapper, GCS/pgvector/
  Redis clients, container/build manifests) and the legacy gRPC server so the
  crate builds and runs standalone with only Rust + cargo.
- Pruned the now-unused dependencies; the default build needs no `protoc` and no
  system libraries.
- Kept the engine intact: the DataFusion optimizer rules and physical operators
  (contract check, row filter, column masking, differential-privacy noise,
  attestation), the sealed engine core, and the DDL guard.
- Added four runnable examples (`plain_sql`, `column_masking`, `row_filter`,
  `dp_noise`) that demonstrate governed output with zero external services.
- `lance` columnar support retained as an optional feature (off by default;
  requires `protoc`).

The engine's behaviour is unchanged from the source commit; this release is a
packaging + documentation pass, not a redesign.
