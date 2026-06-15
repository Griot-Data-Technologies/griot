# GriotQL architecture

GriotQL turns "name a dataset in SQL" into "execute the governing contract". This
document explains the moving parts and the seam that lets one engine serve both
the open-source and the platform worlds.

## The one idea

Governance does not live in the engine — it lives in the **contract**. The engine
only *executes* a decision the contract already made. That decision is captured
by one engine-agnostic type, **`ResolvedPolicy`** (`src/policy.rs`):

```
ResolvedPolicy {
  contract_id, contract_version, tenant_id,
  decision:      Allow | Deny { reason },
  column_masks:  { column -> redact|hash_sha256|tokenize|partial|null|noop },
  row_filter:    Option<SQL predicate>,
  dp_columns:    { column -> { sensitivity, epsilon } },
}
```

Whoever resolves a contract for a caller produces a `ResolvedPolicy`; the engine
turns it into governed execution. Because the policy is engine-agnostic, the
*source* of contracts is pluggable.

## The two seams

```
            ┌─────────────────────────┐
  caller ─► │  ContractSource         │ ─► ResolvedPolicy
            │  (JSON | T03 bundle)    │
            └─────────────────────────┘
            ┌─────────────────────────┐
 dataset ─► │  BindingResolver        │ ─► Arc<dyn TableProvider>  (raw data)
            │  (local Parquet | T02)  │
            └─────────────────────────┘
```

| Trait | Open-source impl | Platform impl |
|---|---|---|
| `ContractSource` | `JsonContractSource` (reads JSON contracts) | `PlatformBundleSource` (fetch + verify T03 signed bundle) |
| `BindingResolver` | `JsonContractSource` (local Parquet → `MemTable`) | T02-backed (e.g. the `lance` table provider) |

## The execution spine

When a query names a dataset, DataFusion asks our catalog to resolve it:

```
SELECT … FROM "sales/orders/v1"
  │
  ▼  GriotSchemaProvider::table("sales/orders/v1")        (src/catalog.rs)
  │     1. ContractSource.resolve(dataset, caller) → ResolvedPolicy
  │     2. if Deny → error;  else
  │     3. BindingResolver.resolve(dataset)        → raw TableProvider
  │     4. ContractTableProvider::new(raw, policy)
  ▼
ContractTableProvider::scan()                            (src/contract_table_provider.rs)
  │  raw.scan(full, no projection)                        ← operators need all columns
  │  → ContractApprovedExec   (proof the scan was contract-checked)
  │  → RowFilterExec          (drop rows the contract forbids)
  │  → MaskingExec            (mask sensitive columns)
  │  → LaplaceNoiseExec       (DP noise, if any)
  │  → ProjectionExec/LimitExec (honor the query's SELECT/LIMIT)
  ▼
governed RecordBatches
```

`GriotEngine::query(sql, caller)` (`src/engine.rs`) ties it together: it builds a
fresh DataFusion session whose **default catalog** is a caller-bound
`GriotCatalogProvider`, so the caller's identity flows into resolution with no
global state. Naming a dataset is the *only* way to get a table, and every such
table is a `ContractTableProvider` — so there is no un-governed scan path.

### Why scan-in-full-then-project

The contract's row filter may reference a column the query didn't select (e.g.
filter on `region` while `SELECT order_id`). So the inner table is scanned in
full, the operators enforce on all columns, and the caller's projection/limit are
applied on top — keeping enforcement correct and the output schema right.

## Reused enforcement operators

The `ResolvedPolicy` is serialised (`to_bundle_bytes`) into the exact JSON the
pre-existing physical operators (`src/physical/*`) already parse —
`column_masking`, `row_filter`, `dp_columns`, `contract_id`,
`contract_version` — so the spine reuses them unchanged. The operators are
sealed (no public constructor bypasses the contract bundle) and each refuses to
run without a `ContractApprovedExec` upstream.

## The platform adapter (`src/platform/`, feature `platform`)

T03 compiles a contract into a **signed `CompiledBundle`**: WASM carriers + Rego
policies + SQL templates + a resolution map, ECDSA-P256-signed. `PlatformBundleSource`:

1. **Fetches** the `.gdcpc.signed` JSON from T03 over HTTP.
2. **Verifies** the signature — `src/platform/bundle.rs` reproduces T03's
   `canonical_digest` / `canonical_signing_payload` byte-for-byte and checks the
   DER ECDSA-P256 signature with `p256`. (Kept in sync with T03's `bundle-signer`;
   a shared crate would remove the duplication.)
3. **Maps** the bundle → `ResolvedPolicy`. Because T03 expresses masking as SQL
   templates (`sha256_hex(email) AS email`) and purpose gates as Rego, the mapping
   *parses* the non-owner read template for masks + row filter and the purpose-gate
   Rego for allowed purposes. Heuristic but faithful to the bundles T03 emits;
   DP is never present (absent from the T03 model).

The mapped policy then flows through the identical spine. A real committed bundle
is exercised offline in `tests/platform_bundle.rs` and
`examples/platform_bundle.rs`.

## Module map

| Path | Role |
|---|---|
| `src/policy.rs` | `ResolvedPolicy`, `MaskAction`, `Decision` — the engine-agnostic primitive |
| `src/contract_source.rs` | `ContractSource`, `Caller`, `JsonContractSource` |
| `src/binding.rs` | `BindingResolver`, `DatasetRef`, local-Parquet loader |
| `src/contract_table_provider.rs` | the governed `TableProvider` (operator stack) |
| `src/catalog.rs` | `GriotSchemaProvider` / `GriotCatalogProvider` (lazy URI resolution) |
| `src/engine.rs` | `GriotEngine` high-level API |
| `src/physical/*` | the enforcement operators (reused unchanged) |
| `src/platform/*` | T03 signed-bundle adapter (feature `platform`) |

## Deliberate non-goals (today)

- Column **hiding** (masking is wired; dropping columns from the visible schema is
  a follow-up).
- Streaming large files (local binding uses an in-memory `MemTable`).
- Auto-attaching signed **attestation** envelopes to results.
- Wiring this engine into the Griot Cloud deployment (replacing the in-cluster
  K04D) — a separate effort.
