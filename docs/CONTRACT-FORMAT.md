# The GriotQL JSON contract format

A contract is the governance surface for one dataset: what it is, who may read
it, and how it is masked/filtered for non-owners. The open-source engine
(`JsonContractSource`) reads the format below. One JSON document = one dataset.

## Full example

```json
{
  "contract_id": "sales_orders_v1",
  "version": "1",
  "dataset": "sales/orders/v1",
  "binding": { "parquet": "/data/orders.parquet" },
  "owner_tenant": "acme",
  "purposes": ["analytics", "marketplace-listing"],
  "columns": [
    { "name": "order_id", "type": "int" },
    { "name": "email",    "type": "text",  "sensitivity": "pii", "mask": "hash_sha256" },
    { "name": "region",   "type": "text" },
    { "name": "amount",   "type": "float" }
  ],
  "row_filter": "region = 'EU'",
  "dp_columns": {
    "amount": { "sensitivity": 1.0, "epsilon": 0.1 }
  }
}
```

## Fields

| Field | Required | Meaning |
|---|---|---|
| `contract_id` | yes | Stable contract identifier (flows into attestation). |
| `version` | yes | Contract version string. |
| `dataset` | yes | The name queries target: `SELECT * FROM "<dataset>"`. Must be unique across loaded contracts. |
| `binding.parquet` | yes | Path to the local Parquet file holding the rows. |
| `owner_tenant` | yes | The tenant that sees raw data. Callers with `Caller.tenant == owner_tenant` bypass masking/filtering. |
| `purposes` | no | Allowed query purposes. If non-empty, a `Caller.purpose` not listed is **denied**. Empty/absent = any purpose. |
| `columns` | no | Column declarations; a column may carry a `mask`. |
| `columns[].name` | yes | Column name. |
| `columns[].type` | no | Informational (`int`/`text`/`float`/…); the actual types come from the Parquet file. |
| `columns[].sensitivity` | no | Informational label (e.g. `pii`). |
| `columns[].mask` | no | Mask action applied for non-owners (see below). |
| `row_filter` | no | A SQL boolean predicate; non-owners only see rows satisfying it. |
| `dp_columns` | no | Map of column → `{ sensitivity, epsilon }` for differential-privacy noise. |

## Mask actions (`columns[].mask`)

| Value | Effect on non-owner reads |
|---|---|
| `redact` | every value → `<REDACTED>` |
| `hash_sha256` | every value → its SHA-256 hex digest |
| `tokenize` | deterministic token (SHA-256) |
| `partial` | keep the last 4 characters, mask the rest |
| `null` | typed NULL |
| `noop` | unchanged (same as omitting `mask`) |

Unknown values are a hard error at load time.

## Semantics

- **Owner vs. non-owner.** `owner_tenant` callers get raw data. Everyone else
  gets `mask`-ed columns + `row_filter` + `dp_columns`.
- **Purpose gate.** Evaluated before anything else; a disallowed purpose denies
  the whole query.
- **Row filter** is a SQL expression over the dataset's columns. It is applied
  even when the referenced column is not in the `SELECT` list.
- **DP** adds Laplace noise to the named columns (sensitivity/ε); it is an
  engine capability and has no T03-platform equivalent.

## Relationship to Griot Cloud (T03) contracts

This JSON is an engine-native, open-source format. On the platform, the same
engine instead consumes T03's compiled, signed bundle
(`--features platform`), which expresses the equivalent policy as Rego + SQL
templates. Both are mapped to the same internal `ResolvedPolicy`; see
[ARCHITECTURE.md](ARCHITECTURE.md).
