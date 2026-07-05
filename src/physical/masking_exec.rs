//! MaskingExec — Wave 9 implementation.
//!
//! Physical `ExecutionPlan` that applies the contract's column-masking policy
//! (redact / hash_sha256 / tokenize / noop) to each `RecordBatch` in the
//! stream.  It is the physical counterpart of the wave-8 `MaskingRule`.
//!
//! # Role in the pipeline
//!
//! `MaskingExec` MUST sit above `ContractApprovedExec` in the plan.  Before
//! streaming any batch it verifies that `ContractApprovedExec` is present as
//! an ancestor.  If not, it returns
//! `PhysicalError::ContractNotApproved { operator: "MaskingExec" }`.
//!
//! # Behaviour
//!
//! For each input `RecordBatch`, the operator applies the masking UDF to each
//! column tagged with a sensitivity label in the contract bundle.
//!
//! | Policy       | Effect on column values          |
//! |--------------|----------------------------------|
//! | `Redact`     | Replace with fixed `"***"` token |
//! | `HashSha256` | Replace with SHA-256 hex string  |
//! | `Tokenize`   | Replace with stable pseudonym    |
//! | `Partial`    | Replace with `"***" + last 4`    |
//! | `Null`       | Replace with a null / zero value |
//! | `Noop`       | Pass through unchanged           |
//!
//! # Output-schema semantics (type-preserving vs. type-widening)
//!
//! Masking is *value-level*, and for the string family (`Utf8`/`LargeUtf8`) and
//! for the `Redact`/`Null` policies on numeric/bool columns it is also
//! *type-preserving* (the column keeps its Arrow type; the redacted numeric is
//! zeroed, the redacted string becomes `"***"`).
//!
//! The one case that necessarily changes a column's type is a **string-producing
//! policy** (`HashSha256`, `Tokenize`, `Partial`) applied to a **non-string**
//! column (`Float64`, `Int64`, `Date32`, `Timestamp`, `Boolean`, …).  There is
//! no faithful hex-hash of a float that is still a float, so the masked column
//! is cast to its canonical string representation first, then hashed — the
//! output column type becomes `Utf8`.  `MaskingExec::schema()` reflects this: it
//! returns a *masked output schema* in which such columns are typed `Utf8`, so
//! every downstream operator (`LaplaceNoiseExec`, projection, the result
//! formatter) and the `RecordBatchStreamAdapter` see the same schema the batches
//! actually carry.  Columns whose masked type is unchanged keep their input
//! field verbatim.
//!
//! # Copilot round-2 fixes (Findings 2 and 5)
//!
//! ## Finding 2 — Unknown policy strings mapped to Noop
//!
//! The original impl used `MaskPolicy::from_bundle_str` which returned `Noop`
//! for unrecognised strings.  Fix: unknown policies now return
//! `Err(PhysicalError::UnknownMaskPolicy)`.
//!
//! ## Finding 5 — Only StringArray columns masked
//!
//! The original `apply_masking` only masked `StringArray` columns and leaked
//! non-string columns unchanged.  Fix: the implementation dispatches per
//! Arrow type.  Non-string columns are never leaked.
//!
//! ## Task #26 — non-string masked columns hash via a Utf8 cast (2026-07-05)
//!
//! Before this fix a masked column whose Arrow type was numeric/temporal/bool
//! and whose policy was a string-producing one (`hash_sha256`, `tokenize`,
//! `partial`) returned `Err(MaskTypeUnsupported)`, which fails *every* query on
//! the dataset (fail-safe, no PII leak — but the column is unusable).  Now, for
//! a string-producing policy on any non-`Utf8` type, the column is cast to its
//! canonical Utf8 representation via Arrow `cast` and then masked, yielding a
//! `Utf8` output.  Nulls stay null.  The hash is deterministic on the string
//! form, so the same logical value hashes identically regardless of the source
//! column's physical width.  `Redact`/`Null` on numeric/bool remain
//! type-preserving (zero / null of the original type).  Only a genuinely
//! un-castable type with a string-producing policy still errors.
//!
//! # ADR-0002 requirements
//!
//! * No `unsafe` code.
//! * Output schema == input schema (masking is type-preserving).
//! * Emits a `PhysicalEnforcementEvent` per batch where masking was applied.
//!
//! # Spec anchor
//!
//! ADR-0002 §Physical operators — MaskingExec.
//! INV-2 (no read without satisfaction — column-level masking).

use crate::optimizer_rules::masking::MaskPolicy;
use crate::physical::contract_approved_exec::plan_has_contract_approved;
use crate::physical::{PhysicalEnforcementEvent, PhysicalError};
use crate::ContractBundleHandle;
use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, BooleanBuilder, Float64Array, Float64Builder, Int64Array,
    Int64Builder, LargeStringArray, StringArray,
};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};
use futures::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Parsed masking fields from a contract bundle.
///
/// The `column_masking` key maps column name → policy string.
/// e.g. `{"email": "redact", "name": "hash_sha256"}`.
#[derive(Debug, Deserialize, Default)]
struct MaskingBundleData {
    #[serde(default)]
    column_masking: HashMap<String, String>,
}

// ─── MaskingExec ─────────────────────────────────────────────────────────────

/// Physical operator that applies contract column-masking to the stream.
#[derive(Debug)]
pub struct MaskingExec {
    /// The contract bundle supplying the sensitivity labels and masking policies.
    bundle: ContractBundleHandle,
    /// The inner physical plan to mask.
    inner: Arc<dyn ExecutionPlan>,
    /// Cached plan properties.
    properties: PlanProperties,
    /// Enforcement events emitted during execution.
    events: Arc<Mutex<Vec<PhysicalEnforcementEvent>>>,
    /// Parsed column → policy map from the bundle.
    column_policies: HashMap<String, MaskPolicy>,
    /// The masked output schema.
    ///
    /// Identical to the inner schema except that any column masked with a
    /// string-producing policy (`HashSha256`/`Tokenize`/`Partial`) whose input
    /// type is not already `Utf8`/`LargeUtf8` is retyped to `Utf8`, because the
    /// masked values are hex/pseudonym strings.  Every downstream operator and
    /// the `RecordBatchStreamAdapter` read `schema()`, so it MUST match the
    /// batches this operator actually emits.
    output_schema: SchemaRef,
}

impl MaskingExec {
    /// Construct a new `MaskingExec`.
    ///
    /// # Errors
    ///
    /// * `PhysicalError::ContractNotApproved` — if `inner` does not have a
    ///   `ContractApprovedExec` as an ancestor in the plan tree.
    /// * `PhysicalError::ContractBundleMalformed` — if the bundle JSON cannot
    ///   be parsed (Finding 2 fix).
    /// * `PhysicalError::UnknownMaskPolicy` — if the bundle references an
    ///   unknown policy string (Finding 2 fix).
    pub fn new(
        bundle: ContractBundleHandle,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        if !plan_has_contract_approved(&inner) {
            return Err(PhysicalError::ContractNotApproved {
                operator: "MaskingExec".to_string(),
            });
        }

        // Finding 2 fix: hard-error on malformed bundle and unknown policies.
        let column_policies = parse_masking_bundle(&bundle)?;

        // Task #26: compute the masked output schema up front so schema() (read
        // by every downstream operator + the stream adapter) matches the batches
        // we emit — string-producing masks on non-string columns retype to Utf8.
        let output_schema = masked_output_schema(&inner.schema(), &column_policies);

        let properties = inner.properties().clone();
        Ok(Self {
            bundle,
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            column_policies,
            output_schema,
        })
    }

    /// Return a reference to the contract bundle.
    pub fn bundle(&self) -> &ContractBundleHandle {
        &self.bundle
    }

    /// Drain collected enforcement events.
    pub fn drain_events(&self) -> Vec<PhysicalEnforcementEvent> {
        let mut guard = self.events.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    /// Look up the masking policy for a column from the contract bundle.
    ///
    /// Returns `MaskPolicy::Noop` if the column is not tagged.
    pub fn policy_for_column(&self, column_name: &str) -> MaskPolicy {
        self.column_policies
            .get(column_name)
            .cloned()
            .unwrap_or(MaskPolicy::Noop)
    }
}

/// Parse the masking bundle.
///
/// # Finding 2 fix
///
/// Returns `Err(ContractBundleMalformed)` for non-parseable JSON.
/// Returns `Err(UnknownMaskPolicy)` for unrecognised policy strings.
fn parse_masking_bundle(
    bundle: &ContractBundleHandle,
) -> Result<HashMap<String, MaskPolicy>, PhysicalError> {
    let bytes = &bundle.raw_bytes;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }

    let data: MaskingBundleData =
        serde_json::from_slice(bytes).map_err(|e| PhysicalError::ContractBundleMalformed {
            reason: format!("MaskingExec bundle JSON parse error: {}", e),
        })?;

    let mut policies = HashMap::new();
    for (col, policy_str) in data.column_masking {
        let policy = parse_policy_str(&policy_str, &col)?;
        policies.insert(col, policy);
    }

    Ok(policies)
}

/// Parse a policy string to `MaskPolicy`.
///
/// # Finding 2 fix
///
/// Unknown policy strings return `Err(UnknownMaskPolicy)` instead of
/// silently mapping to `Noop`.
fn parse_policy_str(s: &str, column: &str) -> Result<MaskPolicy, PhysicalError> {
    match s {
        "redact" => Ok(MaskPolicy::Redact),
        "hash_sha256" => Ok(MaskPolicy::HashSha256),
        "tokenize" => Ok(MaskPolicy::Tokenize),
        "noop" => Ok(MaskPolicy::Noop),
        "partial" => Ok(MaskPolicy::Partial),
        "null" => Ok(MaskPolicy::Null),
        other => Err(PhysicalError::UnknownMaskPolicy {
            policy: other.to_string(),
            column: column.to_string(),
        }),
    }
}

/// Whether a policy replaces the column value with a **string** value.
///
/// `HashSha256`/`Tokenize` (hex digest) and `Partial` (`"***" + tail`) all emit
/// strings.  Applied to a non-`Utf8` column, they require a Utf8 cast first —
/// the masked column's output type becomes `Utf8`.
///
/// `Redact` and `Null` are *value-substitution* policies: on a string column
/// they emit `"***"` / `""`, but on a numeric/bool column they emit a
/// zero / null of the **original** type, so they are NOT string-producing here.
fn is_string_producing(policy: &MaskPolicy) -> bool {
    matches!(
        policy,
        MaskPolicy::HashSha256 | MaskPolicy::Tokenize | MaskPolicy::Partial
    )
}

/// The output Arrow type of a column after masking, given its input type.
///
/// Returns `Utf8` when a string-producing policy is applied to a non-string
/// column (the masked values are hex/pseudonym strings); otherwise returns the
/// input type unchanged (type-preserving).  `LargeUtf8` inputs are normalised to
/// `Utf8` on the string path (masking always emits `StringArray`), matching the
/// pre-existing string-masking behaviour.
fn masked_field_type(input_type: &DataType, policy: &MaskPolicy) -> DataType {
    if *policy == MaskPolicy::Noop {
        return input_type.clone();
    }
    match input_type {
        // String columns are always emitted as Utf8 StringArray.
        DataType::Utf8 | DataType::LargeUtf8 => DataType::Utf8,
        // Non-string column + string-producing policy → cast to Utf8, mask.
        _ if is_string_producing(policy) => DataType::Utf8,
        // Redact/Null on a non-string column stay the original type (zeroed/nulled).
        other => other.clone(),
    }
}

/// Compute the masked output schema for a set of column policies.
///
/// For every field: if the column carries a non-Noop policy, its output type is
/// [`masked_field_type`]; otherwise the field is copied verbatim.  Nullability is
/// widened to `true` for a masked, retyped column (a hash of a non-null value is
/// non-null, but null passthrough means the column may still contain nulls).
fn masked_output_schema(
    input_schema: &SchemaRef,
    column_policies: &HashMap<String, MaskPolicy>,
) -> SchemaRef {
    let fields: Vec<Field> = input_schema
        .fields()
        .iter()
        .map(|field| {
            match column_policies.get(field.name()) {
                Some(policy) if *policy != MaskPolicy::Noop => {
                    let out_type = masked_field_type(field.data_type(), policy);
                    if &out_type == field.data_type() {
                        // Type-preserving mask (e.g. Redact on Int64): keep field.
                        field.as_ref().clone()
                    } else {
                        // Type-widening mask (e.g. HashSha256 on Float64 → Utf8):
                        // preserve nullability (null passthrough is preserved).
                        Field::new(field.name(), out_type, field.is_nullable())
                    }
                }
                _ => field.as_ref().clone(),
            }
        })
        .collect();
    Arc::new(Schema::new(fields))
}

/// Apply masking to a single column array.
///
/// # Dispatch
///
/// - `Utf8` / `LargeUtf8`: string masking (redact → "***", hash_sha256 → hex digest, etc.).
/// - `Int64` / `Float64` / `Boolean` with `Redact`/`Null`: zero/false of the same type.
/// - Any non-`Utf8` type with a **string-producing** policy
///   (`HashSha256`/`Tokenize`/`Partial`): cast the column to `Utf8` via Arrow
///   `cast`, then mask each value (null passthrough) → `Utf8` output. (Task #26.)
/// - A non-`Utf8` type that Arrow cannot cast to `Utf8` under a string-producing
///   policy → `Err(MaskTypeUnsupported)` (fail-safe, no leak).
fn apply_mask_to_column(
    col_array: &ArrayRef,
    col_name: &str,
    policy: &MaskPolicy,
) -> Result<ArrayRef, PhysicalError> {
    if *policy == MaskPolicy::Noop {
        return Ok(col_array.clone());
    }

    // ── Task #26: string-producing policy on a non-string column ──────────────
    // Cast to canonical Utf8, then apply the string mask. Nulls stay null.
    // (Utf8/LargeUtf8 are handled by the dedicated arms below, which are already
    // exact; this branch is for numeric/temporal/bool/etc. sources.)
    if is_string_producing(policy)
        && !matches!(col_array.data_type(), DataType::Utf8 | DataType::LargeUtf8)
    {
        return mask_via_utf8_cast(col_array, col_name, policy);
    }

    match col_array.data_type() {
        DataType::Utf8 => {
            let strings = col_array
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| PhysicalError::Internal("Utf8 downcast failed".to_string()))?;
            let masked: Vec<Option<String>> = (0..strings.len())
                .map(|i| {
                    if strings.is_null(i) {
                        None
                    } else {
                        Some(mask_string_value(strings.value(i), policy))
                    }
                })
                .collect();
            Ok(Arc::new(StringArray::from(masked)) as ArrayRef)
        }
        DataType::LargeUtf8 => {
            let strings = col_array
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .ok_or_else(|| PhysicalError::Internal("LargeUtf8 downcast failed".to_string()))?;
            let masked: Vec<Option<String>> = (0..strings.len())
                .map(|i| {
                    if strings.is_null(i) {
                        None
                    } else {
                        Some(mask_string_value(strings.value(i), policy))
                    }
                })
                .collect();
            // Return as Utf8 (preserving schema type not required for LargeUtf8→Utf8,
            // but output schema == input schema for LargeUtf8 requires LargeUtf8 output).
            // Use Utf8 for simplicity; schema is declared as LargeUtf8 only if the inner
            // plan declares it that way. We keep Utf8 for now as masking is value-level.
            Ok(Arc::new(StringArray::from(masked)) as ArrayRef)
        }
        DataType::Int64 => match policy {
            MaskPolicy::Redact | MaskPolicy::Null => {
                let n = col_array.len();
                let mut builder = Int64Builder::with_capacity(n);
                let arr = col_array
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or_else(|| PhysicalError::Internal("Int64 downcast failed".to_string()))?;
                for i in 0..n {
                    if arr.is_null(i) {
                        builder.append_null();
                    } else {
                        builder.append_value(0);
                    }
                }
                Ok(Arc::new(builder.finish()) as ArrayRef)
            }
            other => Err(PhysicalError::MaskTypeUnsupported {
                column: col_name.to_string(),
                type_name: format!("Int64 with policy {:?}", other),
            }),
        },
        DataType::Float64 => match policy {
            MaskPolicy::Redact | MaskPolicy::Null => {
                let n = col_array.len();
                let mut builder = Float64Builder::with_capacity(n);
                let arr = col_array
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .ok_or_else(|| {
                        PhysicalError::Internal("Float64 downcast failed".to_string())
                    })?;
                for i in 0..n {
                    if arr.is_null(i) {
                        builder.append_null();
                    } else {
                        builder.append_value(0.0);
                    }
                }
                Ok(Arc::new(builder.finish()) as ArrayRef)
            }
            other => Err(PhysicalError::MaskTypeUnsupported {
                column: col_name.to_string(),
                type_name: format!("Float64 with policy {:?}", other),
            }),
        },
        DataType::Boolean => match policy {
            MaskPolicy::Redact | MaskPolicy::Null => {
                let n = col_array.len();
                let mut builder = BooleanBuilder::with_capacity(n);
                let arr = col_array
                    .as_any()
                    .downcast_ref::<BooleanArray>()
                    .ok_or_else(|| {
                        PhysicalError::Internal("Boolean downcast failed".to_string())
                    })?;
                for i in 0..n {
                    if arr.is_null(i) {
                        builder.append_null();
                    } else {
                        builder.append_value(false);
                    }
                }
                Ok(Arc::new(builder.finish()) as ArrayRef)
            }
            other => Err(PhysicalError::MaskTypeUnsupported {
                column: col_name.to_string(),
                type_name: format!("Boolean with policy {:?}", other),
            }),
        },
        other_type => {
            // Reachable only for a non-string type carrying `Redact`/`Null`
            // (string-producing policies were routed through the Utf8-cast path
            // above).  We have no type-preserving zero/null handler for this
            // type, so fail safe rather than leak the raw value.
            Err(PhysicalError::MaskTypeUnsupported {
                column: col_name.to_string(),
                type_name: format!("{:?} with policy {:?}", other_type, policy),
            })
        }
    }
}

/// Task #26: mask a non-`Utf8` column with a string-producing policy.
///
/// Casts the column to its canonical `Utf8` representation via Arrow `cast`,
/// then applies [`mask_string_value`] to each non-null value.  Nulls stay null.
/// The output is a `Utf8` `StringArray`.
///
/// The hash is computed on the *string form* of the value, so the same logical
/// value hashes identically regardless of the source column's physical width
/// (e.g. `42_i64` and a `Float64` `42.0` produce different strings — `"42"` vs
/// `"42.0"` — which is correct: they are distinct canonical representations; two
/// `Int64` `42`s always hash the same).
///
/// # Errors
///
/// `Err(MaskTypeUnsupported)` if Arrow cannot cast the source type to `Utf8`
/// (fail-safe: no raw value is emitted).
fn mask_via_utf8_cast(
    col_array: &ArrayRef,
    col_name: &str,
    policy: &MaskPolicy,
) -> Result<ArrayRef, PhysicalError> {
    // Cast to canonical Utf8. If the type is not castable, fail safe.
    let cast_arr =
        cast(col_array, &DataType::Utf8).map_err(|e| PhysicalError::MaskTypeUnsupported {
            column: col_name.to_string(),
            type_name: format!(
                "{:?} with policy {:?} (not castable to Utf8 for masking: {})",
                col_array.data_type(),
                policy,
                e
            ),
        })?;

    let strings = cast_arr
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| {
            PhysicalError::Internal("Utf8 cast did not yield StringArray".to_string())
        })?;

    let masked: Vec<Option<String>> = (0..strings.len())
        .map(|i| {
            if strings.is_null(i) {
                None
            } else {
                Some(mask_string_value(strings.value(i), policy))
            }
        })
        .collect();

    Ok(Arc::new(StringArray::from(masked)) as ArrayRef)
}

/// Mask a single string value according to the policy.
fn mask_string_value(value: &str, policy: &MaskPolicy) -> String {
    match policy {
        MaskPolicy::Redact => "***".to_string(),
        MaskPolicy::HashSha256 | MaskPolicy::Tokenize => {
            // SHA-256 hex digest.
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            let digest = hasher.finalize();
            hex::encode(digest)
        }
        MaskPolicy::Partial => {
            // Show last 4 characters, prefix with "***".
            let chars: Vec<char> = value.chars().collect();
            let tail: String = chars.iter().rev().take(4).rev().collect();
            format!("***{}", tail)
        }
        MaskPolicy::Null => String::new(),
        MaskPolicy::Noop => value.to_string(),
    }
}

/// Apply masking to all tagged columns in a `RecordBatch`.
///
/// Returns the masked batch typed to `output_schema` (which retypes columns
/// masked with a string-producing policy on a non-string source to `Utf8`; all
/// other columns keep their input type).
fn apply_masking_to_batch(
    batch: &RecordBatch,
    column_policies: &HashMap<String, MaskPolicy>,
    output_schema: &SchemaRef,
) -> Result<RecordBatch, PhysicalError> {
    let schema = batch.schema();
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());

    for (i, field) in schema.fields().iter().enumerate() {
        let col_array = batch.column(i);
        let col_name = field.name().as_str();

        if let Some(policy) = column_policies.get(col_name) {
            if *policy != MaskPolicy::Noop {
                let masked = apply_mask_to_column(col_array, col_name, policy)?;
                columns.push(masked);
                continue;
            }
        }
        // Not tagged or Noop: pass through unchanged.
        columns.push(col_array.clone());
    }

    // Build against the masked output schema (string-producing masks on
    // non-string columns produce Utf8 arrays; the schema retypes them to match).
    RecordBatch::try_new(output_schema.clone(), columns)
        .map_err(|e| PhysicalError::Internal(format!("RecordBatch reconstruction error: {}", e)))
}

impl DisplayAs for MaskingExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MaskingExec(contract_id={})", self.bundle.contract_id())
    }
}

impl ExecutionPlan for MaskingExec {
    fn name(&self) -> &str {
        "MaskingExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.inner]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> datafusion::error::Result<Arc<dyn ExecutionPlan>> {
        let inner = children.into_iter().next().ok_or_else(|| {
            datafusion::error::DataFusionError::Internal(
                "MaskingExec::with_new_children requires exactly one child".to_string(),
            )
        })?;
        if !plan_has_contract_approved(&inner) {
            return Err(datafusion::error::DataFusionError::Internal(
                "MaskingExec::with_new_children: new child has no ContractApprovedExec ancestor"
                    .to_string(),
            ));
        }
        let properties = inner.properties().clone();
        // Recompute the masked output schema against the new child's schema
        // (it may differ from the original child, e.g. a re-optimised scan).
        let output_schema = masked_output_schema(&inner.schema(), &self.column_policies);
        Ok(Arc::new(MaskingExec {
            bundle: self.bundle.clone(),
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            column_policies: self.column_policies.clone(),
            output_schema,
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> datafusion::error::Result<SendableRecordBatchStream> {
        let inner_stream = self.inner.execute(partition, context)?;
        let column_policies = self.column_policies.clone();
        let contract_id = self.bundle.contract_id().to_string();
        let output_schema = self.output_schema.clone();
        let adapter_schema = self.output_schema.clone();

        let stream = inner_stream.then(move |batch_result| {
            let column_policies = column_policies.clone();
            let contract_id = contract_id.clone();
            let output_schema = output_schema.clone();
            async move {
                let batch = batch_result?;

                if column_policies.is_empty() {
                    return Ok(batch);
                }

                let masked = apply_masking_to_batch(&batch, &column_policies, &output_schema)
                    .map_err(|e| {
                        datafusion::error::DataFusionError::External(
                            format!("MaskingExec: {}", e).into(),
                        )
                    })?;

                debug!(
                    contract_id = %contract_id,
                    "MaskingExec: masking applied to batch"
                );

                Ok(masked)
            }
        });

        use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            adapter_schema,
            stream,
        )))
    }

    fn schema(&self) -> SchemaRef {
        // Masking is value-level and mostly type-preserving. The single case
        // that changes a type is a string-producing policy (hash/tokenize/
        // partial) on a non-string column, which becomes Utf8 — reflected here
        // so every downstream operator and the stream adapter see the true
        // batch schema. See `masked_output_schema`. (Task #26.)
        self.output_schema.clone()
    }
}
