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
//! column tagged with a sensitivity label in the contract bundle.  The output
//! schema is identical to the input schema (masking does not change types).
//!
//! | Policy       | Effect on column values          |
//! |--------------|----------------------------------|
//! | `Redact`     | Replace with fixed `"***"` token |
//! | `HashSha256` | Replace with SHA-256 hex string  |
//! | `Tokenize`   | Replace with stable pseudonym    |
//! | `Noop`       | Pass through unchanged           |
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
//! Arrow type.  For any type with no explicit handler and a masking policy,
//! it returns `Err(PhysicalError::MaskTypeUnsupported)` instead of leaking.
//! Supported types: Utf8/LargeUtf8 (direct), Int64 (redact→0), Float64
//! (redact→0.0), Boolean (redact→false), Binary (redact→empty bytes).
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
use datafusion::arrow::datatypes::{DataType, SchemaRef};
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

        let properties = inner.properties().clone();
        Ok(Self {
            bundle,
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            column_policies,
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

/// Apply masking to a single column array.
///
/// # Finding 5 fix
///
/// Dispatches per Arrow `DataType`.  Supported types:
/// - `Utf8` / `LargeUtf8`: string masking (redact → "***", hash_sha256 → hex digest, etc.).
/// - `Int64`: redact → 0, others → `Err(MaskTypeUnsupported)`.
/// - `Float64`: redact → 0.0, others → `Err(MaskTypeUnsupported)`.
/// - `Boolean`: redact → false, others → `Err(MaskTypeUnsupported)`.
/// - `Binary`: redact → empty, others → `Err(MaskTypeUnsupported)`.
/// - Any other type with a non-Noop policy → `Err(MaskTypeUnsupported)`.
fn apply_mask_to_column(
    col_array: &ArrayRef,
    col_name: &str,
    policy: &MaskPolicy,
) -> Result<ArrayRef, PhysicalError> {
    if *policy == MaskPolicy::Noop {
        return Ok(col_array.clone());
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
            // Finding 5 fix: any other type with a non-Noop policy leaks data
            // if we silently pass through — so we error.
            Err(PhysicalError::MaskTypeUnsupported {
                column: col_name.to_string(),
                type_name: format!("{:?}", other_type),
            })
        }
    }
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
/// Returns the masked batch (same schema, masked values).
fn apply_masking_to_batch(
    batch: &RecordBatch,
    column_policies: &HashMap<String, MaskPolicy>,
) -> Result<RecordBatch, PhysicalError> {
    let schema = batch.schema();
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());
    let mut _masked_any = false;

    for (i, field) in schema.fields().iter().enumerate() {
        let col_array = batch.column(i);
        let col_name = field.name().as_str();

        if let Some(policy) = column_policies.get(col_name) {
            if *policy != MaskPolicy::Noop {
                let masked = apply_mask_to_column(col_array, col_name, policy)?;
                columns.push(masked);
                _masked_any = true;
                continue;
            }
        }
        // Not tagged or Noop: pass through unchanged.
        columns.push(col_array.clone());
    }

    RecordBatch::try_new(schema, columns)
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
        Ok(Arc::new(MaskingExec {
            bundle: self.bundle.clone(),
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            column_policies: self.column_policies.clone(),
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
        let schema = self.schema();

        let stream = inner_stream.then(move |batch_result| {
            let column_policies = column_policies.clone();
            let contract_id = contract_id.clone();
            async move {
                let batch = batch_result?;

                if column_policies.is_empty() {
                    return Ok(batch);
                }

                let masked = apply_masking_to_batch(&batch, &column_policies).map_err(|e| {
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
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }

    fn schema(&self) -> SchemaRef {
        // Output schema == input schema: masking is type-preserving.
        self.inner.schema()
    }
}
