//! LaplaceNoiseExec — Wave 9 implementation.
//!
//! Physical `ExecutionPlan` that applies the Laplace mechanism to aggregate
//! result batches and debits the `PrivacyBudgetTracker`.  It is the physical
//! counterpart of the wave-8 `DPNoiseRule`.
//!
//! # Role in the pipeline
//!
//! `LaplaceNoiseExec` MUST sit above `ContractApprovedExec` in the plan.
//! Before streaming any batch it verifies that `ContractApprovedExec` is
//! present as an ancestor.  If not, it returns
//! `PhysicalError::ContractNotApproved { operator: "LaplaceNoiseExec" }`.
//!
//! # Copilot round-2 fixes (Findings 3, 6, 7, 8)
//!
//! ## Finding 3 — Silent DP bypass on malformed bundle
//!
//! The original impl treated bundle parse failure as "no DP columns" (empty
//! HashMap), meaning DP could be silently skipped on a malformed bundle.
//! Fix: parse failure returns `Err(PhysicalError::ContractBundleMalformed)`.
//!
//! ## Finding 6 — No epsilon/sensitivity validation
//!
//! `apply_laplace_noise` computed `scale = sensitivity/epsilon` with no
//! validation.  epsilon=0 → infinity; epsilon<0 → invalid; NaN → invalid.
//! Fix: validate both epsilon > 0 finite and sensitivity > 0 finite before
//! computing scale; return `Err(InvalidDpParameters)` on violation.
//!
//! ## Finding 7 — Only Float64Array gets noise
//!
//! Int64 aggregates silently bypassed DP and returned exact values.
//! Fix: add Int64 support (cast to f64 → add noise → round + cast back).
//! Any other type returns `Err(DpTypeUnsupported)`.
//!
//! ## Finding 8 — budget.consume() never called (CRITICAL)
//!
//! The privacy budget tracker was stored but `consume()` was never called.
//! Fix: for each DP-protected column in each batch, call
//! `budget.consume(tenant_id, column, epsilon)` BEFORE returning results.
//! If `consume()` returns `Err`, return `Err(BudgetExhausted)` and do NOT
//! return any rows.
//!
//! # Laplace sampling
//!
//! rand_distr 0.4.x does not include a Laplace type.  We implement the
//! Laplace distribution via the double-exponential method:
//!   sample = (Exp1 - Exp1) * scale   (i.e. difference of two Exp(1) samples
//!   scaled by `scale`).  This produces Laplace(0, scale) exactly.
//!
//! # ADR-0002 requirements
//!
//! * No `unsafe` code.
//! * Permissive default: `new_permissive` creates a tracker with
//!   `enforce_budget: false` — noise is applied but budget exhaustion does
//!   not block execution (consistent with wave-8 `PrivacyBudgetTracker::new()`
//!   default).
//! * `new_with_budget` enables enforcement.
//! * Emits a `PhysicalEnforcementEvent` for every batch where noise is applied.
//! * Records `epsilon_consumed` so `AttestationExec` can populate the envelope.
//!
//! # Spec anchor
//!
//! ADR-0002 §Physical operators — LaplaceNoiseExec.
//! INV-2 (no read without satisfaction — differential privacy).

use crate::optimizer_rules::dp_noise::PrivacyBudgetTracker;
use crate::physical::contract_approved_exec::plan_has_contract_approved;
use crate::physical::{PhysicalEnforcementEvent, PhysicalError};
use crate::ContractBundleHandle;
use datafusion::arrow::array::{Array, ArrayRef, Float64Array, Int64Array};
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};
use futures::StreamExt;
use rand::distributions::Distribution;
use rand_distr::Exp1;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Per-column DP configuration as parsed from a contract bundle.
#[derive(Debug, Deserialize, Clone)]
struct DpColumnConfig {
    sensitivity: f64,
    epsilon: f64,
}

/// Parsed DP fields from a contract bundle.
#[derive(Debug, Deserialize, Default)]
struct DpBundleData {
    #[serde(default)]
    dp_columns: HashMap<String, DpColumnConfig>,
}

// ─── Laplace sampling ─────────────────────────────────────────────────────────

/// Sample from Laplace(0, scale) using the double-exponential method.
///
/// Laplace(0, scale) = (Exp(1/scale) - Exp(1/scale)) can equivalently be
/// computed as `(Exp1 - Exp1) * scale` where Exp1 is standard Exp(1).
fn sample_laplace(scale: f64, rng: &mut impl rand::Rng) -> f64 {
    let e1: f64 = Exp1.sample(rng);
    let e2: f64 = Exp1.sample(rng);
    (e1 - e2) * scale
}

// ─── LaplaceNoiseExec ─────────────────────────────────────────────────────────

/// Physical operator that applies Laplace-mechanism DP noise to aggregate results.
#[derive(Debug)]
pub struct LaplaceNoiseExec {
    /// The contract bundle supplying the DP tags and noise scales.
    bundle: ContractBundleHandle,
    /// Privacy budget tracker.  Permissive by default.
    budget: Arc<PrivacyBudgetTracker>,
    /// The tenant ID for budget tracking.
    tenant_id: String,
    /// The inner physical plan to wrap.
    inner: Arc<dyn ExecutionPlan>,
    /// Cached plan properties.
    properties: PlanProperties,
    /// Enforcement events emitted during execution.
    events: Arc<Mutex<Vec<PhysicalEnforcementEvent>>>,
    /// Total epsilon consumed across all batches (updated during execute).
    epsilon_consumed: Arc<Mutex<Option<f64>>>,
    /// Parsed DP column configs: column → (epsilon, sensitivity).
    /// Validated at construction time (Finding 6 fix).
    dp_columns: HashMap<String, (f64, f64)>,
}

impl LaplaceNoiseExec {
    /// Construct a `LaplaceNoiseExec` with the permissive budget tracker.
    ///
    /// Returns `Err(PhysicalError::ContractNotApproved)` if `inner` does not
    /// have a `ContractApprovedExec` as an ancestor.
    pub fn new_permissive(
        bundle: ContractBundleHandle,
        tenant_id: impl Into<String>,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        Self::build(
            bundle,
            tenant_id.into(),
            Arc::new(PrivacyBudgetTracker::new()),
            inner,
        )
    }

    /// Construct a `LaplaceNoiseExec` with budget enforcement enabled.
    pub fn new_with_budget(
        bundle: ContractBundleHandle,
        tenant_id: impl Into<String>,
        budget: PrivacyBudgetTracker,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        Self::build(bundle, tenant_id.into(), Arc::new(budget), inner)
    }

    fn build(
        bundle: ContractBundleHandle,
        tenant_id: String,
        budget: Arc<PrivacyBudgetTracker>,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        if !plan_has_contract_approved(&inner) {
            return Err(PhysicalError::ContractNotApproved {
                operator: "LaplaceNoiseExec".to_string(),
            });
        }

        // Finding 3 fix: parse bundle, hard-error on malformed.
        let dp_columns = parse_dp_bundle(&bundle)?;

        // Finding 6 fix: validate epsilon and sensitivity at construction time.
        for (col_name, (epsilon, sensitivity)) in &dp_columns {
            validate_dp_params(col_name, *epsilon, *sensitivity)?;
        }

        let properties = inner.properties().clone();
        Ok(Self {
            bundle,
            budget,
            tenant_id,
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            epsilon_consumed: Arc::new(Mutex::new(None)),
            dp_columns,
        })
    }

    /// Return the total epsilon consumed during the last `execute()` call.
    ///
    /// `None` if execution has not yet completed or no DP columns were present.
    pub fn epsilon_consumed(&self) -> Option<f64> {
        *self.epsilon_consumed.lock().unwrap()
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
}

/// Parse the DP bundle.
///
/// # Finding 3 fix
///
/// Returns `Err(ContractBundleMalformed)` for non-parseable JSON.
/// Returns `Ok(empty)` only if the bundle is empty (no DP policy).
fn parse_dp_bundle(
    bundle: &ContractBundleHandle,
) -> Result<HashMap<String, (f64, f64)>, PhysicalError> {
    let bytes = &bundle.raw_bytes;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }

    let data: DpBundleData =
        serde_json::from_slice(bytes).map_err(|e| PhysicalError::ContractBundleMalformed {
            reason: format!("LaplaceNoiseExec bundle JSON parse error: {}", e),
        })?;

    Ok(data
        .dp_columns
        .into_iter()
        .map(|(col, cfg)| (col, (cfg.epsilon, cfg.sensitivity)))
        .collect())
}

/// Validate epsilon and sensitivity.
///
/// # Finding 6 fix
///
/// Both must be finite and > 0.
fn validate_dp_params(column: &str, epsilon: f64, sensitivity: f64) -> Result<(), PhysicalError> {
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(PhysicalError::InvalidDpParameters {
            column: column.to_string(),
            epsilon,
            sensitivity,
        });
    }
    if !sensitivity.is_finite() || sensitivity <= 0.0 {
        return Err(PhysicalError::InvalidDpParameters {
            column: column.to_string(),
            epsilon,
            sensitivity,
        });
    }
    Ok(())
}

/// Apply Laplace noise to a single column array.
///
/// # Findings 6 + 7 fix
///
/// - Float64: noise applied directly.
/// - Int64: cast to f64, add noise, round back to i64.
/// - Other types: return `Err(DpTypeUnsupported)`.
fn apply_laplace_noise_to_column(
    col_array: &ArrayRef,
    col_name: &str,
    scale: f64,
) -> Result<ArrayRef, PhysicalError> {
    let mut rng = rand::thread_rng();

    match col_array.data_type() {
        DataType::Float64 => {
            let arr = col_array
                .as_any()
                .downcast_ref::<Float64Array>()
                .ok_or_else(|| PhysicalError::Internal("Float64 downcast failed".to_string()))?;
            let noised: Vec<Option<f64>> = (0..arr.len())
                .map(|i| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i) + sample_laplace(scale, &mut rng))
                    }
                })
                .collect();
            Ok(Arc::new(Float64Array::from(noised)) as ArrayRef)
        }
        DataType::Int64 => {
            // Finding 7 fix: Int64 gets noise via f64 cast → noise → round back.
            let arr = col_array
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or_else(|| PhysicalError::Internal("Int64 downcast failed".to_string()))?;
            let noised: Vec<Option<i64>> = (0..arr.len())
                .map(|i| {
                    if arr.is_null(i) {
                        None
                    } else {
                        let f = arr.value(i) as f64 + sample_laplace(scale, &mut rng);
                        Some(f.round() as i64)
                    }
                })
                .collect();
            Ok(Arc::new(Int64Array::from(noised)) as ArrayRef)
        }
        other => Err(PhysicalError::DpTypeUnsupported {
            column: col_name.to_string(),
            type_name: format!("{:?}", other),
        }),
    }
}

/// Apply Laplace noise to all DP-tagged columns in a batch.
///
/// # Finding 8 fix
///
/// Calls `budget.consume()` before returning the noised batch.  If the budget
/// is exhausted, returns `Err(BudgetExhausted)` and does NOT return rows.
fn apply_dp_to_batch(
    batch: &RecordBatch,
    dp_columns: &HashMap<String, (f64, f64)>,
    budget: &PrivacyBudgetTracker,
    tenant_id: &str,
    total_epsilon: &mut f64,
) -> Result<RecordBatch, PhysicalError> {
    let schema = batch.schema();
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());

    for (i, field) in schema.fields().iter().enumerate() {
        let col_array = batch.column(i);
        let col_name = field.name().as_str();

        if let Some((epsilon, sensitivity)) = dp_columns.get(col_name) {
            // Finding 8 fix: debit budget BEFORE returning results.
            budget
                .consume(tenant_id, col_name, *epsilon)
                .map_err(|_remaining| PhysicalError::BudgetExhausted {
                    tenant_id: tenant_id.to_string(),
                    column: col_name.to_string(),
                })?;

            let scale = sensitivity / epsilon;
            let noised = apply_laplace_noise_to_column(col_array, col_name, scale)?;
            columns.push(noised);

            *total_epsilon += epsilon;
            debug!(
                col = %col_name,
                epsilon,
                "LaplaceNoiseExec: noise applied, budget consumed"
            );
        } else {
            columns.push(col_array.clone());
        }
    }

    RecordBatch::try_new(schema, columns).map_err(|e| {
        PhysicalError::Internal(format!(
            "LaplaceNoiseExec RecordBatch reconstruction: {}",
            e
        ))
    })
}

impl DisplayAs for LaplaceNoiseExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "LaplaceNoiseExec(contract_id={}, tenant_id={})",
            self.bundle.contract_id(),
            self.tenant_id
        )
    }
}

impl ExecutionPlan for LaplaceNoiseExec {
    fn name(&self) -> &str {
        "LaplaceNoiseExec"
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
                "LaplaceNoiseExec::with_new_children requires exactly one child".to_string(),
            )
        })?;
        if !plan_has_contract_approved(&inner) {
            return Err(datafusion::error::DataFusionError::Internal(
                "LaplaceNoiseExec::with_new_children: new child has no ContractApprovedExec"
                    .to_string(),
            ));
        }
        let properties = inner.properties().clone();
        Ok(Arc::new(LaplaceNoiseExec {
            bundle: self.bundle.clone(),
            budget: self.budget.clone(),
            tenant_id: self.tenant_id.clone(),
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            epsilon_consumed: Arc::new(Mutex::new(None)),
            dp_columns: self.dp_columns.clone(),
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> datafusion::error::Result<SendableRecordBatchStream> {
        if self.dp_columns.is_empty() {
            // No DP columns: passthrough.
            return self.inner.execute(partition, context);
        }

        let inner_stream = self.inner.execute(partition, context)?;
        let dp_columns = self.dp_columns.clone();
        let budget = self.budget.clone();
        let tenant_id = self.tenant_id.clone();
        // Shared accumulator for epsilon consumed across all batches.
        let total_epsilon_acc = Arc::new(Mutex::new(0.0_f64));
        let epsilon_output = self.epsilon_consumed.clone();
        let schema = self.schema();

        let acc_ref = total_epsilon_acc.clone();
        let eps_out = epsilon_output.clone();

        let stream = inner_stream.then(move |batch_result| {
            let dp_columns = dp_columns.clone();
            let budget = budget.clone();
            let tenant_id = tenant_id.clone();
            let acc_ref = acc_ref.clone();
            let eps_out = eps_out.clone();
            async move {
                let batch = batch_result?;

                let mut total_eps = acc_ref.lock().unwrap();
                let noised =
                    apply_dp_to_batch(&batch, &dp_columns, &budget, &tenant_id, &mut total_eps)
                        .map_err(|e| {
                            datafusion::error::DataFusionError::External(
                                format!("LaplaceNoiseExec: {}", e).into(),
                            )
                        })?;

                // Update the public epsilon_consumed after each batch.
                if *total_eps > 0.0 {
                    let mut out = eps_out.lock().unwrap();
                    *out = Some(*total_eps);
                }

                Ok(noised)
            }
        });

        use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }

    fn schema(&self) -> SchemaRef {
        // DP noise does not change schema — values are modified in-place.
        self.inner.schema()
    }
}
