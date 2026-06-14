//! DPNoiseRule — Wave 8 implementation (round-2 Copilot fixes).
//!
//! ADR-0002: The fourth (final) rule in the optimizer pipeline.  Inspects
//! `Aggregate` nodes.  For each aggregate over a column tagged with
//! differential-privacy requirements in the contract bundle, injects a
//! `LaplaceNoise` logical-plan extension node wrapping the aggregate.
//!
//! Privacy budget is tracked per `(tenant_id, column)` pair via
//! [`PrivacyBudgetTracker`].  If the budget is exhausted, the rule fails the
//! query with a DataFusion error and emits an [`AuditRecord`] with kind
//! [`AuditKind::PrivacyBudgetExhausted`].
//!
//! # Permissive-default (MEMORY.md durable instruction)
//!
//! [`PrivacyBudgetTracker`] defaults to `enabled: false` (unlimited budget).
//! Production wiring calls `PrivacyBudgetTracker::with_enforcement(true, …)`.
//! Tests explicitly opt in to budget enforcement where needed.
//!
//! # Copilot round-2 fixes
//!
//! ## Finding 5 — Only first DP-tagged aggregate column got noise
//!
//! The original loop returned after the first successful DP column match, so
//! aggregates over multiple DP-tagged columns only had noise applied to the
//! first one.  The fix iterates ALL aggregate input columns and wraps each
//! DP-tagged one in its own `LaplaceNoise` Extension node.
//!
//! ## Finding 6 — No ContractApprovedMarker check
//!
//! Aggregates were wrapped unconditionally — even those over scans that
//! `ContractCheckRule` never approved.  The fix: `Aggregate` nodes are only
//! wrapped in `LaplaceNoise` if their input subtree contains a
//! `ContractApprovedMarker` Extension.
//!
//! # LaplaceNoise logical plan node
//!
//! The `LaplaceNoise` node is a `UserDefinedLogicalNode` extension that carries:
//! - The aggregate plan it wraps.
//! - The column name being noised.
//! - The Laplace scale parameter (sensitivity / epsilon).
//!
//! Wave 9 physical operators will convert this to a physical noise injection.
//!
//! # Semantic Law coverage
//!
//! * INV-2 (No read without satisfaction — privacy budget).
//! * INV-5 (No bypass from above trust line): no zone-t imports.

use crate::optimizer_rules::{AuditKind, AuditRecord};
use crate::ContractBundleHandle;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::DFSchemaRef;
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::logical_expr::{Expr, Extension};
use datafusion::logical_expr::{LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Per-column DP config as parsed from a contract bundle.
#[derive(Debug, Deserialize, Clone)]
struct DPColumnConfig {
    epsilon_per_query: f64,
    #[allow(dead_code)]
    noise_mechanism: String,
}

/// Parsed DP fields from a contract bundle.
#[derive(Debug, Deserialize, Default)]
struct DPBundleData {
    #[serde(default)]
    dp_columns: HashMap<String, DPColumnConfig>,
}

// ─── PrivacyBudgetTracker ─────────────────────────────────────────────────────

/// Tracks per-column differential-privacy budget for a tenant.
///
/// # Permissive default
///
/// When `enabled` is `false` (the default), all `consume` calls succeed and
/// no budget is tracked.  This prevents CI environments without budget
/// pre-seeding from failing on import.
///
/// Production wiring uses `with_enforcement(true, initial_budgets)` to opt in.
#[derive(Debug)]
pub struct PrivacyBudgetTracker {
    /// Whether budget enforcement is active.  Defaults to `false`.
    enabled: bool,
    /// Remaining epsilon budget per `(tenant_id, column_name)` key.
    /// Only consulted when `enabled == true`.
    budgets: Mutex<HashMap<(String, String), f64>>,
}

impl Default for PrivacyBudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivacyBudgetTracker {
    /// Construct a new tracker in **permissive mode** (enforcement disabled).
    ///
    /// Use [`Self::with_enforcement`] to opt in to budget enforcement in
    /// production or in tests that explicitly need it.
    pub fn new() -> Self {
        Self {
            enabled: false,
            budgets: Mutex::new(HashMap::new()),
        }
    }

    /// Construct a tracker with enforcement enabled and pre-seeded budgets.
    ///
    /// `initial_budgets` maps `(tenant_id, column_name)` → epsilon allowance.
    ///
    /// # Arguments
    ///
    /// * `enforce` — if `false`, reverts to permissive mode regardless of
    ///   `initial_budgets` (useful for test parameterisation).
    /// * `initial_budgets` — pre-seeded epsilon values.
    pub fn with_enforcement(
        enforce: bool,
        initial_budgets: HashMap<(String, String), f64>,
    ) -> Self {
        Self {
            enabled: enforce,
            budgets: Mutex::new(initial_budgets),
        }
    }

    /// Whether enforcement is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Attempt to consume `epsilon` from the budget for `(tenant_id, column)`.
    ///
    /// Returns `Ok(())` if the budget allows it, or
    /// `Err(remaining_budget)` if the budget is exhausted.
    ///
    /// When enforcement is disabled, always returns `Ok(())`.
    pub fn consume(&self, tenant_id: &str, column: &str, epsilon: f64) -> Result<(), f64> {
        if !self.enabled {
            return Ok(());
        }
        let key = (tenant_id.to_string(), column.to_string());
        let mut guard = self.budgets.lock().unwrap();
        let remaining = guard.get(&key).copied().unwrap_or(0.0);
        if remaining < epsilon - f64::EPSILON {
            // Budget exhausted — return remaining (may be 0.0 or negative).
            debug!(
                tenant_id,
                column, epsilon, remaining, "privacy budget exhausted"
            );
            return Err(remaining);
        }
        let new_remaining = remaining - epsilon;
        guard.insert(key, new_remaining);
        debug!(
            tenant_id,
            column, epsilon, new_remaining, "privacy budget consumed"
        );
        Ok(())
    }

    /// Return the remaining budget for `(tenant_id, column)`.
    ///
    /// Returns `f64::INFINITY` if enforcement is disabled or if the key has
    /// not been seeded.
    pub fn remaining(&self, tenant_id: &str, column: &str) -> f64 {
        if !self.enabled {
            return f64::INFINITY;
        }
        let guard = self.budgets.lock().unwrap();
        *guard
            .get(&(tenant_id.to_string(), column.to_string()))
            .unwrap_or(&0.0)
    }
}

// ─── LaplaceNoise logical plan extension ──────────────────────────────────────

/// A logical plan extension node that represents Laplace noise injection.
///
/// Wave 9 physical operators will convert this into an actual noise injection
/// at execution time.  In the logical plan it serves as a declarative marker
/// that the optimizer has decided DP noise is required for this aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaplaceNoiseNode {
    /// The aggregate plan being wrapped.
    pub input: Arc<LogicalPlan>,
    /// The column being noised (the aggregate output column).
    pub column: String,
    /// The Laplace scale: sensitivity / epsilon.
    /// Encoded as a string for hashing / equality; parsed to f64 at execution.
    pub scale_str: String,
    /// The schema of the output (same as the wrapped aggregate).
    pub output_schema: DFSchemaRef,
}

impl PartialOrd for LaplaceNoiseNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Compare by (column, scale_str) only; schema is derived from input.
        match self.column.partial_cmp(&other.column) {
            Some(std::cmp::Ordering::Equal) => self.scale_str.partial_cmp(&other.scale_str),
            other => other,
        }
    }
}

impl fmt::Display for LaplaceNoiseNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LaplaceNoise(column={}, scale={})",
            self.column, self.scale_str
        )
    }
}

impl UserDefinedLogicalNodeCore for LaplaceNoiseNode {
    fn name(&self) -> &str {
        "LaplaceNoise"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![self.input.as_ref()]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.output_schema
    }

    fn expressions(&self) -> Vec<Expr> {
        vec![]
    }

    fn fmt_for_explain(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LaplaceNoise: column={}, scale={}",
            self.column, self.scale_str
        )
    }

    fn with_exprs_and_inputs(
        &self,
        _exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion::common::Result<Self> {
        Ok(Self {
            input: Arc::new(inputs.into_iter().next().ok_or_else(|| {
                DataFusionError::Internal("LaplaceNoiseNode requires one input".into())
            })?),
            column: self.column.clone(),
            scale_str: self.scale_str.clone(),
            output_schema: self.output_schema.clone(),
        })
    }
}

// ─── DPNoiseRule ─────────────────────────────────────────────────────────────

/// DataFusion optimizer rule that injects differential-privacy noise into
/// aggregate queries over DP-tagged columns.
///
/// Must be registered FOURTH (last) in the optimizer pipeline via
/// `build_pipeline`.
#[derive(Debug)]
pub struct DPNoiseRule {
    /// The signed contract bundle that supplies the DP tags and noise scales.
    bundle: ContractBundleHandle,
    /// The privacy budget tracker (permissive by default).
    budget: PrivacyBudgetTracker,
    /// The tenant ID for budget tracking.
    tenant_id: String,
    /// Audit records collected during this pass.
    audit_records: Mutex<Vec<AuditRecord>>,
}

impl DPNoiseRule {
    /// Construct a `DPNoiseRule` with a **permissive** budget tracker (no
    /// enforcement).  Suitable for unit tests that do not exercise budget
    /// exhaustion.
    pub fn new_permissive(bundle: ContractBundleHandle, tenant_id: impl Into<String>) -> Self {
        Self {
            bundle,
            budget: PrivacyBudgetTracker::new(),
            tenant_id: tenant_id.into(),
            audit_records: Mutex::new(Vec::new()),
        }
    }

    /// Construct a `DPNoiseRule` with enforcement enabled and pre-seeded
    /// budgets.  Use this in tests that verify budget exhaustion.
    pub fn new_with_budget(
        bundle: ContractBundleHandle,
        tenant_id: impl Into<String>,
        initial_budgets: HashMap<(String, String), f64>,
    ) -> Self {
        Self {
            bundle,
            budget: PrivacyBudgetTracker::with_enforcement(true, initial_budgets),
            tenant_id: tenant_id.into(),
            audit_records: Mutex::new(Vec::new()),
        }
    }

    /// Drain and return all audit records from the most recent pass.
    pub fn drain_audit_records(&self) -> Vec<AuditRecord> {
        let mut guard = self.audit_records.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    /// Return a reference to the privacy budget tracker.
    pub fn budget(&self) -> &PrivacyBudgetTracker {
        &self.budget
    }

    /// Return the tenant ID.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Parse the DP policy from the bundle.
    fn parse_bundle(&self) -> Option<DPBundleData> {
        let bytes = &self.bundle.raw_bytes;
        if bytes.is_empty() {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    /// Emit a `PrivacyBudgetExhausted` audit record.
    fn emit_budget_exhausted(&self, column: &str) -> AuditRecord {
        AuditRecord::new(
            AuditKind::PrivacyBudgetExhausted,
            "<aggregate>",
            &self.tenant_id,
            Some(self.bundle.contract_id().to_string()),
            format!("privacy budget exhausted for column '{}'", column),
        )
    }

    /// Collect column names referenced in aggregate expressions.
    ///
    /// Inspects the `aggr_expr` list of an `Aggregate` node to determine
    /// which base columns are aggregated.  Returns a vec of (column_name, expr).
    fn collect_agg_columns(&self, aggr_expr: &[Expr]) -> Vec<String> {
        let mut cols = Vec::new();
        for expr in aggr_expr {
            collect_column_names(expr, &mut cols);
        }
        cols
    }
}

/// Recursively collect leaf column names from an expression tree.
fn collect_column_names(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Column(c) => out.push(c.name.clone()),
        Expr::AggregateFunction(agg) => {
            for arg in &agg.params.args {
                collect_column_names(arg, out);
            }
        }
        Expr::BinaryExpr(b) => {
            collect_column_names(&b.left, out);
            collect_column_names(&b.right, out);
        }
        Expr::Alias(a) => collect_column_names(&a.expr, out),
        Expr::Cast(c) => collect_column_names(&c.expr, out),
        _ => {}
    }
}

impl OptimizerRule for DPNoiseRule {
    fn name(&self) -> &str {
        "griot_dp_noise"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DFResult<Transformed<LogicalPlan>> {
        let bundle_data = match self.parse_bundle() {
            None => {
                debug!("DPNoiseRule: no bundle data; passthrough");
                return Ok(Transformed::no(plan));
            }
            Some(data) => data,
        };

        if bundle_data.dp_columns.is_empty() {
            debug!("DPNoiseRule: no DP columns configured; passthrough");
            return Ok(Transformed::no(plan));
        }

        // Walk the plan and wrap Aggregate nodes where a DP-tagged column
        // is referenced.
        let mut changed = false;
        let mut pending_error: Option<DataFusionError> = None;

        let new_plan = plan.transform_down(|node| {
            if pending_error.is_some() {
                // Short-circuit: a budget exhaustion was already detected.
                return Ok(Transformed::no(node));
            }

            if let LogicalPlan::Aggregate(ref agg) = node {
                // Finding 6 fix: only apply DP noise if the aggregate's input
                // subtree was approved by ContractCheckRule.  Aggregates over
                // un-approved scans are left unchanged.
                if !subtree_has_approval_marker(agg.input.as_ref()) {
                    debug!(
                        "DPNoiseRule: skipping Aggregate with no ContractApprovedMarker in subtree"
                    );
                    return Ok(Transformed::no(node));
                }

                let cols = self.collect_agg_columns(&agg.aggr_expr);

                // Finding 5 fix: collect ALL DP-tagged columns referenced in
                // this aggregate, not just the first one.  Each protected column
                // consumes its own budget slice and gets its own LaplaceNoise
                // wrapper.  We build the chain from innermost to outermost:
                // the Aggregate is wrapped by LaplaceNoise for col1, which is
                // itself wrapped by LaplaceNoise for col2, etc.
                let mut dp_columns_found: Vec<(String, f64)> = Vec::new();

                for col_name in &cols {
                    if let Some(dp_config) = bundle_data.dp_columns.get(col_name) {
                        let epsilon = dp_config.epsilon_per_query;
                        match self.budget.consume(&self.tenant_id, col_name, epsilon) {
                            Err(_remaining) => {
                                warn!(
                                    column = %col_name,
                                    tenant_id = %self.tenant_id,
                                    "privacy budget exhausted",
                                );
                                let audit = self.emit_budget_exhausted(col_name);
                                self.audit_records.lock().unwrap().push(audit);
                                pending_error = Some(DataFusionError::External(
                                    format!(
                                        "privacy budget exhausted for tenant '{}', column '{}'",
                                        self.tenant_id, col_name
                                    )
                                    .into(),
                                ));
                                // Return immediately on budget exhaustion — do
                                // not partially wrap the aggregate.
                                return Ok(Transformed::no(node));
                            }
                            Ok(()) => {
                                // Budget consumed; record this column for wrapping.
                                dp_columns_found.push((col_name.clone(), epsilon));
                            }
                        }
                    }
                }

                // Finding 5 fix: wrap the aggregate in a chain of LaplaceNoise
                // Extension nodes — one per DP-tagged column.  The innermost
                // wrapper carries the Aggregate plan; each subsequent wrapper
                // carries the previous LaplaceNoise Extension.
                if !dp_columns_found.is_empty() {
                    let schema = node.schema().clone();
                    // Start with the Aggregate node itself.
                    let mut current: LogicalPlan = node;

                    for (col_name, epsilon) in &dp_columns_found {
                        let scale = 1.0 / epsilon; // sensitivity=1 assumption
                        debug!(
                            column = %col_name,
                            epsilon, scale,
                            "DPNoiseRule: injecting LaplaceNoise",
                        );
                        let laplace_node = LaplaceNoiseNode {
                            input: Arc::new(current),
                            column: col_name.clone(),
                            scale_str: format!("{:.6}", scale),
                            output_schema: schema.clone(),
                        };
                        current = LogicalPlan::Extension(Extension {
                            node: Arc::new(laplace_node),
                        });
                    }

                    changed = true;
                    // Jump: do not recurse into the Extension chain we just
                    // inserted — the wrapped Aggregate is already processed and
                    // recursing would double-consume budget.
                    return Ok(Transformed::new(current, true, TreeNodeRecursion::Jump));
                }
            }
            Ok(Transformed::no(node))
        })?;

        if let Some(err) = pending_error {
            return Err(err);
        }

        if changed {
            Ok(Transformed::yes(new_plan.data))
        } else {
            Ok(Transformed::no(new_plan.data))
        }
    }
}

/// Check whether a `LogicalPlan` subtree contains a `ContractApprovedMarker`
/// Extension node.
///
/// # Finding 6 fix
///
/// Used by `DPNoiseRule` to gate DP noise injection on prior contract approval.
fn subtree_has_approval_marker(plan: &LogicalPlan) -> bool {
    if let LogicalPlan::Extension(ref ext) = plan {
        if ext.node.name() == "ContractApproved" {
            return true;
        }
    }
    plan.inputs()
        .iter()
        .any(|child| subtree_has_approval_marker(child))
}
