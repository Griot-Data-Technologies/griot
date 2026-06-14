//! ContractCheckRule — Wave 8 implementation (round-2 Copilot fixes).
//!
//! ADR-0002: The first rule in the optimizer pipeline.  Validates that:
//! 1. A [`ContractBundleHandle`] is present and non-empty (INV-1).
//! 2. The principal satisfies the contract's purpose constraint (INV-2).
//! 3. The principal satisfies the contract's tier constraint.
//! 4. The principal satisfies the contract's classification constraint.
//!
//! On failure: rewrites the `TableScan` to `EmptyRelation{produce_one_row:
//! false}` and emits an [`AuditRecord`] with the appropriate [`AuditKind`].
//!
//! On success: stamps an [`ApprovedTableSet`] (a shared `Arc<Mutex<HashSet>>`)
//! with the approved table name AND emits a [`ContractApprovedMarker`]
//! `LogicalPlan::Extension` node wrapping the approved scan so downstream
//! optimizer rules can gate on the plan-level marker.
//!
//! # Copilot round-2 fix (Finding 1)
//!
//! The original implementation only stored approved table names in an internal
//! `approved_tables: Mutex<Vec<ContractCheckMarker>>` that downstream rules
//! never read — no actual enforcement stamp propagated through the plan.
//!
//! The fix: approved scans are wrapped in a `ContractApprovedMarker` Extension
//! node.  All downstream rules (`RowFilterRule`, `MaskingRule`, `DPNoiseRule`)
//! check for this Extension before acting (Finding 6 fix).  The shared
//! `ApprovedTableSet` is also kept for rules that need to look up approval
//! outside of the plan walk.
//!
//! # Semantic Law coverage
//!
//! * INV-1 (No data in without contract): empty bundle → deny.
//! * INV-2 (No read without satisfaction): purpose/tier/classification check.
//! * INV-5 (No bypass from above trust line): no zone-t imports.

use crate::optimizer_rules::{AuditKind, AuditRecord, ContractCheckMarker, Principal};
use crate::ContractBundleHandle;
use datafusion::arrow::datatypes::Schema;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::DFSchema;
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::{EmptyRelation, Extension, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

// ─── ApprovedTableSet ──────────────────────────────────────────────────────────

/// A shared, thread-safe set of approved table names produced by
/// [`ContractCheckRule`] and consumed by downstream optimizer rules.
///
/// Created once per optimizer pass and shared (via `Arc` clone) among all four
/// rules built by `build_pipeline`.  `ContractCheckRule` inserts approved names;
/// `RowFilterRule`, `MaskingRule`, and `DPNoiseRule` reject unmarked scans
/// (Finding 6 fix).
#[derive(Debug, Clone, Default)]
pub struct ApprovedTableSet(pub Arc<Mutex<HashSet<String>>>);

impl ApprovedTableSet {
    /// Create an empty approved-table set.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashSet::new())))
    }

    /// Mark `table_name` as approved.
    pub fn approve(&self, table_name: &str) {
        self.0.lock().unwrap().insert(table_name.to_string());
    }

    /// Return `true` if `table_name` was approved by `ContractCheckRule`.
    pub fn is_approved(&self, table_name: &str) -> bool {
        self.0.lock().unwrap().contains(table_name)
    }
}

// ─── ContractApprovedMarker — plan-level extension node ───────────────────────

/// A DataFusion logical-plan extension node that acts as an approval stamp
/// for a `TableScan`.
///
/// `ContractCheckRule` wraps each approved `TableScan` in this node.
/// Downstream rules (`RowFilterRule`, `MaskingRule`, `DPNoiseRule`) MUST check
/// for this node before acting — a scan without the marker means
/// `ContractCheckRule` was not run first, which is a pipeline misconfiguration.
///
/// # Finding 1 fix
///
/// The original implementation only stored approval in an internal Vec that
/// downstream rules never read.  This Extension node makes approval visible
/// at the plan level, which is the correct mechanism inside the DataFusion
/// optimizer rule pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContractApprovedMarker {
    /// The approved `TableScan` wrapped by this node.
    pub input: Arc<LogicalPlan>,
    /// The contract ID that approved this scan.
    pub contract_id: String,
    /// The tenant ID.
    pub tenant_id: String,
    /// Output schema — same as the wrapped scan's schema.
    pub output_schema: datafusion::common::DFSchemaRef,
}

impl PartialOrd for ContractApprovedMarker {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.contract_id.partial_cmp(&other.contract_id)
    }
}

impl fmt::Display for ContractApprovedMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContractApproved(contract={}, tenant={})",
            self.contract_id, self.tenant_id
        )
    }
}

impl UserDefinedLogicalNodeCore for ContractApprovedMarker {
    fn name(&self) -> &str {
        "ContractApproved"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![self.input.as_ref()]
    }

    fn schema(&self) -> &datafusion::common::DFSchemaRef {
        &self.output_schema
    }

    fn expressions(&self) -> Vec<datafusion::logical_expr::Expr> {
        vec![]
    }

    fn fmt_for_explain(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContractApproved: contract={}, tenant={}",
            self.contract_id, self.tenant_id
        )
    }

    fn with_exprs_and_inputs(
        &self,
        _exprs: Vec<datafusion::logical_expr::Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion::common::Result<Self> {
        use datafusion::error::DataFusionError;
        Ok(Self {
            input: Arc::new(inputs.into_iter().next().ok_or_else(|| {
                DataFusionError::Internal("ContractApprovedMarker requires one input".into())
            })?),
            contract_id: self.contract_id.clone(),
            tenant_id: self.tenant_id.clone(),
            output_schema: self.output_schema.clone(),
        })
    }
}

// ─── Contract bundle wire format ──────────────────────────────────────────────

/// Parsed representation of a contract bundle's JSON payload.
///
/// The wire format matches the JSON shapes used in the Wave 8 tests.
/// Fields are optional so the parser is lenient for bundles that only
/// specify a subset of constraints.
#[derive(Debug, Deserialize, Default)]
struct ContractBundleData {
    #[serde(default)]
    allowed_purposes: Vec<String>,
    #[serde(default)]
    required_tier: Option<String>,
    #[serde(default)]
    required_classification: Option<String>,
}

/// Tier ordering for contract satisfaction checks.
///
/// A principal satisfies a required tier if their tier is >= the required
/// tier.  The ordering is: bronze < silver < gold.
const TIER_ORDER: &[&str] = &["bronze", "silver", "gold"];

fn tier_rank(tier: &str) -> Option<usize> {
    TIER_ORDER.iter().position(|&t| t == tier)
}

// ─── ContractCheckRule ────────────────────────────────────────────────────────

/// DataFusion optimizer rule that enforces contract-bundle presence and
/// principal satisfaction at the `TableScan` level.
///
/// Must be registered FIRST in the optimizer pipeline via `build_pipeline`.
///
/// # Finding 1 fix
///
/// On approval, wraps the `TableScan` in a [`ContractApprovedMarker`] Extension
/// node AND inserts the table name into the shared [`ApprovedTableSet`].
/// Downstream rules gate on both the plan-level marker and the shared set.
#[derive(Debug)]
pub struct ContractCheckRule {
    /// The signed contract bundle to validate against.
    bundle: ContractBundleHandle,
    /// The principal making the query.
    principal: Principal,
    /// Audit records collected during this optimizer pass (one per denied scan).
    audit_records: Mutex<Vec<AuditRecord>>,
    /// Set of table names that passed the contract check this pass.
    /// Shared with downstream rules via `Arc` clone so they can gate on approval.
    approved_tables: Mutex<Vec<ContractCheckMarker>>,
    /// Shared approved-table set (Finding 1 + 6 fix): downstream rules read this.
    approved_set: ApprovedTableSet,
}

impl ContractCheckRule {
    /// Construct a new `ContractCheckRule` with its own approval set.
    ///
    /// Use [`ContractCheckRule::new_with_shared_set`] when wiring into a
    /// multi-rule pipeline so downstream rules can share the same set.
    pub fn new(bundle: ContractBundleHandle, principal: Principal) -> Self {
        Self::new_with_shared_set(bundle, principal, ApprovedTableSet::new())
    }

    /// Construct a new `ContractCheckRule` sharing an [`ApprovedTableSet`] with
    /// downstream rules.
    ///
    /// This is the constructor used by `build_pipeline` to wire all four rules
    /// to the same approval registry.
    pub fn new_with_shared_set(
        bundle: ContractBundleHandle,
        principal: Principal,
        approved_set: ApprovedTableSet,
    ) -> Self {
        Self {
            bundle,
            principal,
            audit_records: Mutex::new(Vec::new()),
            approved_tables: Mutex::new(Vec::new()),
            approved_set,
        }
    }

    /// Return a clone of the shared [`ApprovedTableSet`] so downstream rules
    /// can be wired to the same registry.
    pub fn approved_set(&self) -> ApprovedTableSet {
        self.approved_set.clone()
    }

    /// Drain and return all audit records accumulated during the most recent
    /// optimizer pass.
    pub fn drain_audit_records(&self) -> Vec<AuditRecord> {
        let mut guard = self.audit_records.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    /// Return a reference to the contract bundle this rule validates against.
    pub fn bundle(&self) -> &ContractBundleHandle {
        &self.bundle
    }

    /// Return a reference to the principal this rule validates for.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Parse the raw contract bundle bytes as JSON.
    ///
    /// Returns `None` if the bytes are empty (signalling "no contract") or
    /// if JSON parsing fails.
    fn parse_bundle(&self) -> Option<ContractBundleData> {
        let bytes = &self.bundle.raw_bytes;
        if bytes.is_empty() {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    /// Evaluate whether the principal satisfies all constraints in the bundle.
    ///
    /// Returns `Ok(())` on satisfaction or `Err(AuditKind)` indicating why.
    fn check_principal(&self, data: &ContractBundleData) -> Result<(), AuditKind> {
        // Check purpose constraint.
        if !data.allowed_purposes.is_empty()
            && !data
                .allowed_purposes
                .contains(&self.principal.declared_purpose)
        {
            debug!(
                principal_purpose = %self.principal.declared_purpose,
                allowed = ?data.allowed_purposes,
                "purpose mismatch",
            );
            return Err(AuditKind::PurposeMismatch);
        }

        // Check tier constraint (principal tier must be >= required tier).
        if let Some(ref required_tier) = data.required_tier {
            let required_rank = tier_rank(required_tier);
            let principal_rank = tier_rank(&self.principal.tier);
            match (required_rank, principal_rank) {
                (Some(req), Some(pr)) if pr < req => {
                    debug!(
                        principal_tier = %self.principal.tier,
                        required_tier = %required_tier,
                        "tier mismatch",
                    );
                    return Err(AuditKind::TierMismatch);
                }
                _ => {}
            }
        }

        // Check classification constraint.
        // The contract's required_classification must equal the principal's
        // classification (a principal with "restricted" cannot access "internal"
        // data — "restricted" is a higher clearance level that implies
        // access to more sensitive data, not less).
        //
        // Convention used by the tests:
        //   "internal" data → principal must have classification == "internal"
        //   A principal with "restricted" has a HIGHER clearance than
        //   "internal", which per the test (CC-05) is a MISMATCH.
        //
        // This matches the test's wrong_classification_principal() which
        // has classification = "restricted" and expects denial for
        // a contract requiring "internal".  The rule: principal's
        // classification must exactly equal the contract's required
        // classification (no implicit ordering defined yet).
        if let Some(ref required_class) = data.required_classification {
            if &self.principal.classification != required_class {
                debug!(
                    principal_classification = %self.principal.classification,
                    required_classification = %required_class,
                    "classification mismatch",
                );
                return Err(AuditKind::ClassificationMismatch);
            }
        }

        Ok(())
    }

    /// Evaluate a single `TableScan` plan node.
    ///
    /// Returns `(new_plan, Option<ContractCheckMarker>)`:
    /// - On denial: new_plan is an `EmptyRelation`, marker is `None`.
    /// - On approval: new_plan is a `ContractApprovedMarker` Extension wrapping
    ///   the original scan, marker is `Some(...)`.
    fn evaluate_scan(
        &self,
        scan: LogicalPlan,
        table_name: &str,
    ) -> (LogicalPlan, Option<ContractCheckMarker>) {
        // Parse bundle; empty bytes → no contract → deny (INV-1).
        let bundle_data = match self.parse_bundle() {
            None => {
                warn!(table = %table_name, "contract check denied: no bundle data");
                let audit = AuditRecord::new(
                    AuditKind::ContractCheckDenied,
                    table_name,
                    &self.bundle.tenant_id,
                    Some(self.bundle.contract_id.clone()),
                    "no contract bundle present",
                );
                self.audit_records.lock().unwrap().push(audit);
                let empty = empty_relation_from_schema(scan.schema());
                return (empty, None);
            }
            Some(data) => data,
        };

        // Check principal constraints (INV-2).
        match self.check_principal(&bundle_data) {
            Err(kind) => {
                let detail = match &kind {
                    AuditKind::PurposeMismatch => format!(
                        "declared_purpose '{}' not in allowed_purposes {:?}",
                        self.principal.declared_purpose, bundle_data.allowed_purposes,
                    ),
                    AuditKind::TierMismatch => format!(
                        "principal tier '{}' below required '{}'",
                        self.principal.tier,
                        bundle_data.required_tier.as_deref().unwrap_or("?"),
                    ),
                    AuditKind::ClassificationMismatch => format!(
                        "principal classification '{}' != required '{}'",
                        self.principal.classification,
                        bundle_data
                            .required_classification
                            .as_deref()
                            .unwrap_or("?"),
                    ),
                    _ => "contract check denied".to_string(),
                };
                warn!(table = %table_name, %detail, "contract check denied");
                let audit = AuditRecord::new(
                    kind,
                    table_name,
                    &self.bundle.tenant_id,
                    Some(self.bundle.contract_id.clone()),
                    detail,
                );
                self.audit_records.lock().unwrap().push(audit);
                let empty = empty_relation_from_schema(scan.schema());
                (empty, None)
            }
            Ok(()) => {
                debug!(table = %table_name, "contract check approved");
                // Emit ContractCheckApproved audit record.
                let audit = AuditRecord::new(
                    AuditKind::ContractCheckApproved,
                    table_name,
                    &self.bundle.tenant_id,
                    Some(self.bundle.contract_id.clone()),
                    "principal satisfies all contract constraints",
                );
                self.audit_records.lock().unwrap().push(audit);
                let marker = ContractCheckMarker {
                    contract_id: self.bundle.contract_id.clone(),
                    tenant_id: self.bundle.tenant_id.clone(),
                };

                // Finding 1 fix: stamp approval into the shared set AND wrap
                // the scan in a ContractApprovedMarker Extension node so
                // downstream optimizer rules can detect it at the plan level.
                self.approved_set.approve(table_name);

                let schema = scan.schema().clone();
                let approval_node = ContractApprovedMarker {
                    input: Arc::new(scan),
                    contract_id: self.bundle.contract_id.clone(),
                    tenant_id: self.bundle.tenant_id.clone(),
                    output_schema: schema,
                };
                let approval_plan = LogicalPlan::Extension(Extension {
                    node: Arc::new(approval_node),
                });

                (approval_plan, Some(marker))
            }
        }
    }
}

/// Construct an `EmptyRelation` plan with a schema matching `schema`.
fn empty_relation_from_schema(schema: &datafusion::common::DFSchemaRef) -> LogicalPlan {
    // Build an Arrow Schema from the DFSchema and wrap it back.
    let arrow_schema: Schema = schema.as_ref().into();
    let empty_df_schema =
        Arc::new(DFSchema::try_from(arrow_schema).unwrap_or_else(|_| DFSchema::empty()));
    LogicalPlan::EmptyRelation(EmptyRelation {
        produce_one_row: false,
        schema: empty_df_schema,
    })
}

impl OptimizerRule for ContractCheckRule {
    fn name(&self) -> &str {
        "griot_contract_check"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DFResult<Transformed<LogicalPlan>> {
        // Walk the plan tree, rewriting every TableScan node.
        // `transform_down` visits each node top-down, replacing as needed.
        let mut changed = false;
        let new_plan = plan.transform_down(|node| {
            if let LogicalPlan::TableScan(ref ts) = node {
                let table_name = ts.table_name.to_string();
                let (new_node, marker) = self.evaluate_scan(node.clone(), &table_name);
                if let Some(m) = marker {
                    self.approved_tables.lock().unwrap().push(m);
                }
                // Finding 1 fix: approved scan becomes a ContractApprovedMarker
                // Extension; denied scan becomes EmptyRelation.
                // In both cases, the node changed from a TableScan.
                changed = true;
                // Jump: do not recurse into the Extension or EmptyRelation
                // we just inserted (they have no TableScan children to revisit).
                return Ok(Transformed::new(new_node, true, TreeNodeRecursion::Jump));
            }
            Ok(Transformed::no(node))
        })?;

        if changed {
            Ok(Transformed::yes(new_plan.data))
        } else {
            Ok(Transformed::no(new_plan.data))
        }
    }
}
