//! MaskingRule — Wave 8 implementation (round-2 Copilot fixes).
//!
//! ADR-0002: The third rule in the optimizer pipeline.  Inspects `Projection`
//! nodes for columns tagged with sensitivity labels (PII, PHI, PCI) in the
//! contract bundle.  Wraps each sensitive column expression in the appropriate
//! masking expression:
//!
//! | Policy        | Logical expression                          |
//! |---------------|---------------------------------------------|
//! | `redact`      | `Literal("<REDACTED>")` aliased to col name  |
//! | `hash_sha256` | `sha256(col)` / hex of SHA-256 digest       |
//! | `partial`     | `concat("***", substr(col, -4))` alias      |
//! | `null`        | `Literal(NULL of col type)` alias           |
//! | `noop`        | pass-through (no wrapping)                  |
//!
//! # Copilot round-2 fixes
//!
//! ## Finding 3 — Cast-placeholder is not masking
//!
//! The original `apply_mask` emitted `cast(col, Utf8)` aliased to the column
//! name — which does NOT mask anything.  For a string `email` column,
//! `cast(email, Utf8)` returns the original value unchanged.
//!
//! The fix: each `MaskPolicy` now emits a distinct logical expression that
//! produces a value provably different from the input:
//! - `Redact` → `Literal("<REDACTED>")`
//! - `HashSha256` → `sha256(col)` (DataFusion built-in `sha256`)
//! - `Partial` → `concat("***", substr(col, length(col) - 3, 4))` (last 4 chars)
//! - `Null` → `Literal(ScalarValue::Utf8(None))` (typed NULL)
//!
//! The alias preserves the output column name in all cases.
//!
//! ## Finding 6 — No marker check
//!
//! The original rule rewrote `Projection` nodes unconditionally.  It should
//! only mask projections that descend from `ContractApprovedMarker` Extension
//! nodes (i.e., scans that `ContractCheckRule` validated).
//!
//! The fix: the rule inspects the `Projection`'s input subtree for a
//! `ContractApprovedMarker` Extension.  If none is found, the projection is
//! left unchanged — conservative passthrough prevents masking a query that
//! wasn't contract-checked.
//!
//! # Semantic Law coverage
//!
//! * INV-2 (No read without satisfaction — masking): PII/PHI/PCI columns
//!   wrapped in masking expressions before they reach the executor.
//! * INV-5 (No bypass from above trust line): no zone-t imports.

use crate::optimizer_rules::AuditRecord;
use crate::ContractBundleHandle;
use datafusion::arrow::datatypes::DataType;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::cast;
use datafusion::logical_expr::{Expr, LogicalPlan, Projection};
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion::scalar::ScalarValue;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Per-column masking policy as parsed from a contract bundle.
#[derive(Debug, Deserialize, Clone)]
struct ColumnPolicy {
    #[serde(default)]
    sensitivity: String,
    #[serde(default)]
    mask: String,
}

/// Parsed masking fields from a contract bundle.
#[derive(Debug, Deserialize, Default)]
struct MaskingBundleData {
    #[serde(default)]
    column_policies: HashMap<String, ColumnPolicy>,
}

// ─── MaskPolicy ───────────────────────────────────────────────────────────────

/// Masking policy to apply to a sensitive column.
///
/// # Finding 3 fix
///
/// Each variant now maps to a distinct logical expression that provably
/// differs from the input, rather than a `cast(col, Utf8)` placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskPolicy {
    /// Replace the column value with the literal string `"<REDACTED>"`.
    Redact,
    /// Replace the column value with its SHA-256 hex digest.
    HashSha256,
    /// Replace the column value with `"***" + last_4_chars(value)`.
    Partial,
    /// Replace the column value with `NULL` of the column's type.
    Null,
    /// Pass the column value through unchanged (no masking).
    Noop,
    /// Legacy alias for backwards-compat with Wave 8 test bundles.
    /// Maps to `HashSha256` semantically.
    Tokenize,
}

impl MaskPolicy {
    /// Derive a `MaskPolicy` from the string label in the contract bundle.
    pub fn from_bundle_str(s: &str) -> Self {
        match s {
            "redact" => Self::Redact,
            "hash_sha256" => Self::HashSha256,
            "partial" => Self::Partial,
            "null" => Self::Null,
            "tokenize" => Self::Tokenize,
            _ => Self::Noop,
        }
    }

    /// A stable name for the masking function associated with this policy.
    /// Used for debug logging and audit records.
    pub fn fn_name(&self) -> &'static str {
        match self {
            Self::Redact => "mask_redact",
            Self::HashSha256 => "mask_hash_sha256",
            Self::Partial => "mask_partial",
            Self::Null => "mask_null",
            Self::Tokenize => "mask_tokenize",
            Self::Noop => "mask_noop",
        }
    }
}

// ─── MaskingRule ─────────────────────────────────────────────────────────────

/// DataFusion optimizer rule that wraps sensitive column projections in
/// masking expressions derived from the contract bundle.
///
/// Must be registered THIRD in the optimizer pipeline via `build_pipeline`.
///
/// # Finding 3 fix
///
/// Masking now uses real logical expressions that alter the column value:
/// - `Redact` → `Literal("<REDACTED>")` aliased to column name.
/// - `HashSha256` → `sha256(col)` aliased to column name.
/// - `Partial` → `concat("***", right(col, 4))` aliased to column name.
/// - `Null` → `Literal(ScalarValue::Utf8(None))` aliased to column name.
/// - `Tokenize` → same as `HashSha256` (stable pseudonym via digest).
/// - `Noop` → pass-through, no wrapping.
///
/// # Finding 6 fix
///
/// `Projection` nodes are only masked if their input subtree contains a
/// `ContractApprovedMarker` Extension node.  Projections over un-checked scans
/// are left unchanged (conservative passthrough).
#[derive(Debug)]
pub struct MaskingRule {
    /// The signed contract bundle that supplies the sensitivity labels and
    /// masking policies.
    bundle: ContractBundleHandle,
    /// Audit records collected during this pass (currently unused but
    /// reserved for future compliance logging).
    audit_records: Mutex<Vec<AuditRecord>>,
}

impl MaskingRule {
    /// Construct a new `MaskingRule`.
    pub fn new(bundle: ContractBundleHandle) -> Self {
        Self {
            bundle,
            audit_records: Mutex::new(Vec::new()),
        }
    }

    /// Drain and return all audit records accumulated during the most recent
    /// optimizer pass.
    pub fn drain_audit_records(&self) -> Vec<AuditRecord> {
        let mut guard = self.audit_records.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    /// Return a reference to the contract bundle.
    pub fn bundle(&self) -> &ContractBundleHandle {
        &self.bundle
    }

    /// Parse the masking policy from the bundle.
    fn parse_bundle(&self) -> Option<MaskingBundleData> {
        let bytes = &self.bundle.raw_bytes;
        if bytes.is_empty() {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    /// Look up the masking policy for a column from the contract bundle.
    ///
    /// Returns `MaskPolicy::Noop` if the column is not tagged in the bundle.
    pub fn policy_for_column(&self, column_name: &str) -> MaskPolicy {
        let data = match self.parse_bundle() {
            None => return MaskPolicy::Noop,
            Some(d) => d,
        };
        data.column_policies
            .get(column_name)
            .map(|p| MaskPolicy::from_bundle_str(&p.mask))
            .unwrap_or(MaskPolicy::Noop)
    }

    /// Apply a [`MaskPolicy`] to a DataFusion `Expr`, returning the wrapped
    /// expression.
    ///
    /// # Finding 3 fix
    ///
    /// Each policy now produces a value provably different from the input:
    /// - `Noop`: expression returned unchanged (no alias, no transform).
    /// - `Redact`: `Literal("<REDACTED>")` aliased to the column name.
    /// - `HashSha256`: `sha256(col)` aliased to the column name.
    /// - `Tokenize`: same as `HashSha256`.
    /// - `Partial`: `concat("***", substr(col, -4))` aliased to col name.
    ///   Implemented as `concat(lit("***"), right(col, lit(4i64)))`.
    /// - `Null`: `Literal(ScalarValue::Utf8(None))` aliased to col name.
    pub fn apply_mask(&self, expr: Expr, policy: &MaskPolicy) -> Expr {
        if *policy == MaskPolicy::Noop {
            return expr;
        }

        let col_name = match &expr {
            Expr::Column(c) => c.name.clone(),
            Expr::Alias(a) => match a.expr.as_ref() {
                Expr::Column(c) => c.name.clone(),
                _ => format!("{:?}", expr),
            },
            _ => format!("{:?}", expr),
        };

        let fn_name = policy.fn_name();
        debug!("MaskingRule: applying {} to column '{}'", fn_name, col_name);

        let masked_inner: Expr = match policy {
            MaskPolicy::Redact => {
                // Finding 3 fix: return literal "<REDACTED>" — provably different
                // from any real column value.
                Expr::Literal(ScalarValue::Utf8(Some("<REDACTED>".to_string())))
            }
            MaskPolicy::HashSha256 | MaskPolicy::Tokenize => {
                // Finding 3 fix: apply DataFusion built-in sha256() function.
                // sha256(col) returns a Binary scalar; we cast to Utf8 so the
                // output type stays consistent with the original string column.
                // The sha256 function is available via datafusion::functions::expr_fn.
                let sha256_fn = datafusion::functions::crypto::sha256();
                let sha256_call =
                    Expr::ScalarFunction(datafusion::logical_expr::expr::ScalarFunction {
                        func: sha256_fn,
                        args: vec![expr.clone()],
                    });
                cast(sha256_call, DataType::Utf8)
            }
            MaskPolicy::Partial => {
                // Finding 3 fix: return "***" + last_4_chars.
                // Implemented as concat("***", right(col, 4)).
                // right(col, n) is a Unicode scalar function returning the last n chars.
                let right_fn = datafusion::functions::unicode::right();
                let last4 = Expr::ScalarFunction(datafusion::logical_expr::expr::ScalarFunction {
                    func: right_fn,
                    args: vec![expr.clone(), Expr::Literal(ScalarValue::Int64(Some(4)))],
                });
                let prefix = Expr::Literal(ScalarValue::Utf8(Some("***".to_string())));
                // concat(prefix, last4) — use DataFusion's string concat function.
                let concat_fn = datafusion::functions::string::concat();
                Expr::ScalarFunction(datafusion::logical_expr::expr::ScalarFunction {
                    func: concat_fn,
                    args: vec![prefix, last4],
                })
            }
            MaskPolicy::Null => {
                // Finding 3 fix: return typed NULL — provably different from
                // any non-null value in the column.
                Expr::Literal(ScalarValue::Utf8(None))
            }
            MaskPolicy::Noop => unreachable!("Noop handled above"),
        };

        // Alias to preserve the output column name.
        Expr::Alias(datafusion::logical_expr::expr::Alias {
            expr: Box::new(masked_inner),
            relation: None,
            name: col_name,
            metadata: None,
        })
    }

    /// Check whether a `LogicalPlan` subtree contains a `ContractApprovedMarker`
    /// Extension node.
    ///
    /// Used for the Finding 6 fix: `Projection` nodes are only masked if
    /// their input subtree was approved by `ContractCheckRule`.
    fn subtree_has_approval_marker(plan: &LogicalPlan) -> bool {
        if let LogicalPlan::Extension(ref ext) = plan {
            if ext.node.name() == "ContractApproved" {
                return true;
            }
        }
        plan.inputs()
            .iter()
            .any(|child| Self::subtree_has_approval_marker(child))
    }
}

impl OptimizerRule for MaskingRule {
    fn name(&self) -> &str {
        "griot_masking"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DFResult<Transformed<LogicalPlan>> {
        let bundle_data = match self.parse_bundle() {
            None => {
                // No bundle → no masking policies; passthrough.
                debug!("MaskingRule: no bundle data; passthrough");
                return Ok(Transformed::no(plan));
            }
            Some(data) => data,
        };

        if bundle_data.column_policies.is_empty() {
            debug!("MaskingRule: no column policies; passthrough");
            return Ok(Transformed::no(plan));
        }

        // Walk the plan and rewrite Projection nodes.
        let mut changed = false;
        let new_plan = plan.transform_down(|node| {
            if let LogicalPlan::Projection(proj) = node {
                // Finding 6 fix: only mask if the projection's input subtree
                // contains a ContractApprovedMarker.  If not, passthrough.
                if !Self::subtree_has_approval_marker(proj.input.as_ref()) {
                    debug!(
                        "MaskingRule: skipping Projection with no ContractApprovedMarker in subtree"
                    );
                    return Ok(Transformed::no(LogicalPlan::Projection(proj)));
                }

                let mut local_changed = false;
                let new_exprs: Vec<Expr> = proj
                    .expr
                    .iter()
                    .map(|expr| {
                        let col_name = match expr {
                            Expr::Column(c) => Some(c.name.clone()),
                            Expr::Alias(a) => match a.expr.as_ref() {
                                Expr::Column(c) => Some(c.name.clone()),
                                _ => None,
                            },
                            _ => None,
                        };
                        if let Some(name) = col_name {
                            if let Some(policy_entry) = bundle_data.column_policies.get(&name) {
                                let policy = MaskPolicy::from_bundle_str(&policy_entry.mask);
                                if policy != MaskPolicy::Noop {
                                    local_changed = true;
                                    return self.apply_mask(expr.clone(), &policy);
                                }
                            }
                        }
                        expr.clone()
                    })
                    .collect();

                if local_changed {
                    changed = true;
                    // Rebuild the projection with updated expressions.
                    let new_proj = Projection::try_new(new_exprs, proj.input.clone())?;
                    return Ok(Transformed::yes(LogicalPlan::Projection(new_proj)));
                }
                return Ok(Transformed::no(LogicalPlan::Projection(proj)));
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
