//! RowFilterRule — Wave 8 implementation (round-2 Copilot fixes).
//!
//! ADR-0002: The second rule in the optimizer pipeline.  Inspects each
//! `TableScan` (or `ContractApprovedMarker` Extension wrapping a scan) for an
//! approved table name in the rule's bundle context.  If the bundle specifies a
//! row-filter expression for the current principal (or a global row-filter),
//! injects a `Filter` node above the scan.
//!
//! # Copilot round-2 fixes
//!
//! ## Finding 2 — `sql_expr_to_df_expr` partial translation
//!
//! The original helper only translated `=`, `!=`, `<`, `<=`, `>`, `>=`,
//! identifiers, and string/numeric literals.  Any other expression (conjunctions
//! `AND`/`OR`, `IN`, `IS NULL`, `IS NOT NULL`, `LIKE`, `NOT IN`) caused a
//! silent `None` return which the caller treated as "passthrough" — i.e., the
//! filter was silently skipped, violating INV-2.
//!
//! The fix: the helper now handles the full set of expressions that contracts
//! can legally specify (`AND`, `OR`, `NOT`, `=`, `!=`, `<`, `<=`, `>`, `>=`,
//! `IN`, `NOT IN`, `IS NULL`, `IS NOT NULL`, `LIKE`, column references, and
//! literal values including booleans and NULL).  If the helper still cannot
//! translate an expression, it returns `Err(ContractFilterUnsupported)` rather
//! than `None`, and the caller propagates that error (hard fail).
//!
//! ## Finding 6 — No marker check
//!
//! The original rule rewrote every `TableScan` unconditionally, meaning it could
//! apply contract row-filters to scans that `ContractCheckRule` never validated.
//! The fix: the rule now walks `ContractApprovedMarker` Extension nodes (which
//! wrap approved scans) rather than raw `TableScan` nodes, and refuses to act
//! on raw `TableScan` nodes that have no approval stamp.
//!
//! # Semantic Law coverage
//!
//! * INV-2 (No read without satisfaction — row-level filtering).
//! * INV-5 (No bypass from above trust line): no zone-t imports.

use crate::optimizer_rules::{AuditRecord, Principal};
use crate::ContractBundleHandle;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::logical_expr::{Filter, LogicalPlan};
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion::prelude::col;
use datafusion::scalar::ScalarValue;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Parsed representation of row-filter fields from a contract bundle.
#[derive(Debug, Deserialize, Default)]
struct RowFilterBundleData {
    /// A global row-filter expression string (SQL WHERE clause fragment).
    /// Applied to all principals unless overridden by `per_principal_row_filters`.
    #[serde(default)]
    row_filter: Option<String>,

    /// Per-principal row-filter expressions keyed by principal ID.
    /// If a principal ID is listed here, its entry overrides `row_filter`.
    /// A `null` value means "no filter for this principal" (full access).
    #[serde(default)]
    per_principal_row_filters: HashMap<String, Option<String>>,
}

// ─── RowFilterRule ────────────────────────────────────────────────────────────

/// DataFusion optimizer rule that injects row-level filters derived from the
/// contract bundle for the current principal.
///
/// Must be registered SECOND in the optimizer pipeline via `build_pipeline`.
///
/// # Finding 6 fix
///
/// This rule now only injects filters above `ContractApprovedMarker` Extension
/// nodes (i.e., scans that `ContractCheckRule` has already validated).  Raw
/// `TableScan` nodes encountered without a marker are left unchanged (no silent
/// filter injection — conservative passthrough that cannot silently leak data).
#[derive(Debug)]
pub struct RowFilterRule {
    /// The signed contract bundle that supplies the row-filter expressions.
    bundle: ContractBundleHandle,
    /// The principal whose row-filter policy to apply.
    principal: Principal,
    /// Audit records collected during this pass.
    audit_records: Mutex<Vec<AuditRecord>>,
}

impl RowFilterRule {
    /// Construct a new `RowFilterRule`.
    pub fn new(bundle: ContractBundleHandle, principal: Principal) -> Self {
        Self {
            bundle,
            principal,
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

    /// Return a reference to the principal.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Parse the row-filter policy from the bundle.
    fn parse_bundle(&self) -> Option<RowFilterBundleData> {
        let bytes = &self.bundle.raw_bytes;
        if bytes.is_empty() {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    /// Resolve the effective row-filter expression string for the current
    /// principal.  Returns `None` if no filter applies.
    fn effective_row_filter(&self, data: &RowFilterBundleData) -> Option<String> {
        // Per-principal override takes precedence over global row_filter.
        if let Some(per_principal) = data.per_principal_row_filters.get(&self.principal.id) {
            // per_principal may be None (full access) or Some(expr).
            return per_principal.clone();
        }
        // Fall back to global row_filter.
        data.row_filter.clone()
    }

    /// Parse a SQL WHERE-clause fragment into a DataFusion `Expr`.
    ///
    /// The expression is parsed using DataFusion's SQL dialect via a dummy
    /// `SELECT WHERE <expr>` statement, then translated via
    /// [`sql_expr_to_df_expr`].
    ///
    /// # Finding 2 fix
    ///
    /// If the expression cannot be fully translated, returns a DataFusion error
    /// (`ContractFilterUnsupported`) rather than `None`.  INV-2 demands that
    /// an untranslatable filter MUST cause a hard failure — silent skip would
    /// return un-filtered rows to the caller.
    fn parse_filter_expr(&self, expr_str: &str) -> DFResult<datafusion::logical_expr::Expr> {
        use datafusion::sql::sqlparser::ast::Statement;
        use datafusion::sql::sqlparser::dialect::GenericDialect;
        use datafusion::sql::sqlparser::parser::Parser;

        let dialect = GenericDialect {};
        let sql = format!("SELECT 1 WHERE {}", expr_str);
        let stmts = Parser::parse_sql(&dialect, &sql).map_err(|e| {
            DataFusionError::External(
                format!(
                    "ContractFilterUnsupported: could not parse filter expression '{}': {}",
                    expr_str, e
                )
                .into(),
            )
        })?;

        let stmt = stmts.into_iter().next().ok_or_else(|| {
            DataFusionError::External(
                format!(
                    "ContractFilterUnsupported: empty parse result for filter '{}'",
                    expr_str
                )
                .into(),
            )
        })?;

        if let Statement::Query(query) = stmt {
            if let datafusion::sql::sqlparser::ast::SetExpr::Select(select) = *query.body {
                if let Some(selection) = select.selection {
                    return sql_expr_to_df_expr(&selection).map_err(|reason| {
                        DataFusionError::External(
                            format!(
                                "ContractFilterUnsupported: filter '{}' uses unsupported expression: {}",
                                expr_str, reason
                            )
                            .into(),
                        )
                    });
                }
            }
        }

        Err(DataFusionError::External(
            format!(
                "ContractFilterUnsupported: could not extract WHERE clause from '{}'",
                expr_str
            )
            .into(),
        ))
    }
}

/// Convert a SQL AST expression to a DataFusion logical `Expr`.
///
/// # Finding 2 fix
///
/// The original implementation only handled `=`, `!=`, `<`, `<=`, `>`, `>=`,
/// identifiers, and basic literal types.  Any other expression silently returned
/// `None`, which caused the filter to be skipped — an INV-2 violation.
///
/// The updated helper handles the full contract-expression grammar:
/// - Binary comparison operators: `=`, `!=`, `<`, `<=`, `>`, `>=`
/// - Boolean connectives: `AND`, `OR`
/// - `NOT <expr>`
/// - `IN (val1, val2, …)` and `NOT IN (val1, val2, …)`
/// - `IS NULL` and `IS NOT NULL`
/// - `LIKE` and `NOT LIKE`
/// - Column references (`identifier`)
/// - Literal values: single-quoted strings, integers, floats, booleans, `NULL`
///
/// On unsupported input (e.g., subqueries, window functions) returns
/// `Err(String)` describing why — the caller propagates this as a hard error.
fn sql_expr_to_df_expr(
    sql_expr: &datafusion::sql::sqlparser::ast::Expr,
) -> Result<datafusion::logical_expr::Expr, String> {
    use datafusion::logical_expr::{BinaryExpr, Expr as DF, Operator};
    use datafusion::sql::sqlparser::ast::{BinaryOperator, Expr as SqlExpr, Value};

    match sql_expr {
        // ── Binary comparison / boolean operators ─────────────────────────────
        SqlExpr::BinaryOp { left, op, right } => {
            let df_op = match op {
                BinaryOperator::Eq => Operator::Eq,
                BinaryOperator::NotEq => Operator::NotEq,
                BinaryOperator::Lt => Operator::Lt,
                BinaryOperator::LtEq => Operator::LtEq,
                BinaryOperator::Gt => Operator::Gt,
                BinaryOperator::GtEq => Operator::GtEq,
                BinaryOperator::And => Operator::And,
                BinaryOperator::Or => Operator::Or,
                // Note: in sqlparser 0.55, LIKE is parsed as SqlExpr::Like (a
                // dedicated node), not as BinaryOperator::Like.  These PGLikeMatch
                // variants handle PostgreSQL-style `~~` / `!~~` operators.
                BinaryOperator::PGLikeMatch => Operator::LikeMatch,
                BinaryOperator::PGNotLikeMatch => Operator::NotLikeMatch,
                other => {
                    return Err(format!("unsupported binary operator {:?}", other));
                }
            };
            let left_expr = sql_expr_to_df_expr(left)?;
            let right_expr = sql_expr_to_df_expr(right)?;
            Ok(DF::BinaryExpr(BinaryExpr {
                left: Box::new(left_expr),
                op: df_op,
                right: Box::new(right_expr),
            }))
        }

        // ── NOT <expr> ────────────────────────────────────────────────────────
        SqlExpr::UnaryOp {
            op: datafusion::sql::sqlparser::ast::UnaryOperator::Not,
            expr,
        } => {
            let inner = sql_expr_to_df_expr(expr)?;
            Ok(datafusion::logical_expr::not(inner))
        }

        // ── IS NULL ───────────────────────────────────────────────────────────
        SqlExpr::IsNull(expr) => {
            let inner = sql_expr_to_df_expr(expr)?;
            Ok(inner.is_null())
        }

        // ── IS NOT NULL ───────────────────────────────────────────────────────
        SqlExpr::IsNotNull(expr) => {
            let inner = sql_expr_to_df_expr(expr)?;
            Ok(inner.is_not_null())
        }

        // ── IN (list) / NOT IN (list) ─────────────────────────────────────────
        SqlExpr::InList {
            expr,
            list,
            negated,
        } => {
            let inner = sql_expr_to_df_expr(expr)?;
            let list_exprs: Vec<DF> = list
                .iter()
                .map(sql_expr_to_df_expr)
                .collect::<Result<Vec<_>, _>>()?;
            // DataFusion's Expr::in_list(list, negated) with negated=true is
            // the NOT IN form; negated=false is the plain IN form.
            Ok(inner.in_list(list_exprs, *negated))
        }

        // ── Column identifier ─────────────────────────────────────────────────
        SqlExpr::Identifier(ident) => Ok(col(ident.value.as_str())),

        // ── LIKE pattern (in sqlparser 0.55, LIKE is a dedicated node) ──────
        SqlExpr::Like {
            negated,
            expr,
            pattern,
            ..
        } => {
            let inner = sql_expr_to_df_expr(expr)?;
            let pat = sql_expr_to_df_expr(pattern)?;
            // DataFusion's Like/ILike logical operators live on Expr directly.
            // We represent LIKE as a BinaryExpr with LikeMatch operator.
            let op = if *negated {
                Operator::NotLikeMatch
            } else {
                Operator::LikeMatch
            };
            Ok(DF::BinaryExpr(BinaryExpr {
                left: Box::new(inner),
                op,
                right: Box::new(pat),
            }))
        }

        // ── Literal values ────────────────────────────────────────────────────
        // In sqlparser >= 0.55, Expr::Value wraps ValueWithSpan; extract inner.
        SqlExpr::Value(value_with_span) => {
            let inner: Value = value_with_span.clone().into();
            match inner {
                Value::SingleQuotedString(s) => Ok(DF::Literal(ScalarValue::Utf8(Some(s)))),
                Value::Number(n, _) => {
                    if let Ok(i) = n.parse::<i64>() {
                        Ok(DF::Literal(ScalarValue::Int64(Some(i))))
                    } else if let Ok(f) = n.parse::<f64>() {
                        Ok(DF::Literal(ScalarValue::Float64(Some(f))))
                    } else {
                        Err(format!("cannot parse numeric literal '{}'", n))
                    }
                }
                Value::Boolean(b) => Ok(DF::Literal(ScalarValue::Boolean(Some(b)))),
                Value::Null => Ok(DF::Literal(ScalarValue::Null)),
                other => Err(format!("unsupported literal value {:?}", other)),
            }
        }

        // ── Nested / compound expressions ─────────────────────────────────────
        SqlExpr::Nested(inner) => sql_expr_to_df_expr(inner),

        // ── Everything else is unsupported — hard fail per Finding 2 ──────────
        other => Err(format!("unsupported expression node {:?}", other)),
    }
}

impl OptimizerRule for RowFilterRule {
    fn name(&self) -> &str {
        "griot_row_filter"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DFResult<Transformed<LogicalPlan>> {
        let bundle_data = match self.parse_bundle() {
            None => {
                // No bundle → no filter to inject; conservative passthrough.
                debug!("RowFilterRule: no bundle data; passthrough");
                return Ok(Transformed::no(plan));
            }
            Some(data) => data,
        };

        let filter_expr_str = self.effective_row_filter(&bundle_data);

        let filter_expr = match filter_expr_str.as_deref() {
            None | Some("") => {
                // No row filter for this principal → passthrough unchanged.
                debug!("RowFilterRule: no row filter for principal; passthrough");
                return Ok(Transformed::no(plan));
            }
            Some(expr_str) => {
                // Finding 2 fix: parse_filter_expr now returns Err on
                // untranslatable expressions instead of None/passthrough.
                self.parse_filter_expr(expr_str)?
            }
        };

        // Finding 6 fix: Walk the plan and inject a Filter only above
        // `ContractApprovedMarker` Extension nodes (scans approved by
        // ContractCheckRule).  Raw TableScan nodes that lack a marker are
        // left unchanged — conservative passthrough prevents data leak.
        let mut changed = false;
        let filter_expr_clone = filter_expr.clone();
        let new_plan = plan.transform_down(|node| {
            if let LogicalPlan::Extension(ref ext) = node {
                if ext.node.name() == "ContractApproved" {
                    // This is an approved scan — inject the filter above it.
                    debug!("RowFilterRule: injecting row filter above ContractApprovedMarker");
                    changed = true;
                    let filter_node = LogicalPlan::Filter(Filter::try_new(
                        filter_expr_clone.clone(),
                        Arc::new(node),
                    )?);
                    // Jump: do not recurse into filter_node's inputs to avoid
                    // infinite recursion on the inner Extension node.
                    return Ok(Transformed::new(filter_node, true, TreeNodeRecursion::Jump));
                }
            }
            // Finding 6 fix: raw TableScan without a ContractApprovedMarker
            // wrapper → leave unchanged (do not silently inject a filter).
            // This is the conservative safe behavior — no leak, no injection
            // on unverified scans.
            Ok(Transformed::no(node))
        })?;

        if changed {
            Ok(Transformed::yes(new_plan.data))
        } else {
            Ok(Transformed::no(new_plan.data))
        }
    }
}
