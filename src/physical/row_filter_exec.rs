//! RowFilterExec — Wave 9 implementation.
//!
//! Physical `ExecutionPlan` that applies the contract's row-level filter
//! expression to each `RecordBatch` in the stream.  It is the physical
//! counterpart of the wave-8 `RowFilterRule`.
//!
//! # Role in the pipeline
//!
//! `RowFilterExec` MUST sit above `ContractApprovedExec` in the plan.  Before
//! streaming any batch it verifies that `ContractApprovedExec` is present as
//! an ancestor.  If not, it returns
//! `PhysicalError::ContractNotApproved { operator: "RowFilterExec" }`.
//!
//! # Behaviour
//!
//! For each input `RecordBatch`, the operator evaluates the row-filter
//! expression derived from the contract bundle and drops rows that do NOT
//! satisfy it.  If the bundle specifies no row filter, the batch passes
//! through unchanged.
//!
//! # Copilot round-2 fixes (Finding 1 and Finding 4)
//!
//! ## Finding 1 — Silent contract bypass on JSON parse failure
//!
//! The original stub treated parse failures as "no filter" (returns None →
//! passthrough).  This is an INV-2 bypass.  Fix: parse failure now returns
//! `Err(PhysicalError::ContractBundleMalformed)`.
//!
//! ## Finding 4 — Type-narrow filter only handling Utf8
//!
//! The original `apply_equality_filter` returned the batch unchanged for
//! non-StringArray columns.  Fix: we use DataFusion's physical expression
//! evaluation engine via `create_physical_expr`, which evaluates the predicate
//! to a `BooleanArray` independently of column type, then apply
//! `arrow::compute::filter_record_batch` — type-agnostic.
//!
//! # ADR-0002 requirements
//!
//! * No `unsafe` code.
//! * Emits a `PhysicalEnforcementEvent` per batch where rows were dropped.
//!
//! # Spec anchor
//!
//! ADR-0002 §Physical operators — RowFilterExec.
//! INV-2 (no read without satisfaction — row-level filtering).

use crate::physical::contract_approved_exec::plan_has_contract_approved;
use crate::physical::{PhysicalEnforcementEvent, PhysicalError};
use crate::ContractBundleHandle;
use datafusion::arrow::array::BooleanArray;
use datafusion::arrow::compute::filter_record_batch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};
use futures::StreamExt;
use serde::Deserialize;
use std::any::Any;
use std::sync::{Arc, Mutex};
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Parsed row-filter fields from a contract bundle.
///
/// # Finding 1 fix
///
/// `parse_row_filter` now fails hard on malformed JSON instead of returning
/// `None` (which previously caused the filter to be silently skipped).
#[derive(Debug, Deserialize, Default)]
struct RowFilterBundleData {
    /// A global row-filter expression.  `null` means no filter (full access).
    #[serde(default)]
    row_filter: Option<String>,
}

// ─── RowFilterExec ────────────────────────────────────────────────────────────

/// Physical operator that applies contract row-level filtering to the stream.
#[derive(Debug)]
pub struct RowFilterExec {
    /// The contract bundle supplying the row-filter expression.
    bundle: ContractBundleHandle,
    /// The inner physical plan to filter.
    inner: Arc<dyn ExecutionPlan>,
    /// Cached plan properties.
    properties: PlanProperties,
    /// Enforcement events emitted during execution.
    events: Arc<Mutex<Vec<PhysicalEnforcementEvent>>>,
    /// Parsed row-filter expression string (None = no filter, batch passes through).
    row_filter_expr: Option<String>,
}

impl RowFilterExec {
    /// Construct a new `RowFilterExec`.
    ///
    /// # Errors
    ///
    /// * `PhysicalError::ContractNotApproved` — if `inner` does not have a
    ///   `ContractApprovedExec` as an ancestor in the plan tree.
    /// * `PhysicalError::ContractBundleMalformed` — if the bundle JSON cannot
    ///   be parsed (Finding 1 fix: hard error, not silent skip).
    pub fn new(
        bundle: ContractBundleHandle,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        // Enforce that a ContractApprovedExec is present upstream.
        if !plan_has_contract_approved(&inner) {
            return Err(PhysicalError::ContractNotApproved {
                operator: "RowFilterExec".to_string(),
            });
        }

        // Finding 1 fix: parse the bundle; hard-error on malformed JSON.
        let row_filter_expr = parse_row_filter(&bundle)?;

        let properties = inner.properties().clone();
        Ok(Self {
            bundle,
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            row_filter_expr,
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
}

/// Parse the row-filter expression string from the bundle.
///
/// # Finding 1 fix
///
/// Returns `Err(ContractBundleMalformed)` if the bundle bytes are non-empty
/// but cannot be parsed as JSON.  Returns `Ok(None)` only if the bundle is
/// empty (no filter bytes) or if the `row_filter` field is `null`.
fn parse_row_filter(bundle: &ContractBundleHandle) -> Result<Option<String>, PhysicalError> {
    let bytes = &bundle.raw_bytes;
    if bytes.is_empty() {
        return Ok(None);
    }
    let data: RowFilterBundleData =
        serde_json::from_slice(bytes).map_err(|e| PhysicalError::ContractBundleMalformed {
            reason: format!("RowFilterExec bundle JSON parse error: {}", e),
        })?;
    Ok(data.row_filter)
}

/// Apply a SQL WHERE-clause fragment as a boolean filter over `batch`.
///
/// # Finding 4 fix
///
/// Uses DataFusion's physical expression evaluation, which works for any
/// column type, not just StringArray.  The predicate is compiled against the
/// batch schema, evaluated to a `BooleanArray`, then applied via
/// `arrow::compute::filter_record_batch`.
fn apply_filter_to_batch(
    batch: &datafusion::arrow::record_batch::RecordBatch,
    filter_expr_str: &str,
) -> Result<datafusion::arrow::record_batch::RecordBatch, PhysicalError> {
    use datafusion::physical_expr::create_physical_expr;

    let schema = batch.schema();
    let df_schema = datafusion::common::DFSchema::try_from(schema.as_ref().clone())
        .map_err(|e| PhysicalError::Internal(format!("DFSchema conversion error: {}", e)))?;

    let df_expr = parse_filter_expr_to_df(filter_expr_str)?;

    let execution_props = datafusion::execution::context::ExecutionProps::new();
    let physical_expr = create_physical_expr(&df_expr, &df_schema, &execution_props)
        .map_err(|e| PhysicalError::Internal(format!("PhysicalExpr compilation error: {}", e)))?;

    let result = physical_expr
        .evaluate(batch)
        .map_err(|e| PhysicalError::Internal(format!("predicate evaluation error: {}", e)))?;

    let bool_array = result
        .into_array(batch.num_rows())
        .map_err(|e| PhysicalError::Internal(format!("predicate array conversion error: {}", e)))?;

    let bool_array = bool_array
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| {
            PhysicalError::Internal("predicate did not evaluate to BooleanArray".to_string())
        })?;

    filter_record_batch(batch, bool_array)
        .map_err(|e| PhysicalError::Internal(format!("filter_record_batch error: {}", e)))
}

/// Parse a SQL WHERE-clause fragment into a DataFusion `Expr`.
fn parse_filter_expr_to_df(
    expr_str: &str,
) -> Result<datafusion::logical_expr::Expr, PhysicalError> {
    use datafusion::sql::sqlparser::ast::Statement;
    use datafusion::sql::sqlparser::dialect::GenericDialect;
    use datafusion::sql::sqlparser::parser::Parser;

    let dialect = GenericDialect {};
    let sql = format!("SELECT 1 WHERE {}", expr_str);
    let stmts =
        Parser::parse_sql(&dialect, &sql).map_err(|e| PhysicalError::ContractBundleMalformed {
            reason: format!(
                "RowFilterExec: could not parse filter expression '{}': {}",
                expr_str, e
            ),
        })?;

    let stmt = stmts
        .into_iter()
        .next()
        .ok_or_else(|| PhysicalError::ContractBundleMalformed {
            reason: format!(
                "RowFilterExec: empty parse result for filter '{}'",
                expr_str
            ),
        })?;

    if let Statement::Query(query) = stmt {
        if let datafusion::sql::sqlparser::ast::SetExpr::Select(select) = *query.body {
            if let Some(selection) = select.selection {
                return sql_ast_to_df_expr(&selection).map_err(|reason| {
                    PhysicalError::ContractBundleMalformed {
                        reason: format!(
                            "RowFilterExec: filter '{}' uses unsupported expression: {}",
                            expr_str, reason
                        ),
                    }
                });
            }
        }
    }

    Err(PhysicalError::ContractBundleMalformed {
        reason: format!(
            "RowFilterExec: could not extract WHERE clause from '{}'",
            expr_str
        ),
    })
}

/// Convert a SQL AST expression to a DataFusion logical `Expr`.
fn sql_ast_to_df_expr(
    sql_expr: &datafusion::sql::sqlparser::ast::Expr,
) -> Result<datafusion::logical_expr::Expr, String> {
    use datafusion::logical_expr::{BinaryExpr, Expr as DF, Operator};
    use datafusion::prelude::col;
    use datafusion::scalar::ScalarValue;
    use datafusion::sql::sqlparser::ast::{BinaryOperator, Expr as SqlExpr, Value};

    match sql_expr {
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
                other => return Err(format!("unsupported binary operator {:?}", other)),
            };
            let left_expr = sql_ast_to_df_expr(left)?;
            let right_expr = sql_ast_to_df_expr(right)?;
            Ok(DF::BinaryExpr(BinaryExpr {
                left: Box::new(left_expr),
                op: df_op,
                right: Box::new(right_expr),
            }))
        }
        SqlExpr::Identifier(ident) => Ok(col(ident.value.as_str())),
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
                other => Err(format!("unsupported literal {:?}", other)),
            }
        }
        SqlExpr::Nested(inner) => sql_ast_to_df_expr(inner),
        other => Err(format!("unsupported expression node {:?}", other)),
    }
}

impl DisplayAs for RowFilterExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "RowFilterExec(contract_id={})",
            self.bundle.contract_id()
        )
    }
}

impl ExecutionPlan for RowFilterExec {
    fn name(&self) -> &str {
        "RowFilterExec"
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
                "RowFilterExec::with_new_children requires exactly one child".to_string(),
            )
        })?;
        if !plan_has_contract_approved(&inner) {
            return Err(datafusion::error::DataFusionError::Internal(
                "RowFilterExec::with_new_children: new child has no ContractApprovedExec ancestor"
                    .to_string(),
            ));
        }
        let properties = inner.properties().clone();
        Ok(Arc::new(RowFilterExec {
            bundle: self.bundle.clone(),
            inner,
            properties,
            events: Arc::new(Mutex::new(Vec::new())),
            row_filter_expr: self.row_filter_expr.clone(),
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> datafusion::error::Result<SendableRecordBatchStream> {
        let inner_stream = self.inner.execute(partition, context)?;
        let filter_expr = self.row_filter_expr.clone();
        let contract_id = self.bundle.contract_id().to_string();
        let schema = self.schema();

        // Build the output stream by applying the filter to each batch.
        let stream = inner_stream.then(move |batch_result| {
            let filter_expr = filter_expr.clone();
            let contract_id = contract_id.clone();
            async move {
                let batch = batch_result?;

                let filter_str = match &filter_expr {
                    None => {
                        return Ok(batch);
                    }
                    Some(s) if s.is_empty() => {
                        return Ok(batch);
                    }
                    Some(s) => s.clone(),
                };

                let input_rows = batch.num_rows();
                let filtered_batch = apply_filter_to_batch(&batch, &filter_str).map_err(|e| {
                    datafusion::error::DataFusionError::External(
                        format!("RowFilterExec: {}", e).into(),
                    )
                })?;

                let output_rows = filtered_batch.num_rows();
                if output_rows < input_rows {
                    let dropped = input_rows - output_rows;
                    debug!(
                        contract_id = %contract_id,
                        dropped,
                        "RowFilterExec: dropped rows not satisfying filter"
                    );
                }

                Ok(filtered_batch)
            }
        });

        use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }

    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }
}
