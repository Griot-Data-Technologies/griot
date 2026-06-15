//! [`ContractTableProvider`] — a DataFusion table whose every scan is governed.
//!
//! It wraps a raw (ungoverned) [`TableProvider`] together with a
//! [`ResolvedPolicy`]. When DataFusion asks it to `scan()`, it reads the raw
//! data and threads it through the contract enforcement operators —
//! `ContractApprovedExec` → `RowFilterExec` → `MaskingExec` →
//! (`LaplaceNoiseExec`) — before any rows leave the table. There is no scan path
//! that skips them.
//!
//! The inner table is scanned in full (no projection pushdown) so the operators
//! can see every column the contract references (a row filter may key off a
//! column the query did not select); the caller's projection and limit are then
//! applied on top of the governed plan so the output schema matches what
//! DataFusion expects.

use std::any::Any;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::{DataFusionError, Result as DFResult};
use datafusion::logical_expr::Expr;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::limit::GlobalLimitExec;
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::ExecutionPlan;

use crate::physical::contract_approved_exec::ContractApprovedExec;
use crate::physical::laplace_noise_exec::LaplaceNoiseExec;
use crate::physical::masking_exec::MaskingExec;
use crate::physical::row_filter_exec::RowFilterExec;
use crate::physical::PhysicalError;
use crate::policy::ResolvedPolicy;
use crate::ContractBundleHandle;

/// A table provider that enforces a contract on every scan.
#[derive(Debug)]
pub struct ContractTableProvider {
    inner: Arc<dyn TableProvider>,
    bundle: ContractBundleHandle,
    tenant_id: String,
    has_dp: bool,
}

impl ContractTableProvider {
    /// Wrap `inner` so it is governed by `policy`.
    pub fn new(inner: Arc<dyn TableProvider>, policy: &ResolvedPolicy) -> Self {
        Self {
            inner,
            bundle: policy.to_bundle_handle(),
            tenant_id: policy.tenant_id.clone(),
            has_dp: policy.has_dp(),
        }
    }
}

fn phys_to_df(e: PhysicalError) -> DataFusionError {
    DataFusionError::External(Box::new(e))
}

/// Project `plan` down to `indices` (so the governed full-schema plan matches
/// the projection DataFusion requested for the query).
fn apply_projection(
    plan: Arc<dyn ExecutionPlan>,
    indices: &[usize],
) -> DFResult<Arc<dyn ExecutionPlan>> {
    let schema = plan.schema();
    let exprs: Vec<(Arc<dyn PhysicalExpr>, String)> = indices
        .iter()
        .map(|&i| {
            let field = schema.field(i);
            let col = Arc::new(Column::new(field.name(), i)) as Arc<dyn PhysicalExpr>;
            (col, field.name().to_string())
        })
        .collect();
    Ok(Arc::new(ProjectionExec::try_new(exprs, plan)?))
}

#[async_trait]
impl TableProvider for ContractTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        // Scan the raw table in full — the contract operators need every column
        // the contract references, regardless of the query's SELECT list.
        let inner_plan = self.inner.scan(state, None, &[], None).await?;

        // Build the contract enforcement stack. `ContractApprovedExec` is the
        // proof the scan was contract-checked; the downstream operators refuse
        // to run without it upstream.
        let approved: Arc<dyn ExecutionPlan> = Arc::new(
            ContractApprovedExec::new(self.bundle.clone(), inner_plan).map_err(phys_to_df)?,
        );
        let filtered: Arc<dyn ExecutionPlan> =
            Arc::new(RowFilterExec::new(self.bundle.clone(), approved).map_err(phys_to_df)?);
        let masked: Arc<dyn ExecutionPlan> =
            Arc::new(MaskingExec::new(self.bundle.clone(), filtered).map_err(phys_to_df)?);
        let governed: Arc<dyn ExecutionPlan> = if self.has_dp {
            Arc::new(
                LaplaceNoiseExec::new_permissive(
                    self.bundle.clone(),
                    self.tenant_id.clone(),
                    masked,
                )
                .map_err(phys_to_df)?,
            )
        } else {
            masked
        };

        // Honor the query's projection and limit on top of the governed plan.
        let projected = match projection {
            Some(indices) => apply_projection(governed, indices)?,
            None => governed,
        };
        let limited = match limit {
            Some(n) => {
                Arc::new(GlobalLimitExec::new(projected, 0, Some(n))) as Arc<dyn ExecutionPlan>
            }
            None => projected,
        };

        Ok(limited)
    }
}
