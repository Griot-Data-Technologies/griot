//! ContractApprovedExec — Wave 9 implementation.
//!
//! Physical `ExecutionPlan` that acts as a marker propagating contract approval
//! through the physical execution stream.  It is the physical counterpart of the
//! wave-8 `ContractCheckMarker` logical extension.
//!
//! # Role in the pipeline
//!
//! `ContractApprovedExec` wraps the lowest-level physical plan produced by
//! DataFusion's physical planner.  Its presence in the plan is the proof that
//! `ContractCheckRule` ran and approved the query.  Downstream physical operators
//! (`RowFilterExec`, `MaskingExec`, `LaplaceNoiseExec`) MUST verify that a
//! `ContractApprovedExec` exists somewhere above them in the plan tree.
//!
//! # ADR-0002 requirements
//!
//! * No `unsafe` code.
//! * Sealed constructor: external code cannot instantiate without contract bundle.
//! * Emits a `PhysicalEnforcementEvent` so `AttestationExec` can include it.
//!
//! # Spec anchor
//!
//! ADR-0002 §Physical operators — ContractApprovedExec.
//! INV-1 (no data in without contract).

use crate::physical::{PhysicalEnforcementEvent, PhysicalError};
use crate::ContractBundleHandle;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};
use std::any::Any;
use std::sync::Arc;

/// Physical marker operator that propagates contract approval through the
/// execution stream.
///
/// # Sealed constructor
///
/// The only public constructor is `ContractApprovedExec::new`, which requires
/// a `ContractBundleHandle`.  There is no `Default` or struct-literal
/// construction from outside this module.
#[derive(Debug)]
pub struct ContractApprovedExec {
    /// The signed contract bundle that authorised this query.
    bundle: ContractBundleHandle,
    /// The inner physical plan to execute.
    inner: Arc<dyn ExecutionPlan>,
    /// Cached plan properties (schema, partitioning, etc.).
    properties: PlanProperties,
    /// Enforcement events emitted (collected for AttestationExec).
    events: std::sync::Mutex<Vec<PhysicalEnforcementEvent>>,
}

impl ContractApprovedExec {
    /// Construct a new `ContractApprovedExec` wrapping `inner`.
    ///
    /// `bundle` — the signed contract bundle from T04; must not be empty.
    ///
    /// Returns `Err(PhysicalError::ContractNotApproved)` if `bundle` has no
    /// contract_id (i.e., an unapproved empty handle was passed).
    pub fn new(
        bundle: ContractBundleHandle,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        if bundle.contract_id().is_empty() {
            return Err(PhysicalError::ContractNotApproved {
                operator: "ContractApprovedExec".to_string(),
            });
        }
        let properties = inner.properties().clone();
        Ok(Self {
            bundle,
            inner,
            properties,
            events: std::sync::Mutex::new(Vec::new()),
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

    /// Internal: record a `ContractApproved` enforcement event.
    fn emit_approval_event(&self) {
        let mut guard = self.events.lock().unwrap();
        guard.push(PhysicalEnforcementEvent {
            operator: "ContractApprovedExec".to_string(),
            detail: format!(
                "contract '{}' approved for execution",
                self.bundle.contract_id()
            ),
        });
    }
}

impl DisplayAs for ContractApprovedExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ContractApprovedExec(contract_id={})",
            self.bundle.contract_id()
        )
    }
}

impl ExecutionPlan for ContractApprovedExec {
    fn name(&self) -> &str {
        "ContractApprovedExec"
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
                "ContractApprovedExec::with_new_children requires exactly one child".to_string(),
            )
        })?;
        let properties = inner.properties().clone();
        Ok(Arc::new(ContractApprovedExec {
            bundle: self.bundle.clone(),
            inner,
            properties,
            events: std::sync::Mutex::new(Vec::new()),
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> datafusion::error::Result<SendableRecordBatchStream> {
        // Emit enforcement event on first execution.
        self.emit_approval_event();
        // Pass through to the inner plan — this operator is a passthrough marker.
        self.inner.execute(partition, context)
    }

    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }
}

// ─── Helper: walk a physical plan tree to check for ContractApprovedExec ─────

/// Check whether a physical plan tree has a `ContractApprovedExec` anywhere
/// in its ancestor chain.
///
/// Used by `RowFilterExec`, `MaskingExec`, and `LaplaceNoiseExec` constructors
/// to verify that the pipeline was assembled correctly.
pub fn plan_has_contract_approved(plan: &Arc<dyn ExecutionPlan>) -> bool {
    if plan.name() == "ContractApprovedExec" {
        return true;
    }
    plan.children()
        .iter()
        .any(|child| plan_has_contract_approved(child))
}
