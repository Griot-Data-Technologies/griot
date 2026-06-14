//! DataFusion optimizer rules for ADR-0002 contract-native enforcement.
//!
//! Wave 8 scaffold — stubs for all four rules plus shared types.
//! The implementation agent fills in the `unimplemented!()` bodies in the
//! Wave 8 impl PR.
//!
//! # Rule order (FIXED, enforced by `build_pipeline`)
//!
//! 1. [`contract_check`] — validates contract bundle present + principal satisfies
//!    constraints; rewrites denied TableScan nodes to `EmptyRelation`.
//! 2. [`row_filter`] — injects a `Filter` node above every stamped TableScan if
//!    the contract specifies a row-filter expression.
//! 3. [`masking`] — wraps PII/PHI/PCI column projections in masking scalar
//!    functions (`mask_redact`, `mask_hash_sha256`, `mask_tokenize`, `mask_noop`).
//! 4. [`dp_noise`] — injects `LaplaceNoise` aggregate extension nodes for
//!    columns tagged with differential-privacy requirements, subject to
//!    privacy budget.
//!
//! # Semantic Law coverage
//!
//! * INV-1 (No data in without contract): `ContractCheckRule` enforces this at
//!   the logical optimizer level — any scan without a valid bundle is denied.
//! * INV-2 (No read without satisfaction): `ContractCheckRule` also validates
//!   purpose, tier, and classification constraints from the bundle.
//! * INV-3 (No write without satisfaction): DDL mediated externally via T04
//!   `submit_ddl` opcode; write-path enforcement is outside the query engine.
//! * INV-4 (No AI without provenance): out of scope for these four rules;
//!   handled by `AttestationExec` physical operator (future wave).
//! * INV-5 (No bypass from above trust line): enforced structurally — these
//!   modules import nothing from `zone-t`.

pub mod contract_check;
pub mod dp_noise;
pub mod masking;
pub mod pipeline;
pub mod row_filter;

// ─── Shared types ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kind of event recorded in an [`AuditRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    /// A `ContractCheckRule` denied a TableScan because no bundle was present.
    ContractCheckDenied,
    /// A `ContractCheckRule` denied a TableScan because the principal does not
    /// satisfy the purpose constraint from the bundle.
    PurposeMismatch,
    /// A `ContractCheckRule` denied a TableScan because the principal does not
    /// satisfy the tier constraint.
    TierMismatch,
    /// A `ContractCheckRule` denied a TableScan because the principal does not
    /// satisfy the classification constraint.
    ClassificationMismatch,
    /// A `ContractCheckRule` approved a TableScan and stamped a marker.
    ContractCheckApproved,
    /// A `DPNoiseRule` denied a query because the privacy budget is exhausted.
    PrivacyBudgetExhausted,
}

/// An audit record emitted by an optimizer rule when it applies enforcement.
///
/// In the implementation the engine will forward these to T04 via the
/// `emit_audit_event` X02 opcode.  In tests they are collected in-memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique identifier for this audit event (UUID v4).
    pub event_id: Uuid,
    /// The kind of enforcement event.
    pub kind: AuditKind,
    /// The table or asset that was affected.
    pub table_name: String,
    /// The tenant this query runs for.
    pub tenant_id: String,
    /// The contract ID evaluated (if any).
    pub contract_id: Option<String>,
    /// Human-readable description for debugging.
    pub detail: String,
}

impl AuditRecord {
    /// Construct a new audit record with a fresh UUID.
    pub fn new(
        kind: AuditKind,
        table_name: impl Into<String>,
        tenant_id: impl Into<String>,
        contract_id: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            kind,
            table_name: table_name.into(),
            tenant_id: tenant_id.into(),
            contract_id,
            detail: detail.into(),
        }
    }
}

/// A marker extension attached to a `TableScan` logical plan node when
/// `ContractCheckRule` approves the scan.
///
/// Downstream rules (`RowFilterRule`, `MaskingRule`, `DPNoiseRule`) MUST
/// check for this marker before acting.  A scan without a marker means
/// `ContractCheckRule` was not run — a defensive programming error that
/// each downstream rule must refuse to paper over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractCheckMarker {
    /// The contract ID that was validated.
    pub contract_id: String,
    /// The tenant this check was issued for.
    pub tenant_id: String,
}

/// The principal making the query — used by `ContractCheckRule` and
/// `RowFilterRule` to evaluate per-principal constraints.
#[derive(Debug, Clone, Default)]
pub struct Principal {
    /// The principal's unique identifier (e.g., "user:alice" or "service:k03").
    pub id: String,
    /// The declared purpose for this query (must match contract semantic_purpose).
    pub declared_purpose: String,
    /// The tier level the principal is authorised at (e.g., "bronze", "silver", "gold").
    pub tier: String,
    /// The data classification the principal is authorised to access.
    pub classification: String,
}

/// Errors that can be returned by optimizer rules.
#[derive(Debug, thiserror::Error)]
pub enum OptimizerRuleError {
    #[error("contract check denied: {reason}")]
    ContractCheckDenied { reason: String },

    #[error("privacy budget exhausted for tenant '{tenant_id}', column '{column}'")]
    PrivacyBudgetExhausted { tenant_id: String, column: String },

    #[error("missing ContractCheckMarker on scan of '{table}': ContractCheckRule must run first")]
    MissingMarker { table: String },

    #[error("contract filter unsupported: {reason}")]
    ContractFilterUnsupported { reason: String },

    #[error("datafusion error: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),

    #[error("internal optimizer error: {0}")]
    Internal(String),
}
