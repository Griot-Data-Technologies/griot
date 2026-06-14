//! Physical execution plan operators for ADR-0002 contract-native enforcement.
//!
//! Wave 9 — physical operator layer.  These are DataFusion `ExecutionPlan`
//! implementations that correspond 1-to-1 with the four wave-8 logical-plan
//! optimizer rules.  Wave 9 also introduces `AttestationExec`, the top-level
//! wrapper that produces a cryptographic `AttestationEnvelope` for each query.
//!
//! # Operator pipeline (physical)
//!
//! ```text
//! AttestationExec (wraps entire pipeline)
//!   └─ LaplaceNoiseExec
//!       └─ MaskingExec
//!           └─ RowFilterExec
//!               └─ ContractApprovedExec
//!                   └─ <any DataFusion physical plan>
//! ```
//!
//! # ADR-0002 verified-binary surface
//!
//! All operators in this module MUST:
//! (a) Contain no `unsafe` code.
//! (b) Be sealed: no public constructors that bypass the contract bundle.
//! (c) Emit a structured event for every enforcement decision so
//!     `AttestationExec` can include it in the attestation envelope.
//!
//! # Semantic Law coverage
//!
//! * INV-1 (no data in without contract): `ContractApprovedExec` enforces.
//! * INV-2 (no read without satisfaction): `RowFilterExec` + `MaskingExec` enforce.
//! * INV-4 (no AI without provenance): `AttestationExec` provides the provenance
//!   envelope for every result stream (placeholder signature until wave 10 Sigstore).
//! * INV-5 (no bypass from above trust line): no import from zone-t.

pub mod attestation_exec;
pub mod contract_approved_exec;
pub mod laplace_noise_exec;
pub mod masking_exec;
pub mod row_filter_exec;

// ─── Shared physical-layer types ─────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// A record of a single enforcement event emitted by a physical operator.
///
/// `AttestationExec` collects these across all child operators to populate
/// the `rules_applied` field of the [`AttestationEnvelope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalEnforcementEvent {
    /// Name of the operator that emitted this event
    /// (e.g., "ContractApprovedExec", "RowFilterExec").
    pub operator: String,
    /// Human-readable description of what was enforced.
    pub detail: String,
}

/// The cryptographic attestation envelope produced by `AttestationExec` for
/// every result stream.
///
/// Wave 9 uses a deterministic dummy signature for the `signature` field;
/// wave 10 will wire real Sigstore ES256 signing.
///
/// # Spec anchor
///
/// ADR-0002 §AttestationExec — Verified result envelope.
/// INV-4: No AI without provenance — this IS the provenance record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    /// SHA-256 hex digest of the query SQL string.
    pub query_sha: String,

    /// The contract ID evaluated for this query.
    pub contract_id: String,

    /// The contract version string (e.g., "1.0.0" or a commit hash).
    pub contract_version: String,

    /// xxhash-64 hex digest of all result `RecordBatch` bytes (in order).
    pub result_hash: String,

    /// Names of every optimizer/physical rule that fired, in pipeline order.
    pub rules_applied: Vec<String>,

    /// Total epsilon consumed by `LaplaceNoiseExec` during this query.
    /// `None` if no differential-privacy noise was applied.
    pub epsilon_consumed: Option<f64>,

    /// Total delta consumed (currently always `None`; reserved for Gaussian
    /// mechanism support in a future wave).
    pub delta_consumed: Option<f64>,

    /// UTC timestamp of when `AttestationExec::execute()` was called.
    pub timestamp_utc: String,

    /// Semver string of the engine binary (from `env!("CARGO_PKG_VERSION")`).
    pub engine_version: String,

    /// Placeholder signature bytes.
    ///
    /// Wave 9: deterministic bytes derived from `query_sha + result_hash`.
    /// Wave 10: real Sigstore ES256 JWS over the canonical JSON of this struct
    /// (excluding the `signature` field itself).
    pub signature: Vec<u8>,
}

/// Errors specific to the physical operator layer.
#[derive(Debug, thiserror::Error)]
pub enum PhysicalError {
    /// A query reached `RowFilterExec`, `MaskingExec`, or `LaplaceNoiseExec`
    /// without a `ContractApprovedExec` upstream in the physical plan.
    ///
    /// This is a pipeline configuration error — the plan was assembled without
    /// running `ContractCheckRule` first.
    ///
    /// Spec anchor: INV-2 (no read without satisfaction).
    #[error(
        "ContractApprovedExec not found upstream of '{operator}': \
         contract approval is required before physical enforcement operators"
    )]
    ContractNotApproved { operator: String },

    /// `AttestationExec` was constructed without an inner `ExecutionPlan`.
    #[error("AttestationExec requires an inner ExecutionPlan")]
    MissingInnerPlan,

    /// `AttestationExec` was constructed without a contract reference.
    #[error("AttestationExec requires a contract_id and contract_version")]
    MissingContractReference,

    /// The contract bundle JSON was malformed or unparseable.
    ///
    /// Per Copilot finding cluster A: parse failures must hard-error, not
    /// silently fall back to "no filter / no masking / no DP".
    ///
    /// Spec anchor: INV-2 (no read without satisfaction — enforcement cannot
    /// proceed if the enforcement policy itself is unreadable).
    #[error("contract bundle malformed: {reason}")]
    ContractBundleMalformed { reason: String },

    /// An unknown masking policy string was encountered in the contract bundle.
    ///
    /// Per Copilot finding 2: unknown policy strings must error, not map to Noop.
    ///
    /// Spec anchor: INV-2 (no read without satisfaction — unknown policy = unsafe default).
    #[error("unknown masking policy '{policy}' in contract bundle for column '{column}'")]
    UnknownMaskPolicy { policy: String, column: String },

    /// A masked column has a type for which no masking handler is implemented.
    ///
    /// Per Copilot finding 5: non-string columns with masking policy must not
    /// leak protected data unchanged.
    ///
    /// Spec anchor: INV-2.
    #[error("masking type unsupported: column '{column}' has type '{type_name}' which has no mask handler")]
    MaskTypeUnsupported { column: String, type_name: String },

    /// DP epsilon or sensitivity parameter is invalid.
    ///
    /// Per Copilot finding 6: epsilon must be > 0 and finite; sensitivity > 0 and finite.
    ///
    /// Spec anchor: INV-2 (DP with invalid parameters cannot provide the promised guarantee).
    #[error("invalid DP parameters for column '{column}': epsilon={epsilon}, sensitivity={sensitivity} — both must be > 0 and finite")]
    InvalidDpParameters {
        column: String,
        epsilon: f64,
        sensitivity: f64,
    },

    /// A DP column type has no noise handler implemented.
    ///
    /// Per Copilot finding 7: non-Float64/Int64 aggregates must not silently
    /// bypass DP.
    ///
    /// Spec anchor: INV-2.
    #[error("DP type unsupported: column '{column}' has type '{type_name}' — only Float64 and Int64 are supported for DP noise")]
    DpTypeUnsupported { column: String, type_name: String },

    /// Privacy budget was exhausted for the requested query.
    ///
    /// Per Copilot finding 8: budget must be enforced; if exhausted, no rows
    /// must be returned.
    ///
    /// Spec anchor: INV-2 (no read without satisfaction — budget is a constraint).
    #[error("privacy budget exhausted for tenant '{tenant_id}', column '{column}'")]
    BudgetExhausted { tenant_id: String, column: String },

    /// Arrow IPC serialization failed during result hash computation.
    ///
    /// Per Copilot finding 9: `compute_result_hash` must error if IPC
    /// serialization fails, not fall back to row-count-only hash.
    ///
    /// Spec anchor: INV-4 (no AI without provenance — result hash must be
    /// deterministic from actual bytes).
    #[error("attestation serialization failed: {reason}")]
    AttestationSerializationFailed { reason: String },

    /// A DataFusion internal error propagated from the inner plan.
    #[error("datafusion error: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),

    /// An unexpected internal error in a physical operator.
    #[error("physical operator internal error: {0}")]
    Internal(String),
}
