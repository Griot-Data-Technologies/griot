//! AttestationExec — Wave 9 implementation.
//!
//! Top-level physical `ExecutionPlan` wrapper that produces a cryptographic
//! `AttestationEnvelope` for every query.  It is the physical embodiment of
//! ADR-0002 §AttestationExec — Verified result envelope.
//!
//! # Role in the pipeline
//!
//! `AttestationExec` wraps the ENTIRE physical pipeline:
//!
//! ```text
//! AttestationExec
//!   └─ LaplaceNoiseExec
//!       └─ MaskingExec
//!           └─ RowFilterExec
//!               └─ ContractApprovedExec
//!                   └─ <DataFusion physical plan>
//! ```
//!
//! Its `execute_attested()` method:
//! 1. Records the contract bundle reference, query SQL hash, and timestamp.
//! 2. Runs the inner plan to completion, collecting all result `RecordBatch`es.
//! 3. Computes a `result_hash` (xxhash-64 hex of all output batches in order).
//! 4. Collects `PhysicalEnforcementEvent`s from child operators.
//! 5. Produces an `AttestationEnvelope`.
//! 6. Returns `(Vec<RecordBatch>, AttestationEnvelope)`.
//!
//! # Copilot round-2 fixes (Findings 9 and 10)
//!
//! ## Finding 9 — Attestation falls back to row-count hash on IPC failure
//!
//! The original `compute_result_hash` fell back to hashing only the row count
//! when IPC serialization failed.  This creates hash collisions across different
//! result sets with identical row counts.  Fix: IPC serialization failure now
//! returns `Err(PhysicalError::AttestationSerializationFailed)`.
//!
//! ## Finding 10 — Constructor only checks contract_id
//!
//! The original `AttestationExec::new` only checked `contract_id`, but the spec
//! requires BOTH `contract_id` AND `contract_version`.  Fix: the constructor
//! now parses the bundle JSON to extract `contract_version` and rejects
//! construction if either field is empty.
//!
//! # Signature (wave 9)
//!
//! The `signature` field in the envelope is a deterministic placeholder:
//! SHA-256(`query_sha` + `result_hash` bytes).  Wave 10 will wire real
//! Sigstore ES256 signing via the T05 `request_signing` opcode.
//!
//! # ADR-0002 requirements
//!
//! * No `unsafe` code.
//! * Sealed constructor: requires inner plan + contract reference.
//! * INV-4 (no AI without provenance) — this IS the provenance record.
//!
//! # Spec anchor
//!
//! ADR-0002 §AttestationExec — Verified result envelope.

use crate::physical::laplace_noise_exec::LaplaceNoiseExec;
use crate::physical::{AttestationEnvelope, PhysicalError};
use crate::ContractBundleHandle;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::ipc::writer::FileWriter;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{
    collect, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::any::Any;
use std::sync::Arc;
use tracing::debug;

// ─── Bundle wire format ───────────────────────────────────────────────────────

/// Minimal contract bundle fields needed by AttestationExec.
///
/// # Finding 10 fix
///
/// Both `contract_id` and `contract_version` are required.  The constructor
/// rejects bundles where either is empty.
#[derive(Debug, Deserialize, Default)]
struct AttestationBundleData {
    #[serde(default)]
    contract_id: String,
    #[serde(default)]
    contract_version: String,
}

// ─── AttestationExec ─────────────────────────────────────────────────────────

/// Top-level physical wrapper that produces an `AttestationEnvelope` alongside
/// the query result stream.
#[derive(Debug)]
pub struct AttestationExec {
    /// The signed contract bundle used for this query.
    bundle: ContractBundleHandle,
    /// SHA-256 hex of the original SQL string.
    query_sha: String,
    /// The contract_version extracted from the bundle (Finding 10 fix).
    contract_version: String,
    /// The inner physical plan (the entire pipeline below AttestationExec).
    inner: Arc<dyn ExecutionPlan>,
    /// Cached plan properties.
    properties: PlanProperties,
}

impl AttestationExec {
    /// Construct a new `AttestationExec`.
    ///
    /// # Arguments
    ///
    /// * `bundle` — the signed contract bundle for this query.
    /// * `query_sql` — the original SQL string (used to compute `query_sha`).
    /// * `inner` — the inner physical plan.
    ///
    /// # Errors
    ///
    /// * `PhysicalError::MissingContractReference` if `bundle` has an empty
    ///   `contract_id` OR `contract_version` (Finding 10 fix).
    pub fn new(
        bundle: ContractBundleHandle,
        query_sql: &str,
        inner: Arc<dyn ExecutionPlan>,
    ) -> Result<Self, PhysicalError> {
        // Finding 10 fix: require both contract_id and contract_version.
        if bundle.contract_id().is_empty() {
            return Err(PhysicalError::MissingContractReference);
        }

        // Parse the bundle to extract contract_version.
        let contract_version = extract_contract_version(&bundle)?;
        if contract_version.is_empty() {
            return Err(PhysicalError::MissingContractReference);
        }

        let query_sha = sha256_hex(query_sql);
        let properties = inner.properties().clone();

        Ok(Self {
            bundle,
            query_sha,
            contract_version,
            inner,
            properties,
        })
    }

    /// Execute the inner plan to completion and return results + attestation.
    ///
    /// This is the primary Wave 9 entry point.  It drives the inner plan,
    /// collects all `RecordBatch`es, hashes them, collects enforcement events
    /// from child operators, and assembles the `AttestationEnvelope`.
    ///
    /// # Returns
    ///
    /// `(Vec<RecordBatch>, AttestationEnvelope)` — the query results and the
    /// signed attestation.
    pub async fn execute_attested(
        &self,
        context: Arc<TaskContext>,
    ) -> Result<(Vec<RecordBatch>, AttestationEnvelope), PhysicalError> {
        let timestamp_utc = chrono::Utc::now().to_rfc3339();

        // Collect all result batches from the inner plan.
        let batches = collect(self.inner.clone(), context).await?;

        // Finding 9 fix: compute_result_hash hard-fails on IPC serialization error.
        let result_hash = compute_result_hash(&batches)?;

        // Collect enforcement events from all child operators.
        let rules_applied = collect_rules_applied(self.inner.as_ref());

        // Check if LaplaceNoiseExec is in the pipeline and get epsilon consumed.
        let epsilon_consumed = find_epsilon_consumed(self.inner.as_ref());

        // Build placeholder signature: SHA-256(query_sha + result_hash).
        let signature = build_placeholder_signature(&self.query_sha, &result_hash);

        let envelope = AttestationEnvelope {
            query_sha: self.query_sha.clone(),
            contract_id: self.bundle.contract_id().to_string(),
            contract_version: self.contract_version.clone(),
            result_hash,
            rules_applied,
            epsilon_consumed,
            delta_consumed: None,
            timestamp_utc,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            signature,
        };

        debug!(
            contract_id = %self.bundle.contract_id(),
            query_sha = %self.query_sha,
            "AttestationExec: attestation envelope produced"
        );

        Ok((batches, envelope))
    }

    /// Return the query SHA (SHA-256 hex of the SQL string).
    pub fn query_sha(&self) -> &str {
        &self.query_sha
    }

    /// Return a reference to the contract bundle.
    pub fn bundle(&self) -> &ContractBundleHandle {
        &self.bundle
    }
}

/// Extract the `contract_version` field from the bundle JSON.
///
/// # Finding 10 fix
///
/// Returns `Err(MissingContractReference)` if the bundle JSON is non-empty
/// but cannot be parsed.  Returns `Ok("")` if the bundle is empty (no version
/// configured — caller then rejects with `MissingContractReference`).
fn extract_contract_version(bundle: &ContractBundleHandle) -> Result<String, PhysicalError> {
    let bytes = &bundle.raw_bytes;
    if bytes.is_empty() {
        // No JSON → version is empty; caller decides to reject.
        return Ok(String::new());
    }
    let data: AttestationBundleData =
        serde_json::from_slice(bytes).map_err(|e| PhysicalError::ContractBundleMalformed {
            reason: format!("AttestationExec bundle JSON parse error: {}", e),
        })?;
    Ok(data.contract_version)
}

/// Compute xxhash-64 hex digest of all result batches serialized as Arrow IPC.
///
/// # Finding 9 fix
///
/// Returns `Err(AttestationSerializationFailed)` if Arrow IPC serialization
/// fails for any batch.  Never falls back to row-count-only hash.
fn compute_result_hash(batches: &[RecordBatch]) -> Result<String, PhysicalError> {
    if batches.is_empty() {
        // Empty result: hash of the empty byte sequence.
        return Ok(format!("{:016x}", xxhash_rust::xxh64::xxh64(&[], 0)));
    }

    let schema = batches[0].schema();
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = FileWriter::try_new(&mut buf, &schema).map_err(|e| {
            PhysicalError::AttestationSerializationFailed {
                reason: format!("IPC FileWriter init error: {}", e),
            }
        })?;

        for batch in batches {
            writer
                .write(batch)
                .map_err(|e| PhysicalError::AttestationSerializationFailed {
                    reason: format!("IPC write error: {}", e),
                })?;
        }

        writer
            .finish()
            .map_err(|e| PhysicalError::AttestationSerializationFailed {
                reason: format!("IPC finish error: {}", e),
            })?;
    }

    // Finding 9 fix: we now have the full IPC bytes in `buf`.
    // buf.is_empty() should not occur after a successful FileWriter::finish(),
    // but guard defensively.
    if buf.is_empty() {
        return Err(PhysicalError::AttestationSerializationFailed {
            reason: "IPC serialization produced empty buffer after finish()".to_string(),
        });
    }

    let hash = xxhash_rust::xxh64::xxh64(&buf, 0);
    Ok(format!("{:016x}", hash))
}

/// Collect `rules_applied` names by walking the physical plan tree.
///
/// Traverses children and collects the name of every physical operator that
/// is one of the ADR-0002 contract enforcement operators.
fn collect_rules_applied(plan: &dyn ExecutionPlan) -> Vec<String> {
    let name = plan.name();
    let is_enforcement = matches!(
        name,
        "ContractApprovedExec"
            | "RowFilterExec"
            | "MaskingExec"
            | "LaplaceNoiseExec"
            | "AttestationExec"
    );

    let mut rules: Vec<String> = if is_enforcement {
        vec![name.to_string()]
    } else {
        vec![]
    };

    for child in plan.children() {
        let child_rules = collect_rules_applied(child.as_ref());
        rules.extend(child_rules);
    }

    rules
}

/// Find `epsilon_consumed` from the `LaplaceNoiseExec` in the pipeline, if any.
fn find_epsilon_consumed(plan: &dyn ExecutionPlan) -> Option<f64> {
    if let Some(noise_exec) = plan.as_any().downcast_ref::<LaplaceNoiseExec>() {
        return noise_exec.epsilon_consumed();
    }
    for child in plan.children() {
        if let Some(eps) = find_epsilon_consumed(child.as_ref()) {
            return Some(eps);
        }
    }
    None
}

/// Compute SHA-256 hex digest of a string.
fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Build the wave-9 placeholder signature: SHA-256(query_sha || result_hash).
fn build_placeholder_signature(query_sha: &str, result_hash: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(query_sha.as_bytes());
    hasher.update(result_hash.as_bytes());
    hasher.finalize().to_vec()
}

impl DisplayAs for AttestationExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "AttestationExec(contract_id={}, query_sha={})",
            self.bundle.contract_id(),
            &self.query_sha[..8.min(self.query_sha.len())]
        )
    }
}

impl ExecutionPlan for AttestationExec {
    fn name(&self) -> &str {
        "AttestationExec"
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
                "AttestationExec::with_new_children requires exactly one child".to_string(),
            )
        })?;
        let properties = inner.properties().clone();
        Ok(Arc::new(AttestationExec {
            bundle: self.bundle.clone(),
            query_sha: self.query_sha.clone(),
            contract_version: self.contract_version.clone(),
            inner,
            properties,
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> datafusion::error::Result<SendableRecordBatchStream> {
        // Standard DataFusion execute() path — returns the stream without attestation.
        // Callers wanting the AttestationEnvelope should use execute_attested().
        self.inner.execute(partition, context)
    }

    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }
}
