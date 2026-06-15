//! The on-the-wire T03 signed bundle, its signature verification, and the
//! mapping to a [`ResolvedPolicy`].
//!
//! The struct layout and the canonical hashing below mirror T03's
//! `bundle-signer` crate exactly (the `.gdcpc.signed` JSON format and
//! `canonical_digest` / `canonical_signing_payload`). They must stay byte-for-byte
//! in sync with T03; the long-term fix is a shared types crate.

use std::collections::HashMap;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::contract_source::Caller;
use crate::policy::{Decision, MaskAction, ResolvedPolicy};

// ─── On-disk / on-the-wire shapes (mirror T03 `serialise_signed_bundle`) ──────

/// A compiled-then-signed bundle as produced by T03 (`.gdcpc.signed` JSON).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignedBundleFile {
    /// The compiled bundle content.
    pub bundle: CompiledBundle,
    /// DER-encoded ECDSA P-256 signature, hex-encoded.
    pub signature_hex: String,
    /// Signing metadata (covered by the signature).
    pub metadata: SignedBundleMetadata,
}

/// Signing metadata.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignedBundleMetadata {
    /// SHA-256 digest of the bundle content, hex-encoded.
    pub bundle_hash_hex: String,
    /// Unix-ms timestamp the bundle was signed.
    pub signed_at_unix_ms: u64,
    /// The signing key generation.
    pub key_generation: u32,
}

/// A compiled contract bundle.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CompiledBundle {
    /// Identity of the contract that produced this bundle.
    pub manifest: BundleManifest,
    /// WASM structural-check carriers.
    pub wasm_modules: Vec<WasmModule>,
    /// Rego policy modules (purpose gates, ABAC, masking decisions).
    pub rego_bundles: Vec<RegoBundle>,
    /// SQL templates implementing row filtering + column masking.
    pub sql_templates: Vec<SqlTemplate>,
    /// Index from (dataset, operation) to the check to run.
    pub resolution_map: ResolutionMap,
}

/// Bundle manifest.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BundleManifest {
    /// Contract id.
    pub contract_id: String,
    /// Contract version.
    pub contract_version: u64,
    /// Unix-ms timestamp compilation completed.
    pub compiled_at_unix_ms: u64,
}

/// A WASM module (name + raw bytes).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WasmModule {
    /// Module name.
    pub name: String,
    /// Raw WASM bytes.
    pub bytes: Vec<u8>,
}

/// A Rego policy module (name + source).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RegoBundle {
    /// Policy name.
    pub name: String,
    /// Rego source text.
    pub source: String,
}

/// A SQL template (name + text with `{table}` placeholder).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SqlTemplate {
    /// Template name.
    pub name: String,
    /// SQL text.
    pub template: String,
}

/// The resolution map.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResolutionMap {
    /// All (dataset, operation) → check entries.
    pub entries: Vec<ResolutionMapEntry>,
}

/// One resolution-map entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResolutionMapEntry {
    /// `tenant/contract` dataset id.
    pub dataset_id: String,
    /// Operation, e.g. `read` / `pii-read` / `write`.
    pub operation: String,
    /// Name of the check (Rego rule / SQL template) to apply.
    pub check_ref: String,
}

impl SignedBundleFile {
    /// Parse a `.gdcpc.signed` JSON document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, VerifyError> {
        serde_json::from_slice(bytes).map_err(|e| VerifyError(format!("bundle JSON parse: {e}")))
    }

    /// Verify the ECDSA P-256 signature against `vk`.
    ///
    /// Recomputes the bundle digest (must match `metadata.bundle_hash_hex`),
    /// rebuilds the canonical signing payload, and verifies the DER signature.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), VerifyError> {
        let recomputed = canonical_digest(&self.bundle);
        let recorded = hex::decode(&self.metadata.bundle_hash_hex)
            .map_err(|e| VerifyError(format!("bundle_hash_hex decode: {e}")))?;
        if recomputed != recorded {
            return Err(VerifyError(
                "recomputed bundle digest does not match metadata.bundle_hash".into(),
            ));
        }
        let payload = canonical_signing_payload(
            &recomputed,
            self.metadata.key_generation,
            self.metadata.signed_at_unix_ms,
            &recorded,
        );
        let sig_der =
            hex::decode(&self.signature_hex).map_err(|e| VerifyError(format!("sig hex: {e}")))?;
        let sig = Signature::from_der(&sig_der)
            .map_err(|e| VerifyError(format!("invalid DER signature: {e}")))?;
        vk.verify(&payload, &sig)
            .map_err(|e| VerifyError(format!("signature verification failed: {e}")))
    }

    /// The owning tenant, derived from the resolution map's `dataset_id`
    /// (`tenant/contract`).
    pub fn owner_tenant(&self) -> Option<&str> {
        self.bundle
            .resolution_map
            .entries
            .first()
            .and_then(|e| e.dataset_id.split('/').next())
    }
}

// ─── Canonical hashing (mirrors T03 bundle-signer/types.rs) ────────────────────

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

/// SHA-256 over all bundle fields, length-prefixed and sorted — identical to
/// T03's `canonical_digest`.
pub fn canonical_digest(bundle: &CompiledBundle) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hash_field(&mut hasher, bundle.manifest.contract_id.as_bytes());
    hash_field(&mut hasher, &bundle.manifest.contract_version.to_le_bytes());
    hash_field(
        &mut hasher,
        &bundle.manifest.compiled_at_unix_ms.to_le_bytes(),
    );

    let mut wasm: Vec<_> = bundle.wasm_modules.iter().collect();
    wasm.sort_by_key(|m| m.name.as_str());
    hash_field(&mut hasher, &(wasm.len() as u32).to_be_bytes());
    for m in &wasm {
        hash_field(&mut hasher, m.name.as_bytes());
        hash_field(&mut hasher, &m.bytes);
    }

    let mut rego: Vec<_> = bundle.rego_bundles.iter().collect();
    rego.sort_by_key(|r| r.name.as_str());
    hash_field(&mut hasher, &(rego.len() as u32).to_be_bytes());
    for r in &rego {
        hash_field(&mut hasher, r.name.as_bytes());
        hash_field(&mut hasher, r.source.as_bytes());
    }

    let mut sql: Vec<_> = bundle.sql_templates.iter().collect();
    sql.sort_by_key(|s| s.name.as_str());
    hash_field(&mut hasher, &(sql.len() as u32).to_be_bytes());
    for s in &sql {
        hash_field(&mut hasher, s.name.as_bytes());
        hash_field(&mut hasher, s.template.as_bytes());
    }

    let mut entries: Vec<_> = bundle.resolution_map.entries.iter().collect();
    entries.sort_by(|a, b| {
        a.dataset_id
            .cmp(&b.dataset_id)
            .then(a.operation.cmp(&b.operation))
    });
    hash_field(&mut hasher, &(entries.len() as u32).to_be_bytes());
    for e in &entries {
        hash_field(&mut hasher, e.dataset_id.as_bytes());
        hash_field(&mut hasher, e.operation.as_bytes());
        hash_field(&mut hasher, e.check_ref.as_bytes());
    }

    hasher.finalize().to_vec()
}

/// The signed payload — identical to T03's `canonical_signing_payload`.
pub fn canonical_signing_payload(
    bundle_hash: &[u8],
    key_generation: u32,
    signed_at_unix_ms: u64,
    metadata_bundle_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"t03:bundle-signing-payload:v1");
    hash_field(&mut hasher, bundle_hash);
    hash_field(&mut hasher, &key_generation.to_le_bytes());
    hash_field(&mut hasher, &signed_at_unix_ms.to_le_bytes());
    hash_field(&mut hasher, metadata_bundle_hash);
    hasher.finalize().to_vec()
}

// ─── Mapping: signed bundle → ResolvedPolicy ──────────────────────────────────

/// Map a verified T03 bundle into the engine's [`ResolvedPolicy`] for `caller`.
///
/// Heuristic (see module docs): the owning tenant gets raw access; everyone else
/// gets the masks + row filter parsed out of the non-owner read SQL template,
/// plus any purpose gate found in the Rego.
pub fn map_bundle_to_policy(file: &SignedBundleFile, caller: &Caller) -> ResolvedPolicy {
    let contract_id = file.bundle.manifest.contract_id.clone();
    let version = file.bundle.manifest.contract_version.to_string();
    let owner = file.owner_tenant().unwrap_or("").to_string();

    // Purpose gate, if the Rego declares one.
    if let Some(allowed) = allowed_purposes(&file.bundle) {
        if !allowed.is_empty() && !allowed.contains(&caller.purpose) {
            return ResolvedPolicy {
                contract_id,
                contract_version: version,
                tenant_id: owner,
                decision: Decision::Deny {
                    reason: format!(
                        "purpose '{}' not permitted (allowed: {:?})",
                        caller.purpose, allowed
                    ),
                },
                column_masks: HashMap::new(),
                row_filter: None,
                dp_columns: HashMap::new(),
            };
        }
    }

    let is_owner = !owner.is_empty() && caller.tenant == owner;
    if is_owner {
        return ResolvedPolicy::allow_all(contract_id, version, owner);
    }

    // Non-owner: derive masks + row filter from the non-owner read SQL template.
    let (column_masks, row_filter) = match non_owner_template(&file.bundle) {
        Some(t) => (masks_from_sql(t), row_filter_from_sql(t)),
        None => (HashMap::new(), None),
    };

    ResolvedPolicy {
        contract_id,
        contract_version: version,
        tenant_id: owner,
        decision: Decision::Allow,
        column_masks,
        row_filter,
        dp_columns: HashMap::new(),
    }
}

/// The SQL template T04 would use for a non-owner read (its name contains
/// `non-owner`), else any `pii`/`read` template.
fn non_owner_template(bundle: &CompiledBundle) -> Option<&str> {
    bundle
        .sql_templates
        .iter()
        .find(|t| t.name.contains("non-owner"))
        .or_else(|| {
            bundle
                .sql_templates
                .iter()
                .find(|t| t.name.contains("read"))
        })
        .map(|t| t.template.as_str())
}

/// Extract `sha256_hex(col) AS col` (and `mask_redact(col)`) projections as
/// column mask actions.
fn masks_from_sql(sql: &str) -> HashMap<String, MaskAction> {
    let mut masks = HashMap::new();
    for (func, action) in [
        ("sha256_hex(", MaskAction::HashSha256),
        ("mask_hash_sha256(", MaskAction::HashSha256),
        ("mask_redact(", MaskAction::Redact),
        ("mask_tokenize(", MaskAction::Tokenize),
    ] {
        let mut rest = sql;
        while let Some(pos) = rest.find(func) {
            let after = &rest[pos + func.len()..];
            if let Some(close) = after.find(')') {
                let col = after[..close].trim().trim_matches('"').to_string();
                if !col.is_empty() {
                    masks.insert(col, action);
                }
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
    }
    masks
}

/// Extract the `WHERE` clause as a row filter (a trivial `1=1` means no filter).
fn row_filter_from_sql(sql: &str) -> Option<String> {
    let upper = sql.to_ascii_uppercase();
    let pos = upper.find(" WHERE ")?;
    let clause = sql[pos + " WHERE ".len()..].trim();
    let normalised = clause.replace(char::is_whitespace, "");
    if normalised.is_empty() || normalised == "1=1" {
        None
    } else {
        Some(clause.to_string())
    }
}

/// Collect `input.declared_purpose == "X"` literals from a purpose-gate Rego.
fn allowed_purposes(bundle: &CompiledBundle) -> Option<Vec<String>> {
    let rego = bundle
        .rego_bundles
        .iter()
        .find(|r| r.name.contains("purpose"))?;
    let needle = "declared_purpose";
    let mut out = Vec::new();
    let mut rest = rego.source.as_str();
    while let Some(pos) = rest.find(needle) {
        let after = &rest[pos + needle.len()..];
        // Look for the next quoted string on the same logical comparison.
        if let Some(q1) = after.find('"') {
            let tail = &after[q1 + 1..];
            if let Some(q2) = tail.find('"') {
                out.push(tail[..q2].to_string());
                rest = &tail[q2 + 1..];
                continue;
            }
        }
        rest = after;
    }
    Some(out)
}

/// A signature/parse verification error.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct VerifyError(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    fn demo_bundle_json() -> Vec<u8> {
        // Mirrors the shape of T03's non-owner masking bundle.
        serde_json::json!({
            "bundle": {
                "manifest": { "contract_id": "demo_v1", "contract_version": 1, "compiled_at_unix_ms": 1 },
                "wasm_modules": [],
                "rego_bundles": [{
                    "name": "policy-purpose-gate",
                    "source": "default allow := false\nallow if { input.declared_purpose == \"analytics\" }\nallow if { input.declared_purpose == \"marketplace-listing\" }"
                }],
                "sql_templates": [
                    { "name": "row-filter-owner-read", "template": "SELECT user_id, email FROM {table} WHERE 1=1" },
                    { "name": "row-filter-non-owner-read", "template": "SELECT user_id, sha256_hex(email) AS email FROM {table} WHERE 1=1" }
                ],
                "resolution_map": { "entries": [
                    { "dataset_id": "acme/demo_v1", "operation": "read", "check_ref": "policy-purpose-gate" }
                ]}
            },
            "signature_hex": "",
            "metadata": { "bundle_hash_hex": "", "signed_at_unix_ms": 0, "key_generation": 1 }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        // Proves the canonical-payload + verify path is self-consistent (and so
        // matches T03's, since the byte layout is copied verbatim).
        let mut file = SignedBundleFile::from_json(&demo_bundle_json()).unwrap();

        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);

        let digest = canonical_digest(&file.bundle);
        file.metadata.bundle_hash_hex = hex::encode(&digest);
        let payload = canonical_signing_payload(
            &digest,
            file.metadata.key_generation,
            file.metadata.signed_at_unix_ms,
            &digest,
        );
        let sig: Signature = sk.sign(&payload);
        file.signature_hex = hex::encode(sig.to_der());

        file.verify(&vk).expect("signature must verify");

        // Tampering with the bundle must fail verification.
        let mut tampered = file.clone();
        tampered.bundle.manifest.contract_id = "evil".into();
        assert!(tampered.verify(&vk).is_err());
    }

    #[test]
    fn maps_non_owner_to_masked_email() {
        let file = SignedBundleFile::from_json(&demo_bundle_json()).unwrap();
        let policy = map_bundle_to_policy(&file, &Caller::new("u", "analytics", "globex"));
        assert!(policy.is_allowed());
        assert_eq!(
            policy.column_masks.get("email"),
            Some(&MaskAction::HashSha256)
        );
    }

    #[test]
    fn maps_owner_to_raw() {
        let file = SignedBundleFile::from_json(&demo_bundle_json()).unwrap();
        let policy = map_bundle_to_policy(&file, &Caller::new("u", "analytics", "acme"));
        assert!(policy.is_allowed());
        assert!(policy.column_masks.is_empty());
    }

    #[test]
    fn denies_disallowed_purpose() {
        let file = SignedBundleFile::from_json(&demo_bundle_json()).unwrap();
        let policy = map_bundle_to_policy(&file, &Caller::new("u", "marketing", "globex"));
        assert!(!policy.is_allowed());
    }
}
