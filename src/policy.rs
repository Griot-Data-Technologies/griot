//! `ResolvedPolicy` — the engine-agnostic enforcement primitive.
//!
//! A [`ResolvedPolicy`] is what *any* contract source produces and what the
//! engine executes. It is the seam between the contract world (JSON for
//! open-source use; a signed T03 bundle for the platform) and the query world:
//! whoever resolves a contract for a given caller emits a `ResolvedPolicy`, and
//! the engine turns it into governed query execution.
//!
//! The policy is deliberately *declarative*: it says *what* must happen (mask
//! this column, drop these rows, noise that aggregate) without referencing any
//! engine internals. [`ResolvedPolicy::to_bundle_bytes`] serialises it into the
//! exact JSON the existing physical operators already parse, so the operators
//! are reused unchanged.

use std::collections::HashMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::ContractBundleHandle;

/// What to do to a column's values at read time.
///
/// The string forms match the vocabulary the [`crate::physical::masking_exec`]
/// operator parses out of the contract bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskAction {
    /// Replace every value with `<REDACTED>`.
    Redact,
    /// Replace every value with its SHA-256 hex digest.
    HashSha256,
    /// Deterministic tokenisation (maps to SHA-256 semantically).
    Tokenize,
    /// Keep the last 4 characters, mask the rest (`***1234`).
    Partial,
    /// Replace every value with a typed NULL.
    Null,
    /// No masking — pass the column through unchanged.
    Noop,
}

impl MaskAction {
    /// The token the masking operator expects in the contract bundle JSON.
    pub fn as_bundle_str(self) -> &'static str {
        match self {
            MaskAction::Redact => "redact",
            MaskAction::HashSha256 => "hash_sha256",
            MaskAction::Tokenize => "tokenize",
            MaskAction::Partial => "partial",
            MaskAction::Null => "null",
            MaskAction::Noop => "noop",
        }
    }

    /// Parse a policy token (case-insensitive). Unknown tokens are an error so a
    /// typo can never silently downgrade to "no masking".
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s.to_ascii_lowercase().as_str() {
            "redact" => Ok(MaskAction::Redact),
            "hash_sha256" | "hash" => Ok(MaskAction::HashSha256),
            "tokenize" => Ok(MaskAction::Tokenize),
            "partial" => Ok(MaskAction::Partial),
            "null" => Ok(MaskAction::Null),
            "noop" | "none" => Ok(MaskAction::Noop),
            other => Err(PolicyError::UnknownMaskAction(other.to_string())),
        }
    }
}

/// Differential-privacy parameters for one column.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DpParam {
    /// Query sensitivity (the max influence of a single record).
    pub sensitivity: f64,
    /// Privacy budget per query (ε). Smaller = more noise.
    pub epsilon: f64,
}

/// The access decision for a (contract, caller) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The caller may read; the masks/filters below apply.
    Allow,
    /// The caller may not read this contract at all.
    Deny {
        /// Human-readable reason (surfaced to the caller / agent).
        reason: String,
    },
}

/// The resolved, engine-ready enforcement description for one query.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// The contract that produced this policy.
    pub contract_id: String,
    /// The contract version (pinned; flows into the attestation envelope).
    pub contract_version: String,
    /// The owning tenant (used as the bundle handle's tenant id).
    pub tenant_id: String,
    /// Allow / Deny.
    pub decision: Decision,
    /// Per-column masking actions. Columns absent here are unmasked.
    pub column_masks: HashMap<String, MaskAction>,
    /// An optional SQL boolean predicate restricting visible rows.
    pub row_filter: Option<String>,
    /// Per-column differential-privacy parameters.
    pub dp_columns: HashMap<String, DpParam>,
}

impl ResolvedPolicy {
    /// An allow-everything policy (no masks, no filter, no DP) for `contract`.
    pub fn allow_all(
        contract_id: impl Into<String>,
        contract_version: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            contract_version: contract_version.into(),
            tenant_id: tenant_id.into(),
            decision: Decision::Allow,
            column_masks: HashMap::new(),
            row_filter: None,
            dp_columns: HashMap::new(),
        }
    }

    /// `true` if the caller is allowed to read.
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// `true` if any column carries differential-privacy parameters.
    pub fn has_dp(&self) -> bool {
        !self.dp_columns.is_empty()
    }

    /// Serialise to the contract-bundle JSON that the physical enforcement
    /// operators parse (`column_masking`, `row_filter`, `dp_columns`,
    /// `contract_id`, `contract_version`). `Noop` masks are omitted.
    pub fn to_bundle_bytes(&self) -> Bytes {
        let column_masking: serde_json::Map<String, serde_json::Value> = self
            .column_masks
            .iter()
            .filter(|(_, action)| **action != MaskAction::Noop)
            .map(|(col, action)| {
                (
                    col.clone(),
                    serde_json::Value::String(action.as_bundle_str().to_string()),
                )
            })
            .collect();

        let dp_columns: serde_json::Map<String, serde_json::Value> = self
            .dp_columns
            .iter()
            .map(|(col, p)| {
                (
                    col.clone(),
                    serde_json::json!({ "sensitivity": p.sensitivity, "epsilon": p.epsilon }),
                )
            })
            .collect();

        let value = serde_json::json!({
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "column_masking": column_masking,
            "row_filter": self.row_filter,
            "dp_columns": dp_columns,
        });

        Bytes::from(serde_json::to_vec(&value).expect("ResolvedPolicy is always serialisable"))
    }

    /// Build the opaque [`ContractBundleHandle`] the engine operators consume.
    pub fn to_bundle_handle(&self) -> ContractBundleHandle {
        ContractBundleHandle::from_x02_bytes(
            self.contract_id.clone(),
            self.tenant_id.clone(),
            self.to_bundle_bytes(),
        )
    }
}

/// Errors building or interpreting a [`ResolvedPolicy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A masking token in the contract was not recognised.
    #[error("unknown mask action '{0}' (expected redact|hash_sha256|tokenize|partial|null|noop)")]
    UnknownMaskAction(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_action_parse_and_str_roundtrip() {
        for (s, action) in [
            ("redact", MaskAction::Redact),
            ("hash_sha256", MaskAction::HashSha256),
            ("tokenize", MaskAction::Tokenize),
            ("partial", MaskAction::Partial),
            ("null", MaskAction::Null),
            ("noop", MaskAction::Noop),
        ] {
            assert_eq!(MaskAction::parse(s).unwrap(), action);
            assert_eq!(action.as_bundle_str(), s);
        }
        assert!(MaskAction::parse("rainbow").is_err());
    }

    #[test]
    fn to_bundle_bytes_emits_operator_json() {
        let mut policy = ResolvedPolicy::allow_all("c1", "1", "acme");
        policy
            .column_masks
            .insert("email".into(), MaskAction::HashSha256);
        policy.column_masks.insert("score".into(), MaskAction::Noop); // omitted
        policy.row_filter = Some("region = 'EU'".into());
        policy.dp_columns.insert(
            "amount".into(),
            DpParam {
                sensitivity: 1.0,
                epsilon: 0.1,
            },
        );

        let v: serde_json::Value = serde_json::from_slice(&policy.to_bundle_bytes()).unwrap();

        // Exactly the keys the physical operators parse.
        assert_eq!(v["contract_id"], "c1");
        assert_eq!(v["contract_version"], "1");
        assert_eq!(v["column_masking"]["email"], "hash_sha256");
        assert!(v["column_masking"].get("score").is_none()); // Noop omitted
        assert_eq!(v["row_filter"], "region = 'EU'");
        assert_eq!(v["dp_columns"]["amount"]["sensitivity"], 1.0);
        assert_eq!(v["dp_columns"]["amount"]["epsilon"], 0.1);
    }

    #[test]
    fn allow_all_has_no_enforcement() {
        let p = ResolvedPolicy::allow_all("c", "1", "t");
        assert!(p.is_allowed());
        assert!(!p.has_dp());
        assert!(p.column_masks.is_empty());
        assert!(p.row_filter.is_none());
    }
}
