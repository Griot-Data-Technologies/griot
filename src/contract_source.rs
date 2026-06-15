//! Contract sources: turning a contract + a caller into a [`ResolvedPolicy`].
//!
//! [`JsonContractSource`] is the open-source path — it reads a simple JSON
//! contract format (see `docs/CONTRACT-FORMAT.md`) and evaluates a small set of
//! per-caller rules. The platform path ([`crate::platform`], feature
//! `platform`) consumes T03's signed bundle instead. Both produce the same
//! [`ResolvedPolicy`], so the engine is identical underneath.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::datasource::TableProvider;
use serde::Deserialize;

use crate::binding::{load_parquet_as_provider, BindingError, BindingResolver, DatasetRef};
use crate::policy::{Decision, DpParam, MaskAction, PolicyError, ResolvedPolicy};

/// The identity and intent of whoever is running a query.
///
/// The contract source uses this to decide visibility — e.g. a caller from the
/// owning tenant may see raw data while everyone else sees masked data.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Stable principal id (e.g. `"user:alice"` or `"service:k03"`).
    pub id: String,
    /// The declared purpose of this query (must satisfy the contract).
    pub purpose: String,
    /// The caller's tenant.
    pub tenant: String,
    /// Authorisation tier (e.g. `bronze` / `silver` / `gold`).
    pub tier: String,
    /// Data classification the caller is cleared for.
    pub classification: String,
}

impl Caller {
    /// Convenience constructor for the common case (id + purpose + tenant).
    pub fn new(
        id: impl Into<String>,
        purpose: impl Into<String>,
        tenant: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            purpose: purpose.into(),
            tenant: tenant.into(),
            tier: "bronze".to_string(),
            classification: "internal".to_string(),
        }
    }
}

/// Resolves a contract for a caller into an engine-ready [`ResolvedPolicy`].
#[async_trait]
pub trait ContractSource: Send + Sync {
    /// Evaluate the contract governing `dataset` against `caller`.
    async fn resolve(
        &self,
        dataset: &DatasetRef,
        caller: &Caller,
    ) -> Result<ResolvedPolicy, ContractError>;
}

// ─── JSON contract format (open-source) ───────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct JsonContract {
    contract_id: String,
    version: String,
    dataset: String,
    binding: JsonBinding,
    owner_tenant: String,
    #[serde(default)]
    purposes: Vec<String>,
    #[serde(default)]
    columns: Vec<JsonColumn>,
    #[serde(default)]
    row_filter: Option<String>,
    #[serde(default)]
    dp_columns: HashMap<String, DpParam>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonBinding {
    /// Path to a local Parquet file holding this dataset's rows.
    parquet: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonColumn {
    name: String,
    #[serde(default)]
    mask: Option<String>,
}

/// An open-source contract source backed by JSON contract documents.
///
/// Contracts are keyed by their `dataset` field; that is the name a query
/// targets (`SELECT * FROM "<dataset>"`).
pub struct JsonContractSource {
    contracts: HashMap<String, JsonContract>,
}

impl JsonContractSource {
    /// Build from in-memory JSON contract strings.
    pub fn from_json_strs<I, S>(docs: I) -> Result<Self, ContractError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut contracts = HashMap::new();
        for doc in docs {
            let c: JsonContract = serde_json::from_str(doc.as_ref())
                .map_err(|e| ContractError::Parse(e.to_string()))?;
            contracts.insert(c.dataset.clone(), c);
        }
        Ok(Self { contracts })
    }

    /// Load every `*.json` contract under `dir`.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, ContractError> {
        let dir = dir.as_ref();
        let mut docs = Vec::new();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| ContractError::Parse(format!("read_dir {dir:?}: {e}")))?;
        for entry in entries {
            let path = entry
                .map_err(|e| ContractError::Parse(e.to_string()))?
                .path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| ContractError::Parse(format!("read {path:?}: {e}")))?;
                docs.push(text);
            }
        }
        Self::from_json_strs(docs)
    }

    fn get(&self, dataset: &DatasetRef) -> Result<&JsonContract, ContractError> {
        self.contracts
            .get(dataset.as_str())
            .ok_or_else(|| ContractError::NotFound(dataset.to_string()))
    }
}

#[async_trait]
impl ContractSource for JsonContractSource {
    async fn resolve(
        &self,
        dataset: &DatasetRef,
        caller: &Caller,
    ) -> Result<ResolvedPolicy, ContractError> {
        let contract = self.get(dataset)?;

        // Purpose gate: the caller's declared purpose must be allowed.
        if !contract.purposes.is_empty() && !contract.purposes.contains(&caller.purpose) {
            return Ok(ResolvedPolicy {
                contract_id: contract.contract_id.clone(),
                contract_version: contract.version.clone(),
                tenant_id: contract.owner_tenant.clone(),
                decision: Decision::Deny {
                    reason: format!(
                        "purpose '{}' is not permitted by contract '{}' (allowed: {:?})",
                        caller.purpose, contract.contract_id, contract.purposes
                    ),
                },
                column_masks: HashMap::new(),
                row_filter: None,
                dp_columns: HashMap::new(),
            });
        }

        // The owning tenant sees raw data; everyone else gets masks + filters.
        let is_owner = caller.tenant == contract.owner_tenant;
        if is_owner {
            return Ok(ResolvedPolicy::allow_all(
                contract.contract_id.clone(),
                contract.version.clone(),
                contract.owner_tenant.clone(),
            ));
        }

        let mut column_masks = HashMap::new();
        for col in &contract.columns {
            if let Some(mask) = &col.mask {
                let action = MaskAction::parse(mask)?;
                if action != MaskAction::Noop {
                    column_masks.insert(col.name.clone(), action);
                }
            }
        }

        Ok(ResolvedPolicy {
            contract_id: contract.contract_id.clone(),
            contract_version: contract.version.clone(),
            tenant_id: contract.owner_tenant.clone(),
            decision: Decision::Allow,
            column_masks,
            row_filter: contract.row_filter.clone(),
            dp_columns: contract.dp_columns.clone(),
        })
    }
}

#[async_trait]
impl BindingResolver for JsonContractSource {
    async fn resolve(&self, dataset: &DatasetRef) -> Result<Arc<dyn TableProvider>, BindingError> {
        let contract = self
            .contracts
            .get(dataset.as_str())
            .ok_or_else(|| BindingError::NotFound(dataset.to_string()))?;
        load_parquet_as_provider(Path::new(&contract.binding.parquet))
    }
}

/// Errors resolving a contract.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    /// No contract governs the requested dataset.
    #[error("no contract for dataset '{0}'")]
    NotFound(String),

    /// A contract document could not be parsed.
    #[error("contract parse error: {0}")]
    Parse(String),

    /// A masking token in the contract was invalid.
    #[error(transparent)]
    Policy(#[from] PolicyError),

    /// A platform (T03) bundle could not be fetched, verified, or mapped
    /// (feature `platform`).
    #[error("platform bundle error: {0}")]
    Platform(String),
}
