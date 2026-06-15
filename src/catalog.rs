//! The DataFusion catalog that makes `SELECT * FROM "tenant/dataset/v1"` resolve
//! through a contract.
//!
//! When DataFusion encounters a (quoted) table reference it cannot find, it asks
//! the registered [`SchemaProvider`] to produce it. [`GriotSchemaProvider`]
//! treats the reference as a dataset URI, resolves the governing contract for
//! the current caller into a [`ResolvedPolicy`], resolves the physical binding,
//! and returns a [`ContractTableProvider`] — so the very act of naming a dataset
//! in SQL is what triggers contract evaluation. There is no un-resolved path.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::catalog::{CatalogProvider, SchemaProvider};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DFResult};

use crate::binding::{BindingResolver, DatasetRef};
use crate::contract_source::{Caller, ContractSource};
use crate::contract_table_provider::ContractTableProvider;
use crate::policy::Decision;

/// A schema whose tables are contract-bound datasets resolved on demand for one
/// caller.
pub struct GriotSchemaProvider {
    source: Arc<dyn ContractSource>,
    binding: Arc<dyn BindingResolver>,
    caller: Caller,
}

impl fmt::Debug for GriotSchemaProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GriotSchemaProvider")
            .field("caller", &self.caller.id)
            .finish()
    }
}

impl GriotSchemaProvider {
    /// Build a schema bound to one caller's identity.
    pub fn new(
        source: Arc<dyn ContractSource>,
        binding: Arc<dyn BindingResolver>,
        caller: Caller,
    ) -> Self {
        Self {
            source,
            binding,
            caller,
        }
    }
}

#[async_trait]
impl SchemaProvider for GriotSchemaProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn table_names(&self) -> Vec<String> {
        // Datasets are resolved lazily by name; we do not enumerate them.
        Vec::new()
    }

    async fn table(&self, name: &str) -> DFResult<Option<Arc<dyn TableProvider>>> {
        let dataset = DatasetRef::new(name);

        let policy = self
            .source
            .resolve(&dataset, &self.caller)
            .await
            .map_err(|e| {
                DataFusionError::Plan(format!("contract resolution failed for '{name}': {e}"))
            })?;

        match &policy.decision {
            Decision::Deny { reason } => Err(DataFusionError::Plan(format!(
                "contract denied access to '{name}': {reason}"
            ))),
            Decision::Allow => {
                let inner = self.binding.resolve(&dataset).await.map_err(|e| {
                    DataFusionError::Plan(format!("binding failed for '{name}': {e}"))
                })?;
                Ok(Some(Arc::new(ContractTableProvider::new(inner, &policy))))
            }
        }
    }

    fn table_exist(&self, _name: &str) -> bool {
        // Resolution is lazy and may hit the network; always attempt `table()`
        // and let it return a precise error if the dataset is unknown/denied.
        true
    }
}

/// A catalog exposing a single [`GriotSchemaProvider`] schema.
pub struct GriotCatalogProvider {
    schema_name: String,
    schema: Arc<GriotSchemaProvider>,
}

impl fmt::Debug for GriotCatalogProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GriotCatalogProvider")
            .field("schema_name", &self.schema_name)
            .finish()
    }
}

impl GriotCatalogProvider {
    /// Wrap `schema` under the schema name `schema_name`.
    pub fn new(schema_name: impl Into<String>, schema: Arc<GriotSchemaProvider>) -> Self {
        Self {
            schema_name: schema_name.into(),
            schema,
        }
    }
}

impl CatalogProvider for GriotCatalogProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema_names(&self) -> Vec<String> {
        vec![self.schema_name.clone()]
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn SchemaProvider>> {
        if name == self.schema_name {
            Some(self.schema.clone())
        } else {
            None
        }
    }
}
