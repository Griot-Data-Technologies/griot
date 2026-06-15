//! [`GriotEngine`] — the high-level, contract-resolving query API.
//!
//! ```ignore
//! let engine = GriotEngine::from_json_contracts_dir("./contracts")?;
//! let rows = engine
//!     .query(r#"SELECT * FROM "sales/orders/v1""#, Caller::new("user:bob", "analytics", "globex"))
//!     .await?;
//! ```
//!
//! Each query runs in a fresh DataFusion session whose default catalog is a
//! caller-bound [`GriotCatalogProvider`], so the caller's identity flows into
//! contract resolution without any global state.

use std::sync::Arc;

use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::{SessionConfig, SessionContext};

use crate::binding::BindingResolver;
use crate::catalog::{GriotCatalogProvider, GriotSchemaProvider};
use crate::contract_source::{Caller, ContractError, ContractSource, JsonContractSource};
use crate::{DdlGuard, EngineError};

/// The catalog name bare quoted dataset references resolve under.
const CATALOG_NAME: &str = "griot";
/// The schema name within the griot catalog.
const SCHEMA_NAME: &str = "data";

/// A query engine that resolves a contract + a data location for every query and
/// returns governed rows.
pub struct GriotEngine {
    source: Arc<dyn ContractSource>,
    binding: Arc<dyn BindingResolver>,
}

impl GriotEngine {
    /// Build from any contract source + binding resolver.
    pub fn new(source: Arc<dyn ContractSource>, binding: Arc<dyn BindingResolver>) -> Self {
        Self { source, binding }
    }

    /// Build an open-source engine from a directory of JSON contracts. The same
    /// [`JsonContractSource`] supplies both the policy and the (local Parquet)
    /// binding.
    pub fn from_json_contracts_dir(
        dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, ContractError> {
        let src = Arc::new(JsonContractSource::from_dir(dir)?);
        Ok(Self::new(
            src.clone() as Arc<dyn ContractSource>,
            src as Arc<dyn BindingResolver>,
        ))
    }

    /// Build an open-source engine from in-memory JSON contract documents.
    pub fn from_json_contracts<I, S>(docs: I) -> Result<Self, ContractError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let src = Arc::new(JsonContractSource::from_json_strs(docs)?);
        Ok(Self::new(
            src.clone() as Arc<dyn ContractSource>,
            src as Arc<dyn BindingResolver>,
        ))
    }

    /// Run `sql` as `caller`, returning governed rows.
    ///
    /// Datasets are referenced by their (quoted) URI, e.g.
    /// `SELECT * FROM "sales/orders/v1"`. Masking, row filtering and DP noise
    /// from the governing contract are applied inside the query plan.
    pub async fn query(&self, sql: &str, caller: Caller) -> Result<Vec<RecordBatch>, EngineError> {
        // Defence-in-depth: reject unsafe DDL before planning.
        DdlGuard::reject_unsafe_ddl(sql)?;

        let schema = Arc::new(GriotSchemaProvider::new(
            self.source.clone(),
            self.binding.clone(),
            caller,
        ));
        let catalog = Arc::new(GriotCatalogProvider::new(SCHEMA_NAME, schema));

        let config =
            SessionConfig::new().with_default_catalog_and_schema(CATALOG_NAME, SCHEMA_NAME);
        let ctx = SessionContext::new_with_config(config);
        ctx.register_catalog(CATALOG_NAME, catalog);

        let df = ctx.sql(sql).await?;
        let batches = df.collect().await?;
        Ok(batches)
    }
}
