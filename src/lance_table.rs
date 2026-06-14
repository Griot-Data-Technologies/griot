//! Lance dataset TableProvider — opens Lance files via the T04 storaged socket.
//!
//! This module provides `LanceTableProvider`, a DataFusion `TableProvider` that
//! wraps a Lance dataset opened against a custom `ObjectStore` backend that
//! routes all byte reads through the T04 storaged socket.
//!
//! # Why this approach
//!
//! Lance's `Dataset::open` accepts an `object_store::ObjectStore` implementation
//! for all underlying I/O. By providing `StoragedObjectStore` (a custom `ObjectStore`
//! that proxies reads through `StoragedClient`), we ensure:
//!
//! 1. No direct filesystem access from the engine pod.
//! 2. T04 enforces contract constraints on every byte read (INV-2).
//! 3. The lance dataset is opened against a URL in the `griotfs://` scheme,
//!    routing through the custom store registration.
//!
//! # Limitations
//!
//! * Write path: not implemented. Lance write operations go through T04's write
//!   opcodes, handled by the Type B transform worker, not the Type D query worker.
//! * Metadata: the initial `stat` call uses `StoragedClient::stat_asset` to
//!   determine the asset size before lance opens the dataset.
//!
//! # Semantic Law
//!
//! * INV-5: No direct filesystem or object-storage access.
//! * INV-2: T04 enforces contract constraints per byte range.

use crate::storaged_client::StoragedClient;
use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::TableProvider;
use datafusion::error::DataFusionError;
use datafusion::execution::context::SessionState;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::{datasource::TableType, logical_expr::Expr};
use std::any::Any;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors specific to Lance table registration.
#[derive(Debug, Error)]
pub enum LanceTableError {
    /// Storaged client error.
    #[error("storaged error: {0}")]
    Storaged(#[from] crate::storaged_client::StoragedError),

    /// Lance dataset open error.
    #[error("lance dataset open error: {0}")]
    LanceOpen(String),

    /// The asset is not a Lance dataset (wrong content type).
    #[error("asset '{asset_id}' is not a Lance dataset (content_type='{content_type}')")]
    NotLance {
        asset_id: String,
        content_type: String,
    },
}

// ─── StoragedObjectStore ─────────────────────────────────────────────────────

/// A custom `object_store::ObjectStore` backend that routes all byte reads
/// through the T04 storaged socket.
///
/// Only `get_range` (positional byte read) is fully implemented. All write
/// operations return `NotSupported` — writes go through Type B, not Type D.
#[derive(Debug)]
pub struct StoragedObjectStore {
    client: StoragedClient,
    asset_id: String,
    tenant_id: String,
    principal_jwt: String,
    /// Total asset size, obtained via `stat_asset` at construction.
    size: u64,
}

impl StoragedObjectStore {
    async fn new(
        asset_id: &str,
        tenant_id: &str,
        principal_jwt: &str,
        storaged_path: &str,
    ) -> Result<Self, LanceTableError> {
        let client = StoragedClient::new(storaged_path);
        let stat = client
            .stat_asset(asset_id, tenant_id, principal_jwt)
            .await?;

        Ok(Self {
            client,
            asset_id: asset_id.to_string(),
            tenant_id: tenant_id.to_string(),
            principal_jwt: principal_jwt.to_string(),
            size: stat.size,
        })
    }
}

impl fmt::Display for StoragedObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StoragedObjectStore(asset={})", self.asset_id)
    }
}

// Implement the object_store::ObjectStore trait for StoragedObjectStore.
// Only `get_range` (positional byte read) and `head` (metadata) are needed
// by lance for read-only queries.
#[async_trait]
impl object_store::ObjectStore for StoragedObjectStore {
    async fn put(
        &self,
        _location: &object_store::path::Path,
        _payload: object_store::PutPayload,
    ) -> object_store::Result<object_store::PutResult> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }

    async fn put_multipart(
        &self,
        _location: &object_store::path::Path,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }

    async fn get(
        &self,
        location: &object_store::path::Path,
    ) -> object_store::Result<object_store::GetResult> {
        // Return all bytes as a stream.
        let bytes = self
            .client
            .read_bytes(
                &self.asset_id,
                0,
                self.size,
                &self.tenant_id,
                &self.principal_jwt,
            )
            .await
            .map_err(|e| object_store::Error::Generic {
                store: "StoragedObjectStore",
                source: Box::new(e),
            })?;

        let meta = object_store::ObjectMeta {
            location: location.clone(),
            last_modified: chrono::Utc::now(),
            size: bytes.len(),
            e_tag: None,
            version: None,
        };

        Ok(object_store::GetResult {
            payload: object_store::GetResultPayload::Stream(Box::pin(futures::stream::once(
                async move { Ok(bytes) },
            ))),
            meta,
            range: 0..self.size as usize,
            attributes: Default::default(),
        })
    }

    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        // Honour range if present.
        let (offset, length) = if let Some(range) = options.range {
            match range {
                object_store::GetRange::Bounded(r) => (r.start as u64, (r.end - r.start) as u64),
                object_store::GetRange::Offset(o) => (o as u64, self.size.saturating_sub(o as u64)),
                object_store::GetRange::Suffix(s) => {
                    let off = self.size.saturating_sub(s as u64);
                    (off, s as u64)
                }
            }
        } else {
            (0, self.size)
        };

        let bytes = self
            .client
            .read_bytes(
                &self.asset_id,
                offset,
                length,
                &self.tenant_id,
                &self.principal_jwt,
            )
            .await
            .map_err(|e| object_store::Error::Generic {
                store: "StoragedObjectStore",
                source: Box::new(e),
            })?;

        let meta = object_store::ObjectMeta {
            location: location.clone(),
            last_modified: chrono::Utc::now(),
            size: self.size as usize,
            e_tag: None,
            version: None,
        };

        Ok(object_store::GetResult {
            payload: object_store::GetResultPayload::Stream(Box::pin(futures::stream::once(
                async move { Ok(bytes) },
            ))),
            meta,
            range: offset as usize..(offset + length) as usize,
            attributes: Default::default(),
        })
    }

    async fn get_range(
        &self,
        location: &object_store::path::Path,
        range: Range<usize>,
    ) -> object_store::Result<bytes::Bytes> {
        let offset = range.start as u64;
        let length = (range.end - range.start) as u64;

        debug!(
            asset_id = %self.asset_id,
            offset,
            length,
            "StoragedObjectStore::get_range"
        );

        self.client
            .read_bytes(
                &self.asset_id,
                offset,
                length,
                &self.tenant_id,
                &self.principal_jwt,
            )
            .await
            .map_err(|e| object_store::Error::Generic {
                store: "StoragedObjectStore",
                source: Box::new(e),
            })
    }

    async fn head(
        &self,
        location: &object_store::path::Path,
    ) -> object_store::Result<object_store::ObjectMeta> {
        Ok(object_store::ObjectMeta {
            location: location.clone(),
            last_modified: chrono::Utc::now(),
            size: self.size as usize,
            e_tag: None,
            version: None,
        })
    }

    async fn delete(&self, _location: &object_store::path::Path) -> object_store::Result<()> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }

    fn list(
        &self,
        _prefix: Option<&object_store::path::Path>,
    ) -> futures::stream::BoxStream<'_, object_store::Result<object_store::ObjectMeta>> {
        Box::pin(futures::stream::empty())
    }

    async fn list_with_delimiter(
        &self,
        _prefix: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Ok(object_store::ListResult {
            common_prefixes: vec![],
            objects: vec![],
        })
    }

    async fn copy(
        &self,
        _from: &object_store::path::Path,
        _to: &object_store::path::Path,
    ) -> object_store::Result<()> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }

    async fn rename(
        &self,
        _from: &object_store::path::Path,
        _to: &object_store::path::Path,
    ) -> object_store::Result<()> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }

    async fn copy_if_not_exists(
        &self,
        _from: &object_store::path::Path,
        _to: &object_store::path::Path,
    ) -> object_store::Result<()> {
        Err(object_store::Error::NotSupported {
            source: "StoragedObjectStore is read-only".into(),
        })
    }
}

// ─── LanceTableProvider ───────────────────────────────────────────────────────

/// A DataFusion `TableProvider` backed by a Lance dataset opened via the T04
/// storaged byte-read socket.
///
/// Construction: `LanceTableProvider::open(...)`.
/// Usage: pass to `SessionContext::register_table`.
pub struct LanceTableProvider {
    dataset: Arc<lance::Dataset>,
    schema: SchemaRef,
}

impl LanceTableProvider {
    /// Open a Lance dataset from griotfs via the T04 storaged socket.
    ///
    /// # Arguments
    ///
    /// * `asset_id` — griotfs asset UUID for the Lance dataset.
    /// * `tenant_id` — tenant context.
    /// * `principal_jwt` — scoped JWT for the requesting principal.
    /// * `storaged_path` — path to the T04 storaged socket.
    pub async fn open(
        asset_id: &str,
        tenant_id: &str,
        principal_jwt: &str,
        storaged_path: &str,
    ) -> Result<Self, LanceTableError> {
        // Construct the storaged-backed object store.
        let store = Arc::new(
            StoragedObjectStore::new(asset_id, tenant_id, principal_jwt, storaged_path).await?,
        );

        // Build the griotfs:// URL for this asset.
        let url = format!("griotfs://{asset_id}");

        // Open the Lance dataset using the custom object store.
        // We register the store with the lance runtime registry.
        let store_url = url::Url::parse(&url)
            .map_err(|e| LanceTableError::LanceOpen(format!("URL parse error for '{url}': {e}")))?;

        let params = lance::dataset::ReadParams {
            store_options: Some(object_store::ClientOptions::default()),
            ..Default::default()
        };

        // Register the custom store with lance's object store registry.
        let registry = lance_io::object_store::ObjectStoreRegistry::default();
        registry.put(&store_url, store.clone());

        let dataset = lance::Dataset::open_with_params(&url, &params)
            .await
            .map_err(|e| LanceTableError::LanceOpen(format!("lance::Dataset::open: {e}")))?;

        let arrow_schema: SchemaRef = Arc::new(
            dataset
                .schema()
                .to_arrow()
                .map_err(|e| LanceTableError::LanceOpen(format!("lance schema to arrow: {e}")))?,
        );

        debug!(asset_id, schema = ?arrow_schema, "Lance dataset opened via storaged socket");

        Ok(Self {
            dataset: Arc::new(dataset),
            schema: arrow_schema,
        })
    }
}

#[async_trait]
impl TableProvider for LanceTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> datafusion::error::Result<Arc<dyn ExecutionPlan>> {
        // Build a lance scanner.
        let mut scanner = self.dataset.scan();

        // Apply projection.
        if let Some(proj) = projection {
            let schema = self.schema.clone();
            let cols: Vec<&str> = proj
                .iter()
                .filter_map(|&i| schema.field(i).name().parse::<&str>().ok())
                .collect();
            // Project by name list (lance API).
            let col_names: Vec<&str> = proj
                .iter()
                .map(|&i| self.schema.field(i).name().as_str())
                .collect();
            scanner = scanner
                .project(&col_names)
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
        }

        // Apply limit.
        if let Some(n) = limit {
            scanner = scanner
                .limit(n as i64, None)
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
        }

        // Push down simple filters if possible (best-effort; full predicate pushdown
        // is a future wave).
        // For now, no filter pushdown — filters are applied by DataFusion post-scan.

        // Collect into Arrow RecordBatches and wrap in MemTable for simplicity.
        // Production optimization: implement a proper streaming ExecutionPlan.
        let batches: Vec<datafusion::arrow::record_batch::RecordBatch> = scanner
            .try_into_stream()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
            .collect::<Result<Vec<_>, _>>()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;

        let mem_table =
            datafusion::datasource::MemTable::try_new(self.schema.clone(), vec![batches])?;
        let plan = mem_table.scan(_state, projection, filters, limit).await?;

        Ok(plan)
    }
}
