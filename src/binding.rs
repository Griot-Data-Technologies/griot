//! Binding resolution: mapping a dataset reference to the physical data.
//!
//! A [`BindingResolver`] answers "where do the bytes for this dataset live, and
//! how do I read them?" by returning a DataFusion [`TableProvider`]. This is the
//! seam that lets the same engine read a local Parquet file (open-source) or a
//! T02-managed Lance dataset (platform) without the query path knowing which.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::datasource::{MemTable, TableProvider};

/// A reference to a contract-bound dataset, e.g. `"sales/orders/v1"`.
///
/// This is the (quoted) table name a query targets:
/// `SELECT * FROM "sales/orders/v1"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetRef(String);

impl DatasetRef {
    /// Wrap a raw dataset URI / id.
    pub fn new(uri: impl Into<String>) -> Self {
        Self(uri.into())
    }

    /// The raw URI string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DatasetRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolves a dataset reference to a readable DataFusion table.
#[async_trait]
pub trait BindingResolver: Send + Sync {
    /// Return the raw (ungoverned) table provider for `dataset`.
    async fn resolve(&self, dataset: &DatasetRef) -> Result<Arc<dyn TableProvider>, BindingError>;
}

/// Load a local Parquet file fully into memory and expose it as a table.
///
/// Reading the whole file into a [`MemTable`] keeps the open-source path
/// dependency-free (no object store, no `ListingTable` plumbing) and is ideal
/// for the dev/demo datasets the standalone engine targets. Large-file
/// streaming via `ListingTable` is a documented follow-up.
pub fn load_parquet_as_provider(path: &Path) -> Result<Arc<dyn TableProvider>, BindingError> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(path).map_err(|e| BindingError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .map_err(|e| BindingError::Parquet(format!("{path:?}: {e}")))?;
    let schema = builder.schema().clone();
    let reader = builder
        .build()
        .map_err(|e| BindingError::Parquet(format!("{path:?}: {e}")))?;

    let mut batches = Vec::new();
    for batch in reader {
        batches.push(batch.map_err(|e| BindingError::Parquet(format!("{path:?}: {e}")))?);
    }

    let table = MemTable::try_new(schema, vec![batches])
        .map_err(|e| BindingError::Build(format!("MemTable: {e}")))?;
    Ok(Arc::new(table))
}

/// Errors resolving a dataset binding.
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    /// The dataset has no binding registered / could not be located.
    #[error("no binding for dataset '{0}'")]
    NotFound(String),

    /// The backing file could not be opened.
    #[error("io error reading '{path}': {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying io error.
        source: std::io::Error,
    },

    /// The Parquet file could not be read.
    #[error("parquet read error: {0}")]
    Parquet(String),

    /// The in-memory table could not be constructed.
    #[error("failed to build table provider: {0}")]
    Build(String),
}
