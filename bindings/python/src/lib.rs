//! PyO3 bindings exposing the GriotQL open-source engine to Python.
//!
//! The native module returns query results as Arrow IPC stream bytes; the thin
//! Python wrapper (`python/griotql/__init__.py`) turns them into a
//! `pyarrow.Table`. This keeps the native surface free of any pyarrow/pyo3
//! version coupling.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use griot::contract_source::Caller as RsCaller;
use griot::engine::GriotEngine;
use griot::result_formatter::{ResultFormat, ResultFormatter};

/// The identity + intent of whoever runs a query.
#[pyclass]
#[derive(Clone)]
struct Caller {
    inner: RsCaller,
}

#[pymethods]
impl Caller {
    #[new]
    #[pyo3(signature = (id, purpose, tenant, tier=None, classification=None))]
    fn new(
        id: String,
        purpose: String,
        tenant: String,
        tier: Option<String>,
        classification: Option<String>,
    ) -> Self {
        Caller {
            inner: RsCaller {
                id,
                purpose,
                tenant,
                tier: tier.unwrap_or_else(|| "bronze".to_string()),
                classification: classification.unwrap_or_else(|| "internal".to_string()),
            },
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Caller(id='{}', purpose='{}', tenant='{}')",
            self.inner.id, self.inner.purpose, self.inner.tenant
        )
    }
}

/// A contract-resolving query engine.
#[pyclass]
struct Engine {
    inner: GriotEngine,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl Engine {
    /// Build from a directory of JSON contracts (+ local Parquet bindings).
    #[staticmethod]
    fn from_json_contracts_dir(dir: String) -> PyResult<Self> {
        let inner = GriotEngine::from_json_contracts_dir(&dir).map_err(to_py)?;
        Ok(Self {
            inner,
            rt: runtime()?,
        })
    }

    /// Build from in-memory JSON contract documents.
    #[staticmethod]
    fn from_json_contracts(docs: Vec<String>) -> PyResult<Self> {
        let inner = GriotEngine::from_json_contracts(docs).map_err(to_py)?;
        Ok(Self {
            inner,
            rt: runtime()?,
        })
    }

    /// Run `sql` as `caller`; returns the governed result as Arrow IPC bytes.
    fn query<'py>(
        &self,
        py: Python<'py>,
        sql: String,
        caller: &Caller,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let caller = caller.inner.clone();
        let batches = py
            .allow_threads(|| self.rt.block_on(self.inner.query(&sql, caller)))
            .map_err(to_py)?;
        let ipc = ResultFormatter::format_results(&batches, ResultFormat::Arrow).map_err(to_py)?;
        Ok(PyBytes::new(py, &ipc))
    }
}

fn runtime() -> PyResult<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

fn to_py<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Engine>()?;
    m.add_class::<Caller>()?;
    Ok(())
}
