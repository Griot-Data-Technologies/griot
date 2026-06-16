// Suppress lints that are expected in the Wave 8/10 scaffold.
// - private_bounds: the sealed-trait pattern (ADR-0002 §c) intentionally
//   exposes a pub trait bounded on a private trait.
// - dead_code: raw_bytes and optimizer-rule stub internals are placeholders
//   for the Wave 8 impl PR.
#![allow(private_bounds, dead_code)]
//! K04D DataFusion-based Query Engine — Shell
//!
//! ADR-0002 (2026-05-04): Query-level contract enforcement moves from T04 into
//! this engine.  Contract evaluation happens as DataFusion optimizer rules and
//! physical operators so that no data path exists except through a
//! contract-evaluating engine.
//!
//! This module is the engine SHELL:
//! - [`K04DEngine`] — the top-level engine struct, construction is sealed
//!   (no public constructors; only [`K04DEngine::new_with_config`] and only
//!   callable from inside this crate via the sealed trait).
//! - [`InitConfig`] — builder for engine configuration (tenant, contract
//!   bundle endpoint, etc.).
//! - [`ContractBundleHandle`] — opaque handle to a signed contract bundle
//!   received from T04's `get_contract_bundle` X02 opcode.
//!
//! # Semantic Law invariants upheld by this shell
//!
//! * INV-1 (No data in without contract): engine refuses to open a read
//!   session until a [`ContractBundleHandle`] is injected.
//! * INV-2/3 (No read/write without satisfaction): enforced by optimizer rules
//!   (not yet implemented in this shell; will be added in subsequent waves).
//! * INV-5 (No bypass from above trust line): this crate imports nothing from
//!   zone-t. Contract bundles arrive via a signed X02 socket handle — never
//!   via a direct in-process call to T04 internals.
//!
//! # ADR-0002 verified-binary surface requirements
//!
//! Per ADR-0002 and CLAUDE.md Hard Constraints:
//! (a) Reproducibly built in CI — enforced by pinned Cargo.lock and
//!     rust-toolchain.toml.
//! (b) Sigstore attestation — wired in CI (not this crate's concern).
//! (c) Enforcement primitives behind sealed traits — see [`sealed::EngineCore`].
//! (d) No INSTALL/LOAD/ATTACH/COPY — enforced by [`DdlGuard::reject_unsafe_ddl`].

use thiserror::Error;
use uuid::Uuid;

// ─── Sealed-trait module ──────────────────────────────────────────────────────

/// Module that prevents external implementations of [`EngineCore`].
///
/// This is the standard Rust sealed-trait pattern.
///
/// The outer module `sealed` is **public** so that external callers (test
/// binaries, downstream crates) can NAME the trait as a bound or call methods
/// through a trait object.  The inner module `private` is **pub(crate)** so
/// that external code CANNOT implement `Sealed` and therefore cannot create a
/// new implementation of `EngineCore` that bypasses contract enforcement.
///
/// ADR-0002 verified-binary surface rule (c): enforcement primitives behind
/// sealed traits.
pub mod sealed {
    /// Private marker — inaccessible outside this crate, preventing external
    /// implementations of [`EngineCore`].
    pub mod private {
        /// Marker trait — only types inside this crate (k04d-query-rs) can
        /// implement it, because the module is `pub(crate)`.
        pub(crate) trait Sealed {}
    }

    /// The sealed enforcement trait.  Only [`super::K04DEngine`] implements this.
    /// External code can call the methods through a trait object or bound, but
    /// cannot provide a new implementation that skips contract enforcement.
    ///
    pub trait EngineCore: private::Sealed {
        /// Return the tenant ID this engine instance was initialised for.
        fn tenant_id(&self) -> &str;

        /// Return whether a contract bundle has been injected.
        fn has_contract_bundle(&self) -> bool;
    }
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// Errors emitted by the K04D engine shell.
#[derive(Debug, Error)]
pub enum EngineError {
    /// A SQL statement contains a disallowed DDL verb: INSTALL, LOAD, ATTACH,
    /// or COPY.  These are prohibited per ADR-0002 to prevent unsigned plugin
    /// injection (Semantic Law invariant 5 and verified-binary surface rule (d)).
    #[error("unsafe DDL rejected: statement contains disallowed verb '{verb}'")]
    UnsafeDdlRejected { verb: String },

    /// The engine was asked to execute a query before a contract bundle was
    /// injected.  Semantic Law invariant 1 — no read without contract.
    #[error("no contract bundle: inject a ContractBundleHandle before querying")]
    NoContractBundle,

    /// The [`InitConfig`] was incomplete or inconsistent.
    #[error("invalid engine configuration: {reason}")]
    InvalidConfig { reason: String },

    /// A DataFusion internal error.
    #[error("datafusion error: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),

    /// The Lance dataset could not be opened or registered.
    #[error("lance table registration failed for asset '{asset_id}': {reason}")]
    LanceRegistration { asset_id: String, reason: String },

    /// The storaged socket could not be reached when opening a Lance dataset.
    #[error("storaged unavailable for lance registration: {0}")]
    StoragedUnavailable(String),

    /// An unexpected internal error.
    #[error("internal engine error: {0}")]
    Internal(String),
}

/// Builder for [`K04DEngine`] initialisation parameters.
///
/// All fields are required before calling [`K04DEngine::new_with_config`].
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// The tenant whose data this engine instance will serve.
    pub tenant_id: String,

    /// URI of the T04 `get_contract_bundle` X02 socket endpoint.
    /// Format: `unix:///run/griot/t04.sock` or `grpc://127.0.0.1:9090`.
    pub contract_bundle_endpoint: String,

    /// URI of the T05 `request_signing` X02 socket endpoint (for result
    /// attestation envelopes).
    pub attestation_endpoint: String,

    /// Maximum number of rows returned in a single result batch.
    pub max_result_rows: usize,

    /// Path to the T04 storaged byte-read socket.
    /// Default: `/run/griot/t04.sock`.
    pub storaged_socket: String,
}

impl InitConfig {
    /// Validate the config.  Returns `Err` if any required field is empty or
    /// inconsistent.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.tenant_id.is_empty() {
            return Err(EngineError::InvalidConfig {
                reason: "tenant_id must not be empty".into(),
            });
        }
        if self.contract_bundle_endpoint.is_empty() {
            return Err(EngineError::InvalidConfig {
                reason: "contract_bundle_endpoint must not be empty".into(),
            });
        }
        if self.attestation_endpoint.is_empty() {
            return Err(EngineError::InvalidConfig {
                reason: "attestation_endpoint must not be empty".into(),
            });
        }
        if self.max_result_rows == 0 {
            return Err(EngineError::InvalidConfig {
                reason: "max_result_rows must be > 0".into(),
            });
        }
        if self.storaged_socket.is_empty() {
            return Err(EngineError::InvalidConfig {
                reason: "storaged_socket must not be empty".into(),
            });
        }
        Ok(())
    }
}

/// An opaque handle to a signed contract bundle received from T04 via the X02
/// `get_contract_bundle` opcode.
///
/// The bundle is never decoded here; it is passed verbatim to the DataFusion
/// optimizer rules that need it.  This keeps the signing surface inside T04
/// and prevents the engine from modifying bundle contents before evaluating
/// them.
#[derive(Debug, Clone)]
pub struct ContractBundleHandle {
    /// Internal correlation ID assigned at injection time.
    pub(crate) handle_id: Uuid,

    /// The raw signed bundle bytes exactly as received from T04.
    pub(crate) raw_bytes: bytes::Bytes,

    /// The contract ID this bundle covers.
    pub(crate) contract_id: String,

    /// The tenant this bundle was issued for.
    pub(crate) tenant_id: String,
}

impl ContractBundleHandle {
    /// Construct a handle from raw bundle bytes received over the X02 socket.
    ///
    /// The bytes are stored opaquely.  Signature verification is performed by
    /// the optimizer rule when the bundle is first used.
    pub fn from_x02_bytes(
        contract_id: impl Into<String>,
        tenant_id: impl Into<String>,
        raw_bytes: bytes::Bytes,
    ) -> Self {
        Self {
            handle_id: Uuid::new_v4(),
            raw_bytes,
            contract_id: contract_id.into(),
            tenant_id: tenant_id.into(),
        }
    }

    /// Return the contract ID.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Return the tenant ID.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Return the unique handle identifier (for correlation/tracing).
    pub fn handle_id(&self) -> Uuid {
        self.handle_id
    }
}

// ─── DDL guard ────────────────────────────────────────────────────────────────

/// Guards against unsafe DDL verbs in SQL statements.
///
/// Per ADR-0002 and CLAUDE.md Hard Constraints §Verified-binary surface rule (d):
/// the engine must never accept or execute `INSTALL`, `LOAD`, `ATTACH`, or
/// `COPY` statements.  These allow unsigned plugin injection and violate both
/// Semantic Law invariant 5 and the verified-binary trust surface.
///
/// # Bypass prevention (STORY-K04-CATCHUP-001, Copilot thread PRRT_kwDOSEqhas5_il4W)
///
/// The original implementation only checked the first whitespace-delimited
/// token of the raw SQL string.  Three bypass vectors existed:
///
/// 1. **Block-comment prefix** — `/*hi*/ COPY foo FROM '...'`
/// 2. **Line-comment prefix** — `-- evil\nCOPY foo FROM '...'`
/// 3. **Multi-statement** — `SELECT 1; COPY foo FROM '...'`
///
/// The fix adds two pre-processing steps before the deny-list check:
/// (a) Strip all SQL comments (block `/* … */` with nesting, line `-- … \n`).
/// (b) Split the cleaned SQL on `;` and check EVERY statement's first token.
pub struct DdlGuard;

impl DdlGuard {
    /// The set of disallowed DDL verbs — case-insensitive, exact-token match.
    ///
    /// These are the verbs that DataFusion (and DuckDB) support for registering
    /// external resources or loading unsigned plugins.  Any statement whose
    /// first meaningful token is in this list is rejected.
    const DISALLOWED_VERBS: &'static [&'static str] =
        &["INSTALL", "LOAD", "ATTACH", "COPY", "EXTENSION"];

    /// Strip SQL comments from `sql` and return the cleaned string.
    ///
    /// Handles:
    /// - Block comments `/* … */`, including **nested** block comments.
    /// - Line comments `-- … \n` (newline terminates; end-of-input also closes).
    ///
    /// The content of comments is replaced with a single space so that adjacent
    /// tokens that were only separated by a comment are not accidentally joined.
    /// For example, `SELECT/**/1` becomes `SELECT 1` rather than `SELECT1`.
    fn strip_comments(sql: &str) -> String {
        let bytes = sql.as_bytes();
        let len = bytes.len();
        let mut out = String::with_capacity(len);
        let mut i = 0;

        while i < len {
            // Check for block-comment start `/*`.
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                // Skip nested block comments by counting depth.
                let mut depth = 1usize;
                i += 2; // consume `/*`
                while i < len && depth > 0 {
                    if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                // Replace the comment with a space to keep tokens separate.
                out.push(' ');
            }
            // Check for line-comment start `--`.
            else if i + 1 < len && bytes[i] == b'-' && bytes[i + 1] == b'-' {
                // Consume until newline or end-of-input.
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                // Emit a space so that the rest of the line after `-- comment` is
                // still separated from whatever preceded the comment.
                out.push(' ');
            }
            // Handle SQL single-quoted string literals: pass through verbatim so
            // that `'--'` or `'/* */'` inside a string is not mistaken for a comment.
            else if bytes[i] == b'\'' {
                out.push('\'');
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        out.push('\'');
                        i += 1;
                        // Escaped quote `''` — peek ahead.
                        if i < len && bytes[i] == b'\'' {
                            out.push('\'');
                            i += 1;
                        }
                        break;
                    }
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            // All other characters pass through unchanged.
            else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }

        out
    }

    /// Check `sql` for disallowed DDL verbs after stripping comments.
    ///
    /// # Algorithm
    ///
    /// 1. Strip all SQL comments (block and line) from the input.
    /// 2. Split the result on `;` to obtain individual statements.
    /// 3. For each non-empty statement, take the first whitespace-delimited
    ///    token and compare it (case-insensitively) against the deny-list.
    ///
    /// Returns `Err(EngineError::UnsafeDdlRejected)` if any statement's first
    /// token matches a disallowed verb.  Returns `Ok(())` otherwise.
    ///
    /// # ADR-0002 verified-binary surface rule (d)
    ///
    /// This is a syntactic first-pass check.  Full AST-level rejection is
    /// wired in the DataFusion optimizer rules (future wave).  Both layers
    /// must remain active: the AST-level check is the primary gate; this
    /// syntactic check is the defence-in-depth pre-parse gate.
    pub fn reject_unsafe_ddl(sql: &str) -> Result<(), EngineError> {
        let cleaned = Self::strip_comments(sql);

        // Split on `;` to handle multi-statement inputs.
        for statement in cleaned.split(';') {
            let first_token = statement
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();

            if first_token.is_empty() {
                // Empty statement (e.g., trailing `;` or whitespace-only): skip.
                continue;
            }

            for &verb in Self::DISALLOWED_VERBS {
                if first_token == verb {
                    return Err(EngineError::UnsafeDdlRejected {
                        verb: verb.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// The K04D DataFusion-based query engine.
///
/// # Construction
///
/// Instances are created **only** via [`K04DEngine::new_with_config`].  There
/// is no `Default`, no `K04DEngine { .. }` struct literal (fields are
/// private), and no `impl From<…>` for external types.  This is the sealed
/// constructor pattern required by ADR-0002 §verified-binary surface rule (c).
///
/// # Contract bundle injection
///
/// After construction the engine has no contract bundle.  Call
/// [`K04DEngine::inject_contract_bundle`] before issuing any query.  Queries
/// issued without a bundle return [`EngineError::NoContractBundle`].
pub struct K04DEngine {
    config: InitConfig,
    contract_bundle: Option<ContractBundleHandle>,
    /// The DataFusion session context.  Created lazily on first query.
    ctx: Option<datafusion::execution::context::SessionContext>,
}

// Seal K04DEngine so that external code cannot implement EngineCore.
impl sealed::private::Sealed for K04DEngine {}

impl sealed::EngineCore for K04DEngine {
    fn tenant_id(&self) -> &str {
        &self.config.tenant_id
    }

    fn has_contract_bundle(&self) -> bool {
        self.contract_bundle.is_some()
    }
}

impl K04DEngine {
    /// Create a new engine from a validated [`InitConfig`].
    ///
    /// Returns `Err` if the config fails validation.  This is the ONLY public
    /// constructor.  No `K04DEngine::default()` exists.
    pub fn new_with_config(config: InitConfig) -> Result<Self, EngineError> {
        config.validate()?;
        Ok(Self {
            config,
            contract_bundle: None,
            ctx: None,
        })
    }

    /// Inject a signed contract bundle received from T04's
    /// `get_contract_bundle` X02 opcode.
    ///
    /// Must be called at least once before [`K04DEngine::query`].
    /// Subsequent calls replace the bundle (e.g., on contract version rotation).
    pub fn inject_contract_bundle(&mut self, bundle: ContractBundleHandle) {
        tracing::debug!(
            tenant_id = %self.config.tenant_id,
            contract_id = %bundle.contract_id,
            handle_id = %bundle.handle_id,
            "contract bundle injected",
        );
        self.contract_bundle = Some(bundle);
    }

    /// Return a reference to the currently-injected contract bundle, if any.
    pub fn contract_bundle(&self) -> Option<&ContractBundleHandle> {
        self.contract_bundle.as_ref()
    }

    /// Initialise the DataFusion [`SessionContext`] if not already done.
    ///
    /// This is called lazily by [`K04DEngine::query`].  Separated here so
    /// tests can inspect context creation independently.
    fn ensure_ctx(&mut self) -> Result<(), EngineError> {
        if self.ctx.is_none() {
            let ctx = datafusion::execution::context::SessionContext::new();
            self.ctx = Some(ctx);
        }
        Ok(())
    }

    /// Execute a SQL query against an in-memory record batch provider.
    ///
    /// # Contract gate
    ///
    /// Returns [`EngineError::NoContractBundle`] if no bundle has been
    /// injected.  This enforces Semantic Law invariant 1 at the shell level.
    /// Future waves add invariant 2/3 enforcement as DataFusion optimizer rules.
    ///
    /// # DDL guard
    ///
    /// Returns [`EngineError::UnsafeDdlRejected`] for statements starting with
    /// INSTALL, LOAD, ATTACH, or COPY (ADR-0002 verified-binary surface rule d).
    pub async fn query(
        &mut self,
        sql: &str,
    ) -> Result<Vec<datafusion::arrow::record_batch::RecordBatch>, EngineError> {
        // INV-1: require contract bundle before any query.
        if self.contract_bundle.is_none() {
            return Err(EngineError::NoContractBundle);
        }
        // ADR-0002 rule (d): reject unsafe DDL verbs.
        DdlGuard::reject_unsafe_ddl(sql)?;

        self.ensure_ctx()?;
        let ctx = self.ctx.as_ref().unwrap();
        let df = ctx.sql(sql).await?;
        let batches = df.collect().await?;
        Ok(batches)
    }

    /// Register an in-memory Arrow table for testing.
    ///
    /// Production use cases register Lance-backed tables; this entry point
    /// supports the test scaffold without requiring Lance.
    pub async fn register_memory_table(
        &mut self,
        name: &str,
        schema: datafusion::arrow::datatypes::SchemaRef,
        partitions: Vec<Vec<datafusion::arrow::record_batch::RecordBatch>>,
    ) -> Result<(), EngineError> {
        self.ensure_ctx()?;
        let ctx = self.ctx.as_ref().unwrap();
        let provider = datafusion::datasource::MemTable::try_new(schema, partitions)?;
        ctx.register_table(name, std::sync::Arc::new(provider))?;
        Ok(())
    }

    /// Register a Parquet file as a queryable table.
    ///
    /// Used in tests that exercise the Parquet path without full Lance.
    pub async fn register_parquet_table(
        &mut self,
        name: &str,
        path: &str,
    ) -> Result<(), EngineError> {
        self.ensure_ctx()?;
        let ctx = self.ctx.as_ref().unwrap();
        ctx.register_parquet(
            name,
            path,
            datafusion::datasource::file_format::options::ParquetReadOptions::default(),
        )
        .await?;
        Ok(())
    }

    /// Register a Lance dataset as a queryable DataFusion table.
    ///
    /// # How this works
    ///
    /// Lance files live in griotfs (T02 managed object storage). The engine
    /// must NEVER access griotfs directly. Instead, this method:
    ///
    /// 1. Opens a `StoragedLanceIo` object-store implementation that routes
    ///    all byte reads through the T04 storaged byte-read socket.
    /// 2. Opens the Lance dataset against that IO layer.
    /// 3. Wraps the Lance dataset in a `LanceTableProvider` (implements
    ///    DataFusion `TableProvider`).
    /// 4. Registers the provider under `name` in the DataFusion session context.
    ///
    /// # Arguments
    ///
    /// * `name` — the table name to register in DataFusion (e.g. `"events"`).
    /// * `asset_id` — the griotfs asset UUID for the Lance dataset.
    /// * `tenant_id` — tenant context for T04 contract enforcement.
    /// * `principal_jwt` — scoped JWT for the requesting principal.
    ///
    /// # ADR-0002 / Semantic Law
    ///
    /// * INV-5: No direct filesystem access. All byte reads through T04.
    /// * INV-2: T04 enforces contract constraints on every byte read.
    ///
    /// # Notes on the current implementation
    ///
    /// The `lance` crate's `Dataset::open` accepts a `url` parameter.
    /// Routing through T04 is implemented via a custom `object_store::ObjectStore`
    /// backend (`StoragedObjectStore`) that wraps `StoragedClient`.
    /// The URL passed to lance uses the custom scheme `griotfs://`.
    ///
    /// Requires the `lance` Cargo feature (protoc at build time).
    #[cfg(feature = "lance")]
    pub async fn register_lance_table(
        &mut self,
        name: &str,
        asset_id: &str,
        tenant_id: &str,
        principal_jwt: &str,
    ) -> Result<(), EngineError> {
        use crate::lance_table::LanceTableProvider;
        use std::sync::Arc;

        self.ensure_ctx()?;

        let storaged_path = self.config.storaged_socket.clone();
        let provider = LanceTableProvider::open(asset_id, tenant_id, principal_jwt, &storaged_path)
            .await
            .map_err(|e| EngineError::LanceRegistration {
                asset_id: asset_id.to_string(),
                reason: e.to_string(),
            })?;

        let ctx = self.ctx.as_ref().unwrap();
        ctx.register_table(name, Arc::new(provider))
            .map_err(EngineError::DataFusion)?;

        Ok(())
    }
}

// ─── Wave 8 optimizer-rule module ─────────────────────────────────────────────
/// DataFusion logical-plan optimizer rules that enforce contract constraints
/// natively inside the query engine (ADR-0002 wave 8).
pub mod optimizer_rules;

// ─── Wave 9 physical-operator module ──────────────────────────────────────────
/// DataFusion physical `ExecutionPlan` implementations for contract-native
/// enforcement, plus the `AttestationExec` wrapper (ADR-0002 wave 9).
pub mod physical;

// ─── Wave 1 production-bar modules ────────────────────────────────────────────

/// T04 storaged byte-read Unix domain socket client.
/// The engine's ONLY data-access path — all reads route through T04.
/// Unix-only (uses `tokio::net::UnixStream`); not used by the contract spine.
#[cfg(unix)]
pub mod storaged_client;

/// T05 GDCP Notary attestation-signing client (opcode 0x42).
/// Replaces the SHA-256 placeholder in AttestationExec with real ES256 JWS.
/// Unix-only (uses `tokio::net::UnixStream`); not used by the contract spine.
#[cfg(unix)]
pub mod t05_client;

/// Result formatter: Arrow IPC / Parquet / newline-delimited JSON.
pub mod result_formatter;

/// Per-tenant hot-result cache (LRU, bounded at 256MB / 10k entries / 60s TTL).
pub mod query_cache;

/// Long-running pool manager: N workers, sticky tenant routing, graceful drain.
pub mod long_running_pool_manager;

/// Lance dataset TableProvider with storaged-socket IO layer.
/// Only compiled when the `lance` feature is enabled (requires protoc at build time).
#[cfg(feature = "lance")]
pub mod lance_table;

// ─── Contract resolution spine ────────────────────────────────────────────────
// Turns a dataset reference + a caller into governed query execution: a contract
// source produces a `ResolvedPolicy`, a binding resolver locates the data, and a
// DataFusion catalog wraps the raw scan in the enforcement operators above.

/// The engine-agnostic enforcement primitive (`ResolvedPolicy`) every contract
/// source produces and the engine executes.
pub mod policy;

/// Mapping a dataset reference to its physical data (`BindingResolver`).
pub mod binding;

/// Contract sources: `ContractSource` + the open-source `JsonContractSource`.
pub mod contract_source;

/// `ContractTableProvider`: a DataFusion table whose every scan is governed.
pub mod contract_table_provider;

/// The DataFusion catalog that resolves `SELECT * FROM "<dataset-uri>"`.
pub mod catalog;

/// The high-level, contract-resolving `GriotEngine` query API.
pub mod engine;

/// Platform adapter: consume T03's signed contract bundle (feature `platform`).
#[cfg(feature = "platform")]
pub mod platform;
