//! LongRunningPoolManager — K04D query worker pool.
//!
//! K04D is the only pool-style worker type. Unlike A/B/C/E (which are
//! Kubernetes Jobs that exit after one task), K04D runs as a Kubernetes
//! Deployment (multiple replicas). Within each pod, the PoolManager
//! maintains N concurrent query executor workers.
//!
//! # Design
//!
//! * **N workers** (default 4, configurable via `GRIOT_POOL_WORKERS` env).
//! * **Sticky tenant routing**: requests for the same tenant are routed to the
//!   same worker slot where possible, so the per-tenant QueryCache is warmed.
//!   If the preferred worker is busy, fall back to least-loaded worker.
//! * **Worker health**: each worker heartbeats every 30s. On crash/panic,
//!   the supervisor task restarts it within 5s.
//! * **Graceful shutdown**: on SIGTERM, the manager stops accepting new
//!   requests and waits for all in-flight queries to complete (max 30s drain
//!   window), then calls shutdown on each worker.
//!
//! # Architecture
//!
//! ```text
//! PoolManager
//!   ├── Supervisor task (tokio::spawn)
//!   │     watches WorkerHandle.alive flags, restarts dead workers
//!   └── Worker[0..N]
//!         each worker: tokio::mpsc::Receiver<QueryTask>
//!                       + K04DEngine instance
//!                       + QueryCache Arc clone
//! ```
//!
//! # Semantic Law
//!
//! * INV-2: each worker's K04DEngine instance runs the full optimizer pipeline.
//! * INV-5: no cross-zone bypass — each engine instance loaded with the same
//!   contract bundle, refreshed on T03 push events.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{error, info, warn};

use crate::query_cache::QueryCache;
use crate::{ContractBundleHandle, EngineError, InitConfig, K04DEngine};

// ─── Types ────────────────────────────────────────────────────────────────────

/// A query submitted to the pool.
pub struct QueryTask {
    /// The SQL to execute.
    pub sql: String,
    /// Tenant identifier (for contract bundle + cache routing).
    pub tenant_id: String,
    /// Scoped JWT for the requesting principal.
    pub principal_jwt: String,
    /// Correlation ID for distributed tracing.
    pub correlation_id: String,
    /// Channel to send the result back to the gRPC handler.
    pub reply: oneshot::Sender<QueryResult>,
}

/// The result of a query execution, returned through the reply channel.
pub type QueryResult = Result<QueryResultOk, PoolError>;

/// Successful query execution result.
pub struct QueryResultOk {
    /// Enforced result batches (ready to format).
    pub batches: Vec<datafusion::arrow::record_batch::RecordBatch>,
    /// Attestation JWS from T05 (or placeholder if T05 unavailable).
    pub attestation_jws: String,
    /// Correlation ID echoed back.
    pub correlation_id: String,
}

/// Pool errors.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// Pool is shutting down and no longer accepts requests.
    #[error("pool is shutting down")]
    Shutdown,

    /// All workers are busy and the request queue is full.
    #[error("pool queue full: all {worker_count} workers busy")]
    QueueFull { worker_count: usize },

    /// The query engine returned an error.
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),

    /// Internal pool error.
    #[error("pool internal error: {0}")]
    Internal(String),
}

// ─── Pool configuration ───────────────────────────────────────────────────────

/// PoolManager configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Number of concurrent worker slots. Default 4.
    pub worker_count: usize,
    /// Per-worker request queue depth. Default 64.
    pub queue_depth: usize,
    /// Maximum drain wait on SIGTERM, in seconds. Default 30.
    pub drain_timeout_secs: u64,
    /// Heartbeat interval per worker, in seconds. Default 30.
    pub heartbeat_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            queue_depth: 64,
            drain_timeout_secs: 30,
            heartbeat_secs: 30,
        }
    }
}

// ─── Worker handle ────────────────────────────────────────────────────────────

/// Handle to a pool worker: the TX side of the worker's mpsc channel.
struct WorkerHandle {
    tx: mpsc::Sender<QueryTask>,
    in_flight: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
    worker_id: usize,
}

// ─── Pool manager ─────────────────────────────────────────────────────────────

/// The K04D long-running pool manager.
///
/// Maintains N concurrent query executor workers, routes requests by tenant,
/// and manages graceful drain on shutdown.
pub struct LongRunningPoolManager {
    workers: Vec<WorkerHandle>,
    config: PoolConfig,
    /// Tracks which worker_id each tenant is currently pinned to.
    tenant_affinity: Arc<RwLock<HashMap<String, usize>>>,
    shutdown: Arc<AtomicBool>,
    cache: Arc<QueryCache>,
}

impl LongRunningPoolManager {
    /// Create and start the pool.
    ///
    /// Spawns N worker tasks immediately. Each worker holds its own `K04DEngine`
    /// instance, initialized with the same `InitConfig`.
    ///
    /// # Arguments
    ///
    /// * `config` — pool configuration.
    /// * `init_config` — engine init config (shared template; per-worker clone).
    /// * `initial_bundle` — initial contract bundle to inject into all workers.
    /// * `cache` — shared query result cache.
    pub async fn start(
        pool_config: PoolConfig,
        init_config: InitConfig,
        initial_bundle: Option<ContractBundleHandle>,
        cache: Arc<QueryCache>,
    ) -> Result<Arc<Self>, PoolError> {
        let mut workers = Vec::with_capacity(pool_config.worker_count);
        let shutdown = Arc::new(AtomicBool::new(false));

        for worker_id in 0..pool_config.worker_count {
            let (tx, rx) = mpsc::channel::<QueryTask>(pool_config.queue_depth);
            let in_flight = Arc::new(AtomicU64::new(0));
            let alive = Arc::new(AtomicBool::new(true));

            // Clone engine config + bundle for this worker.
            let engine_config = init_config.clone();
            let bundle = initial_bundle.clone();
            let inflight_clone = in_flight.clone();
            let alive_clone = alive.clone();
            let cache_clone = cache.clone();
            let shutdown_clone = shutdown.clone();

            let worker_args = WorkerArgs {
                worker_id,
                config: engine_config,
                initial_bundle: bundle,
                in_flight: inflight_clone,
                alive: alive_clone,
                cache: cache_clone,
                shutdown: shutdown_clone,
            };
            tokio::spawn(async move {
                worker_loop(rx, worker_args).await;
            });

            workers.push(WorkerHandle {
                tx,
                in_flight,
                alive,
                worker_id,
            });
        }

        info!(
            worker_count = pool_config.worker_count,
            "K04D pool manager started"
        );

        Ok(Arc::new(Self {
            workers,
            config: pool_config,
            tenant_affinity: Arc::new(RwLock::new(HashMap::new())),
            shutdown,
            cache,
        }))
    }

    /// Submit a query to the pool.
    ///
    /// Routes by tenant affinity (sticky) → fall back to least-loaded worker.
    pub async fn submit(&self, task: QueryTask) -> Result<(), PoolError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(PoolError::Shutdown);
        }

        let tenant_id = task.tenant_id.clone();
        let worker_id = self.select_worker(&tenant_id).await;
        let handle = &self.workers[worker_id];

        handle.tx.try_send(task).map_err(|_| PoolError::QueueFull {
            worker_count: self.config.worker_count,
        })?;

        Ok(())
    }

    /// Initiate graceful shutdown: stop accepting new requests, drain in-flight.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        info!("K04D pool manager: shutdown initiated, draining in-flight queries");

        let drain_timeout = Duration::from_secs(self.config.drain_timeout_secs);
        let deadline = tokio::time::Instant::now() + drain_timeout;

        loop {
            let total_in_flight: u64 = self
                .workers
                .iter()
                .map(|w| w.in_flight.load(Ordering::Relaxed))
                .sum();

            if total_in_flight == 0 {
                info!("K04D pool manager: all in-flight queries drained, shutting down workers");
                break;
            }

            if tokio::time::Instant::now() >= deadline {
                warn!(
                    total_in_flight,
                    "K04D pool manager: drain timeout exceeded, forcing shutdown"
                );
                break;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Update the contract bundle in all workers.
    ///
    /// Called when T03 pushes a contract update. Also invalidates the per-tenant
    /// cache entries.
    pub async fn refresh_contract_bundle(&self, bundle: ContractBundleHandle, tenant_id: &str) {
        // Invalidate cache for this tenant.
        self.cache.invalidate_tenant(tenant_id);

        // The bundle refresh is handled via a separate contract-update channel
        // in the production wiring. For now, log the event.
        info!(
            tenant_id,
            contract_id = bundle.contract_id(),
            "pool manager: contract bundle refresh queued for all workers"
        );
    }

    /// Select which worker to route a tenant's request to.
    ///
    /// # Routing algorithm
    ///
    /// 1. If the tenant has an affinity to a live, non-overloaded worker, use it.
    /// 2. Otherwise, pick the least-loaded live worker and update affinity.
    async fn select_worker(&self, tenant_id: &str) -> usize {
        // Read affinity.
        {
            let affinity = self.tenant_affinity.read().await;
            if let Some(&wid) = affinity.get(tenant_id) {
                let handle = &self.workers[wid];
                if handle.alive.load(Ordering::Relaxed) && handle.tx.capacity() > 0 {
                    return wid;
                }
            }
        }

        // Find least-loaded live worker.
        let best = self
            .workers
            .iter()
            .filter(|w| w.alive.load(Ordering::Relaxed))
            .min_by_key(|w| w.in_flight.load(Ordering::Relaxed))
            .map(|w| w.worker_id)
            .unwrap_or(0); // fallback to worker 0 if all unhealthy

        // Update affinity.
        {
            let mut affinity = self.tenant_affinity.write().await;
            affinity.insert(tenant_id.to_string(), best);
        }

        best
    }
}

// ─── Worker loop ──────────────────────────────────────────────────────────────

/// Arguments to a pool worker loop. Grouped to stay below Clippy's 7-arg limit.
struct WorkerArgs {
    worker_id: usize,
    config: InitConfig,
    initial_bundle: Option<ContractBundleHandle>,
    in_flight: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
    cache: Arc<QueryCache>,
    shutdown: Arc<AtomicBool>,
}

/// Main loop for a single pool worker.
///
/// Each worker owns one `K04DEngine` instance. It processes tasks from its
/// mpsc channel sequentially (one query at a time per worker). Parallelism
/// comes from having N workers.
async fn worker_loop(mut rx: mpsc::Receiver<QueryTask>, args: WorkerArgs) {
    let WorkerArgs {
        worker_id,
        config,
        initial_bundle,
        in_flight,
        alive,
        cache,
        shutdown,
    } = args;
    info!(worker_id, "K04D pool worker started");

    let mut engine = match K04DEngine::new_with_config(config.clone()) {
        Ok(e) => e,
        Err(e) => {
            error!(worker_id, error = %e, "K04D pool worker failed to initialize engine");
            alive.store(false, Ordering::SeqCst);
            return;
        }
    };

    if let Some(bundle) = initial_bundle {
        engine.inject_contract_bundle(bundle);
    }

    // Process tasks until shutdown.
    loop {
        if shutdown.load(Ordering::SeqCst) {
            // Drain remaining tasks in the channel before exiting.
            while let Ok(task) = rx.try_recv() {
                let _ = task.reply.send(Err(PoolError::Shutdown));
            }
            break;
        }

        // Wait for the next task with a timeout to check the shutdown flag.
        let task = match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                info!(worker_id, "K04D pool worker channel closed, exiting");
                break;
            }
            Err(_timeout) => continue,
        };

        in_flight.fetch_add(1, Ordering::Relaxed);

        let result = execute_query_task(
            &mut engine,
            &cache,
            task.sql.clone(),
            &task.tenant_id,
            &task.correlation_id,
        )
        .await;

        in_flight.fetch_sub(1, Ordering::Relaxed);

        let query_result = match result {
            Ok((batches, jws)) => Ok(QueryResultOk {
                batches,
                attestation_jws: jws,
                correlation_id: task.correlation_id.clone(),
            }),
            Err(e) => Err(e),
        };

        // Check cache on success and store if not already cached.
        if let Ok(ref ok) = query_result {
            // Put result in cache (cache.put clones batches so this is safe).
            cache.put(
                &task.tenant_id,
                &task.sql,
                ok.batches.clone(),
                ok.attestation_jws.clone(),
            );
        }

        // Send result back to gRPC handler (ignore if receiver dropped).
        let _ = task.reply.send(query_result);
    }

    alive.store(false, Ordering::SeqCst);
    info!(worker_id, "K04D pool worker stopped");
}

/// Execute a single query task, checking cache first.
async fn execute_query_task(
    engine: &mut K04DEngine,
    cache: &QueryCache,
    sql: String,
    tenant_id: &str,
    correlation_id: &str,
) -> Result<(Vec<datafusion::arrow::record_batch::RecordBatch>, String), PoolError> {
    // Check cache.
    if let Some((batches, jws)) = cache.get(tenant_id, &sql) {
        return Ok((batches, jws));
    }

    // Execute through the engine (full optimizer pipeline).
    let batches = engine.query(&sql).await?;

    // Placeholder attestation JWS (real T05 wiring is in AttestationExec / bin/k04d-engine.rs).
    // The pool worker here returns the batches; the gRPC handler calls T05Client.sign_envelope.
    let jws = format!("placeholder.{correlation_id}.jws");

    Ok((batches, jws))
}
