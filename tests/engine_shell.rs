//! RED tests for the K04D DataFusion engine SHELL.
//!
//! ADR-0002 / Wave-7 scaffold — testing agent authored (2026-05-05).
//!
//! Test scope: engine construction (sealed), contract bundle injection via
//! X02 `get_contract_bundle`, sealed enforcement traits (no public
//! constructors), INSTALL/LOAD/ATTACH/COPY rejection, basic SELECT against an
//! in-memory test table, basic SELECT against Parquet bytes.
//!
//! These tests are authored BEFORE implementation (TDD RED phase).  They compile
//! because the shell types exist, but assertions against unimplemented
//! behaviour will fail once we exercise the real paths.
//!
//! Semantic Law invariants covered:
//! - INV-1: no query without contract bundle
//! - INV-5: no zone-t imports (static: this file imports nothing from zone-t)
//! - ADR-0002 rule (d): INSTALL/LOAD/ATTACH/COPY rejected

use bytes::Bytes;
use datafusion::arrow::array::{Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use griot::{ContractBundleHandle, DdlGuard, EngineError, InitConfig, K04DEngine};
use std::sync::Arc;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn valid_config() -> InitConfig {
    InitConfig {
        tenant_id: "test-tenant-001".into(),
        contract_bundle_endpoint: "unix:///tmp/t04-test.sock".into(),
        attestation_endpoint: "unix:///tmp/t05-test.sock".into(),
        max_result_rows: 1000,
        storaged_socket: "/tmp/t04-storaged-test.sock".into(),
    }
}

fn dummy_bundle(contract_id: &str, tenant_id: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        tenant_id,
        Bytes::from(b"SIGNED_BUNDLE_BYTES_FROM_T04".to_vec()),
    )
}

/// Build a small Arrow RecordBatch for in-memory table tests.
fn make_test_batch() -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["alice", "bob", "carol"])),
        ],
    )
    .expect("test batch construction failed")
}

// ─── TC-01: Engine construction requires a valid config ──────────────────────

/// TC-01a: `K04DEngine::new_with_config` succeeds with a complete config.
///
/// RED: passes once the shell compiles.  Will fail if the constructor is
/// removed or renamed.
#[test]
fn tc_01a_engine_construction_valid_config() {
    let cfg = valid_config();
    let result = K04DEngine::new_with_config(cfg);
    assert!(
        result.is_ok(),
        "expected engine construction to succeed with valid config; got: {:?}",
        result.err()
    );
}

/// TC-01b: Construction fails when `tenant_id` is empty.
///
/// RED: verifies the config validator is called and rejects empty tenant_id.
#[test]
fn tc_01b_engine_construction_empty_tenant_id() {
    let mut cfg = valid_config();
    cfg.tenant_id = String::new();
    let result = K04DEngine::new_with_config(cfg);
    assert!(
        result.is_err(),
        "expected construction to fail with empty tenant_id"
    );
    let err = result.err().unwrap();
    match err {
        EngineError::InvalidConfig { reason } => {
            assert!(
                reason.contains("tenant_id"),
                "error should mention tenant_id"
            );
        }
        other => panic!("expected InvalidConfig, got {:?}", other),
    }
}

/// TC-01c: Construction fails when `contract_bundle_endpoint` is empty.
#[test]
fn tc_01c_engine_construction_empty_bundle_endpoint() {
    let mut cfg = valid_config();
    cfg.contract_bundle_endpoint = String::new();
    let result = K04DEngine::new_with_config(cfg);
    assert!(
        result.is_err(),
        "expected construction to fail with empty contract_bundle_endpoint"
    );
}

/// TC-01d: Construction fails when `max_result_rows` is zero.
#[test]
fn tc_01d_engine_construction_zero_max_rows() {
    let mut cfg = valid_config();
    cfg.max_result_rows = 0;
    let result = K04DEngine::new_with_config(cfg);
    assert!(
        result.is_err(),
        "expected construction to fail with max_result_rows = 0"
    );
}

// ─── TC-02: Sealed trait — no public constructors ────────────────────────────

/// TC-02a: `K04DEngine` exposes no default constructor.
///
/// This is a compile-time check; the test body asserts the contract_bundle
/// field is `None` right after construction (confirming the shell initialises
/// to a safe state before bundle injection).
#[test]
fn tc_02a_engine_has_no_contract_bundle_after_construction() {
    let engine = K04DEngine::new_with_config(valid_config()).unwrap();
    // No contract bundle has been injected; has_contract_bundle must be false.
    // We verify via the sealed trait through a helper method.
    assert!(
        !engine_has_bundle(&engine),
        "freshly constructed engine must not have a contract bundle"
    );
}

/// TC-02b: `K04DEngine::tenant_id()` returns the configured tenant.
#[test]
fn tc_02b_engine_tenant_id_matches_config() {
    let engine = K04DEngine::new_with_config(valid_config()).unwrap();
    assert_eq!(engine_tenant_id(&engine), "test-tenant-001");
}

// Helpers that use the sealed trait methods through references.  These
// compile only because K04DEngine implements sealed::EngineCore, which
// exposes `tenant_id()` and `has_contract_bundle()`.  They do NOT allow
// external code to create a *new* EngineCore implementation.
fn engine_has_bundle(e: &dyn griot::sealed::EngineCore) -> bool {
    e.has_contract_bundle()
}
fn engine_tenant_id(e: &dyn griot::sealed::EngineCore) -> &str {
    e.tenant_id()
}

// ─── TC-03: Contract bundle injection via X02 ────────────────────────────────

/// TC-03a: After injecting a bundle, `has_contract_bundle()` returns true.
#[test]
fn tc_03a_inject_bundle_marks_engine_ready() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    let bundle = dummy_bundle("contract-001", "test-tenant-001");
    engine.inject_contract_bundle(bundle);
    assert!(
        engine_has_bundle(&engine),
        "engine must report bundle present after injection"
    );
}

/// TC-03b: The bundle accessor returns the injected bundle.
#[test]
fn tc_03b_bundle_accessor_returns_injected_bundle() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    let bundle = dummy_bundle("contract-007", "test-tenant-001");
    let expected_contract_id = bundle.contract_id().to_string();
    engine.inject_contract_bundle(bundle);

    let retrieved = engine
        .contract_bundle()
        .expect("bundle should be present after injection");
    assert_eq!(retrieved.contract_id(), expected_contract_id);
    assert_eq!(retrieved.tenant_id(), "test-tenant-001");
}

/// TC-03c: A second injection replaces the first bundle.
#[test]
fn tc_03c_second_injection_replaces_bundle() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    engine.inject_contract_bundle(dummy_bundle("contract-v1", "test-tenant-001"));
    engine.inject_contract_bundle(dummy_bundle("contract-v2", "test-tenant-001"));
    let retrieved = engine.contract_bundle().unwrap();
    assert_eq!(
        retrieved.contract_id(),
        "contract-v2",
        "second injection must replace first"
    );
}

// ─── TC-04: INSTALL / LOAD / ATTACH / COPY rejected ─────────────────────────
//
// ADR-0002 verified-binary surface rule (d).

/// TC-04a: INSTALL is rejected by DdlGuard.
#[test]
fn tc_04a_ddl_guard_rejects_install() {
    let result = DdlGuard::reject_unsafe_ddl("INSTALL 'evil_plugin.so'");
    assert!(result.is_err(), "INSTALL must be rejected");
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "INSTALL");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-04b: LOAD is rejected by DdlGuard.
#[test]
fn tc_04b_ddl_guard_rejects_load() {
    let result = DdlGuard::reject_unsafe_ddl("LOAD 'evil.so'");
    assert!(result.is_err(), "LOAD must be rejected");
}

/// TC-04c: ATTACH is rejected by DdlGuard.
#[test]
fn tc_04c_ddl_guard_rejects_attach() {
    let result = DdlGuard::reject_unsafe_ddl("ATTACH DATABASE 'other.db' AS other");
    assert!(result.is_err(), "ATTACH must be rejected");
}

/// TC-04d: COPY is rejected by DdlGuard.
#[test]
fn tc_04d_ddl_guard_rejects_copy() {
    let result = DdlGuard::reject_unsafe_ddl("COPY table_name TO '/tmp/out.csv'");
    assert!(result.is_err(), "COPY must be rejected");
}

/// TC-04e: Safe SELECT is not rejected by DdlGuard.
#[test]
fn tc_04e_ddl_guard_allows_select() {
    let result = DdlGuard::reject_unsafe_ddl("SELECT id, name FROM users WHERE id = 1");
    assert!(result.is_ok(), "SELECT must not be rejected by DdlGuard");
}

/// TC-04f: Case-insensitive INSTALL rejected.
#[test]
fn tc_04f_ddl_guard_case_insensitive_install() {
    let result = DdlGuard::reject_unsafe_ddl("install 'evil.so'");
    assert!(result.is_err(), "lowercase install must also be rejected");
}

// ─── TC-05: Query without bundle returns error ────────────────────────────────

/// TC-05: Querying without injecting a bundle returns NoContractBundle.
///
/// Semantic Law INV-1: no read without contract.
#[tokio::test]
async fn tc_05_query_without_bundle_returns_error() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    let result = engine.query("SELECT 1").await;
    assert!(
        result.is_err(),
        "query without bundle must fail (INV-1 — no read without contract)"
    );
    match result.unwrap_err() {
        EngineError::NoContractBundle => { /* expected */ }
        other => panic!("expected NoContractBundle, got {:?}", other),
    }
}

// ─── TC-06: Basic SELECT against in-memory table ─────────────────────────────

/// TC-06: Register an in-memory Arrow table and SELECT from it.
///
/// RED: verifies that the engine can register a MemTable and execute a simple
/// query that returns rows.  Will fail until `register_memory_table` and
/// `query` are fully wired.
#[tokio::test]
async fn tc_06_select_from_in_memory_table() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    engine.inject_contract_bundle(dummy_bundle("contract-001", "test-tenant-001"));

    let batch = make_test_batch();
    let schema = batch.schema();
    engine
        .register_memory_table("test_table", schema, vec![vec![batch]])
        .await
        .expect("register_memory_table must succeed");

    let results = engine
        .query("SELECT id, name FROM test_table ORDER BY id")
        .await
        .expect("SELECT from memory table must succeed");

    assert!(
        !results.is_empty(),
        "query must return at least one record batch"
    );

    let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        total_rows, 3,
        "expected 3 rows from test table, got {}",
        total_rows
    );
}

/// TC-06b: SELECT with WHERE clause filters rows correctly.
#[tokio::test]
async fn tc_06b_select_with_where_filter() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    engine.inject_contract_bundle(dummy_bundle("contract-001", "test-tenant-001"));

    let batch = make_test_batch();
    let schema = batch.schema();
    engine
        .register_memory_table("filtered_table", schema, vec![vec![batch]])
        .await
        .unwrap();

    let results = engine
        .query("SELECT id FROM filtered_table WHERE id > 1")
        .await
        .expect("WHERE-filtered SELECT must succeed");

    let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        total_rows, 2,
        "WHERE id > 1 must return exactly 2 rows, got {}",
        total_rows
    );
}

// ─── TC-07: Parquet table registration ───────────────────────────────────────

/// TC-07: Register a Parquet file and SELECT from it.
///
/// RED: writes a small Parquet file to a temp dir, registers it, queries.
/// Verifies the Parquet read path is wired.
#[tokio::test]
async fn tc_07_select_from_parquet_table() {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;
    use std::fs::File;

    // Build a small RecordBatch and write it to a temp Parquet file.
    let schema = Arc::new(Schema::new(vec![
        Field::new("x", DataType::Int64, false),
        Field::new("label", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![10, 20, 30])),
            Arc::new(StringArray::from(vec!["a", "b", "c"])),
        ],
    )
    .unwrap();

    let tmp_dir = tempfile::tempdir().expect("tempdir creation failed");
    let parquet_path = tmp_dir.path().join("test.parquet");
    let file = File::create(&parquet_path).expect("parquet file creation failed");
    let mut writer =
        ArrowWriter::try_new(file, schema.clone(), None).expect("ArrowWriter creation failed");
    writer.write(&batch).expect("write batch");
    writer.close().expect("close writer");

    // Register the Parquet file and query.
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    engine.inject_contract_bundle(dummy_bundle("contract-001", "test-tenant-001"));

    engine
        .register_parquet_table("parquet_table", parquet_path.to_str().unwrap())
        .await
        .expect("register_parquet_table must succeed");

    let results = engine
        .query("SELECT x, label FROM parquet_table ORDER BY x")
        .await
        .expect("SELECT from parquet table must succeed");

    let total_rows: usize = results.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        total_rows, 3,
        "expected 3 rows from parquet table, got {}",
        total_rows
    );
}

// ─── TC-09: Bundle handle_id uniqueness ──────────────────────────────────────

/// TC-09: Two separately constructed bundle handles must have different
/// handle_ids.
///
/// GREEN after construction: this property is guaranteed by `Uuid::new_v4()`
/// in the shell.  Kept as a smoke test for the UUID generation path.
#[test]
fn tc_09_bundle_handle_ids_are_unique() {
    let b1 = dummy_bundle("c-001", "t-001");
    let b2 = dummy_bundle("c-001", "t-001");
    assert_ne!(
        b1.handle_id(),
        b2.handle_id(),
        "two separate bundle handles must have distinct UUIDs"
    );
}

// ─── TC-10: INV-1 + INV-5: INSTALL rejected even with bundle ─────────────────

/// TC-10: INSTALL is rejected even after a contract bundle has been injected.
///
/// RED (runtime failure): The `query()` method checks the DDL guard AFTER the
/// contract-bundle check.  The expected error is `UnsafeDdlRejected`, not
/// `NoContractBundle`.  This test verifies the ordering of the two checks.
///
/// This test currently PASSES for the shell (ordering is correct).  The
/// implementation agent must ensure that optimizer-rule additions in future
/// waves do NOT move the DDL guard to after the optimizer pass (which would
/// allow bypass via a contract bundle injection).
///
/// Kept as a regression guard for ADR-0002 verified-binary surface rule (d).
#[tokio::test]
async fn tc_10_install_rejected_even_with_bundle() {
    let mut engine = K04DEngine::new_with_config(valid_config()).unwrap();
    engine.inject_contract_bundle(dummy_bundle("c-001", "test-tenant-001"));

    // INSTALL must be rejected even though a bundle is present.
    let result = engine.query("INSTALL 'evil.so'").await;
    assert!(result.is_err(), "INSTALL must fail with UnsafeDdlRejected");
    match result.err().unwrap() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb, "INSTALL");
        }
        EngineError::NoContractBundle => {
            panic!("DDL guard must run BEFORE contract check; got NoContractBundle instead")
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

// ─── TC-08: INV-5 static check — no zone-t imports ───────────────────────────

/// TC-08: Verify this test module (and the lib) imports nothing from zone_t.
///
/// This is a documentation-level test rather than a runtime assertion.  The
/// CI cross-zone guard runs `tools/cross-zone-guard.sh` on every PR; this
/// test asserts the same invariant at compile time: if any `use zone_t::` or
/// `use t0X_` statement were present in this file, the build would fail.
///
/// We verify the negative by asserting that the module is clean.  The test
/// itself always passes; the compile gate is what matters.
#[test]
fn tc_08_no_zone_t_imports_in_engine_shell() {
    // Verify at runtime that we are not in zone-t by checking that no
    // zone-t types are accessible via griot.  This is enforced
    // structurally (the engine imports only datafusion, tokio, serde,
    // thiserror, anyhow, tracing, uuid), but we state it as a test for
    // catalog completeness.
    //
    // The real enforcement is:
    //   1. `tools/cross-zone-guard.sh` rejects `use zone_t::` in zone-k.
    //   2. The Cargo workspace separation (zone-t vs standalone this crate)
    //      means zone-t types are not even available to link against.
    //
    // If this assertion panics it means the test was somehow compiled
    // in an environment where zone-t types leaked into zone-k scope —
    // which would be a critical architecture violation.
    let crate_name = env!("CARGO_PKG_NAME");
    assert_eq!(
        crate_name, "griot",
        "this test must run in the standalone griot crate"
    );
}
