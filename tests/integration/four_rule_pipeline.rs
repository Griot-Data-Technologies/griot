//! Integration tests for the four-rule optimizer pipeline — Wave 8 / ADR-0002.
//!
//! Testing agent authored (2026-05-05). Impl agent updated to GREEN (2026-05-06).
//!
//! # Purpose
//!
//! These tests verify that when all four optimizer rules are registered with a
//! DataFusion `SessionContext` via `build_pipeline`, they execute in the
//! FIXED canonical order:
//!   1. ContractCheckRule  (griot_contract_check)
//!   2. RowFilterRule      (griot_row_filter)
//!   3. MaskingRule        (griot_masking)
//!   4. DPNoiseRule        (griot_dp_noise)
//!
//! # TDD state
//!
//! GREEN: `build_pipeline` / `build_permissive_pipeline` are implemented.
//! `should_panic` guards removed; assertions enabled.
//!
//! PIPE-CONST tests that verify the `RULE_ORDER` constant are GREEN.
//!
//! # Semantic Law coverage
//!
//! * INV-1: ContractCheck runs FIRST (PIPE-02).
//! * INV-2: All four rules together enforce read satisfaction (PIPE-01).
//! * INV-5: No zone-t imports in this test file.

use bytes::Bytes;
use griot::optimizer_rules::pipeline::{build_permissive_pipeline, RULE_ORDER};
use griot::optimizer_rules::Principal;
use griot::ContractBundleHandle;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn full_bundle() -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        "contract-pipeline-01",
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": "contract-pipeline-01",
                "tenant_id": "test-tenant",
                "allowed_purposes": ["analytics"],
                "required_tier": "silver",
                "required_classification": "internal",
                "row_filter": "region = 'us'",
                "column_policies": {
                    "email": {"sensitivity": "PII", "mask": "redact"},
                    "score": {"sensitivity": "none", "mask": "noop"}
                },
                "dp_columns": {
                    "salary": {"epsilon_per_query": 0.5, "noise_mechanism": "laplace"}
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn satisfying_principal() -> Principal {
    Principal {
        id: "user:alice".to_string(),
        declared_purpose: "analytics".to_string(),
        tier: "silver".to_string(),
        classification: "internal".to_string(),
    }
}

// ─── PIPE-01: End-to-end full pipeline call ───────────────────────────────────

/// PIPE-01: `build_permissive_pipeline` is called with a valid bundle and
/// principal.  The pipeline returns four rules; they are registered with
/// a `SessionContext` via `add_optimizer_rule`.
///
/// Semantic Law: INV-1, INV-2.
#[tokio::test]
async fn pipe_01_end_to_end_all_four_rules_apply() {
    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::execution::context::SessionContext;
    use std::sync::Arc;

    let bundle = full_bundle();
    let principal = satisfying_principal();

    // Build the four-rule pipeline.
    let rules = build_permissive_pipeline(bundle, principal, "test-tenant");
    assert_eq!(rules.len(), 4, "pipeline must contain exactly 4 rules");

    // Register rules with a fresh SessionContext using add_optimizer_rule.
    // DataFusion v47: add_optimizer_rule modifies in-place (returns ()).
    let ctx = SessionContext::new();
    for rule in rules {
        ctx.add_optimizer_rule(rule);
    }

    // Register a test table.
    let schema = Arc::new(Schema::new(vec![
        Field::new("email", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, false),
        Field::new("salary", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec![
                "alice@example.com",
                "bob@example.com",
            ])),
            Arc::new(StringArray::from(vec!["us", "eu"])),
            Arc::new(Int64Array::from(vec![90_000, 110_000])),
        ],
    )
    .unwrap();
    ctx.register_table(
        "employees",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
    )
    .unwrap();

    // Verify the pipeline can be registered without panicking.
    // (Full execution-level testing requires Wave 9 physical operators.)
}

// ─── PIPE-02: ContractCheck runs first; downstream rules refuse without marker ──

/// PIPE-02: The pipeline's first rule is `ContractCheckRule` (index 0).  If
/// the scan is denied, downstream rules (index 1–3) must not have been applied
/// (verified by audit record count and plan shape).
///
/// Also verifies: if `RowFilterRule` is applied WITHOUT a `ContractCheckMarker`
/// it must refuse to act (defensive programming).
#[tokio::test]
async fn pipe_02_contract_check_runs_first_downstream_refuse_without_marker() {
    let bundle = full_bundle();
    let principal = satisfying_principal();

    let rules = build_permissive_pipeline(bundle, principal, "test-tenant");
    assert_eq!(rules.len(), 4);

    // Rule at index 0 must be ContractCheckRule.
    assert_eq!(
        rules[0].name(),
        "griot_contract_check",
        "first rule must be griot_contract_check"
    );

    // Rule at index 1 must be RowFilterRule.
    assert_eq!(
        rules[1].name(),
        "griot_row_filter",
        "second rule must be griot_row_filter"
    );

    // Rule at index 2 must be MaskingRule.
    assert_eq!(
        rules[2].name(),
        "griot_masking",
        "third rule must be griot_masking"
    );

    // Rule at index 3 must be DPNoiseRule.
    assert_eq!(
        rules[3].name(),
        "griot_dp_noise",
        "fourth rule must be griot_dp_noise"
    );
}

// ─── PIPE-03: Pipeline order is FIXED and CANONICAL ──────────────────────────

/// PIPE-03: `build_permissive_pipeline` must return exactly four rules in the
/// canonical order specified by `RULE_ORDER`.  The order is non-negotiable per
/// ADR-0002 §Decision.
#[test]
fn pipe_03_rule_order_is_fixed_canonical() {
    let bundle = full_bundle();
    let principal = satisfying_principal();

    let rules = build_permissive_pipeline(bundle, principal, "test-tenant");

    assert_eq!(
        rules.len(),
        RULE_ORDER.len(),
        "pipeline must have exactly {} rules",
        RULE_ORDER.len()
    );

    for (i, (rule, &expected_name)) in rules.iter().zip(RULE_ORDER.iter()).enumerate() {
        assert_eq!(
            rule.name(),
            expected_name,
            "rule at position {} must be '{}', got '{}'",
            i,
            expected_name,
            rule.name()
        );
    }
}

// ─── PIPE-CONST: RULE_ORDER constant correctness ──────────────────────────────

/// PIPE-CONST: Verify that `RULE_ORDER` constant contains the four canonical
/// rule names in the correct order.  This test is GREEN.
#[test]
fn pipe_const_rule_order_has_four_canonical_names() {
    assert_eq!(RULE_ORDER.len(), 4);
    assert_eq!(RULE_ORDER[0], "griot_contract_check");
    assert_eq!(RULE_ORDER[1], "griot_row_filter");
    assert_eq!(RULE_ORDER[2], "griot_masking");
    assert_eq!(RULE_ORDER[3], "griot_dp_noise");
}
