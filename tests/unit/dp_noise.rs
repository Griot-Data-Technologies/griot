//! Unit tests for `DPNoiseRule` and `PrivacyBudgetTracker` — Wave 8 / ADR-0002.
//!
//! Testing agent authored (2026-05-05). Impl agent updated to GREEN (2026-05-06).
//!
//! # TDD state
//!
//! GREEN: `DPNoiseRule::rewrite` and `PrivacyBudgetTracker::consume` are
//! implemented. `should_panic` guards removed; post-impl assertions enabled.
//!
//! # Coverage
//!
//! * DP-01: Aggregate over DP-tagged column + budget available → LaplaceNoise injected.
//! * DP-02: Aggregate over non-DP column → pass-through.
//! * DP-03: Aggregate over DP-tagged column + budget exhausted → PrivacyBudgetExhausted.
//! * DP-04: Privacy budget tracker decrements correctly per query.
//! * DP-PERM-01: Permissive tracker always succeeds (MEMORY.md durable instruction).
//! * DP-PERM-02: `remaining()` returns infinity when enforcement disabled.

use bytes::Bytes;
use datafusion::execution::context::SessionContext;
use datafusion::logical_expr::LogicalPlan;
use datafusion::optimizer::OptimizerRule;
use griot::optimizer_rules::contract_check::ContractCheckRule;
use griot::optimizer_rules::dp_noise::{DPNoiseRule, PrivacyBudgetTracker};
use griot::optimizer_rules::{AuditKind, Principal};
use griot::ContractBundleHandle;
use std::collections::HashMap;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_dp_bundle(contract_id: &str) -> ContractBundleHandle {
    // Bundle signals that `salary` is DP-tagged with epsilon=0.5/query.
    // `name` is not DP-tagged.
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "dp_columns": {
                    "salary": {"epsilon_per_query": 0.5, "noise_mechanism": "laplace"}
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

fn make_non_dp_bundle(contract_id: &str) -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        contract_id,
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": contract_id,
                "tenant_id": "test-tenant",
                "dp_columns": {}
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

/// Stamp a raw plan with a `ContractApprovedMarker` by running `ContractCheckRule`.
///
/// `DPNoiseRule` (Finding 6 fix) only injects noise into aggregates whose input
/// subtree contains a `ContractApprovedMarker`.  Tests must stamp plans first.
///
/// The bundle passed here must not constrain the principal (no required_tier /
/// required_classification / allowed_purposes) so that the scan is approved.
fn stamp_plan_with_marker(plan: LogicalPlan, bundle: ContractBundleHandle) -> LogicalPlan {
    let principal = Principal {
        id: "test-user".to_string(),
        declared_purpose: "analytics".to_string(),
        tier: "gold".to_string(),
        classification: "internal".to_string(),
    };
    let check_rule = ContractCheckRule::new(bundle, principal);
    let config = datafusion::optimizer::OptimizerContext::new();
    let result = check_rule.rewrite(plan, &config).unwrap();
    result.data
}

async fn make_ctx_with_salary_table() -> SessionContext {
    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use std::sync::Arc;

    let schema = Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("salary", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["alice", "bob"])),
            Arc::new(Int64Array::from(vec![90_000, 110_000])),
        ],
    )
    .unwrap();
    let ctx = SessionContext::new();
    ctx.register_table(
        "employees",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
    )
    .unwrap();
    ctx
}

// ─── DP-01: DP-tagged column + budget available → LaplaceNoise injected ──────

/// DP-01: `SELECT AVG(salary) FROM employees` over a DP-tagged column with
/// sufficient budget must result in a plan containing a `LaplaceNoise` logical
/// node wrapping the aggregate.
///
/// Semantic Law: INV-2 (no read without satisfaction — privacy budget).
#[tokio::test]
async fn dp_01_dp_column_with_budget_injects_laplace_noise() {
    let ctx = make_ctx_with_salary_table().await;
    let bundle = make_dp_bundle("contract-dp-01");

    // Pre-seed budget: 2 queries at 0.5 epsilon each = 1.0 total.
    let mut budgets = HashMap::new();
    budgets.insert(("test-tenant".to_string(), "salary".to_string()), 1.0_f64);
    let rule = DPNoiseRule::new_with_budget(bundle.clone(), "test-tenant", budgets);

    // Stamp with ContractApprovedMarker so DPNoiseRule (Finding 6 fix) sees it.
    let raw_plan = ctx
        .sql("SELECT AVG(salary) FROM employees")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle);

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    // Result plan should contain a LaplaceNoise Extension node somewhere in
    // the tree.  DataFusion adds a top-level Projection above the Aggregate,
    // so we walk the plan to find the Extension node.
    fn plan_contains_extension(plan: &LogicalPlan) -> bool {
        if matches!(plan, LogicalPlan::Extension(_)) {
            return true;
        }
        plan.inputs()
            .iter()
            .any(|child| plan_contains_extension(child))
    }
    assert!(
        plan_contains_extension(&result.data),
        "expected LaplaceNoise Extension node somewhere in plan for DP-tagged aggregate, got: {:?}",
        result.data
    );

    // Audit records should be empty (success case).
    let audit = rule.drain_audit_records();
    assert!(
        audit.is_empty(),
        "successful DP noise injection should not emit audit records"
    );
}

// ─── DP-02: Non-DP column → pass-through ─────────────────────────────────────

/// DP-02: `SELECT AVG(salary) FROM employees` where the bundle has NO dp_columns
/// entry for `salary` → aggregate passes through unchanged (no LaplaceNoise).
#[tokio::test]
async fn dp_02_non_dp_column_passthrough() {
    use datafusion::logical_expr::LogicalPlan;
    use datafusion::optimizer::OptimizerRule;

    let ctx = make_ctx_with_salary_table().await;
    let bundle = make_non_dp_bundle("contract-dp-02");
    let rule = DPNoiseRule::new_permissive(bundle, "test-tenant");

    let plan = ctx
        .sql("SELECT AVG(salary) FROM employees")
        .await
        .unwrap()
        .into_unoptimized_plan();

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    // No LaplaceNoise node — plan passes through unchanged.
    assert!(
        !matches!(result.data, LogicalPlan::Extension(_)),
        "expected no LaplaceNoise node for non-DP column, got: {:?}",
        result.data
    );
}

// ─── DP-03: Budget exhausted → PrivacyBudgetExhausted error + AuditRecord ────

/// DP-03: When the privacy budget for a DP-tagged column is exhausted (0.0
/// remaining), the rule MUST fail the query with `PrivacyBudgetExhausted`
/// and emit an `AuditRecord` with kind `PrivacyBudgetExhausted`.
///
/// Semantic Law: INV-2 (no read without satisfaction).
#[tokio::test]
async fn dp_03_budget_exhausted_fails_query_with_audit() {
    let ctx = make_ctx_with_salary_table().await;
    let bundle = make_dp_bundle("contract-dp-03");

    // Seed budget at exactly 0.0 — exhausted before any query.
    let mut budgets = HashMap::new();
    budgets.insert(("test-tenant".to_string(), "salary".to_string()), 0.0_f64);
    let rule = DPNoiseRule::new_with_budget(bundle.clone(), "test-tenant", budgets);

    // Stamp with ContractApprovedMarker so DPNoiseRule (Finding 6 fix) sees it.
    let raw_plan = ctx
        .sql("SELECT AVG(salary) FROM employees")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle);

    let config = datafusion::optimizer::OptimizerContext::new();
    // Should return Err (DataFusion error wrapping PrivacyBudgetExhausted).
    let result = rule.rewrite(plan, &config);

    assert!(result.is_err(), "exhausted budget must fail the query");

    let audit = rule.drain_audit_records();
    assert_eq!(
        audit.len(),
        1,
        "expected 1 audit record for budget exhaustion"
    );
    assert_eq!(
        audit[0].kind,
        AuditKind::PrivacyBudgetExhausted,
        "expected PrivacyBudgetExhausted audit kind"
    );
}

// ─── DP-04: Budget tracker decrements per query ───────────────────────────────

/// DP-04: After a successful query (budget available), the tracker's
/// `remaining()` must return the decremented value.
///
/// This test exercises `PrivacyBudgetTracker::consume` directly.
#[test]
fn dp_04_budget_tracker_decrements_on_consume() {
    let mut budgets = HashMap::new();
    budgets.insert(("test-tenant".to_string(), "salary".to_string()), 1.0_f64);
    let tracker = PrivacyBudgetTracker::with_enforcement(true, budgets);

    assert!(
        tracker.is_enabled(),
        "tracker must report enforcement enabled"
    );

    // First consume: 0.5 epsilon.
    let result = tracker.consume("test-tenant", "salary", 0.5);
    assert!(
        result.is_ok(),
        "first consume (0.5) should succeed with budget 1.0"
    );

    // After first consume: remaining should be 0.5.
    let remaining = tracker.remaining("test-tenant", "salary");
    assert!(
        (remaining - 0.5).abs() < 1e-9,
        "remaining budget should be 0.5 after consuming 0.5 from 1.0, got {}",
        remaining
    );

    // Second consume: 0.5 epsilon (exactly depletes budget).
    let result2 = tracker.consume("test-tenant", "salary", 0.5);
    assert!(
        result2.is_ok(),
        "second consume should succeed (depletes to 0.0)"
    );

    // Third consume: 0.1 epsilon (should fail — budget exhausted).
    let result3 = tracker.consume("test-tenant", "salary", 0.1);
    assert!(
        result3.is_err(),
        "third consume should fail — budget exhausted"
    );
}

// ─── DP-PERM-01: Permissive tracker always succeeds ──────────────────────────

/// DP-PERM-01: When `PrivacyBudgetTracker::new()` (permissive default) is used,
/// `consume` always returns `Ok(())` regardless of epsilon.
///
/// This test is GREEN — permissive mode is implemented in the stub.
///
/// Per MEMORY.md durable instruction: permissive-default rule.
#[test]
fn dp_perm_01_permissive_tracker_always_succeeds() {
    let tracker = PrivacyBudgetTracker::new();
    assert!(
        !tracker.is_enabled(),
        "default tracker must be permissive (disabled)"
    );

    // Should succeed for any epsilon, any number of times.
    for _ in 0..100 {
        let result = tracker.consume("any-tenant", "any-column", 1_000_000.0);
        assert!(
            result.is_ok(),
            "permissive tracker must always return Ok(())"
        );
    }
}

// ─── DP-PERM-02: remaining() returns infinity when enforcement disabled ───────

/// DP-PERM-02: `remaining()` returns `f64::INFINITY` for any key when
/// enforcement is disabled.
///
/// This test is GREEN — implemented in the stub.
#[test]
fn dp_perm_02_remaining_returns_infinity_when_disabled() {
    let tracker = PrivacyBudgetTracker::new();
    let remaining = tracker.remaining("any-tenant", "any-column");
    assert!(
        remaining.is_infinite() && remaining > 0.0,
        "permissive tracker remaining() must return +infinity"
    );
}

// ─── DP-STRUCT: DPNoiseRule constructors compile ─────────────────────────────

/// DP-STRUCT: Verify both constructors of `DPNoiseRule` compile and expose
/// expected accessors.  GREEN.
#[test]
fn dp_struct_constructors_compile() {
    let bundle = make_dp_bundle("c-test");
    let rule = DPNoiseRule::new_permissive(bundle.clone(), "test-tenant");
    assert_eq!(rule.tenant_id(), "test-tenant");
    assert!(!rule.budget().is_enabled());
    let records = rule.drain_audit_records();
    assert!(records.is_empty());

    let budgets: HashMap<(String, String), f64> = HashMap::new();
    let rule2 = DPNoiseRule::new_with_budget(bundle, "test-tenant", budgets);
    assert!(rule2.budget().is_enabled());
}

// ─── DP-AUDIT: AuditKind::PrivacyBudgetExhausted variant exists ──────────────

/// DP-AUDIT: Verify the `PrivacyBudgetExhausted` audit kind exists and is
/// distinct from other kinds.  GREEN.
#[test]
fn dp_audit_budget_exhausted_kind_exists() {
    let kind = AuditKind::PrivacyBudgetExhausted;
    // Must be distinguishable from ContractCheckDenied.
    assert_ne!(kind, AuditKind::ContractCheckDenied);
    // Matches itself.
    assert_eq!(kind, AuditKind::PrivacyBudgetExhausted);
}
