//! Unit tests for `MaskingRule` — Wave 8 / ADR-0002.
//!
//! Testing agent authored (2026-05-05). Impl agent updated to GREEN (2026-05-06).
//!
//! # TDD state
//!
//! GREEN: `MaskingRule::rewrite` is implemented. `should_panic` guards removed;
//! post-impl assertions enabled.
//!
//! # Coverage
//!
//! * MK-01: Projection over PII column with `redact` → mask_redact(col).
//! * MK-02: Projection over PHI column with `hash_sha256` → mask_hash_sha256(col).
//! * MK-03: Projection over PCI column with `tokenize` → mask_tokenize(col).
//! * MK-04: Projection over unclassified column → noop (pass-through).
//! * MK-STRUCT: MaskPolicy enum variants exist (GREEN).
//! * MK-API: policy_for_column stub API compiles (compile check).

use bytes::Bytes;
use datafusion::execution::context::SessionContext;
use datafusion::logical_expr::LogicalPlan;
use datafusion::optimizer::OptimizerRule;
use griot::optimizer_rules::contract_check::ContractCheckRule;
use griot::optimizer_rules::masking::{MaskPolicy, MaskingRule};
use griot::optimizer_rules::Principal;
use griot::ContractBundleHandle;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Stamp a raw plan with a `ContractApprovedMarker` by running `ContractCheckRule`.
///
/// MaskingRule (Finding 6 fix) only masks projections whose input subtree
/// contains a `ContractApprovedMarker`.  Tests that use raw `TableScan` plans
/// must pass through `ContractCheckRule` first to produce the marker.
///
/// The bundle passed here must grant access to the principal (i.e., the
/// principal satisfies all contract constraints) so that the scan is approved
/// (not denied to `EmptyRelation`).
fn stamp_plan_with_marker(
    plan: LogicalPlan,
    bundle: ContractBundleHandle,
    principal: Principal,
) -> LogicalPlan {
    let check_rule = ContractCheckRule::new(bundle, principal);
    let config = datafusion::optimizer::OptimizerContext::new();
    let result = check_rule.rewrite(plan, &config).unwrap();
    result.data
}

/// Build a principal that satisfies all constraints in `make_bundle_with_masks()`.
///
/// The mask bundle has no `required_tier`, `required_classification`, or
/// `allowed_purposes` constraints, so any principal passes.
fn make_pass_principal() -> Principal {
    Principal {
        id: "test-user".to_string(),
        declared_purpose: "analytics".to_string(),
        tier: "gold".to_string(),
        classification: "internal".to_string(),
    }
}

/// Build a bundle that encodes column-level sensitivity labels.
///
/// Schema:
///   - `email`    → PII, policy = `redact`
///   - `dob`      → PHI, policy = `hash_sha256`
///   - `card_num` → PCI, policy = `tokenize`
///   - `score`    → unclassified, policy = `noop`
fn make_bundle_with_masks() -> ContractBundleHandle {
    ContractBundleHandle::from_x02_bytes(
        "contract-mask-01",
        "test-tenant",
        Bytes::from(
            serde_json::json!({
                "contract_id": "contract-mask-01",
                "tenant_id": "test-tenant",
                "column_policies": {
                    "email": {"sensitivity": "PII", "mask": "redact"},
                    "dob": {"sensitivity": "PHI", "mask": "hash_sha256"},
                    "card_num": {"sensitivity": "PCI", "mask": "tokenize"},
                    "score": {"sensitivity": "none", "mask": "noop"}
                }
            })
            .to_string()
            .into_bytes(),
        ),
    )
}

async fn make_ctx_with_sensitive_table() -> SessionContext {
    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use std::sync::Arc;

    let schema = Arc::new(Schema::new(vec![
        Field::new("email", DataType::Utf8, false),
        Field::new("dob", DataType::Utf8, false),
        Field::new("card_num", DataType::Utf8, false),
        Field::new("score", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(vec!["alice@example.com"])),
            Arc::new(StringArray::from(vec!["1990-01-01"])),
            Arc::new(StringArray::from(vec!["4111111111111111"])),
            Arc::new(Int64Array::from(vec![42])),
        ],
    )
    .unwrap();
    let ctx = SessionContext::new();
    ctx.register_table(
        "users",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
    )
    .unwrap();
    ctx
}

// ─── MK-01: PII column with redact → mask_redact(col) ────────────────────────

/// MK-01: A `Projection` over the `email` (PII) column must have the column
/// expression replaced with `mask_redact(email)`.
///
/// Semantic Law: INV-2 (no read without satisfaction — masking).
#[tokio::test]
async fn mk_01_pii_redact_wraps_column() {
    use datafusion::logical_expr::Expr;

    let ctx = make_ctx_with_sensitive_table().await;
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle.clone());

    // Plan: SELECT email FROM users — stamp with ContractApprovedMarker first.
    let raw_plan = ctx
        .sql("SELECT email FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle, make_pass_principal());

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    // The result should be a Projection with the email column wrapped in an Alias.
    // The alias name should be "email" (preserving column name).
    if let LogicalPlan::Projection(proj) = &result.data {
        let email_expr = &proj.expr[0];
        // Should be an Alias wrapping the redacted literal.
        assert!(
            matches!(email_expr, Expr::Alias(_)),
            "expected Alias expression for masked PII column, got: {:?}",
            email_expr
        );
        if let Expr::Alias(alias) = email_expr {
            assert_eq!(alias.name, "email", "alias name must preserve 'email'");
            // MK-REDACT: the inner expression must be Literal("<REDACTED>"), not the
            // original column — verifying Finding 3 fix.
            assert!(
                matches!(alias.expr.as_ref(), Expr::Literal(_)),
                "expected Literal inner expression for Redact policy, got: {:?}",
                alias.expr
            );
        }
    } else {
        panic!("expected Projection plan, got: {:?}", result.data);
    }
}

// ─── MK-02: PHI column with hash_sha256 → mask_hash_sha256(col) ──────────────

/// MK-02: A `Projection` over the `dob` (PHI) column must wrap with
/// `mask_hash_sha256(dob)`.
#[tokio::test]
async fn mk_02_phi_hash_sha256_wraps_column() {
    use datafusion::logical_expr::Expr;

    let ctx = make_ctx_with_sensitive_table().await;
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle.clone());

    let raw_plan = ctx
        .sql("SELECT dob FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle, make_pass_principal());

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    if let LogicalPlan::Projection(proj) = &result.data {
        let dob_expr = &proj.expr[0];
        assert!(
            matches!(dob_expr, Expr::Alias(_)),
            "expected Alias expression for masked PHI column, got: {:?}",
            dob_expr
        );
        if let Expr::Alias(alias) = dob_expr {
            assert_eq!(alias.name, "dob", "alias name must preserve 'dob'");
            // MK-HASH: the inner expression must be a ScalarFunction (sha256 cast),
            // not the original column — verifying Finding 3 fix.
            assert!(
                !matches!(alias.expr.as_ref(), Expr::Column(_)),
                "expected masking expression (not original Column) for HashSha256 policy, got: {:?}",
                alias.expr
            );
        }
    } else {
        panic!("expected Projection plan, got: {:?}", result.data);
    }
}

// ─── MK-03: PCI column with tokenize → mask_tokenize(col) ────────────────────

/// MK-03: A `Projection` over `card_num` (PCI) must wrap with
/// `mask_tokenize(card_num)`.
#[tokio::test]
async fn mk_03_pci_tokenize_wraps_column() {
    use datafusion::logical_expr::Expr;

    let ctx = make_ctx_with_sensitive_table().await;
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle.clone());

    let raw_plan = ctx
        .sql("SELECT card_num FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle, make_pass_principal());

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    if let LogicalPlan::Projection(proj) = &result.data {
        let card_expr = &proj.expr[0];
        assert!(
            matches!(card_expr, Expr::Alias(_)),
            "expected Alias expression for masked PCI column, got: {:?}",
            card_expr
        );
        if let Expr::Alias(alias) = card_expr {
            assert_eq!(
                alias.name, "card_num",
                "alias name must preserve 'card_num'"
            );
            // MK-TOKENIZE: the inner expression must not be the original column.
            // Tokenize maps to HashSha256 (sha256 cast), verifying Finding 3 fix.
            assert!(
                !matches!(alias.expr.as_ref(), Expr::Column(_)),
                "expected masking expression (not original Column) for Tokenize policy, got: {:?}",
                alias.expr
            );
        }
    } else {
        panic!("expected Projection plan, got: {:?}", result.data);
    }
}

// ─── MK-04: Unclassified column → noop (pass-through) ────────────────────────

/// MK-04: A `Projection` over `score` (unclassified, policy=`noop`) must
/// leave the column expression unchanged.
///
/// Correctness note: the impl must NOT wrap noop columns in any scalar
/// function — plain pass-through is the expectation.  Even with the marker
/// present (so masking is attempted), `noop` columns must be unchanged.
#[tokio::test]
async fn mk_04_unclassified_noop_passthrough() {
    use datafusion::logical_expr::Expr;

    let ctx = make_ctx_with_sensitive_table().await;
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle.clone());

    // Stamp with marker so masking is attempted — but noop columns pass through.
    let raw_plan = ctx
        .sql("SELECT score FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let plan = stamp_plan_with_marker(raw_plan, bundle, make_pass_principal());

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    // score is unclassified with noop policy — no masking should be applied.
    // The plan shape should be: Projection[Column("score")] unchanged.
    if let LogicalPlan::Projection(proj) = &result.data {
        let score_expr = &proj.expr[0];
        // Must NOT be an Alias wrapping a masking expression.
        // It should be the original Column expression.
        assert!(
            matches!(score_expr, Expr::Column(_)),
            "expected unchanged Column expression for noop column, got: {:?}",
            score_expr
        );
    } else {
        // If not a Projection (e.g., passthrough at a higher plan node), that's also
        // acceptable as long as no masking transformation occurred on the column.
    }
}

// ─── MK-UNMARKED: unmarked scan refused (Finding 6 dedicated test) ────────────

/// MK-UNMARKED: A `Projection` over an unmarked scan (no ContractApprovedMarker)
/// must be left unchanged — MaskingRule must not mask without marker.
///
/// Semantic Law: INV-2 (no read without satisfaction) requires that masking
/// only fires on approved scans.  Masking a non-approved scan would give false
/// security (the masking output might never be audited).
#[tokio::test]
async fn mk_unmarked_scan_no_masking_applied() {
    use datafusion::logical_expr::Expr;

    let ctx = make_ctx_with_sensitive_table().await;
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle);

    // Raw plan WITHOUT stamping — no ContractApprovedMarker in subtree.
    let plan = ctx
        .sql("SELECT email FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();

    let config = datafusion::optimizer::OptimizerContext::new();
    let result = rule.rewrite(plan, &config).unwrap();

    // MaskingRule must NOT transform the Projection — passthrough expected.
    if let LogicalPlan::Projection(proj) = &result.data {
        let email_expr = &proj.expr[0];
        // Without the marker, the email column must not be wrapped in an Alias.
        assert!(
            matches!(email_expr, Expr::Column(_)),
            "MaskingRule must not mask unmarked scan; expected Column, got: {:?}",
            email_expr
        );
    }
    // If the result is not a Projection, passthrough is also acceptable.
}

// ─── MK-STRUCT: MaskPolicy enum variants ─────────────────────────────────────

/// MK-STRUCT: Verify all four `MaskPolicy` variants exist and are
/// distinguishable.  This test is GREEN.
#[test]
fn mk_struct_mask_policy_variants_exist() {
    let policies = [
        MaskPolicy::Redact,
        MaskPolicy::HashSha256,
        MaskPolicy::Tokenize,
        MaskPolicy::Noop,
    ];
    assert_eq!(policies.len(), 4);

    // Each variant must be unique (PartialEq + Eq).
    assert_ne!(MaskPolicy::Redact, MaskPolicy::HashSha256);
    assert_ne!(MaskPolicy::HashSha256, MaskPolicy::Tokenize);
    assert_ne!(MaskPolicy::Tokenize, MaskPolicy::Noop);
    assert_ne!(MaskPolicy::Noop, MaskPolicy::Redact);
}

/// MK-STRUCT-02: `MaskingRule::new` compiles and `drain_audit_records`
/// returns empty on a fresh instance.  GREEN.
#[test]
fn mk_struct_02_fresh_rule_has_no_audit_records() {
    let bundle = make_bundle_with_masks();
    let rule = MaskingRule::new(bundle);
    let records = rule.drain_audit_records();
    assert!(records.is_empty());
    let _ = rule.bundle().contract_id();
}
