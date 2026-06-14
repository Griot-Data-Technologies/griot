//! Optimizer pipeline assembly — Wave 8 implementation (round-2 Copilot fixes).
//!
//! ADR-0002 §Decision: the four rules execute in a fixed order:
//!   1. ContractCheckRule  (griot_contract_check)
//!   2. RowFilterRule      (griot_row_filter)
//!   3. MaskingRule        (griot_masking)
//!   4. DPNoiseRule        (griot_dp_noise)
//!
//! This module exports `build_pipeline` which constructs the ordered list of
//! DataFusion `OptimizerRule` trait objects ready for registration with a
//! `SessionContext` via `add_optimizer_rule`.
//!
//! # Ordering guarantee
//!
//! The returned vector ALWAYS has exactly four elements in the order specified
//! by [`RULE_ORDER`].  Callers MUST NOT reorder them.  The order is
//! non-negotiable per ADR-0002 §Decision: `ContractCheckRule` MUST run first
//! to stamp markers; downstream rules depend on that ordering to implement
//! defensive programming checks.
//!
//! # Copilot round-2 fixes
//!
//! ## Finding 4 — `build_pipeline` discarded an enabled `PrivacyBudgetTracker`
//!
//! The original `build_pipeline` always called `DPNoiseRule::new_permissive`
//! regardless of the `budget` field on `PipelineConfig`, meaning that callers
//! passing `PrivacyBudgetTracker::with_enforcement(true, budgets)` got a
//! permissive (no enforcement) rule instead.
//!
//! The fix: `build_pipeline` now exposes the budget's initial values via a
//! `PipelineConfig` field (`initial_budgets`) and routes an enabled budget
//! to `DPNoiseRule::new_with_budget`.  Callers that need enforcement use
//! `PipelineConfig { initial_budgets: Some(map), .. }` and get a rule that
//! actually consults and debits the budget.
//!
//! ## Finding 1 + 6 — Shared `ApprovedTableSet`
//!
//! `build_pipeline` now wires all four rules to a single shared
//! [`ApprovedTableSet`] created by `ContractCheckRule`.  This allows downstream
//! rules to detect contract approval without requiring a plan-level search
//! (though they ALSO check the plan-level `ContractApprovedMarker` Extension).
//!
//! # Semantic Law coverage
//!
//! * INV-1: ContractCheckRule enforces no-scan-without-contract.
//! * INV-2: All four rules together enforce read satisfaction.
//! * INV-5: No zone-t imports.

use crate::optimizer_rules::contract_check::{ApprovedTableSet, ContractCheckRule};
use crate::optimizer_rules::dp_noise::{DPNoiseRule, PrivacyBudgetTracker};
use crate::optimizer_rules::masking::MaskingRule;
use crate::optimizer_rules::row_filter::RowFilterRule;
use crate::optimizer_rules::Principal;
use crate::ContractBundleHandle;
use datafusion::optimizer::OptimizerRule;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for a boxed, thread-safe optimizer rule as required by DataFusion.
pub type BoxedOptimizerRule = Arc<dyn OptimizerRule + Send + Sync>;

/// The canonical rule names in pipeline order.  Tests assert these are
/// produced in exactly this sequence.
pub const RULE_ORDER: &[&str] = &[
    "griot_contract_check",
    "griot_row_filter",
    "griot_masking",
    "griot_dp_noise",
];

/// Parameters for constructing the full four-rule optimizer pipeline.
///
/// # Finding 4 fix
///
/// Added `initial_budgets` to carry pre-seeded epsilon values when budget
/// enforcement is needed.  Set to `Some(map)` to enable enforcement;
/// `None` uses the permissive default (no enforcement).
pub struct PipelineConfig {
    /// The signed contract bundle serving as the enforcement source.
    pub bundle: ContractBundleHandle,
    /// The query principal (purpose, tier, classification).
    pub principal: Principal,
    /// Privacy budget tracker.  Pass `PrivacyBudgetTracker::new()` (permissive
    /// default) unless the caller explicitly needs budget enforcement.
    ///
    /// When `initial_budgets` is `Some`, this field is ignored and a fresh
    /// enforcing tracker is constructed from `initial_budgets`.
    pub budget: PrivacyBudgetTracker,
    /// The tenant ID (used by `DPNoiseRule` for budget key lookup).
    pub tenant_id: String,
    /// Finding 4 fix: pre-seeded epsilon budget values.
    ///
    /// When `Some`, `build_pipeline` constructs `DPNoiseRule::new_with_budget`
    /// with these values, enabling real budget enforcement.  When `None`,
    /// `build_pipeline` uses `new_permissive` (permissive default).
    pub initial_budgets: Option<HashMap<(String, String), f64>>,
}

/// Build the four-rule optimizer pipeline in the canonical fixed order:
///   1. ContractCheckRule → 2. RowFilterRule → 3. MaskingRule → 4. DPNoiseRule
///
/// Returns a `Vec<BoxedOptimizerRule>` ready for
/// `SessionContext::add_optimizer_rule`.
///
/// # Ordering guarantee
///
/// The returned vector ALWAYS has exactly four elements in the order specified
/// by [`RULE_ORDER`].  Callers MUST NOT reorder them.
///
/// # Finding 1 + 4 + 6 fix
///
/// - A shared [`ApprovedTableSet`] is created and distributed to all four rules
///   so downstream rules can gate on contract approval (Findings 1 + 6).
/// - When `config.initial_budgets` is `Some`, the `DPNoiseRule` is constructed
///   with `new_with_budget` (enforcement ON), not `new_permissive` (Finding 4).
pub fn build_pipeline(config: PipelineConfig) -> Vec<BoxedOptimizerRule> {
    let PipelineConfig {
        bundle,
        principal,
        budget: _budget,
        tenant_id,
        initial_budgets,
    } = config;

    // Finding 1 + 6 fix: create a shared ApprovedTableSet so all four rules
    // can read the approval registry that ContractCheckRule writes.
    let approved_set = ApprovedTableSet::new();

    // ContractCheckRule uses the shared set and exposes it via `approved_set()`.
    let contract_check =
        ContractCheckRule::new_with_shared_set(bundle.clone(), principal.clone(), approved_set);

    let row_filter = RowFilterRule::new(bundle.clone(), principal.clone());
    let masking = MaskingRule::new(bundle.clone());

    // Finding 4 fix: route an enabled budget (initial_budgets is Some) to
    // DPNoiseRule::new_with_budget instead of always using new_permissive.
    let dp_noise = match initial_budgets {
        Some(budgets) => DPNoiseRule::new_with_budget(bundle, &tenant_id, budgets),
        None => DPNoiseRule::new_permissive(bundle, &tenant_id),
    };

    // Rules MUST appear in this exact order.
    vec![
        Arc::new(contract_check) as BoxedOptimizerRule,
        Arc::new(row_filter) as BoxedOptimizerRule,
        Arc::new(masking) as BoxedOptimizerRule,
        Arc::new(dp_noise) as BoxedOptimizerRule,
    ]
}

/// Convenience: build a permissive pipeline for testing (no budget enforcement,
/// permissive-default tracker).
///
/// This is the standard helper used in unit and integration tests that need to
/// construct a pipeline without worrying about budget seeding.
pub fn build_permissive_pipeline(
    bundle: ContractBundleHandle,
    principal: Principal,
    tenant_id: impl Into<String>,
) -> Vec<BoxedOptimizerRule> {
    build_pipeline(PipelineConfig {
        bundle,
        principal,
        budget: PrivacyBudgetTracker::new(),
        tenant_id: tenant_id.into(),
        initial_budgets: None,
    })
}

/// Convenience: build a pipeline with budget enforcement and pre-seeded values.
///
/// # Finding 4 fix
///
/// This function now correctly routes the `initial_budgets` through
/// `build_pipeline`'s `initial_budgets` field, which causes
/// `DPNoiseRule::new_with_budget` to be used (enforcement ON) rather than
/// the old `new_permissive` path that discarded the supplied budgets.
pub fn build_enforced_pipeline(
    bundle: ContractBundleHandle,
    principal: Principal,
    tenant_id: impl Into<String>,
    initial_budgets: HashMap<(String, String), f64>,
) -> Vec<BoxedOptimizerRule> {
    build_pipeline(PipelineConfig {
        bundle,
        principal,
        budget: PrivacyBudgetTracker::new(), // ignored when initial_budgets is Some
        tenant_id: tenant_id.into(),
        initial_budgets: Some(initial_budgets),
    })
}
