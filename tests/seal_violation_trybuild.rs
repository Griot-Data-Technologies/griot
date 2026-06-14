//! Trybuild-driven compile-fail test: external crate cannot implement the
//! sealed `EngineCore` trait.
//!
//! ADR-0002 verified-binary surface rule (c): "enforcement primitives behind
//! sealed traits."
//!
//! Wave 8 / Testing agent authored (2026-05-05).
//!
//! # How this works
//!
//! `trybuild` compiles the fixture at `tests/compile-fail/seal_violation.rs`
//! in isolation (as a standalone binary that depends on this crate) and
//! asserts that:
//!   1. The compilation fails.
//!   2. The compiler message contains the text recorded in
//!      `tests/compile-fail/seal_violation.stderr` (if present; if absent,
//!      trybuild captures it on first run).
//!
//! This test is GREEN on a clean crate (the seal is correctly applied).
//! It becomes RED if the impl agent accidentally removes the sealed-trait
//! pattern (the fixture would then compile successfully, triggering a trybuild
//! assertion failure).

#[test]
fn sealed_trait_cannot_be_implemented_externally() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/seal_violation.rs");
}
