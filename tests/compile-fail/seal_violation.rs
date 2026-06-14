//! Compile-fail fixture: external crate cannot implement `EngineCore`.
//!
//! ADR-0002 §verified-binary surface rule (c): enforcement primitives must be
//! behind sealed traits.  This file is NOT a test binary — it is a trybuild
//! fixture that MUST fail to compile.
//!
//! Trybuild runs this via `tests/seal_violation_trybuild.rs` and asserts that
//! the compiler emits the expected "method `sealed::private::Sealed` is not
//! accessible" error.

// Attempt to implement `EngineCore` from outside the crate.
// This MUST fail compilation because `private::Sealed` is `pub(crate)`.

struct FakeEngine;

// This impl requires `sealed::private::Sealed` but that trait is `pub(crate)`
// inside griot and therefore unreachable from here.
impl griot::sealed::EngineCore for FakeEngine {
    fn tenant_id(&self) -> &str {
        "evil-tenant"
    }
    fn has_contract_bundle(&self) -> bool {
        true // bypass contract enforcement
    }
}

fn main() {}
