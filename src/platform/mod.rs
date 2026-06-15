//! Platform adapter — consume Griot Cloud's signed contract bundle (feature
//! `platform`).
//!
//! The open-source engine reads a simple JSON contract
//! ([`crate::contract_source::JsonContractSource`]). The *platform* speaks a
//! richer artefact: the T03 Contract Authority compiles a contract into a
//! **signed `CompiledBundle`** (WASM carriers + Rego policies + SQL templates +
//! a resolution map), ECDSA-P256-signed. This module fetches that bundle, can
//! verify its signature, and maps it into the same [`crate::policy::ResolvedPolicy`]
//! the engine already executes — so the platform path reuses the entire engine
//! unchanged.
//!
//! ## Honest notes on the mapping
//!
//! The T03 bundle is *execution-oriented*: per-caller masking is expressed as
//! distinct SQL templates (e.g. the non-owner read template selects
//! `sha256_hex(email) AS email`), and purpose gating lives in Rego source —
//! not as a structured "column → mask" map. [`bundle::map_bundle_to_policy`]
//! therefore derives a [`ResolvedPolicy`](crate::policy::ResolvedPolicy) by
//! reading the resolution map, picking the owner/non-owner SQL template, and
//! extracting masks + row filters from it. This is a faithful but *heuristic*
//! mapping; a future T03 enhancement that emits the structured policy directly
//! (or a shared types crate) would make it exact.
//!
//! Differential privacy is absent from the T03 contract model, so policies
//! mapped from a platform bundle never carry DP parameters.

pub mod bundle;
pub mod bundle_source;

pub use bundle::{map_bundle_to_policy, SignedBundleFile, VerifyError};
pub use bundle_source::PlatformBundleSource;
