# Contributing to GriotQL

Thanks for your interest. GriotQL is a standalone snapshot of the query engine
from the Griot Cloud platform (see [Provenance](README.md#provenance)).

## Development setup

You only need a recent stable Rust toolchain (≥ 1.88). Everything else is
vendored through cargo.

```bash
git clone <this-repo> griotql && cd griotql
cargo build
cargo test
```

## Before you open a PR

Run the same gates CI runs (these must all pass):

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

- Keep the default feature set building **without `protoc`**. Anything that
  needs `protoc` (e.g. the Lance columnar path) must stay behind the `lance`
  feature.
- Match the surrounding style: the engine source predates clippy's inline
  format-args lint, which is allowed crate-wide — don't churn unrelated lines.
- Add or update an example when you add user-visible behaviour, and make sure
  `cargo run --example <name>` still works with no external services.

## Scope

This repo packages the engine for standalone use. Deeper changes that invert the
engine's dependencies (so the upstream platform can consume this as a published
library) are tracked separately and are out of scope here. Bug fixes,
documentation, examples, and build/CI improvements are all welcome.

## Reporting issues

Please include the command you ran, the full output, your `rustc --version`, and
your OS. For enforcement bugs (masking/row-filter/DP), a minimal reproduction
that constructs the engine in memory (as the examples do) is ideal.
