//! Unit tests for [`DdlGuard::reject_unsafe_ddl`] — comment-strip + multi-statement.
//!
//! Story:   STORY-K04-CATCHUP-001
//! Copilot: PRRT_kwDOSEqhas5_il4W (DdlGuard SQL-comment bypass)
//! Semantic Law: INV-5 — No bypass from above trust line.
//! ADR:     ADR-0002, verified-binary surface rule (d).
//!
//! These tests verify that three previously-exploitable bypass vectors are
//! now rejected:
//!
//!   1. Block-comment prefix: `/*hi*/ COPY foo FROM '...'`
//!   2. Line-comment prefix: `-- evil\nCOPY foo FROM '...'`
//!   3. Multi-statement: `SELECT 1; COPY foo FROM '...'`
//!
//! They also verify that legitimate SQL (SELECT, WITH, CREATE TABLE, CREATE VIEW)
//! continues to pass.

use griot::{DdlGuard, EngineError};

// ─── Bypass-via-block-comment tests ──────────────────────────────────────────

/// TC-DG-01: Block comment before COPY must be stripped, COPY rejected.
///
/// Copilot finding PRRT_kwDOSEqhas5_il4W, bypass vector 1.
#[test]
fn bypass_via_block_comment() {
    let sql = "/*hi*/ COPY foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "block-comment prefix must not bypass DdlGuard; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(
                verb.to_uppercase(),
                "COPY",
                "rejection must name COPY as the unsafe verb"
            );
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-02: Block comment immediately adjacent to COPY (no whitespace gap).
#[test]
fn bypass_via_block_comment_no_space() {
    // `/*hi*/COPY` — after stripping the comment, the first token is COPY.
    let sql = "/*hi*/COPY foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "block-comment with no trailing space must still be rejected; sql={sql:?}"
    );
}

/// TC-DG-03: Mixed case COPY after block comment is rejected.
#[test]
fn bypass_via_mixed_case_with_comment() {
    let sql = "/*hi*/CoPy foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "mixed-case COPY after block comment must be rejected; sql={sql:?}"
    );
}

/// TC-DG-04: Nested block comments stripped correctly.
///
/// `/* outer /* inner */ outer */` — depth tracking must handle nesting.
#[test]
fn nested_block_comments() {
    let sql = "/* outer /* inner */ outer */ COPY foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "COPY after nested block comment must be rejected; sql={sql:?}"
    );
}

/// TC-DG-05: Deeply nested block comments.
#[test]
fn deeply_nested_block_comments() {
    // Three levels of nesting.
    let sql = "/* a /* b /* c */ b */ a */ INSTALL 'evil.so'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "INSTALL after deeply nested block comment must be rejected; sql={sql:?}"
    );
}

// ─── Bypass-via-line-comment tests ───────────────────────────────────────────

/// TC-DG-06: Line comment before COPY must be stripped, COPY rejected.
///
/// Copilot finding PRRT_kwDOSEqhas5_il4W, bypass vector 2.
#[test]
fn bypass_via_line_comment() {
    let sql = "-- evil\nCOPY foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "line-comment prefix must not bypass DdlGuard; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "COPY");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-07: LOAD hidden behind a line comment on the first line.
#[test]
fn bypass_via_line_comment_load() {
    let sql = "-- innocent comment\nLOAD 'plugin.so'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "LOAD after line comment must be rejected; sql={sql:?}"
    );
}

/// TC-DG-08: Multiple line comments before INSTALL.
#[test]
fn bypass_via_multiple_line_comments() {
    let sql = "-- comment 1\n-- comment 2\nINSTALL 'evil.so'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "INSTALL after multiple line comments must be rejected; sql={sql:?}"
    );
}

// ─── Bypass-via-multi-statement tests ────────────────────────────────────────

/// TC-DG-09: COPY in the second statement must be rejected.
///
/// Copilot finding PRRT_kwDOSEqhas5_il4W, bypass vector 3.
#[test]
fn bypass_via_multi_statement() {
    let sql = "SELECT 1; COPY foo FROM 'x'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "COPY in a second statement must be rejected; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "COPY");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-10: INSTALL in the third statement must be rejected.
#[test]
fn bypass_via_multi_statement_third() {
    let sql = "SELECT 1; SELECT 2; INSTALL 'evil.so'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "INSTALL in third statement must be rejected"
    );
}

/// TC-DG-11: ATTACH in a multi-statement chain is rejected.
#[test]
fn bypass_via_multi_statement_attach() {
    let sql = "WITH cte AS (SELECT 1); ATTACH DATABASE 'other.db' AS other";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "ATTACH in second statement must be rejected; sql={sql:?}"
    );
}

/// TC-DG-12: Combination of block comment and multi-statement.
///
/// The input has a block comment, then a safe SELECT, then COPY.
#[test]
fn bypass_via_block_comment_and_multi_statement() {
    let sql = "/* comment */ SELECT 1; COPY tbl TO '/tmp/out.csv'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "COPY after block comment + multi-statement must be rejected; sql={sql:?}"
    );
}

// ─── Valid-SQL happy-path tests ───────────────────────────────────────────────

/// TC-DG-13: Simple SELECT is allowed.
#[test]
fn valid_select_passes() {
    let sql = "SELECT id, name FROM users WHERE id = 1";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(result.is_ok(), "SELECT must be allowed; sql={sql:?}");
}

/// TC-DG-14: CTE (WITH clause) is allowed.
#[test]
fn valid_with_clause_passes() {
    let sql = "WITH ranked AS (SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM users) \
               SELECT id FROM ranked WHERE rn <= 10";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(result.is_ok(), "WITH clause must be allowed; sql={sql:?}");
}

/// TC-DG-15: CREATE TABLE is NOT in the deny-list (DDL goes through submit_ddl).
///
/// The DdlGuard deny-list is for unsigned-plugin-injection verbs only.
/// CREATE TABLE / CREATE VIEW are legitimate DDL operations submitted via the
/// submit_ddl X02 opcode path.  They must not be rejected by DdlGuard.
#[test]
fn valid_create_table_passes() {
    let sql = "CREATE TABLE tenant.events (id INT, ts TIMESTAMP)";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_ok(),
        "CREATE TABLE must not be rejected by DdlGuard (it goes through submit_ddl); sql={sql:?}"
    );
}

/// TC-DG-16: CREATE VIEW is allowed by DdlGuard.
#[test]
fn valid_create_view_passes() {
    let sql = "CREATE VIEW v AS SELECT 1 AS id";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(result.is_ok(), "CREATE VIEW must be allowed; sql={sql:?}");
}

/// TC-DG-17: SELECT with inline comment is allowed.
#[test]
fn valid_select_with_inline_block_comment() {
    // `SELECT /* pick columns */ id FROM t` — comment in the middle, not a bypass.
    let sql = "SELECT /* pick columns */ id FROM t";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_ok(),
        "SELECT with inline block comment must be allowed; sql={sql:?}"
    );
}

/// TC-DG-18: Trailing semicolon produces an empty statement that is silently skipped.
#[test]
fn valid_select_with_trailing_semicolon() {
    let sql = "SELECT 1;";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_ok(),
        "trailing semicolon must not cause spurious rejection; sql={sql:?}"
    );
}

/// TC-DG-19: String literal containing `COPY` keyword is not mistaken for a COPY statement.
#[test]
fn valid_string_literal_containing_copy_keyword() {
    // The word COPY is in a string literal — it is not a SQL verb.
    let sql = "SELECT 'COPY' AS label FROM t";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_ok(),
        "COPY inside a string literal must not be rejected; sql={sql:?}"
    );
}

/// TC-DG-20: String literal containing `--` is not treated as a line comment.
#[test]
fn valid_string_literal_containing_comment_sequence() {
    let sql = "SELECT '-- not a comment' AS msg FROM t";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_ok(),
        "double-dash inside string literal must not be treated as a line comment; sql={sql:?}"
    );
}

// ─── EXTENSION deny-list tests ───────────────────────────────────────────────

/// TC-DG-21: EXTENSION is in the deny-list (DataFusion extension registration).
#[test]
fn extension_verb_rejected() {
    let sql = "EXTENSION LOAD 'plugin'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "EXTENSION must be rejected as an unsafe DDL verb; sql={sql:?}"
    );
}

// ─── Scope-pack gap-7 additional bypass tests ─────────────────────────────────

/// TC-DG-22: Standalone ATTACH is rejected.
///
/// Scope-pack gap-7: `ATTACH 'foo.db' AS bar` must be rejected as a standalone statement.
#[test]
fn standalone_attach_rejected() {
    let sql = "ATTACH 'foo.db' AS bar";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "standalone ATTACH must be rejected; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(
                verb.to_uppercase(),
                "ATTACH",
                "rejection must name ATTACH as the unsafe verb"
            );
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-23: Standalone COPY is rejected.
///
/// Scope-pack gap-7: `COPY tbl FROM '...'` standalone.
#[test]
fn standalone_copy_rejected() {
    let sql = "COPY tbl FROM '/data/file.csv'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "standalone COPY must be rejected; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "COPY");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-24: INSTALL in the first statement followed by SELECT is rejected.
///
/// Scope-pack gap-7: `INSTALL httpfs; SELECT 1` — the INSTALL verb must be
/// caught even though a safe SELECT follows it.
#[test]
fn install_first_then_select_rejected() {
    let sql = "INSTALL httpfs; SELECT 1";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "INSTALL httpfs; SELECT 1 must be rejected; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "INSTALL");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-25: Block-comment prefix before INSTALL is rejected.
///
/// Scope-pack gap-7: `/* comment */ INSTALL httpfs`.
#[test]
fn block_comment_before_install_rejected() {
    let sql = "/* comment */ INSTALL httpfs";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "/* comment */ INSTALL must be rejected; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "INSTALL");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}

/// TC-DG-26: Empty leading statements (multiple semicolons) do not bypass the guard.
///
/// Scope-pack gap-7: `;;;COPY foo FROM 'bar'` — leading empty statements must
/// not allow the COPY verb through.
#[test]
fn empty_leading_statements_do_not_bypass() {
    let sql = ";;;COPY foo FROM 'bar'";
    let result = DdlGuard::reject_unsafe_ddl(sql);
    assert!(
        result.is_err(),
        "empty leading semicolons must not bypass the DdlGuard; sql={sql:?}"
    );
    match result.unwrap_err() {
        EngineError::UnsafeDdlRejected { verb } => {
            assert_eq!(verb.to_uppercase(), "COPY");
        }
        other => panic!("expected UnsafeDdlRejected, got {:?}", other),
    }
}
