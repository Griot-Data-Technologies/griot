"""Tests for the GriotQL Python wheel.

Run (from `bindings/python`, after `maturin develop`):
    pytest
"""

import json

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import griotql


def _engine(tmp_path):
    path = str(tmp_path / "orders.parquet")
    pq.write_table(
        pa.table(
            {
                "order_id": [1, 2, 3, 4, 5],
                "email": [
                    "alice@acme.com",
                    "bob@globex.com",
                    "carol@acme.com",
                    "dan@initech.com",
                    "erin@acme.com",
                ],
                "region": ["EU", "US", "EU", "APAC", "US"],
            }
        ),
        path,
    )
    contract = json.dumps(
        {
            "contract_id": "sales_orders_v1",
            "version": "1",
            "dataset": "sales/orders/v1",
            "binding": {"parquet": path},
            "owner_tenant": "acme",
            "purposes": ["analytics"],
            "columns": [{"name": "email", "type": "text", "mask": "hash_sha256"}],
            "row_filter": "region = 'EU'",
        }
    )
    return griotql.Engine.from_json_contracts([contract])


SQL = 'SELECT order_id, email, region FROM "sales/orders/v1" ORDER BY order_id'


def test_outsider_is_masked_and_filtered(tmp_path):
    eng = _engine(tmp_path)
    t = eng.query(SQL, griotql.Caller("user:bob", "analytics", "globex"))
    assert t.num_rows == 2  # EU-only
    emails = t.column("email").to_pylist()
    assert all("@" not in e and len(e) == 64 for e in emails)  # SHA-256 hex


def test_owner_sees_raw(tmp_path):
    eng = _engine(tmp_path)
    t = eng.query(SQL, griotql.Caller("user:alice", "analytics", "acme"))
    assert t.num_rows == 5
    assert any("@" in e for e in t.column("email").to_pylist())


def test_disallowed_purpose_is_denied(tmp_path):
    eng = _engine(tmp_path)
    with pytest.raises(Exception) as exc:
        eng.query(SQL, griotql.Caller("u", "marketing", "globex"))
    assert "denied" in str(exc.value)


def test_returns_pyarrow_table(tmp_path):
    eng = _engine(tmp_path)
    t = eng.query(SQL, griotql.Caller("u", "analytics", "acme"))
    assert isinstance(t, pa.Table)
