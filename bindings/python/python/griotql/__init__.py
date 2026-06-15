"""GriotQL — a contract-resolving, privacy-enforcing SQL engine.

Point SQL at a contract-bound dataset and get governed rows: the engine resolves
the contract for the caller, locates the data, and applies the contract's masking
and row filtering inside the query plan.

    import griotql

    engine = griotql.Engine.from_json_contracts_dir("./contracts")
    table = engine.query(
        'SELECT email, region FROM "sales/orders/v1"',
        griotql.Caller("user:bob", "analytics", "globex"),
    )
    print(table.to_pandas())   # email is masked for the outside tenant
"""

from __future__ import annotations

import pyarrow as _pa

from ._native import Caller, Engine as _NativeEngine

__all__ = ["Engine", "Caller"]
__version__ = "0.2.0"


class Engine:
    """A contract-resolving query engine.

    Build one with :meth:`from_json_contracts_dir` or
    :meth:`from_json_contracts`, then call :meth:`query`.
    """

    def __init__(self, native: _NativeEngine) -> None:
        self._native = native

    @classmethod
    def from_json_contracts_dir(cls, directory) -> "Engine":
        """Load every ``*.json`` contract under ``directory``."""
        return cls(_NativeEngine.from_json_contracts_dir(str(directory)))

    @classmethod
    def from_json_contracts(cls, docs) -> "Engine":
        """Build from an iterable of JSON contract strings."""
        return cls(_NativeEngine.from_json_contracts([str(d) for d in docs]))

    def query(self, sql: str, caller: "Caller") -> "_pa.Table":
        """Run ``sql`` as ``caller`` and return a governed ``pyarrow.Table``.

        Datasets are referenced by their quoted URI, e.g.
        ``SELECT * FROM "sales/orders/v1"``.
        """
        ipc = self._native.query(sql, caller)
        if not ipc:
            # Empty result set (no batches): return an empty table.
            return _pa.table({})
        return _pa.ipc.open_file(_pa.py_buffer(ipc)).read_all()
