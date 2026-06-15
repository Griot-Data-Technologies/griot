# GriotQL (Python)

A contract-resolving, privacy-enforcing SQL engine — point SQL at a *contract*,
get *governed* rows. Python bindings for the [GriotQL](../../README.md) engine.

```bash
pip install griotql
```

```python
import griotql

engine = griotql.Engine.from_json_contracts_dir("./contracts")

table = engine.query(
    'SELECT email, region FROM "sales/orders/v1"',
    griotql.Caller("user:bob", purpose="analytics", tenant="globex"),
)
print(table.to_pandas())   # email is SHA-256 hashed for the outside tenant
```

The owning tenant sees raw rows; everyone else gets the contract's masking and
row filtering, enforced inside the query plan. Results come back as a
`pyarrow.Table`. See the main project's `docs/CONTRACT-FORMAT.md` for the JSON
contract format.

No Rust toolchain is required to use the published wheel.
