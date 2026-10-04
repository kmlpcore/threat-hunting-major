"""Iceberg REST catalog (Lakekeeper) bootstrap and client.

M0 only creates the warehouse and the namespaces; tables arrive with the
milestones that write them (summary in M2, artefacts in M4, ...).
"""
from __future__ import annotations

import logging
import time

import httpx

from engine.common.config import Settings

log = logging.getLogger(__name__)

DEFAULT_PROJECT = "00000000-0000-0000-0000-000000000000"
NAMESPACES = ("summary", "artefacts", "ti", "ti_staging", "results", "index")


def _wait_healthy(client: httpx.Client, timeout_s: int = 120) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if client.get("/health").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise TimeoutError("Lakekeeper did not become healthy")
        time.sleep(2)


def bootstrap_lakekeeper(settings: Settings) -> dict:
    """Idempotent: bootstrap the server, create the warehouse on MinIO, create namespaces."""
    assert settings.lakekeeper_url, "LAKEKEEPER_URL is not set"
    with httpx.Client(base_url=settings.lakekeeper_url, timeout=30) as client:
        _wait_healthy(client)

        info = client.get("/management/v1/info").json()
        if not info.get("bootstrapped"):
            client.post("/management/v1/bootstrap", json={"accept-terms-of-use": True}).raise_for_status()
            log.info("lakekeeper bootstrapped")

        existing = client.get("/management/v1/warehouse").json().get("warehouses", [])
        if not any(w.get("name") == settings.warehouse_name for w in existing):
            resp = client.post("/management/v1/warehouse", json={
                "warehouse-name": settings.warehouse_name,
                "project-id": DEFAULT_PROJECT,
                "storage-profile": {
                    "type": "s3",
                    "bucket": settings.buckets.warehouse,
                    "key-prefix": "iceberg",
                    "endpoint": settings.s3_endpoint,
                    "region": settings.s3_region,
                    "path-style-access": True,
                    "flavor": "s3-compat",
                    "sts-enabled": False,
                },
                "storage-credential": {
                    "type": "s3",
                    "credential-type": "access-key",
                    "access-key-id": settings.s3_access_key,
                    "secret-access-key": settings.s3_secret_key,
                },
            })
            resp.raise_for_status()
            log.info("warehouse %s created", settings.warehouse_name)

    catalog = load_catalog(settings)
    for ns in NAMESPACES:
        catalog.create_namespace_if_not_exists(ns)
    return {"warehouse": settings.warehouse_name, "namespaces": [".".join(n) for n in catalog.list_namespaces()]}


def load_catalog(settings: Settings):
    """Lakekeeper vends table IO with S3 *remote signing* (requests are signed by the catalog,
    which enforces access). PyIceberg implements that through fsspec/s3fs, hence the s3fs extra.
    The s3.* properties below are only used for catalog-level operations."""
    from pyiceberg.catalog.rest import RestCatalog
    return RestCatalog(
        "lakekeeper",
        uri=f"{settings.lakekeeper_url.rstrip('/')}/catalog",
        warehouse=settings.warehouse_name,
        **{
            "s3.endpoint": settings.s3_endpoint,
            "s3.access-key-id": settings.s3_access_key,
            "s3.secret-access-key": settings.s3_secret_key,
            "s3.region": settings.s3_region,
            "s3.path-style-access": "true",
        },
    )


# --------------------------------------------------------------------------- table helpers (M2+)
_CATALOG = None


def get_catalog(settings: Settings):
    """Lakekeeper REST catalog in compose; a SQLite-backed catalog in local mode (Linux only:
    PyIceberg's local file IO does not handle Windows drive paths)."""
    global _CATALOG
    if _CATALOG is None:
        if settings.lakekeeper_url:
            _CATALOG = load_catalog(settings)
        else:
            from pyiceberg.catalog.sql import SqlCatalog
            root = settings.local_storage_root.absolute().as_posix()
            _CATALOG = SqlCatalog("local", uri=f"sqlite:///{root}/iceberg_catalog.db",
                                  warehouse=f"file://{root}/{settings.buckets.warehouse}")
            for ns in NAMESPACES:
                _CATALOG.create_namespace_if_not_exists(ns)
    return _CATALOG


def reset_catalog() -> None:
    global _CATALOG
    _CATALOG = None


def ensure_table(catalog, name: str, schema, partition_by: tuple[str, ...] = ("day",)):
    """Create the Iceberg table from an Arrow schema if missing, partitioned by identity columns."""
    from pyiceberg.exceptions import NoSuchTableError
    try:
        return catalog.load_table(name)
    except NoSuchTableError:
        table = catalog.create_table(name, schema=schema)
        if partition_by:
            with table.update_spec() as spec:
                for col in partition_by:
                    spec.add_identity(col)
        return catalog.load_table(name)


def replace_rows(table, rows, **match) -> int | None:
    """Idempotent write: replace every row matching `match` (column == value) with `rows`.
    Returns the new snapshot id."""
    from functools import reduce

    from pyiceberg.expressions import And, EqualTo
    import pyarrow as pa
    filt = reduce(And, [EqualTo(k, v) for k, v in match.items()]) if len(match) > 1 else \
        EqualTo(*next(iter(match.items())))
    rows = rows.cast(table.schema().as_arrow()) if isinstance(rows, pa.Table) else rows
    import warnings
    with warnings.catch_warnings():
        # The first write of a day has nothing to replace; PyIceberg warns about that.
        warnings.filterwarnings("ignore", message="Delete operation did not match any records")
        if rows.num_rows:
            table.overwrite(rows, overwrite_filter=filt)
        else:
            table.delete(delete_filter=filt)
    table.refresh()
    snap = table.current_snapshot()
    return snap.snapshot_id if snap else None


def table_stats(catalog, name: str) -> dict:
    """Rows, data files and bytes of the current snapshot."""
    from pyiceberg.exceptions import NoSuchTableError
    try:
        table = catalog.load_table(name)
    except NoSuchTableError:
        return {"table": name, "exists": False, "rows": 0, "files": 0, "bytes": 0, "snapshot_id": None}
    files = list(table.scan().plan_files())
    snap = table.current_snapshot()
    return {"table": name, "exists": True, "rows": sum(f.file.record_count for f in files), "files": len(files),
            "bytes": sum(f.file.file_size_in_bytes for f in files), "snapshot_id": snap.snapshot_id if snap else None}


def read_table(catalog, name: str, row_filter=None, snapshot_id: int | None = None, limit: int | None = None):
    """Snapshot-pinned read. Returns (arrow table, snapshot_id actually read)."""
    from pyiceberg.exceptions import NoSuchTableError
    import pyarrow as pa
    try:
        table = catalog.load_table(name)
    except NoSuchTableError:
        return pa.table({}), None
    snap = snapshot_id or (table.current_snapshot().snapshot_id if table.current_snapshot() else None)
    if snap is None:
        return table.schema().as_arrow().empty_table(), None
    kwargs = {"snapshot_id": snap, "limit": limit}
    if row_filter is not None:
        kwargs["row_filter"] = row_filter
    return table.scan(**kwargs).to_arrow(), snap
