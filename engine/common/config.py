"""Runtime settings, read from environment variables.

The same code runs in two modes:
- compose: Postgres + Redis Streams + MinIO (see docker-compose.yml)
- local:   SQLite + in-memory bus + local filesystem (tests, laptops without Docker)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


@dataclass(frozen=True)
class Buckets:
    raw: str = "raw"
    incoming: str = "incoming"
    quarantine: str = "quarantine"
    warehouse: str = "warehouse"
    index: str = "index"


@dataclass(frozen=True)
class Settings:
    database_url: str
    bus_url: str
    storage_backend: str  # "s3" | "local"
    s3_endpoint: str | None
    s3_access_key: str | None
    s3_secret_key: str | None
    s3_region: str
    local_storage_root: Path
    lakekeeper_url: str | None
    warehouse_name: str
    ground_truth_dir: Path
    raw_row_group_rows: int
    writer_max_attempts: int
    buckets: Buckets = field(default_factory=Buckets)
    repo_root: Path = REPO_ROOT

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_url=_env("DATABASE_URL", f"sqlite:///{REPO_ROOT / '.local' / 'engine.db'}"),
            bus_url=_env("BUS_URL", "memory://"),
            storage_backend=_env("STORAGE_BACKEND", "local"),
            s3_endpoint=_env("S3_ENDPOINT"),
            s3_access_key=_env("S3_ACCESS_KEY"),
            s3_secret_key=_env("S3_SECRET_KEY"),
            s3_region=_env("S3_REGION", "us-east-1"),
            local_storage_root=Path(_env("LOCAL_STORAGE_ROOT", str(REPO_ROOT / ".local" / "objects"))),
            lakekeeper_url=_env("LAKEKEEPER_URL"),
            warehouse_name=_env("WAREHOUSE_NAME", "threathunt"),
            ground_truth_dir=Path(_env("GROUND_TRUTH_DIR", str(REPO_ROOT / "benchmarks" / "ground_truth"))),
            raw_row_group_rows=int(_env("RAW_ROW_GROUP_ROWS", "1000000")),
            writer_max_attempts=int(_env("WRITER_MAX_ATTEMPTS", "3")),
        )

    def with_overrides(self, **kwargs) -> "Settings":
        values = {f: getattr(self, f) for f in self.__dataclass_fields__}
        values.update(kwargs)
        return Settings(**values)
