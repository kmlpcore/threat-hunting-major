"""S3-compatible object storage behind one small interface.

Paths are always "<bucket>/<key>". The local backend maps buckets to directories
under LOCAL_STORAGE_ROOT, so the same keys work in both modes.

Two extras matter for the design:
- Object tags (sealing drives the archive lifecycle through `sealed=true`).
- Raw-access accounting: every byte read from the raw bucket is counted, and a
  guard can forbid raw reads entirely (feature backfills must never touch raw).
"""
from __future__ import annotations

import contextlib
import gzip
import io
import json
import threading
from collections import Counter
from typing import Iterable, Iterator

import pyarrow as pa
import pyarrow.fs as pafs
import pyarrow.parquet as pq

from engine.common.config import Settings


class RawAccessDenied(RuntimeError):
    """Raised when code running under `deny_raw()` tries to read the raw bucket."""


class ObjectStore:
    def __init__(self, fs: pafs.FileSystem, description: str, settings: Settings | None = None):
        self.fs = fs
        self.description = description
        self.settings = settings
        self.raw_bucket = settings.buckets.raw if settings else "raw"
        self.bytes_read: Counter[str] = Counter()
        self._local = threading.local()
        self._s3 = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "ObjectStore":
        if settings.storage_backend == "s3":
            endpoint = settings.s3_endpoint or ""
            scheme = "https" if endpoint.startswith("https://") else "http"
            host = endpoint.split("://", 1)[-1]
            fs = pafs.S3FileSystem(
                access_key=settings.s3_access_key,
                secret_key=settings.s3_secret_key,
                endpoint_override=host or None,
                scheme=scheme,
                region=settings.s3_region,
                allow_bucket_creation=False,
            )
            return cls(fs, f"s3:{endpoint}", settings)
        root = settings.local_storage_root
        root.mkdir(parents=True, exist_ok=True)
        for bucket in vars(settings.buckets).values():
            (root / bucket).mkdir(exist_ok=True)
        return cls(pafs.SubTreeFileSystem(str(root.absolute()).replace("\\", "/"), pafs.LocalFileSystem()),
                   f"local:{root}", settings)

    @property
    def is_s3(self) -> bool:
        return isinstance(self.fs, pafs.S3FileSystem)

    # -- raw-access accounting ------------------------------------------------
    @contextlib.contextmanager
    def deny_raw(self):
        """Within this block any read from the raw bucket raises RawAccessDenied."""
        prev = getattr(self._local, "deny", False)
        self._local.deny = True
        try:
            yield
        finally:
            self._local.deny = prev

    def _account(self, path: str, n: int) -> None:
        bucket = path.split("/", 1)[0]
        if bucket == self.raw_bucket and getattr(self._local, "deny", False):
            raise RawAccessDenied(f"raw access denied in this context: {path}")
        self.bytes_read[bucket] += n

    # -- bytes ---------------------------------------------------------------
    def put_bytes(self, path: str, data: bytes) -> None:
        self._ensure_parent(path)
        with self.fs.open_output_stream(path, compression=None) as out:
            out.write(data)

    def get_bytes(self, path: str) -> bytes:
        self._account(path, 0)
        with self.fs.open_input_stream(path, compression=None) as src:
            data = src.read()
        self._account(path, len(data))
        return data

    def exists(self, path: str) -> bool:
        return self.fs.get_file_info(path).type != pafs.FileType.NotFound

    def size(self, path: str) -> int:
        return self.fs.get_file_info(path).size

    def list(self, prefix: str, suffix: str = "") -> list[str]:
        if not self.exists(prefix):
            return []
        infos = self.fs.get_file_info(pafs.FileSelector(prefix, recursive=True))
        return sorted(i.path for i in infos if i.type == pafs.FileType.File and i.path.endswith(suffix))

    def total_size(self, prefix: str) -> tuple[int, int]:
        """(objects, bytes) under a prefix."""
        if not self.exists(prefix):
            return 0, 0
        infos = [i for i in self.fs.get_file_info(pafs.FileSelector(prefix, recursive=True))
                 if i.type == pafs.FileType.File]
        return len(infos), sum(i.size for i in infos)

    # -- JSON / JSONL --------------------------------------------------------
    def put_json(self, path: str, obj) -> None:
        self.put_bytes(path, json.dumps(obj, indent=2, default=str).encode())

    def get_json(self, path: str):
        return json.loads(self.get_bytes(path))

    def put_jsonl_gz(self, path: str, records: Iterable[dict]) -> int:
        buf = io.BytesIO()
        n = 0
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            for rec in records:
                gz.write(json.dumps(rec, separators=(",", ":"), default=str).encode() + b"\n")
                n += 1
        self.put_bytes(path, buf.getvalue())
        return n

    def iter_jsonl_gz(self, path: str) -> Iterator[dict]:
        data = gzip.decompress(self.get_bytes(path))
        for line in data.splitlines():
            if line.strip():
                yield json.loads(line)

    # -- Parquet -------------------------------------------------------------
    def write_parquet(self, path: str, table: pa.Table, row_group_rows: int, metadata: dict | None = None) -> int:
        if metadata:
            existing = table.schema.metadata or {}
            table = table.replace_schema_metadata({**existing, **{k.encode(): str(v).encode() for k, v in metadata.items()}})
        self._ensure_parent(path)
        pq.write_table(table, path, filesystem=self.fs, compression="zstd", row_group_size=row_group_rows,
                       write_statistics=True, store_schema=False)
        return self.size(path)

    def read_parquet(self, path: str, columns: list[str] | None = None) -> pa.Table:
        self._account(path, 0)
        table = pq.read_table(path, filesystem=self.fs, columns=columns)
        self._account(path, self.size(path))
        return table

    def parquet_metadata(self, path: str) -> pq.FileMetaData:
        """Footer only; reading metadata is not a restore of the data."""
        with self.fs.open_input_file(path) as f:
            return pq.ParquetFile(f).metadata

    def read_row_groups(self, path: str, row_groups: list[int],
                        columns: list[str] | None = None) -> tuple[pa.Table, int]:
        """Selective restore: read only some row groups. Returns (table, compressed bytes read)."""
        self._account(path, 0)
        with self.fs.open_input_file(path) as f:
            pf = pq.ParquetFile(f)
            table = pf.read_row_groups(sorted(set(row_groups)), columns=columns)
            nbytes = sum(pf.metadata.row_group(i).total_byte_size for i in set(row_groups))
        self._account(path, nbytes)
        return table, nbytes

    # -- tags (S3 object tagging; JSON sidecars in local mode) ----------------
    def _client(self):
        if self._s3 is None:
            import boto3
            from botocore.config import Config
            s = self.settings
            self._s3 = boto3.client("s3", endpoint_url=s.s3_endpoint, aws_access_key_id=s.s3_access_key,
                                    aws_secret_access_key=s.s3_secret_key, region_name=s.s3_region,
                                    config=Config(s3={"addressing_style": "path"}))
        return self._s3

    def set_tags(self, path: str, tags: dict[str, str]) -> None:
        bucket, key = path.split("/", 1)
        if self.is_s3:
            self._client().put_object_tagging(
                Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": k, "Value": str(v)} for k, v in tags.items()]})
        else:
            self.put_json(f"{bucket}/.tags/{key}.json", tags)

    def get_tags(self, path: str) -> dict[str, str]:
        bucket, key = path.split("/", 1)
        if self.is_s3:
            resp = self._client().get_object_tagging(Bucket=bucket, Key=key)
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        sidecar = f"{bucket}/.tags/{key}.json"
        return json.loads(self.get_bytes(sidecar)) if self.exists(sidecar) else {}

    def storage_class(self, path: str) -> str:
        """STANDARD, or the remote tier name once the lifecycle has transitioned the object."""
        if not self.is_s3:
            return "STANDARD"
        bucket, key = path.split("/", 1)
        return self._client().head_object(Bucket=bucket, Key=key).get("StorageClass", "STANDARD")

    def _ensure_parent(self, path: str) -> None:
        parent = path.rsplit("/", 1)[0]
        if parent and isinstance(self.fs, pafs.SubTreeFileSystem):
            self.fs.create_dir(parent, recursive=True)
