"""BuildIndex(source, day): bloom sidecars per hour partition + one Tantivy index per source-day.

Layout in the (hot) index bucket:
    index/bloom/source=<s>/date=<d>/hour=<hh>/<field>.bloom
    index/fts/source=<s>/date=<d>/segment.tar.zst
    index/fts/source=<s>/date=<d>/manifest.json   {generation, docs, backend, ...}

Every document stores its address in raw: (raw_file, row_group, row_offset), so a
hit can be restored by reading a single row group.
"""
from __future__ import annotations

import io
import json
import logging
import shutil
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path

import zstandard
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.config import Settings
from engine.common.db import utcnow
from engine.common.events import IndexBuilt
from engine.common.storage import ObjectStore
from engine.indexer.bloom import BLOOM_FIELDS, BloomFilter, normalise_value
from engine.indexer.fts_tantivy import INDEX_VERSION, TantivyBackend

log = logging.getLogger(__name__)


def fts_prefix(settings: Settings, source: str, day: str) -> str:
    return f"{settings.buckets.index}/fts/source={source}/date={day}"


def bloom_path(settings: Settings, partition_id: str, field: str) -> str:
    return f"{settings.buckets.index}/bloom/{partition_id}/{field}.bloom"


def bloom_bundle_path(settings: Settings, source: str, day: str) -> str:
    return f"{settings.buckets.index}/bloom/source={source}/date={day}/bundle.blooms"


def pack_bundle(filters: dict[str, bytes], generation: str) -> bytes:
    offsets, blobs, pos = {}, [], 0
    for key, data in filters.items():
        offsets[key] = [pos, len(data)]
        blobs.append(data)
        pos += len(data)
    header = json.dumps({"generation": generation, "filters": offsets}).encode()
    return len(header).to_bytes(4, "big") + header + b"".join(blobs)


def unpack_bundle(data: bytes) -> tuple[str, dict[str, BloomFilter]]:
    hl = int.from_bytes(data[:4], "big")
    header = json.loads(data[4:4 + hl])
    body = data[4 + hl:]
    return header["generation"], {k: BloomFilter.from_bytes(body[o:o + n]) for k, (o, n) in header["filters"].items()}


def pack_dir(path: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for f in sorted(path.iterdir()):
            tar.add(f, arcname=f.name)
    return zstandard.ZstdCompressor(level=6).compress(buf.getvalue())


def unpack_to(data: bytes, path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    raw = zstandard.ZstdDecompressor().decompress(data, max_output_size=2 ** 31)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r") as tar:
        tar.extractall(path, filter="data")


def _iter_docs(store: ObjectStore, files) -> tuple[list[dict], dict[str, dict[str, set]]]:
    docs, values = [], defaultdict(lambda: defaultdict(set))
    for f in files:
        meta = store.parquet_metadata(f.file)
        table = store.read_parquet(f.file)
        rows = table.to_pylist()
        offset = 0
        for rg in range(meta.num_row_groups):
            n = meta.row_group(rg).num_rows
            for i in range(n):
                row = rows[offset + i]
                docs.append({"row": row, "raw_file": f.file, "row_group": rg, "row_offset": i,
                             "source": f.partition_id.split("/", 1)[0].split("=", 1)[1]})
                pid = f.partition_id
                for field in BLOOM_FIELDS:
                    v = row.get(field)
                    for x in (v if isinstance(v, list) else [v]):
                        if x not in (None, ""):
                            values[pid][field].add(normalise_value(x))
            offset += n
    return docs, values


def build_index(conn: Connection, store: ObjectStore, settings: Settings, source: str, day: str,
                generation: str, command_id: str) -> IndexBuilt:
    files = stages.day_files(conn, source, day)
    docs, values = _iter_docs(store, files)

    blooms = 0
    bundle: dict[str, bytes] = {}
    for pid in sorted({f.partition_id for f in files}):
        for field in BLOOM_FIELDS:
            vals = values[pid].get(field, set())
            bf = BloomFilter.for_capacity(len(vals))
            for v in vals:
                bf.add(v)
            data = bf.to_bytes()
            store.put_bytes(bloom_path(settings, pid, field), data)   # per-partition sidecar (plan 3.5a)
            bundle[f"{pid}|{field}"] = data
            blooms += 1
    # The same filters bundled per source-day: one GET instead of hours x fields on a cold sweep.
    store.put_bytes(bloom_bundle_path(settings, source, day), pack_bundle(bundle, generation))

    backend = TantivyBackend()
    tmp = Path(tempfile.mkdtemp(prefix="idx-"))
    try:
        n_docs = backend.build(docs, tmp / "segment")
        packed = pack_dir(tmp / "segment")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    prefix = fts_prefix(settings, source, day)
    store.put_bytes(f"{prefix}/segment.tar.zst", packed)
    manifest = {"source": source, "day": day, "generation": generation, "docs": n_docs, "backend": backend.version,
                "index_version": INDEX_VERSION, "bytes": len(packed), "built_at": utcnow().isoformat(),
                "partitions": sorted({f.partition_id for f in files}), "bloom_fields": list(BLOOM_FIELDS)}
    store.put_json(f"{prefix}/manifest.json", manifest)

    stages.record(conn, "index", f"{source}/{day}", generation, INDEX_VERSION,
                  {"docs": n_docs, "bytes": len(packed), "blooms": blooms}, command_id)
    log.info("index %s/%s: %d docs, %d bloom filters, %d bytes", source, day, n_docs, blooms, len(packed))
    return IndexBuilt(source=source, day=day, generation=generation, index_version=INDEX_VERSION, docs=n_docs,
                      index_bytes=len(packed), bloom_filters=blooms, partitions=manifest["partitions"])
