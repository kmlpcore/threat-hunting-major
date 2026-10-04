"""Bloom-filter sidecars (plan.md section 3.5a).

One filter per (hour partition, field). They live in the hot `index` bucket, so an
IOC sweep can rule out partitions without touching raw (which may be archived).
False positives only cost an extra index lookup; there are no false negatives.
"""
from __future__ import annotations

import hashlib
import json
import math

# ECS fields with exact-match IOC semantics.
BLOOM_FIELDS = (
    "related.ip", "source.ip", "destination.ip", "host.ip",
    "process.hash.sha256", "file.hash.sha256", "related.hash",
    "dns.question.name", "dns.question.registered_domain",
    "url.domain", "url.registered_domain", "destination.domain",
    "user.name", "host.name",
)
TARGET_FPR = 0.01


class BloomFilter:
    def __init__(self, m_bits: int, k: int, bits: bytearray | None = None, n: int = 0):
        self.m, self.k = max(8, m_bits), max(1, k)
        self.bits = bits if bits is not None else bytearray((self.m + 7) // 8)
        self.n = n

    @classmethod
    def for_capacity(cls, n: int, fpr: float = TARGET_FPR) -> "BloomFilter":
        n = max(1, n)
        m = math.ceil(-n * math.log(fpr) / (math.log(2) ** 2))
        return cls(m, round(m / n * math.log(2)))

    def _positions(self, value: str):
        h = hashlib.sha256(value.encode()).digest()
        h1 = int.from_bytes(h[:8], "big")
        h2 = int.from_bytes(h[8:16], "big") | 1
        return ((h1 + i * h2) % self.m for i in range(self.k))

    def add(self, value: str) -> None:
        for p in self._positions(value):
            self.bits[p >> 3] |= 1 << (p & 7)
        self.n += 1

    def __contains__(self, value: str) -> bool:
        return all(self.bits[p >> 3] & (1 << (p & 7)) for p in self._positions(value))

    def to_bytes(self) -> bytes:
        header = json.dumps({"m": self.m, "k": self.k, "n": self.n, "hash": "sha256-double", "v": 1}).encode()
        return len(header).to_bytes(4, "big") + header + bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        hl = int.from_bytes(data[:4], "big")
        header = json.loads(data[4:4 + hl])
        return cls(header["m"], header["k"], bytearray(data[4 + hl:]), header["n"])


def normalise_value(value: str) -> str:
    return str(value).strip().lower()
