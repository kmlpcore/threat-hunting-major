"""IndexBackend interface (plan.md section 3.5b). Tantivy is the implementation; a
DuckDB-FTS backend could sit behind the same interface."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Protocol

# ECS field → index field. Text fields are tokenised and BM25-scored; keyword
# fields use the raw tokenizer (exact, lower-cased) for IOC sweeps.
TEXT_FIELDS = {
    "process.command_line": "process_command_line",
    "process.parent.command_line": "process_parent_command_line",
    "url.full": "url_full",
    "file.path": "file_path",
    "user_agent.original": "user_agent",
    "dns.question.name": "dns_question_text",
    "event.original": "message",
}
KEYWORD_FIELDS = {
    "related.ip": "related_ip", "source.ip": "source_ip", "destination.ip": "destination_ip",
    "host.ip": "host_ip",
    "process.hash.sha256": "process_hash", "file.hash.sha256": "file_hash", "related.hash": "related_hash",
    "dns.question.name": "dns_question_name", "dns.question.registered_domain": "dns_registered_domain",
    "url.domain": "url_domain", "url.registered_domain": "url_registered_domain",
    "destination.domain": "destination_domain",
    "user.name": "user_name", "host.name": "host_name", "event.action": "event_action",
    "event.code": "event_code", "process.name": "process_name",
}

# Which keyword fields an IOC of a given type is matched against.
IOC_FIELDS = {
    "ip": ["related.ip", "source.ip", "destination.ip", "host.ip"],
    "hash": ["process.hash.sha256", "file.hash.sha256", "related.hash"],
    "domain": ["dns.question.name", "dns.question.registered_domain", "url.domain", "url.registered_domain",
               "destination.domain"],
    "user": ["user.name"],
    "host": ["host.name"],
}


@dataclass
class DocAddress:
    raw_file: str
    row_group: int
    row_offset: int
    event_id: str
    timestamp: datetime
    source: str
    score: float = 0.0


class IndexBackend(Protocol):
    name: str
    version: str

    def build(self, docs: Iterable[dict], out_dir: Path) -> int: ...
    def text_search(self, index_dir: Path, query: str, limit: int, start: datetime | None,
                    end: datetime | None) -> list[DocAddress]: ...
    def term_search(self, index_dir: Path, ecs_field: str, value: str, limit: int) -> list[DocAddress]: ...
