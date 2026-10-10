"""HMAC-keyed pseudonyms for identifiers that leave the boundary or land in TI tables
(plan.md sections 3.9 and 12.4).

    pseudonym("host", "ws-fin-003") -> "host_5c0f1e9a2b7d"

The same value always maps to the same pseudonym under one key, so patterns stay linkable,
but the mapping cannot be reversed without the key, which never leaves the organisation.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging

from engine.common.config import Settings

log = logging.getLogger(__name__)
DEV_KEY = "dev-only-pseudonymisation-key-change-me"
_warned = False

INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                      "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def key(settings: Settings) -> bytes:
    global _warned
    if settings.pseudonymisation_key:
        return settings.pseudonymisation_key.encode()
    if not _warned:
        log.warning("PSEUDONYMISATION_HMAC_KEY is not set: using the development key (do not use in production)")
        _warned = True
    return DEV_KEY.encode()


def pseudonym(settings: Settings, kind: str, value: str | None) -> str | None:
    if value in (None, ""):
        return None
    digest = hmac.new(key(settings), f"{kind}\x1f{str(value).lower()}".encode(), hashlib.sha256).hexdigest()
    return f"{kind}_{digest[:12]}"


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in n for n in INTERNAL_NETWORKS)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
