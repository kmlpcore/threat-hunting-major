"""Entity resolution at ingest.

- Users: DOMAIN\\user, user@domain, bare sAMAccountName, SIDs and cloud principals
  are canonicalised to one `user.id` via the identity alias table.
- Hosts: FQDNs are shortened; network-only sources get `host.name` from the
  time-bounded IP lease table (DHCP) or static assignments in the asset inventory.
"""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.db import as_utc, assets, identities, identity_aliases, ip_leases
from engine.normaliser.mapping import _hostname, network_config


class LeaseTable:
    def __init__(self):
        self._by_ip: dict[str, list[tuple[datetime, datetime, str]]] = defaultdict(list)
        self._starts: dict[str, list[datetime]] = {}

    def add(self, ip: str, start: datetime, end: datetime, host: str) -> None:
        self._by_ip[ip].append((start, end, host))
        self._starts.pop(ip, None)

    def host_at(self, ip: str, ts: datetime) -> str | None:
        leases = self._by_ip.get(ip)
        if not leases:
            return None
        if ip not in self._starts:
            leases.sort()
            self._starts[ip] = [s for s, _, _ in leases]
        i = bisect.bisect_right(self._starts[ip], ts) - 1
        while i >= 0:  # latest lease that started before ts and is still valid
            start, end, host = leases[i]
            if start <= ts < end:
                return host
            i -= 1
        return None


class EntityResolver:
    def __init__(self, aliases: dict[str, str], ids: dict[str, tuple[str, str | None]],
                 hosts: dict[str, str], static_ips: dict[str, str], leases: LeaseTable):
        self.aliases, self.ids, self.hosts, self.static_ips, self.leases = aliases, ids, hosts, static_ips, leases
        self.stats: Counter[str] = Counter()
        self.net = network_config()

    @classmethod
    def load(cls, conn: Connection, start: datetime | None, end: datetime | None) -> "EntityResolver":
        aliases = {r.alias: r.user_id for r in conn.execute(select(identity_aliases))}
        ids = {r.user_id: (r.name, r.domain) for r in conn.execute(select(identities))}
        hosts, static_ips = {}, {}
        for r in conn.execute(select(assets)):
            hosts[r.host_name] = r.host_id
            if r.static_ip:
                static_ips[r.static_ip] = r.host_name
        leases = LeaseTable()
        q = select(ip_leases)
        if start and end:
            q = q.where(ip_leases.c.start < end, ip_leases.c.end > start)
        for r in conn.execute(q):
            leases.add(r.ip, as_utc(r.start), as_utc(r.end), r.host_name)
        return cls(aliases, ids, hosts, static_ips, leases)

    # -- users ---------------------------------------------------------------
    def resolve_user(self, name, domain=None, sid=None) -> dict:
        if sid and (uid := self.aliases.get(str(sid).lower())):
            return self._user(uid, "sid")
        if not name:
            self.stats["user:none"] += 1
            return {"labels.user_resolution": "none"}
        name = str(name).strip()
        if "\\" in name:
            domain, name = name.split("\\", 1)
        candidates = []
        if domain:
            candidates.append(f"{domain}\\{name}".lower())
        candidates.append(name.lower())
        for c in candidates:
            if uid := self.aliases.get(c):
                return self._user(uid, "alias")
        self.stats["user:unresolved"] += 1
        bare = name.split("@", 1)[0].lower()
        return {"user.name": bare, "user.domain": (domain or "").upper() or None,
                "labels.user_resolution": "unresolved"}

    def _user(self, uid: str, how: str) -> dict:
        self.stats[f"user:{how}"] += 1
        name, domain = self.ids.get(uid, (None, None))
        return {"user.id": uid, "user.name": name, "user.domain": domain, "labels.user_resolution": how}

    # -- hosts ---------------------------------------------------------------
    def resolve_host(self, name, row: dict, ip_fields: list[str], ts: datetime) -> dict:
        if name:
            host = _hostname(name)
            self.stats["host:native"] += 1
            return {"host.name": host, "host.id": self.hosts.get(host), "labels.host_resolution": "native"}
        saw_internal = False
        for field in ip_fields:
            ip = row.get(field)
            if not ip or not self.net.is_internal(ip):
                continue
            saw_internal = True
            if host := self.leases.host_at(ip, ts):
                self.stats["host:lease"] += 1
                return {"host.name": host, "host.id": self.hosts.get(host), "labels.host_resolution": "lease"}
            if host := self.static_ips.get(ip):
                self.stats["host:static"] += 1
                return {"host.name": host, "host.id": self.hosts.get(host), "labels.host_resolution": "static"}
        how = "unresolved" if saw_internal else "none"
        self.stats[f"host:{how}"] += 1
        return {"labels.host_resolution": how}
