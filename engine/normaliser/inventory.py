"""Identity directory + asset inventory loader (LoadInventory command).

Expected objects under the inventory URI:
    identities.json  [{user_id, name, domain, upn, display_name, department, kind, is_admin, aliases: [...]}]
    assets.json      [{host_name, host_id, fqdn, asset_class, business_unit, os, static_ip, owner_user_id}]
"""
from __future__ import annotations

from sqlalchemy.engine import Connection

from engine.common.db import assets, identities, identity_aliases, upsert, utcnow
from engine.common.events import InventoryLoaded
from engine.common.storage import ObjectStore


def aliases_for(ident: dict) -> set[str]:
    name, domain = ident["name"].lower(), (ident.get("domain") or "").lower()
    out = {name, ident["user_id"].lower(), *(a.lower() for a in ident.get("aliases", []))}
    if domain:
        out.add(f"{domain}\\{name}")
    if ident.get("upn"):
        out.add(ident["upn"].lower())
    return out


def load_inventory(conn: Connection, store: ObjectStore, uri: str) -> InventoryLoaded:
    prefix = uri.rstrip("/")
    idents = store.get_json(f"{prefix}/identities.json")
    hosts = store.get_json(f"{prefix}/assets.json")
    now = utcnow()
    n_alias = 0
    for ident in idents:
        upsert(conn, identities, {"user_id": ident["user_id"]}, {
            "name": ident["name"].lower(), "domain": ident.get("domain"), "upn": ident.get("upn"),
            "display_name": ident.get("display_name"), "department": ident.get("department"),
            "kind": ident.get("kind", "human"), "is_admin": bool(ident.get("is_admin")), "updated_at": now})
        for alias in aliases_for(ident):
            upsert(conn, identity_aliases, {"alias": alias}, {"user_id": ident["user_id"]})
            n_alias += 1
    for a in hosts:
        upsert(conn, assets, {"host_name": a["host_name"].lower()}, {
            "host_id": a["host_id"], "fqdn": a.get("fqdn"), "asset_class": a["asset_class"],
            "business_unit": a.get("business_unit"), "os": a.get("os"), "static_ip": a.get("static_ip"),
            "owner_user_id": a.get("owner_user_id"), "updated_at": now})
    return InventoryLoaded(uri=uri, identities=len(idents), aliases=n_alias, assets=len(hosts),
                           static_leases=sum(1 for a in hosts if a.get("static_ip")))
