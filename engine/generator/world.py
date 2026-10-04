"""Synthetic enterprise: users, hosts, network layout and the internet they talk to."""
from __future__ import annotations

import hashlib
import ipaddress
import random
from dataclasses import dataclass, field

DOMAIN = "CORP"
FQDN = "corp.local"
DOMAIN_SID = "S-1-5-21-3623811015-3361044348-30300820"
AWS_ACCOUNT = "123456789012"
CORP_EGRESS_IP = "192.0.2.10"     # NAT address seen by cloud providers
DHCP_POOL = ipaddress.ip_network("10.10.16.0/20")

DEPARTMENTS = {  # name: (code, weight, aws_access, browse_rate_per_hour)
    "Finance": ("FIN", 3, False, 10),
    "Engineering": ("ENG", 4, True, 14),
    "Sales": ("SAL", 3, False, 16),
    "HR": ("HR", 1, False, 9),
    "IT": ("IT", 2, True, 12),
}
FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj",
         "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter", "wendy", "arjun", "priya", "rahul",
         "sneha", "vikram", "ananya", "kiran", "meera", "rohan", "divya", "li", "wei", "yuki", "hana", "omar",
         "fatima", "lucas", "sofia", "mateo", "elena"]
LAST = ["smith", "jones", "patel", "sharma", "kumar", "garcia", "nguyen", "kim", "chen", "wang", "singh", "khan",
        "brown", "taylor", "wilson", "martin", "lee", "walker", "hall", "young", "iyer", "rao", "das", "mehta"]

SERVERS = [  # name, ip, asset_class, os
    ("DC01", "10.10.1.10", "domain_controller", "Windows Server 2022"),
    ("DC02", "10.10.1.11", "domain_controller", "Windows Server 2022"),
    ("FS01", "10.10.1.20", "file_server", "Windows Server 2019"),
    ("SQL01", "10.10.1.30", "database", "Windows Server 2019"),
    ("APP01", "10.10.1.40", "application_server", "Windows Server 2022"),
    ("WEB01", "10.10.5.50", "web_server", "Windows Server 2022"),
    ("JUMP01", "10.10.1.60", "jump_host", "Windows Server 2022"),
]

# (registered domain, weight, subdomains, typical mime) — weights roughly Zipf-like.
WEB_DOMAINS = [
    ("google.com", 40, ["www", "mail", "docs", "apis"], "text/html"),
    ("microsoft.com", 25, ["www", "login", "go"], "text/html"),
    ("office.com", 30, ["www", "outlook", "teams"], "application/json"),
    ("office365.com", 18, ["outlook", "substrate"], "application/json"),
    ("live.com", 10, ["login"], "text/html"),
    ("github.com", 12, ["", "api", "codeload"], "application/json"),
    ("slack.com", 9, ["app", "files"], "application/json"),
    ("zoom.us", 7, ["", "us02web"], "text/html"),
    ("salesforce.com", 8, ["login", "corp"], "text/html"),
    ("linkedin.com", 6, ["www"], "text/html"),
    ("amazon.com", 5, ["www"], "text/html"),
    ("amazonaws.com", 10, ["s3", "ec2.us-east-1", "sts"], "application/json"),
    ("cloudflare.com", 4, ["www", "cdnjs"], "application/javascript"),
    ("akamaihd.net", 8, ["a248.e", "static"], "image/png"),
    ("wikipedia.org", 4, ["en"], "text/html"),
    ("stackoverflow.com", 6, ["", "cdn.sstatic"], "text/html"),
    ("youtube.com", 5, ["www", "i"], "video/mp4"),
    ("bbc.co.uk", 3, ["www"], "text/html"),
    ("zscaler.net", 2, ["gateway"], "application/json"),
    ("windowsupdate.com", 6, ["download", "ctldl"], "application/octet-stream"),
    ("digicert.com", 3, ["ocsp", "crl3"], "application/ocsp-response"),
    ("adobe.com", 3, ["www", "acrobat"], "text/html"),
    ("atlassian.net", 7, ["corp"], "application/json"),
    ("npmjs.org", 3, ["registry"], "application/json"),
    ("pypi.org", 3, ["", "files"], "application/octet-stream"),
]
INTERNAL_DNS = ["dc01.corp.local", "fs01.corp.local", "sql01.corp.local", "app01.corp.local",
                "_ldap._tcp.dc._msdcs.corp.local", "wpad.corp.local", "intranet.corp.local"]
BROWSERS = {
    "chrome": ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/128.0.0.0 Safari/537.36"),
    "edge": ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.2739.42"),
}


def det_ip(name: str, salt: str = "") -> str:
    """Deterministic public-looking IPv4 for an external name."""
    h = hashlib.sha256(f"{salt}{name}".encode()).digest()
    first = [13, 20, 23, 34, 35, 40, 52, 54, 104, 142, 151, 157, 172, 185][h[0] % 14]
    if first == 172:
        first = 173  # stay out of 172.16/12
    return f"{first}.{h[1]}.{h[2]}.{max(1, h[3] % 254)}"


def det_hex(*parts: object, n: int = 64) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:n]


@dataclass
class User:
    sam: str
    sid: str
    display: str
    department: str
    kind: str = "human"            # human | service | builtin
    is_admin: bool = False
    aws: bool = False
    workstation: str | None = None
    browser: str = "chrome"
    browse_rate: int = 10

    @property
    def upn(self) -> str:
        return f"{self.sam}@{FQDN}"


@dataclass
class Host:
    name: str
    asset_class: str
    business_unit: str
    os: str
    static_ip: str | None = None
    owner: str | None = None
    mac: str = ""

    @property
    def fqdn(self) -> str:
        return f"{self.name}.{FQDN}"

    @property
    def host_id(self) -> str:
        return det_hex("host", self.name, n=32)


@dataclass
class World:
    seed: int
    users: list[User] = field(default_factory=list)
    service_accounts: list[User] = field(default_factory=list)
    builtin: list[User] = field(default_factory=list)
    hosts: dict[str, Host] = field(default_factory=dict)

    @property
    def humans(self) -> list[User]:
        return [u for u in self.users if u.kind == "human"]

    @property
    def admins(self) -> list[User]:
        return [u for u in self.users if u.is_admin]

    @property
    def servers(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.static_ip]

    def user(self, sam: str) -> User:
        return next(u for u in self.users + self.service_accounts if u.sam == sam)

    def inventory(self) -> tuple[list[dict], list[dict]]:
        identities = []
        for u in self.users + self.service_accounts + self.builtin:
            identities.append({
                "user_id": u.sid, "name": u.sam, "domain": DOMAIN if u.kind != "builtin" else "NT AUTHORITY",
                "upn": u.upn if u.kind != "builtin" else None, "display_name": u.display,
                "department": u.department, "kind": u.kind, "is_admin": u.is_admin,
                "aliases": [f"nt authority\\{u.sam}"] if u.kind == "builtin" else [],
            })
        assets = [{
            "host_name": h.name.lower(), "host_id": h.host_id, "fqdn": h.fqdn.lower(), "asset_class": h.asset_class,
            "business_unit": h.business_unit, "os": h.os, "static_ip": h.static_ip, "owner_user_id": h.owner,
        } for h in self.hosts.values()]
        return identities, assets


def build_world(seed: int, n_users: int) -> World:
    rng = random.Random(seed)
    world = World(seed=seed)
    names = {(f, l) for f in FIRST for l in LAST}
    picked = rng.sample(sorted(names), n_users)
    depts = list(DEPARTMENTS)
    weights = [DEPARTMENTS[d][1] for d in depts]
    counters: dict[str, int] = {}
    for i, (first, last) in enumerate(picked):
        dept = depts[i % len(depts)] if i < len(depts) else rng.choices(depts, weights)[0]
        code, _, aws, rate = DEPARTMENTS[dept]
        counters[code] = counters.get(code, 0) + 1
        ws = Host(name=f"WS-{code}-{counters[code]:03d}", asset_class="workstation", business_unit=dept,
                  os="Windows 11 Enterprise", mac=det_hex("mac", first, last, n=12).upper())
        user = User(sam=f"{first[0]}{last}" if rng.random() < 0.7 else f"{first}.{last}",
                    sid=f"{DOMAIN_SID}-{1104 + i}", display=f"{first.title()} {last.title()}", department=dept,
                    is_admin=dept == "IT", aws=aws and rng.random() < 0.8, workstation=ws.name,
                    browser=rng.choice(list(BROWSERS)), browse_rate=rate)
        if any(u.sam == user.sam for u in world.users):
            user.sam = f"{user.sam}{i}"
        ws.owner = user.sid
        world.users.append(user)
        world.hosts[ws.name] = ws
    for i, (sam, display) in enumerate([("svc_backup", "Backup Service"), ("svc_sql", "SQL Service"),
                                        ("svc_web", "IIS App Pool")]):
        world.service_accounts.append(User(sam=sam, sid=f"{DOMAIN_SID}-{1050 + i}", display=display,
                                           department="IT", kind="service"))
    world.builtin = [User(sam="system", sid="S-1-5-18", display="Local System", department="", kind="builtin"),
                     User(sam="local service", sid="S-1-5-19", display="Local Service", department="", kind="builtin"),
                     User(sam="network service", sid="S-1-5-20", display="Network Service", department="",
                          kind="builtin")]
    for name, ip, cls, os_ in SERVERS:
        world.hosts[name] = Host(name=name, asset_class=cls, business_unit="IT", os=os_, static_ip=ip,
                                 mac=det_hex("mac", name, n=12).upper())
    return world
