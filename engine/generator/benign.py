"""Benign baseline: a working week for every user, workstation and server."""
from __future__ import annotations

import random
from datetime import date, datetime, time, timedelta, timezone

from engine.generator.emitters import Sink
from engine.generator.world import (BROWSERS, CORP_EGRESS_IP, DHCP_POOL, DOMAIN, INTERNAL_DNS, WEB_DOMAINS, Host,
                                    User, World, det_ip)

SYS = "NT AUTHORITY\\SYSTEM"
WIN = "C:\\Windows\\System32"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16"
APPS = {
    "outlook": (f"{OFFICE}\\OUTLOOK.EXE", '"{img}"'),
    "excel": (f"{OFFICE}\\EXCEL.EXE", '"{img}" /dde'),
    "winword": (f"{OFFICE}\\WINWORD.EXE", '"{img}" /n "C:\\Users\\{user}\\Documents\\report.docx"'),
    "teams": ("C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", '"{img}" --processStart'),
    "onedrive": ("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", '"{img}" /background'),
    "notepad": (f"{WIN}\\notepad.exe", '"{img}" C:\\Users\\{user}\\Desktop\\notes.txt'),
    "code": ("C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", '"{img}"'),
    "git": ("C:\\Program Files\\Git\\cmd\\git.exe", "git pull --rebase origin main"),
    "python": ("C:\\Program Files\\Python312\\python.exe", "python -m pytest tests"),
}
DEPT_APPS = {
    "Finance": ["outlook", "excel", "excel", "teams", "winword"],
    "Engineering": ["outlook", "code", "git", "python", "teams", "code"],
    "Sales": ["outlook", "teams", "excel", "winword"],
    "HR": ["outlook", "winword", "teams", "excel"],
    "IT": ["outlook", "teams", "code", "notepad"],
}
ADMIN_COMMANDS = [
    ("powershell.exe", "powershell.exe -NoProfile -Command Get-Service | Where-Object Status -eq 'Stopped'"),
    ("powershell.exe", "powershell.exe -Command Get-ADUser -Filter * -SearchBase 'OU=Staff,DC=corp,DC=local'"),
    ("cmd.exe", "cmd.exe /c ipconfig /all"),
    ("cmd.exe", "cmd.exe /c ping -n 2 fs01"),
    ("powershell.exe", "powershell.exe -Command Test-NetConnection sql01 -Port 1433"),
]
AWS_CALLS = [  # (eventSource, eventName, readOnly, weight)
    ("s3.amazonaws.com", "ListBuckets", True, 4), ("s3.amazonaws.com", "GetObject", True, 10),
    ("s3.amazonaws.com", "PutObject", False, 4), ("ec2.amazonaws.com", "DescribeInstances", True, 8),
    ("sts.amazonaws.com", "GetCallerIdentity", True, 3), ("iam.amazonaws.com", "ListRoles", True, 2),
    ("lambda.amazonaws.com", "Invoke", False, 3), ("logs.amazonaws.com", "FilterLogEvents", True, 4),
    ("cloudformation.amazonaws.com", "DescribeStacks", True, 2), ("ecr.amazonaws.com", "GetAuthorizationToken",
                                                                   True, 2),
]
URL_PATHS = ["/", "/index.html", "/api/v1/items", "/search?q=quarterly+report", "/static/app.js", "/login",
             "/owa/", "/v2/feed", "/assets/logo.png", "/en/latest/", "/messages", "/calendar"]


def at(day: date, hours: float) -> datetime:
    return datetime.combine(day, time(0), tzinfo=timezone.utc) + timedelta(hours=hours)


class DhcpState:
    """Tracks which pool address each workstation holds."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.free = [str(ip) for ip in list(DHCP_POOL.hosts())[16:]]
        rng.shuffle(self.free)
        self.held: dict[str, str] = {}

    def boot(self, sink: Sink, host: Host, ts: datetime) -> str:
        current = self.held.get(host.name)
        if current and self.rng.random() < 0.05:   # occasionally the host gets a new address
            sink.dhcp(ts - timedelta(seconds=5), 12, current, host.name, host.mac)
            self.free.append(current)
            current = None
        if current is None:
            current = self.free.pop(0)
            self.held[host.name] = current
            sink.dhcp(ts, 10, current, host.name, host.mac)
        else:
            sink.dhcp(ts, 11, current, host.name, host.mac)
        return current


class Baseline:
    def __init__(self, world: World, sink: Sink, rng: random.Random):
        self.world, self.sink, self.rng = world, sink, rng
        self.dhcp = DhcpState(rng)
        self.domains = [d for d in WEB_DOMAINS]
        self.weights = [d[1] for d in WEB_DOMAINS]
        self.on_intervals: dict[str, list[tuple[datetime, datetime]]] = {}
        self.ws_ip: dict[tuple[str, date], str] = {}

    # ------------------------------------------------------------------ helpers
    def _jitter(self, mean: float, sd: float) -> float:
        return self.rng.gauss(mean, sd)

    def _proc(self, ts, host, user: User, key, parent=("explorer.exe", f"C:\\Windows\\explorer.exe")):
        img_t, cmd_t = APPS[key]
        img = img_t.format(user=user.sam)
        self.sink.process(ts, host, f"{DOMAIN}\\{user.sam}", img, cmd_t.format(img=img, user=user.sam), parent[1])

    def browse(self, ts: datetime, user: User, ip: str, *, proxy_user: str | None = None) -> None:
        reg, _, subs, mime = self.rng.choices(self.domains, self.weights)[0]
        sub = self.rng.choice(subs)
        fqdn = f"{sub}.{reg}" if sub else reg
        dst = det_ip(fqdn)
        if self.rng.random() < 0.6:
            self.sink.dns(ts - timedelta(milliseconds=self.rng.randint(5, 80)), ip, fqdn, [dst])
        resp = int(self.rng.lognormvariate(9.5, 1.3))
        self.sink.conn(ts, ip, dst, 443, service="ssl", orig_bytes=self.rng.randint(400, 4000), resp_bytes=resp,
                       duration=self.rng.uniform(0.05, 20))
        status = self.rng.choices([200, 304, 302, 404, 403], [80, 8, 6, 4, 2])[0]
        ua = BROWSERS[user.browser][1]
        self.sink.proxy(ts, ip, proxy_user or user.sam, "GET", f"https://{fqdn}{self.rng.choice(URL_PATHS)}", status,
                        resp if status != 403 else 0, dst if status != 403 else None, mime, ua)

    # ------------------------------------------------------------------ per-day activity
    def run(self, start: date, days: int) -> None:
        for d in range(days):
            day = start + timedelta(days=d)
            weekend = day.weekday() >= 5
            for server in self.world.servers:
                self.server_day(server, day)
            for user in self.world.humans:
                if weekend and self.rng.random() > 0.08:
                    continue
                self.user_day(user, day, short=weekend)
            self.service_accounts(day)

    def user_day(self, user: User, day: date, short: bool = False) -> None:
        rng, sink = self.rng, self.sink
        ws = self.world.hosts[user.workstation]
        begin = at(day, max(6.5, self._jitter(8.6, 0.6)))
        end = begin + timedelta(hours=self._jitter(3 if short else 9, 0.7))
        self.on_intervals.setdefault(ws.name, []).append((begin - timedelta(minutes=3), end + timedelta(minutes=2)))
        ip = self.dhcp.boot(sink, ws, begin - timedelta(minutes=2))
        self.ws_ip[(ws.name, day)] = ip
        dc = rng.choice(["DC01", "DC02"])
        dc_ip = self.world.hosts[dc].static_ip

        # Morning logon (sometimes after a typo), Kerberos at the DC, SMB to the file server.
        t = begin
        if rng.random() < 0.06:
            for _ in range(rng.randint(1, 2)):
                sink.win_auth(t, 4625, ws.name, user.sam, "S-1-0-0", 2, "127.0.0.1", status="0xC000006D",
                              sub_status="0xC000006A", package="Negotiate")
                t += timedelta(seconds=rng.uniform(3, 12))
        name_form = user.sam if rng.random() < 0.8 else user.upn
        sink.win_auth(t, 4624, ws.name, name_form, user.sid, rng.choice([2, 2, 2, 11]), "127.0.0.1",
                      package="Negotiate")
        sink.win_auth(t + timedelta(milliseconds=300), 4624, dc, user.sam, user.sid, 3, ip)
        sink.conn(t, ip, dc_ip, 88, service="krb_tcp", orig_bytes=1500, resp_bytes=1700)
        sink.conn(t + timedelta(seconds=1), ip, dc_ip, 389, service="ldap", orig_bytes=900, resp_bytes=4200)
        sink.process(t + timedelta(seconds=2), ws.name, f"{DOMAIN}\\{user.sam}", "C:\\Windows\\explorer.exe",
                     "C:\\Windows\\Explorer.EXE", f"{WIN}\\userinit.exe")
        for i, key in enumerate(["onedrive", "teams", "outlook"]):
            self._proc(t + timedelta(seconds=10 + 7 * i), ws.name, user, key)
        browser_img = BROWSERS[user.browser][0]
        sink.process(t + timedelta(seconds=40), ws.name, f"{DOMAIN}\\{user.sam}", browser_img, f'"{browser_img}"',
                     "C:\\Windows\\explorer.exe")
        for q in rng.sample(INTERNAL_DNS[:5], 3):
            sink.dns(t + timedelta(seconds=rng.uniform(1, 30)), ip, q, [self.world.hosts["DC01"].static_ip])

        # Through the day: browsing, app launches, file-server access, unlocks.
        hours = (end - begin).total_seconds() / 3600
        n_browse = int(rng.gauss(user.browse_rate * hours, 4))
        for _ in range(max(0, n_browse)):
            self.browse(begin + timedelta(seconds=rng.uniform(60, (end - begin).total_seconds())), user, ip,
                        proxy_user=user.sam if rng.random() < 0.9 else f"{DOMAIN}\\{user.sam}")
        for _ in range(rng.randint(3, 9)):
            self._proc(begin + timedelta(seconds=rng.uniform(300, (end - begin).total_seconds())), ws.name, user,
                       rng.choice(DEPT_APPS[user.department]))
        fs = self.world.hosts["FS01"]
        for _ in range(rng.randint(1, 5)):
            ts = begin + timedelta(seconds=rng.uniform(600, (end - begin).total_seconds()))
            sink.win_auth(ts, 4624, "FS01", user.sam, user.sid, 3, ip)
            sink.conn(ts, ip, fs.static_ip, 445, service="smb", orig_bytes=rng.randint(2_000, 400_000),
                      resp_bytes=rng.randint(10_000, 8_000_000), duration=rng.uniform(1, 120))
        for _ in range(rng.randint(0, 3)):
            sink.win_auth(begin + timedelta(seconds=rng.uniform(1800, (end - begin).total_seconds())), 4624,
                          ws.name, user.sam, user.sid, 7, "127.0.0.1", package="Negotiate")
        if rng.random() < 0.15:
            sink.dns(begin + timedelta(seconds=rng.uniform(60, 3600)), ip, "wpad.corp.local", None, rcode="NXDOMAIN")

        if user.is_admin:
            self.admin_work(user, ws, ip, begin, end)
        if user.aws:
            self.cloud_work(user, begin, end)
        self.workstation_metrics(ws, begin, end)
        sink.win_auth(end, 4634, ws.name, user.sam, user.sid, 2)

    def admin_work(self, user: User, ws: Host, ip: str, begin: datetime, end: datetime) -> None:
        rng, sink = self.rng, self.sink
        jump = self.world.hosts["JUMP01"]
        ts = begin + timedelta(minutes=rng.uniform(20, 90))
        sink.win_auth(ts, 4624, "JUMP01", user.sam, user.sid, 10, ip)
        sink.win_auth(ts + timedelta(milliseconds=50), 4672, "JUMP01", user.sam, user.sid)
        sink.conn(ts, ip, jump.static_ip, 3389, service="rdp", orig_bytes=rng.randint(10**5, 10**6),
                  resp_bytes=rng.randint(10**6, 10**7), duration=rng.uniform(300, 3600))
        for server in rng.sample(["FS01", "SQL01", "APP01", "DC01"], rng.randint(1, 3)):
            t2 = ts + timedelta(minutes=rng.uniform(2, 60))
            sink.win_auth(t2, 4624, server, user.sam, user.sid, 3, jump.static_ip)
            sink.win_auth(t2 + timedelta(milliseconds=40), 4672, server, user.sam, user.sid)
        for _ in range(rng.randint(1, 4)):
            name, cmd = rng.choice(ADMIN_COMMANDS)
            img = f"{WIN}\\WindowsPowerShell\\v1.0\\{name}" if name.startswith("powershell") else f"{WIN}\\{name}"
            sink.process(begin + timedelta(seconds=rng.uniform(600, (end - begin).total_seconds())), ws.name,
                         f"{DOMAIN}\\{user.sam}", img, cmd, "C:\\Windows\\explorer.exe")

    def cloud_work(self, user: User, begin: datetime, end: datetime) -> None:
        rng = self.rng
        role = "Developer" if user.department == "Engineering" else "Admin"
        for _ in range(rng.randint(5, 40)):
            src, name, ro, _ = rng.choices(AWS_CALLS, [c[3] for c in AWS_CALLS])[0]
            err = ("AccessDenied", f"User is not authorized to perform: {src.split('.')[0]}:{name}") \
                if rng.random() < 0.03 else None
            self.sink.cloudtrail(begin + timedelta(seconds=rng.uniform(0, (end - begin).total_seconds())), user.sam,
                                 src, name, rng.choices(["us-east-1", "eu-west-1", "ap-south-1"], [7, 2, 1])[0],
                                 CORP_EGRESS_IP, ro, "aws-cli/2.17.20 Python/3.11.9 Windows/10 exe/AMD64",
                                 error=err, assumed_role=role if rng.random() < 0.5 else None)

    def workstation_metrics(self, ws: Host, begin: datetime, end: datetime, interval: int = 600) -> None:
        t = begin.replace(minute=(begin.minute // 10) * 10, second=0, microsecond=0) + timedelta(minutes=10)
        while t < end:
            self.sink.metric(t, ws.name, self.rng.uniform(3, 35), self.rng.uniform(35, 75),
                             self.rng.randint(10**5, 5 * 10**7), self.rng.randint(10**4, 5 * 10**6), interval)
            t += timedelta(seconds=interval)

    def server_day(self, server: Host, day: date, interval: int = 600) -> None:
        rng = self.rng
        base_cpu = {"database": 30, "domain_controller": 15, "file_server": 12, "web_server": 25}.get(
            server.asset_class, 10)
        for i in range(86400 // interval):
            t = at(day, i * interval / 3600)
            busy = 1.6 if 8 <= t.hour < 18 and day.weekday() < 5 else 0.7
            self.sink.metric(t, server.name, max(1, rng.gauss(base_cpu * busy, 4)), rng.uniform(40, 80),
                             rng.randint(10**6, 10**8), rng.randint(10**6, 10**8), interval)
        # Background services, once a day per server.
        self.sink.process(at(day, rng.uniform(0, 2)), server.name, SYS, f"{WIN}\\svchost.exe",
                          f"{WIN}\\svchost.exe -k netsvcs -p -s Schedule", f"{WIN}\\services.exe")
        self.sink.process(at(day, rng.uniform(2, 3)), server.name, SYS, f"{WIN}\\taskhostw.exe",
                          "taskhostw.exe Install $(Arg0)", f"{WIN}\\svchost.exe")
        if server.asset_class == "web_server":  # Internet-facing: steady inbound HTTPS
            for _ in range(rng.randint(200, 400)):
                ts = at(day, rng.uniform(0, 24))
                client = det_ip(f"client{rng.randint(1, 5000)}", "web")
                self.sink.conn(ts, client, server.static_ip, 443, service="ssl", orig_bytes=rng.randint(500, 5000),
                               resp_bytes=rng.randint(2_000, 300_000), duration=rng.uniform(0.1, 5))

    def service_accounts(self, day: date) -> None:
        sink, rng = self.sink, self.rng
        backup = self.world.user("svc_backup")
        for server in ("FS01", "SQL01"):
            ts = at(day, 1 + rng.uniform(0, 0.5))
            sink.win_auth(ts, 4624, server, backup.sam, backup.sid, 5)
            sink.win_auth(ts + timedelta(milliseconds=30), 4672, server, backup.sam, backup.sid,
                          privileges="SeBackupPrivilege SeRestorePrivilege")
            sink.process(ts + timedelta(seconds=5), server, f"{DOMAIN}\\{backup.sam}",
                         "C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe",
                         '"Veeam.EndPoint.Service.exe" -job nightly', f"{WIN}\\services.exe")
        sql = self.world.user("svc_sql")
        sink.win_auth(at(day, 0.05), 4624, "SQL01", sql.sam, sql.sid, 5)
        web = self.world.user("svc_web")
        sink.win_auth(at(day, 0.07), 4624, "WEB01", web.sam, web.sid, 5)
