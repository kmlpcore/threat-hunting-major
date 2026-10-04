"""Native-format record builders, one per log source.

Records are written the way the real products write them (Windows event JSON,
Sysmon, Zeek JSON, Squid text lines, CloudTrail JSON, DHCP audit CSV), including
per-sensor clock skew, so the normaliser has real work to do.
"""
from __future__ import annotations

import random
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from engine.generator.world import AWS_ACCOUNT, DOMAIN, FQDN, det_hex

# Seconds each sensor's clock is off from true time (native = true + skew).
# The ECS mappings carry the matching correction (clock_skew_seconds = -skew).
SENSOR_SKEW = {"zeek_conn": -2.5, "zeek_dns": -2.5, "proxy": 7.0}
SOURCES = ("dhcp", "windows_security", "sysmon", "zeek_conn", "zeek_dns", "proxy", "cloudtrail", "host_metrics")


@dataclass
class Entry:
    ts: datetime          # true time
    seq: int
    record: dict
    scenario: str | None


@dataclass
class Sink:
    rng: random.Random
    entries: dict[str, list[Entry]] = field(default_factory=lambda: defaultdict(list))
    scenario: str | None = None   # set while a scenario is emitting
    _seq: int = 0
    _record_ids: dict[str, int] = field(default_factory=lambda: defaultdict(lambda: 1_000_000))

    def add(self, source: str, ts: datetime, record: dict) -> Entry:
        self._seq += 1
        e = Entry(ts, self._seq, record, self.scenario)
        self.entries[source].append(e)
        return e

    def native_ts(self, source: str, ts: datetime) -> datetime:
        return ts + timedelta(seconds=SENSOR_SKEW.get(source, 0.0))

    def record_id(self, computer: str) -> int:
        self._record_ids[computer] += 1
        return self._record_ids[computer]

    def guid(self) -> str:
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128))).upper() + "}"

    def zeek_uid(self) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return "C" + "".join(self.rng.choice(alphabet) for _ in range(17))

    # ------------------------------------------------------------------ Windows Security
    def win_auth(self, ts: datetime, event_id: int, computer: str, user: str | None, user_sid: str | None,
                 logon_type: int | None = None, ip: str | None = None, domain: str = DOMAIN,
                 status: str | None = None, sub_status: str | None = None, package: str = "Kerberos",
                 privileges: str | None = None, extra: dict | None = None) -> Entry:
        rec = {
            "EventID": event_id, "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": _iso(ts), "Computer": f"{computer}.{FQDN}", "EventRecordID": self.record_id(computer),
        }
        if event_id == 4672:
            rec.update({"SubjectUserName": user, "SubjectDomainName": domain, "SubjectUserSid": user_sid,
                        "PrivilegeList": privileges or "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege"})
        else:
            rec.update({"TargetUserName": user, "TargetDomainName": domain, "TargetUserSid": user_sid or "S-1-0-0"})
        if logon_type is not None:
            rec["LogonType"] = logon_type
            rec["IpAddress"] = ip or "-"
            rec["IpPort"] = str(self.rng.randint(49152, 65535)) if ip and ip != "127.0.0.1" else "0"
            rec["AuthenticationPackageName"] = package
            rec["WorkstationName"] = computer if logon_type in (2, 7, 11) else "-"
        if status:
            rec["Status"], rec["SubStatus"] = status, sub_status or status
        if extra:
            rec.update(extra)
        return self.add("windows_security", ts, rec)

    # ------------------------------------------------------------------ Sysmon
    def process(self, ts: datetime, computer: str, user: str, image: str, command_line: str,
                parent_image: str, parent_cmd: str | None = None, integrity: str = "Medium",
                hash_seed: str | None = None) -> Entry:
        sha = det_hex("sha256", hash_seed or image.lower())
        md5 = det_hex("md5", hash_seed or image.lower(), n=32)
        rec = {
            "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
            "Computer": f"{computer}.{FQDN}", "EventRecordID": self.record_id(f"sysmon:{computer}"),
            "ProcessGuid": self.guid(), "ProcessId": self.rng.randint(1000, 30000), "Image": image,
            "CommandLine": command_line, "CurrentDirectory": "C:\\Windows\\system32\\", "User": user,
            "IntegrityLevel": integrity, "Hashes": f"MD5={md5.upper()},SHA256={sha.upper()}",
            "ParentProcessGuid": self.guid(), "ParentProcessId": self.rng.randint(500, 30000),
            "ParentImage": parent_image, "ParentCommandLine": parent_cmd or f'"{parent_image}"',
        }
        return self.add("sysmon", ts, rec)

    # ------------------------------------------------------------------ Zeek
    def conn(self, ts: datetime, src: str, dst: str, dport: int, proto: str = "tcp", service: str | None = None,
             orig_bytes: int = 0, resp_bytes: int = 0, duration: float = 0.5, state: str = "SF") -> Entry:
        n = self.native_ts("zeek_conn", ts)
        rec = {
            "ts": round(n.timestamp(), 6), "uid": self.zeek_uid(), "id.orig_h": src,
            "id.orig_p": self.rng.randint(49152, 65535), "id.resp_h": dst, "id.resp_p": dport, "proto": proto,
            "service": service, "duration": round(duration, 6), "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
            "conn_state": state, "local_orig": src.startswith("10."), "local_resp": dst.startswith("10."),
            "missed_bytes": 0, "history": "ShADadFf" if state == "SF" else "S",
            "orig_pkts": max(1, orig_bytes // 1200), "resp_pkts": max(1, resp_bytes // 1200),
        }
        if service is None:
            del rec["service"]
        return self.add("zeek_conn", ts, rec)

    def dns(self, ts: datetime, src: str, query: str, answers: list[str] | None, qtype: str = "A",
            rcode: str = "NOERROR", resolver: str = "10.10.1.10") -> Entry:
        n = self.native_ts("zeek_dns", ts)
        rec = {
            "ts": round(n.timestamp(), 6), "uid": self.zeek_uid(), "id.orig_h": src,
            "id.orig_p": self.rng.randint(49152, 65535), "id.resp_h": resolver, "id.resp_p": 53, "proto": "udp",
            "trans_id": self.rng.randint(1, 65535), "query": query, "qclass": 1, "qclass_name": "C_INTERNET",
            "qtype_name": qtype, "rcode_name": rcode, "AA": False, "RD": True, "RA": True, "rejected": False,
        }
        if answers:
            rec["answers"] = answers
            rec["TTLs"] = [float(self.rng.choice([60, 300, 3600]))] * len(answers)
        return self.add("zeek_dns", ts, rec)

    # ------------------------------------------------------------------ Squid
    def proxy(self, ts: datetime, client_ip: str, user: str | None, method: str, url: str, status: int,
              bytes_resp: int, server_ip: str | None, mime: str, user_agent: str, bytes_req: int = 0,
              elapsed_ms: int | None = None) -> Entry:
        n = self.native_ts("proxy", ts)
        code = "TCP_DENIED" if status == 403 else ("TCP_MISS" if self.rng.random() < 0.8 else "TCP_TUNNEL")
        hier = "HIER_NONE" if status == 403 else "HIER_DIRECT"
        line = (f"{n.timestamp():.3f} {elapsed_ms if elapsed_ms is not None else self.rng.randint(20, 900):>6} "
                f"{client_ip} {code}/{status:03d} {bytes_resp} {method} {url} {user or '-'} "
                f"{hier}/{server_ip or '-'} {mime} \"{user_agent}\" {bytes_req or self.rng.randint(300, 1800)}")
        return self.add("proxy", ts, {"message": line})

    # ------------------------------------------------------------------ CloudTrail
    def cloudtrail(self, ts: datetime, user: str, event_source: str, event_name: str, region: str,
                   source_ip: str, read_only: bool, user_agent: str, error: tuple[str, str] | None = None,
                   assumed_role: str | None = None, request: dict | None = None) -> Entry:
        if assumed_role:
            identity = {"type": "AssumedRole", "principalId": f"AROA{det_hex(user, n=16).upper()}:{user}",
                        "arn": f"arn:aws:sts::{AWS_ACCOUNT}:assumed-role/{assumed_role}/{user}",
                        "accountId": AWS_ACCOUNT}
        else:
            identity = {"type": "IAMUser", "principalId": f"AIDA{det_hex(user, n=16).upper()}",
                        "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{user}", "accountId": AWS_ACCOUNT,
                        "userName": user}
        rec = {
            "eventVersion": "1.09", "userIdentity": identity, "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": event_source, "eventName": event_name, "awsRegion": region,
            "sourceIPAddress": source_ip, "userAgent": user_agent, "requestParameters": request,
            "responseElements": None, "requestID": str(uuid.UUID(int=self.rng.getrandbits(128))),
            "eventID": str(uuid.UUID(int=self.rng.getrandbits(128))), "readOnly": read_only,
            "eventType": "AwsApiCall", "managementEvent": True, "recipientAccountId": AWS_ACCOUNT,
            "eventCategory": "Management",
        }
        if error:
            rec["errorCode"], rec["errorMessage"] = error
        return self.add("cloudtrail", ts, rec)

    # ------------------------------------------------------------------ host metrics
    def metric(self, ts: datetime, host: str, cpu: float, mem: float, net_in: int, net_out: int,
               interval_s: int) -> Entry:
        rec = {"timestamp": _iso(ts), "host": host, "agent": "endpoint-agent/7.4", "interval_s": interval_s,
               "cpu_pct": round(min(cpu, 100.0), 2), "mem_pct": round(min(mem, 100.0), 2),
               "net_in_bytes": int(net_in), "net_out_bytes": int(net_out)}
        return self.add("host_metrics", ts, rec)

    # ------------------------------------------------------------------ DHCP
    def dhcp(self, ts: datetime, event_id: int, ip: str, host: str, mac: str) -> Entry:
        desc = {10: "Assign", 11: "Renew", 12: "Release"}[event_id]
        line = (f"{event_id},{ts:%m/%d/%y},{ts:%H:%M:%S},{desc},{ip},{host}.{FQDN},{mac},,"
                f"{self.rng.randint(10**8, 10**9)},0")
        return self.add("dhcp", ts, {"message": line})


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"
