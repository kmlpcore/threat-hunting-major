from datetime import datetime, timedelta, timezone

import pytest

from engine.common.ids import stable_event_ids
from engine.generator.emitters import SENSOR_SKEW
from engine.normaliser import ecs
from engine.normaliser.entity import EntityResolver, LeaseTable
from engine.normaliser.mapping import available_sources, load_mapping, registered_domain
from engine.normaliser.normalise import normalise_records

T0 = datetime(2026, 9, 8, 10, 0, tzinfo=timezone.utc)
SID = "S-1-5-21-1-2-3-1104"


@pytest.fixture
def resolver():
    leases = LeaseTable()
    leases.add("10.10.20.5", T0 - timedelta(hours=1), T0 + timedelta(hours=8), "ws-fin-001")
    return EntityResolver(
        aliases={"asmith": SID, "corp\\asmith": SID, "asmith@corp.local": SID, SID.lower(): SID,
                 "nt authority\\system": "S-1-5-18"},
        ids={SID: ("asmith", "CORP"), "S-1-5-18": ("system", "NT AUTHORITY")},
        hosts={"ws-fin-001": "h1", "dc01": "h2"}, static_ips={"10.10.1.10": "dc01"}, leases=leases)


def norm(source, records, resolver):
    return normalise_records(load_mapping(source), records, resolver, "batch-1", "8.11.0")


def test_every_mapping_loads_and_only_uses_catalogued_fields():
    fields = set(ecs.catalog().fields)
    for source in available_sources():
        m = load_mapping(source)
        used = set(m.fields) | set(m.static) | {f for o in m.overrides for f in o.fields}
        assert used <= fields, (source, used - fields)


def test_mapping_clock_skew_matches_generator_sensors():
    for source, skew in SENSOR_SKEW.items():
        assert load_mapping(source).clock_skew_seconds == -skew


def test_stable_event_ids_are_deterministic_and_unique_for_duplicates():
    recs = [{"a": 1}, {"a": 1}, {"a": 2}]
    ids = stable_event_ids("proxy", recs)
    assert ids == stable_event_ids("proxy", recs)
    assert len(set(ids)) == 3
    assert stable_event_ids("dns", recs) != ids


def test_windows_logon_resolves_upn_alias_to_sid(resolver):
    rec = {"EventID": 4624, "TimeCreated": "2026-09-08T10:00:00.000000Z", "Computer": "WS-FIN-001.corp.local",
           "EventRecordID": 7, "TargetUserName": "asmith@corp.local", "TargetDomainName": "CORP",
           "TargetUserSid": "S-1-0-0", "LogonType": 3, "IpAddress": "10.10.20.5", "IpPort": "50000"}
    res = norm("windows_security", [rec], resolver)
    assert not res.invalid
    row = res.rows[0]
    assert row["user.id"] == SID and row["user.name"] == "asmith"
    assert row["host.name"] == "ws-fin-001" and row["host.id"] == "h1"
    assert row["event.category"] == ["authentication"] and row["event.outcome"] == "success"
    assert row["winlog.logon.type"] == "Network"
    assert row["labels.ingest_partition"] == "source=windows_security/date=2026-09-08/hour=10"


def test_group_membership_override_uses_subject_and_member(resolver):
    rec = {"EventID": 4728, "TimeCreated": "2026-09-08T10:00:00Z", "Computer": "DC01.corp.local",
           "SubjectUserName": "asmith", "SubjectDomainName": "CORP", "SubjectUserSid": SID,
           "TargetUserName": "Domain Admins", "TargetSid": "S-1-5-21-1-2-3-512",
           "MemberName": "CN=Bob Jones,OU=Staff,DC=corp,DC=local", "MemberSid": "S-1-5-21-1-2-3-9999"}
    row = norm("windows_security", [rec], resolver).rows[0]
    assert row["group.name"] == "Domain Admins"
    assert row["user.id"] == SID
    assert row["user.target.name"] == "bob jones"   # unresolved member keeps the CN
    assert row["event.type"] == ["group", "change"]


def test_zeek_conn_gets_host_from_lease_and_skew_correction(resolver):
    rec = {"ts": T0.timestamp() - 2.5, "uid": "C1", "id.orig_h": "10.10.20.5", "id.orig_p": 50000,
           "id.resp_h": "142.1.2.3", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "duration": 1.5,
           "orig_bytes": 100, "resp_bytes": 900, "conn_state": "SF"}
    row = norm("zeek_conn", [rec], resolver).rows[0]
    assert row["@timestamp"] == T0
    assert row["host.name"] == "ws-fin-001" and row["labels.host_resolution"] == "lease"
    assert row["network.direction"] == "outbound" and row["network.bytes"] == 1000
    assert row["event.duration"] == 1_500_000_000


def test_lease_window_is_respected(resolver):
    rec = {"ts": (T0 + timedelta(days=1)).timestamp(), "uid": "C1", "id.orig_h": "10.10.20.5", "id.orig_p": 1,
           "id.resp_h": "142.1.2.3", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}
    row = norm("zeek_conn", [rec], resolver).rows[0]
    assert "host.name" not in row and row["labels.host_resolution"] == "unresolved"


def test_proxy_line_is_parsed(resolver):
    line = ('1788861607.000    120 10.10.20.5 TCP_MISS/200 5120 GET https://docs.google.com/a?b=1 CORP\\asmith '
            'HIER_DIRECT/142.250.1.1 text/html "Mozilla/5.0 (Windows NT 10.0)" 700')
    row = norm("proxy", [{"message": line}], resolver).rows[0]
    assert row["user.id"] == SID
    assert row["url.domain"] == "docs.google.com" and row["url.registered_domain"] == "google.com"
    assert row["destination.domain"] == "docs.google.com"
    assert row["http.response.status_code"] == 200 and row["event.outcome"] == "success"
    assert row["event.original"] == line


def test_dns_subdomain_split(resolver):
    rec = {"ts": T0.timestamp(), "uid": "C", "id.orig_h": "10.10.20.5", "id.orig_p": 1, "id.resp_h": "10.10.1.10",
           "id.resp_p": 53, "proto": "udp", "query": "AbC.t.Exfil-DNS.example", "qtype_name": "TXT",
           "rcode_name": "NXDOMAIN"}
    row = norm("zeek_dns", [rec], resolver).rows[0]
    assert row["dns.question.registered_domain"] == "exfil-dns.example"
    assert row["dns.question.subdomain"] == "abc.t"
    assert row["event.outcome"] == "failure" and row["network.direction"] == "internal"


def test_cloudtrail_assumed_role_principal(resolver):
    rec = {"eventTime": "2026-09-08T10:00:00Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
           "awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.10", "readOnly": True,
           "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/Dev/asmith"},
           "recipientAccountId": "1", "errorCode": "AccessDenied"}
    row = norm("cloudtrail", [rec], resolver).rows[0]
    assert row["user.id"] == SID and row["cloud.service.name"] == "s3"
    assert row["event.type"] == ["access"] and row["event.outcome"] == "failure"


def test_dhcp_csv_and_bad_record_quarantined(resolver):
    good = {"message": "10,09/08/26,09:58:00,Assign,10.10.20.5,WS-FIN-001.corp.local,AABBCCDDEEFF,,1,0"}
    bad = {"message": "garbage"}
    res = norm("dhcp", [good, bad], resolver)
    assert len(res.rows) == 1 and len(res.invalid) == 1
    row = res.rows[0]
    assert row["host.ip"] == ["10.10.20.5"] and row["host.mac"] == ["AA-BB-CC-DD-EE-FF"]
    assert row["event.action"] == "dhcp-assign"


def test_validator_rejects_bad_categorisation():
    row = {"@timestamp": T0, "event.id": "x", "event.kind": "event", "event.category": ["authentication"],
           "event.type": ["connection"], "event.dataset": "d", "event.module": "m", "ecs.version": "8.11.0",
           "labels.ingest_partition": "p", "labels.ingest_batch": "b", "labels.ecs_mapping_version": "1"}
    assert any("unexpected for category" in e for e in ecs.validate(row))


def test_registered_domain():
    assert registered_domain("a.b.bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("www.google.com") == "google.com"
    assert registered_domain("10.0.0.1") is None
