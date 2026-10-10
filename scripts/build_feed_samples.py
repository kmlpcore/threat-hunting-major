"""Write the synthetic TI feed samples under data/feeds/samples/.

Each file mimics the real feed's format so connectors can be exercised offline. Every value is
fictional: RFC 5737 documentation addresses, `.example` domains, and CVE-2099-* identifiers.
A few values match the attacker infrastructure planted by scenarios/default.yaml, so the M7
loop (feed pull -> retro-sweep -> sighting) has something to find; the rest are decoys, plus one
warninglisted value to show suppression.

    python scripts/build_feed_samples.py
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "feeds" / "samples"
XMRIG_SHA256 = "bac81aacc6e2bd334db5e1ba318bc3129f408144e78db290226dc1ca931ac580"
NOTE = "SYNTHETIC SAMPLE - fictional values in the format of the real feed; not real threat intelligence."


def threatfox() -> dict:
    def ioc(i, value, typ, threat, family, conf, tags, first="2026-10-08 09:12:44 UTC"):
        return {"id": str(i), "ioc": value, "threat_type": threat, "threat_type_desc": threat, "ioc_type": typ,
                "ioc_type_desc": typ, "malware": f"win.{family.lower().replace(' ', '_')}",
                "malware_printable": family, "malware_alias": None, "malware_malpedia": None,
                "confidence_level": conf, "first_seen": first, "last_seen": None, "reference": None,
                "reporter": "synthetic", "tags": tags}
    return {"query_status": "ok", "_note": NOTE, "data": [
        ioc(9100001, "203.0.113.80:80", "ip:port", "botnet_cc", "Cobalt Strike", 75, ["cobaltstrike", "c2"]),
        ioc(9100002, "update-check.badcdn.example", "domain", "payload_delivery", "Cobalt Strike", 75,
            ["cobaltstrike", "powershell"]),
        ioc(9100003, "pool.minexmr-mirror.example", "domain", "botnet_cc", "XMRig", 50, ["miner", "xmrig"]),
        ioc(9100004, "198.51.100.199:443", "ip:port", "botnet_cc", "QakBot", 100, ["qakbot"]),
        ioc(9100005, "http://dl.malware-cdn.example/stage2.exe", "url", "payload_delivery", "AsyncRAT", 90,
            ["asyncrat"]),
        ioc(9100006, "0f" * 32, "sha256_hash", "payload", "AsyncRAT", 100, ["asyncrat"]),
        ioc(9100007, "1.1.1.1:443", "ip:port", "botnet_cc", "Unknown malware", 25, ["false-positive-test"]),
    ]}


URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)          #
# """ + NOTE + """
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3300001","2026-10-08 10:01:12","http://cdn-static.badcdn.example/payload.dat","online","2026-10-09 08:00:00","malware_download","PikaBot,dll","https://urlhaus.abuse.ch/url/3300001/","synthetic"
"3300002","2026-10-08 11:20:40","http://cdn-static.badcdn.example/x.hta","offline","2026-10-08 12:00:00","malware_download","PikaBot,hta","https://urlhaus.abuse.ch/url/3300002/","synthetic"
"3300003","2026-10-09 02:13:09","http://files.decoy-host.example/invoice.zip","online","2026-10-09 09:00:00","malware_download","AgentTesla,zip","https://urlhaus.abuse.ch/url/3300003/","synthetic"
"""

BAZAAR = f"""################################################################
# MalwareBazaar recent malware samples (CSV)                   #
# {NOTE}
################################################################
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-10-08 07:00:00","{XMRIG_SHA256}","{"ab" * 16}","{"cd" * 20}","synthetic","xmrig.exe","exe","application/x-dosexec","XMRig","n/a","n/a","n/a","n/a","n/a"
"2026-10-08 07:30:00","{"1e" * 32}","{"2e" * 16}","{"3e" * 20}","synthetic","loader.dll","dll","application/x-dosexec","PikaBot","n/a","n/a","n/a","n/a","n/a"
"""

FEODO = [
    {"ip_address": "203.0.113.81", "port": 80, "status": "online", "hostname": None, "as_number": 64500,
     "as_name": "DOCUMENTATION-AS", "country": "ZZ", "first_seen": "2026-10-07 18:00:00",
     "last_online": "2026-10-09", "malware": "PikaBot", "_note": NOTE},
    {"ip_address": "198.51.100.150", "port": 443, "status": "offline", "hostname": None, "as_number": 64501,
     "as_name": "DOCUMENTATION-AS", "country": "ZZ", "first_seen": "2026-10-01 10:00:00",
     "last_online": "2026-10-05", "malware": "Emotet"},
]

SSLBL = f"""################################################################
# abuse.ch SSLBL Botnet C2 IP Blacklist (CSV)                  #
# {NOTE}
################################################################
# Firstseen,DstIP,DstPort
2026-10-08 06:10:00,198.51.100.160,443
2026-10-08 07:45:00,198.51.100.161,8443
"""

BLOCKLIST = f"""# Generic blocklist - {NOTE}
# one indicator per line; defanged values are fine
files-share[.]example
203.0.113.200
exfil-dns.example
hxxp://files-share[.]example/upload
192.0.2.250
"""

MISP = {"response": {"Attribute": [
    {"id": "70001", "event_id": "501", "type": "ip-dst|port", "category": "Network activity", "to_ids": True,
     "value": "203.0.113.66|443", "timestamp": "1791500000", "Tag": [{"name": "tlp:amber"}],
     "Event": {"info": "Brute force campaign against exposed web hosts (synthetic)",
               "Tag": [{"name": 'misp-galaxy:threat-actor="SYNTHETIC SPIDER"'}]}},
    {"id": "70002", "event_id": "501", "type": "domain", "category": "Network activity", "to_ids": True,
     "value": "login-portal.decoy.example", "timestamp": "1791500000", "Tag": [{"name": "tlp:red"}],
     "Event": {"info": "Brute force campaign against exposed web hosts (synthetic)"}},
    {"id": "70003", "event_id": "502", "type": "comment", "category": "Other", "to_ids": False,
     "value": "not an indicator", "timestamp": "1791500000"},
]}, "_note": NOTE}

STIX1 = f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {NOTE} -->
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1" xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
    xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
    xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2" xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    id="example:Package-1" version="1.2">
  <stix:Indicators>
    <stix:Indicator id="example:indicator-1" timestamp="2026-10-08T12:00:00Z" xsi:type="indicator:IndicatorType">
      <indicator:Title>Password spray source (synthetic ISAC report)</indicator:Title>
      <indicator:Observable id="example:Observable-1"><cybox:Object><cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
        <AddressObj:Address_Value>198.51.100.23</AddressObj:Address_Value></cybox:Properties></cybox:Object></indicator:Observable>
      <indicator:Confidence><stixCommon:Value>High</stixCommon:Value></indicator:Confidence>
    </stix:Indicator>
    <stix:Indicator id="example:indicator-2" timestamp="2026-10-08T12:00:00Z" xsi:type="indicator:IndicatorType">
      <indicator:Title>Decoy domain</indicator:Title>
      <indicator:Observable id="example:Observable-2"><cybox:Object><cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
        <DomainNameObj:Value>stix1-decoy.example</DomainNameObj:Value></cybox:Properties></cybox:Object></indicator:Observable>
      <indicator:Confidence><stixCommon:Value>Medium</stixCommon:Value></indicator:Confidence>
    </stix:Indicator>
    <stix:Indicator id="example:indicator-3" timestamp="2026-10-08T12:00:00Z" xsi:type="indicator:IndicatorType">
      <indicator:Title>Decoy file</indicator:Title>
      <indicator:Observable id="example:Observable-3"><cybox:Object><cybox:Properties xsi:type="FileObj:FileObjectType">
        <FileObj:Hashes><cyboxCommon:Hash><cyboxCommon:Type>SHA256</cyboxCommon:Type>
        <cyboxCommon:Simple_Hash_Value>{"9a" * 32}</cyboxCommon:Simple_Hash_Value></cyboxCommon:Hash></FileObj:Hashes>
      </cybox:Properties></cybox:Object></indicator:Observable>
    </stix:Indicator>
  </stix:Indicators>
</stix:STIX_Package>
"""

KEV = {"title": "CISA Catalog of Known Exploited Vulnerabilities (synthetic sample)", "catalogVersion": "2026.10.09",
       "dateReleased": "2026-10-09T14:00:00.000Z", "count": 2, "_note": NOTE, "vulnerabilities": [
           {"cveID": "CVE-2099-0001", "vendorProject": "ExampleSoft", "product": "Example VPN",
            "vulnerabilityName": "ExampleSoft Example VPN authentication bypass (fictional)",
            "dateAdded": "2026-10-01", "shortDescription": "Fictional entry.", "requiredAction": "Apply updates.",
            "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known", "notes": ""},
           {"cveID": "CVE-2099-0002", "vendorProject": "ExampleCorp", "product": "Example Mail",
            "vulnerabilityName": "ExampleCorp Example Mail remote code execution (fictional)",
            "dateAdded": "2026-10-05", "shortDescription": "Fictional entry.", "requiredAction": "Apply updates.",
            "dueDate": "2026-10-26", "knownRansomwareCampaignUse": "Unknown", "notes": ""}]}

TAXII21 = {"more": False, "_note": NOTE, "objects": [
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--0b1d3f4e-1111-4c4c-9a9a-000000000001",
     "created": "2026-10-08T10:00:00.000Z", "modified": "2026-10-08T10:00:00.000Z",
     "name": "Exfiltration endpoint (synthetic)", "pattern": "[ipv4-addr:value = '203.0.113.200']",
     "pattern_type": "stix", "valid_from": "2026-10-08T10:00:00Z", "confidence": 80,
     "indicator_types": ["malicious-activity"], "labels": ["exfiltration"],
     "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--0b1d3f4e-1111-4c4c-9a9a-000000000002",
     "created": "2026-10-08T10:00:00.000Z", "modified": "2026-10-08T10:00:00.000Z", "name": "Decoy domain",
     "pattern": "[domain-name:value = 'taxii-decoy.example' OR url:value = 'http://taxii-decoy.example/a']",
     "pattern_type": "stix", "valid_from": "2026-10-08T10:00:00Z", "confidence": 60},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--0b1d3f4e-1111-4c4c-9a9a-000000000003",
     "created": "2026-10-08T10:00:00.000Z", "modified": "2026-10-08T10:00:00.000Z", "name": "Sigma, not STIX",
     "pattern": "title: x", "pattern_type": "sigma", "valid_from": "2026-10-08T10:00:00Z"},
]}

OTX = {"_note": NOTE, "count": 1, "next": None, "results": [
    {"id": "6700000000000000000000aa", "name": "DNS tunnelling infrastructure (synthetic)", "TLP": "green",
     "created": "2026-10-08T00:00:00", "modified": "2026-10-08T00:00:00", "tags": ["dns-tunnel"],
     "malware_families": [], "attack_ids": [{"id": "T1071.004"}],
     "indicators": [{"indicator": "exfil-dns.example", "type": "domain", "created": "2026-10-08T00:00:00"},
                    {"indicator": "otx-decoy.example", "type": "hostname", "created": "2026-10-08T00:00:00"}]}]}

ABUSEIPDB = {"meta": {"generatedAt": "2026-10-09T00:00:00+00:00"}, "_note": NOTE, "data": [
    {"ipAddress": "203.0.113.66", "countryCode": "ZZ", "abuseConfidenceScore": 100,
     "lastReportedAt": "2026-10-08T22:30:00+00:00"},
    {"ipAddress": "198.51.100.210", "countryCode": "ZZ", "abuseConfidenceScore": 95,
     "lastReportedAt": "2026-10-08T20:00:00+00:00"}]}

WEBHOOK = {"_note": NOTE, "indicators": [
    {"value": "push-decoy.example", "type": "domain", "threat_type": "botnet_cc", "confidence": 70,
     "tlp": "TLP:GREEN"}]}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "threatfox_get_iocs.json": json.dumps(threatfox(), indent=1), "urlhaus_recent.csv": URLHAUS,
        "malwarebazaar_recent.csv": BAZAAR, "feodo_ipblocklist.json": json.dumps(FEODO, indent=1),
        "sslbl_ipblacklist.csv": SSLBL, "blocklist.txt": BLOCKLIST, "misp_restsearch.json": json.dumps(MISP, indent=1),
        "stix1_package.xml": STIX1, "cisa_kev.json": json.dumps(KEV, indent=1),
        "taxii21_objects.json": json.dumps(TAXII21, indent=1), "otx_pulses.json": json.dumps(OTX, indent=1),
        "abuseipdb_blacklist.json": json.dumps(ABUSEIPDB, indent=1), "webhook_push.json": json.dumps(WEBHOOK, indent=1),
    }
    for name, text in files.items():
        (OUT / name).write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} samples to {OUT}")


if __name__ == "__main__":
    main()
