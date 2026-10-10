"""Write data/attack/enterprise-attack-subset.json: a small STIX 2.1 bundle of MITRE ATT&CK
Enterprise tactics and techniques, enough for offline validation of TI output.

The validator prefers the full official bundle when present:
    data/attack/enterprise-attack.json   (download it with `make attack-bundle`)
This subset only exists so a fresh checkout validates technique IDs without network access.

    python scripts/build_attack_subset.py
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"), ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"), ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"), ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"), ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"), ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"), ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"), ("TA0040", "impact", "Impact"),
]
VALID = ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]
TECHNIQUES = [
    ("T1003", "OS Credential Dumping", ["credential-access"]),
    ("T1003.001", "LSASS Memory", ["credential-access"]),
    ("T1018", "Remote System Discovery", ["discovery"]),
    ("T1021", "Remote Services", ["lateral-movement"]),
    ("T1021.002", "SMB/Windows Admin Shares", ["lateral-movement"]),
    ("T1027", "Obfuscated Files or Information", ["defense-evasion"]),
    ("T1033", "System Owner/User Discovery", ["discovery"]),
    ("T1036", "Masquerading", ["defense-evasion"]),
    ("T1041", "Exfiltration Over C2 Channel", ["exfiltration"]),
    ("T1046", "Network Service Discovery", ["discovery"]),
    ("T1047", "Windows Management Instrumentation", ["execution"]),
    ("T1048", "Exfiltration Over Alternative Protocol", ["exfiltration"]),
    ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", ["exfiltration"]),
    ("T1053", "Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    ("T1053.005", "Scheduled Task", ["execution", "persistence", "privilege-escalation"]),
    ("T1059", "Command and Scripting Interpreter", ["execution"]),
    ("T1059.001", "PowerShell", ["execution"]),
    ("T1059.003", "Windows Command Shell", ["execution"]),
    ("T1069", "Permission Groups Discovery", ["discovery"]),
    ("T1069.002", "Domain Groups", ["discovery"]),
    ("T1070", "Indicator Removal", ["defense-evasion"]),
    ("T1070.001", "Clear Windows Event Logs", ["defense-evasion"]),
    ("T1071", "Application Layer Protocol", ["command-and-control"]),
    ("T1071.001", "Web Protocols", ["command-and-control"]),
    ("T1071.004", "DNS", ["command-and-control"]),
    ("T1078", "Valid Accounts", VALID),
    ("T1078.002", "Domain Accounts", VALID),
    ("T1082", "System Information Discovery", ["discovery"]),
    ("T1087", "Account Discovery", ["discovery"]),
    ("T1087.002", "Domain Account", ["discovery"]),
    ("T1090", "Proxy", ["command-and-control"]),
    ("T1095", "Non-Application Layer Protocol", ["command-and-control"]),
    ("T1098", "Account Manipulation", ["persistence", "privilege-escalation"]),
    ("T1105", "Ingress Tool Transfer", ["command-and-control"]),
    ("T1110", "Brute Force", ["credential-access"]),
    ("T1110.001", "Password Guessing", ["credential-access"]),
    ("T1110.003", "Password Spraying", ["credential-access"]),
    ("T1112", "Modify Registry", ["defense-evasion"]),
    ("T1114", "Email Collection", ["collection"]),
    ("T1133", "External Remote Services", ["persistence", "initial-access"]),
    ("T1136", "Create Account", ["persistence"]),
    ("T1136.003", "Cloud Account", ["persistence"]),
    ("T1140", "Deobfuscate/Decode Files or Information", ["defense-evasion"]),
    ("T1189", "Drive-by Compromise", ["initial-access"]),
    ("T1190", "Exploit Public-Facing Application", ["initial-access"]),
    ("T1197", "BITS Jobs", ["defense-evasion", "persistence"]),
    ("T1204", "User Execution", ["execution"]),
    ("T1204.002", "Malicious File", ["execution"]),
    ("T1218", "System Binary Proxy Execution", ["defense-evasion"]),
    ("T1218.005", "Mshta", ["defense-evasion"]),
    ("T1218.011", "Rundll32", ["defense-evasion"]),
    ("T1486", "Data Encrypted for Impact", ["impact"]),
    ("T1490", "Inhibit System Recovery", ["impact"]),
    ("T1496", "Resource Hijacking", ["impact"]),
    ("T1530", "Data from Cloud Storage", ["collection"]),
    ("T1555", "Credentials from Password Stores", ["credential-access"]),
    ("T1558", "Steal or Forge Kerberos Tickets", ["credential-access"]),
    ("T1558.003", "Kerberoasting", ["credential-access"]),
    ("T1560", "Archive Collected Data", ["collection"]),
    ("T1562", "Impair Defenses", ["defense-evasion"]),
    ("T1562.008", "Disable or Modify Cloud Logs", ["defense-evasion"]),
    ("T1566", "Phishing", ["initial-access"]),
    ("T1566.001", "Spearphishing Attachment", ["initial-access"]),
    ("T1567", "Exfiltration Over Web Service", ["exfiltration"]),
    ("T1567.002", "Exfiltration to Cloud Storage", ["exfiltration"]),
    ("T1569", "System Services", ["execution"]),
    ("T1569.002", "Service Execution", ["execution"]),
    ("T1570", "Lateral Tool Transfer", ["lateral-movement"]),
    ("T1571", "Non-Standard Port", ["command-and-control"]),
    ("T1573", "Encrypted Channel", ["command-and-control"]),
    ("T1583", "Acquire Infrastructure", ["resource-development"]),
    ("T1588", "Obtain Capabilities", ["resource-development"]),
    ("T1595", "Active Scanning", ["reconnaissance"]),
]
NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
CREATED = "2025-01-01T00:00:00.000Z"


def main() -> Path:
    objects = []
    for tid, short, name in TACTICS:
        objects.append({
            "type": "x-mitre-tactic", "spec_version": "2.1", "id": f"x-mitre-tactic--{uuid.uuid5(NS, tid)}",
            "created": CREATED, "modified": CREATED, "name": name, "x_mitre_shortname": short,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                     "url": f"https://attack.mitre.org/tactics/{tid}/"}]})
    for tid, name, tactics in TECHNIQUES:
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--{uuid.uuid5(NS, tid)}",
            "created": CREATED, "modified": CREATED, "name": name,
            "x_mitre_is_subtechnique": "." in tid, "x_mitre_domains": ["enterprise-attack"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                     "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}]})
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, 'subset')}", "objects": objects,
              "x_note": "Subset of MITRE ATT&CK Enterprise for offline validation. Prefer the full bundle "
                        "(data/attack/enterprise-attack.json); ATT&CK is (c) The MITRE Corporation."}
    out = Path(__file__).resolve().parents[1] / "data" / "attack" / "enterprise-attack-subset.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=1) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    print(main())
