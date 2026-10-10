"""STIX 1.x packages over TAXII 1.1 (legacy government / ISAC sharing still in use).

fetch: TAXII 1.1 Poll_Request (XML) to the poll service; every Content_Block holds a STIX 1.x
package. parse: CybOX observables of indicators (Address, DomainName, URI, File hashes).
"""
from __future__ import annotations

import base64
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts

CONFIDENCE = {"high": 85, "medium": 60, "low": 30}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xsi_type(el) -> str:
    for k, v in el.attrib.items():
        if _local(k) == "type":
            return v.split(":")[-1]
    return ""


def _children(el, name: str):
    return [c for c in el.iter() if _local(c.tag) == name]


class Stix1Taxii1(FeedConnector):
    name = "stix1_taxii1"
    version = "1"
    feed_generation = "legacy"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        begin = f"<taxii_11:Exclusive_Begin_Timestamp>{since.isoformat()}</taxii_11:Exclusive_Begin_Timestamp>" \
            if since else ""
        poll = (f'<taxii_11:Poll_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" '
                f'message_id="{uuid.uuid4()}" collection_name="{self.config.get("collection", "default")}">{begin}'
                f'<taxii_11:Poll_Parameters allow_asynch="false"><taxii_11:Response_Type>FULL</taxii_11:Response_Type>'
                f'</taxii_11:Poll_Parameters></taxii_11:Poll_Request>')
        headers = {"Content-Type": "application/xml", "Accept": "application/xml",
                   "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
                   "X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.1", "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
                   "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:https:1.0"}
        cred = self.secret()
        if cred:
            headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        resp = self.http.post(self.config["url"], content=poll.encode(), headers=headers)
        root = ET.fromstring(resp.body)
        out = []
        for block in _children(root, "Content"):
            pkg = next(iter(block), None)
            if pkg is not None:
                out.append(RawPayload(resp.url, ET.tostring(pkg), "application/xml"))
        return out

    def parse(self, raw: RawPayload) -> list[Indicator]:
        root = ET.fromstring(raw.body)
        out = []
        for ind in _children(root, "Indicator"):
            title = next((t.text for t in _children(ind, "Title") if t.text), None)
            conf = next((v.text for c in _children(ind, "Confidence") for v in _children(c, "Value") if v.text), None)
            ts = parse_ts(ind.attrib.get("timestamp"))
            ref = ind.attrib.get("id")
            for props in _children(ind, "Properties"):
                kind = _xsi_type(props)
                values: list[tuple[str, str | None]] = []
                if kind == "AddressObjectType":
                    values = [(v.text, None) for v in _children(props, "Address_Value") if v.text]
                elif kind in ("DomainNameObjectType", "URIObjectType"):
                    values = [(v.text, "url" if kind == "URIObjectType" else "domain")
                              for v in _children(props, "Value") if v.text]
                elif kind == "FileObjectType":
                    for h in _children(props, "Hash"):
                        t = next((x.text for x in _children(h, "Type") if x.text), "")
                        v = next((x.text for x in _children(h, "Simple_Hash_Value") if x.text), None)
                        if v:
                            values.append((v, t.lower().replace("-", "") or None))
                for v, t in values:
                    out.append(Indicator(value=v.strip(), type=t if t in ("url", "domain", "md5", "sha1", "sha256")
                                         else None, source_ref=ref, confidence=CONFIDENCE.get((conf or "").lower(), 50),
                                         first_seen=ts, last_seen=ts, tags=[title] if title else [], reference=title))
        return out
