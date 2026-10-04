"""Against a running `docker compose` stack. Skipped unless E2E=1.

    make up && E2E=1 docker compose run --rm --entrypoint python cli -m pytest -q tests/e2e
"""
import os
import time
import uuid

import httpx
import pytest

pytestmark = pytest.mark.skipif(os.environ.get("E2E") != "1", reason="set E2E=1 with the compose stack running")

CMD = os.environ.get("COMMAND_API_URL", "http://localhost:8000")
QRY = os.environ.get("QUERY_API_URL", "http://localhost:8001")


def test_m0_ping_round_trip():
    assert httpx.get(f"{CMD}/health").json()["status"] == "ok"
    health = httpx.get(f"{QRY}/health").json()
    assert health["status"] == "ok" and health["bus"] is True

    nonce = str(uuid.uuid4())
    cid = httpx.post(f"{CMD}/commands/Ping", json={"message": "e2e", "nonce": nonce}).json()["command_id"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        r = httpx.get(f"{QRY}/commands/{cid}")
        if r.status_code == 200 and r.json()["status"] == "succeeded":
            break
        time.sleep(0.5)
    else:
        pytest.fail("ping was not projected within 30 s")
    assert any(p["command_id"] == cid for p in httpx.get(f"{QRY}/pings").json()["items"])
