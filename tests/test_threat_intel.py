import os
from io import BytesIO
from unittest.mock import patch

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["THREAT_INTEL_AUTO_REFRESH"] = "0"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic.packet_parse import PacketMeta
from backend.logic.rules import save_rules, upsert_rule
from backend.logic.threat_intel import ThreatIntelManager, manager
from backend.logic.verdict import ACCEPT, DROP, decide
from main import app

FEED = """
# emerging threats dummy
203.0.113.50
198.51.100.9
10.0.0.0/30
# comment only
not-an-ip
"""


class _FakeResponse:
    def __init__(self, text: str):
        self._buf = BytesIO(text.encode("utf-8"))

    def read(self):
        return self._buf.getvalue()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def setup_function():
    manager.enabled = True
    manager.malicious_ips.clear()
    manager._nets.clear()
    manager.last_updated = None
    save_rules([])


def test_mocked_feed_drops_listed_ip():
    intel = ThreatIntelManager(auto_refresh=False)
    with patch("urllib.request.urlopen", return_value=_FakeResponse(FEED)):
        status = intel.refresh_feeds()
    assert status["ip_count"] >= 2
    assert intel.is_malicious("203.0.113.50")
    assert not intel.is_malicious("8.8.8.8")

    manager.malicious_ips = set(intel.malicious_ips)
    manager._nets = list(intel._nets)
    manager.enabled = True
    action, details = decide(PacketMeta("203.0.113.50", "10.0.0.1", 6, 1, 80, 40))
    assert action == DROP
    assert details["rule_id"] == "threat_intel:malicious_ip"
    assert details["reason"] == "Matched public threat feed"
    allow, _ = decide(PacketMeta("8.8.8.8", "10.0.0.1", 6, 1, 80, 40))
    assert allow == ACCEPT


def test_json_allow_whitelists_feed_ip():
    manager.malicious_ips = {"203.0.113.50"}
    upsert_rule(
        {
            "id": 90,
            "priority": 200,
            "action": "allow",
            "src": "203.0.113.50/32",
            "enabled": True,
        }
    )
    action, details = decide(PacketMeta("203.0.113.50", "10.0.0.1", 6, 1, 80, 40))
    assert action == ACCEPT
    assert details["rule_id"] == 90


def test_threat_intel_api_status_and_refresh():
    client = app.test_client()
    listed = client.get("/api/threat-intel/status")
    assert listed.status_code == 200
    body = listed.get_json()
    assert "enabled" in body and "ip_count" in body and "last_updated" in body

    client.post(
        "/auth/register",
        json={"username": "ti_std", "password": "secret12", "advanced_mode": False},
    )
    std_token = client.post(
        "/auth/login", json={"username": "ti_std", "password": "secret12"}
    ).get_json()["token"]
    forbidden = client.post(
        "/api/threat-intel/refresh",
        headers={"Authorization": f"Bearer {std_token}"},
    )
    assert forbidden.status_code == 403

    client.post(
        "/auth/register",
        json={"username": "ti_adv", "password": "secret12", "advanced_mode": True},
    )
    adv_token = client.post(
        "/auth/login", json={"username": "ti_adv", "password": "secret12"}
    ).get_json()["token"]
    with patch("urllib.request.urlopen", return_value=_FakeResponse(FEED)):
        refreshed = client.post(
            "/api/threat-intel/refresh",
            headers={"Authorization": f"Bearer {adv_token}"},
        )
    assert refreshed.status_code == 200
    payload = refreshed.get_json()
    assert payload["ip_count"] >= 2
    assert payload["last_updated"] is not None
    action, details = decide(PacketMeta("198.51.100.9", "10.0.0.1", 6, 1, 80, 40))
    assert action == DROP
    assert details["rule_id"] == "threat_intel:malicious_ip"
