import os

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic.packet_parse import PacketMeta
from backend.logic.rules import delete_rule, list_rules, save_rules, upsert_rule
from backend.logic.verdict import ACCEPT, DROP, decide
from main import app


def _auth_headers(advanced=True):
    client = app.test_client()
    username = "advuser" if advanced else "stduser"
    client.post(
        "/auth/register",
        json={"username": username, "password": "secret12", "advanced_mode": advanced},
    )
    login = client.post("/auth/login", json={"username": username, "password": "secret12"})
    token = login.get_json()["token"]
    return client, {"Authorization": f"Bearer {token}"}


def setup_function():
    save_rules([])


def test_allow_overrides_lower_priority_deny():
    upsert_rule(
        {
            "id": 1,
            "priority": 10,
            "action": "deny",
            "src": "203.0.113.0/24",
            "enabled": True,
        }
    )
    upsert_rule(
        {
            "id": 2,
            "priority": 200,
            "action": "allow",
            "src": "203.0.113.5/32",
            "enabled": True,
        }
    )
    allow_meta = PacketMeta("203.0.113.5", "10.0.0.1", 6, 1, 80, 40)
    deny_meta = PacketMeta("203.0.113.9", "10.0.0.1", 6, 1, 80, 40)
    action, details = decide(allow_meta)
    assert action == ACCEPT
    assert details["rule_id"] == 2
    action2, details2 = decide(deny_meta)
    assert action2 == DROP
    assert details2["rule_id"] == 1


def test_rules_api_requires_advanced_to_mutate():
    save_rules([])
    client, headers = _auth_headers(advanced=True)
    created = client.post(
        "/api/rules",
        json={"priority": 5, "action": "deny", "src": "192.0.2.1/32"},
        headers=headers,
    )
    assert created.status_code == 201
    rid = created.get_json()["id"]
    listed = client.get("/api/rules", headers=headers)
    assert listed.status_code == 200
    assert any(r["id"] == rid for r in listed.get_json())

    std, std_headers = _auth_headers(advanced=False)
    blocked = std.post(
        "/api/rules",
        json={"priority": 1, "action": "deny", "src": "192.0.2.2/32"},
        headers=std_headers,
    )
    assert blocked.status_code == 403
    delete_rule(rid)
