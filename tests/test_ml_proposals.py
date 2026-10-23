import os

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic.ml_pipeline import record_anomaly, reset_ml
from backend.logic.packet_parse import PacketMeta
from backend.logic.rules import list_ml_proposals, list_rules, propose_ml_rule, save_rules
from backend.logic.verdict import ACCEPT, DROP, decide
from backend.utils.json_handler import DATA_DIR
from main import app


def setup_function():
    reset_ml()
    save_rules([])


def _auth(advanced: bool, username: str):
    client = app.test_client()
    client.post(
        "/auth/register",
        json={"username": username, "password": "secret12", "advanced_mode": advanced},
    )
    token = client.post(
        "/auth/login", json={"username": username, "password": "secret12"}
    ).get_json()["token"]
    return client, {"Authorization": f"Bearer {token}"}


def test_repeated_anomalies_write_disabled_rule():
    src = "198.51.100.77"
    proposed = None
    for i in range(5):
        proposed = record_anomaly(src, now=1_700_000_000.0 + i, reason="ml_anomaly")
    assert proposed is not None
    assert proposed["enabled"] is False
    assert proposed["action"] == "DROP"
    assert proposed["src_ip"] == src
    assert proposed["metadata"]["source"] == "ml_proposal"
    on_disk = list_rules()
    assert any(r.get("id") == proposed["id"] and r.get("enabled") is False for r in on_disk)
    rules_path = DATA_DIR / "rules.json"
    assert rules_path.is_file()
    text = rules_path.read_text(encoding="utf-8")
    assert proposed["id"] in text
    assert '"enabled": false' in text.lower()
    meta = PacketMeta(src, "10.0.0.1", 6, 1, 80, 40)
    action, _ = decide(meta)
    assert action == ACCEPT
    assert record_anomaly(src, now=1_700_000_000.0 + 10) is None


def test_get_ml_proposals_filters_disabled_drafts():
    propose_ml_rule("203.0.113.8", "test draft")
    client = app.test_client()
    resp = client.get("/api/ml/proposals")
    assert resp.status_code == 200
    rows = resp.get_json()
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "203.0.113.8"
    assert rows[0]["enabled"] is False
    assert rows[0]["metadata"]["source"] == "ml_proposal"


def test_standard_forbidden_advanced_approve_and_reject():
    draft = propose_ml_rule("192.0.2.88", "approve me")
    other = propose_ml_rule("192.0.2.89", "reject me")
    assert draft and other
    std, std_headers = _auth(False, "ml_std")
    adv, adv_headers = _auth(True, "ml_adv")

    forbidden = std.post(f"/api/ml/proposals/{draft['id']}/approve", headers=std_headers)
    assert forbidden.status_code == 403
    still = list_ml_proposals()
    assert any(r["id"] == draft["id"] and r["enabled"] is False for r in still)

    approved = adv.post(f"/api/ml/proposals/{draft['id']}/approve", headers=adv_headers)
    assert approved.status_code == 200
    body = approved.get_json()
    assert body["enabled"] is True
    listed = app.test_client().get("/api/ml/proposals").get_json()
    assert all(r["id"] != draft["id"] for r in listed)
    action, details = decide(PacketMeta("192.0.2.88", "10.0.0.1", 6, 1, 80, 40))
    assert action == DROP
    assert details["rule_id"] == draft["id"]

    rejected = adv.post(f"/api/ml/proposals/{other['id']}/reject", headers=adv_headers)
    assert rejected.status_code == 200
    remaining = list_rules()
    assert all(r.get("id") != other["id"] for r in remaining)
    action2, _ = decide(PacketMeta("192.0.2.89", "10.0.0.1", 6, 1, 80, 40))
    assert action2 == ACCEPT

    std_reject = std.post(f"/api/ml/proposals/{draft['id']}/reject", headers=std_headers)
    assert std_reject.status_code == 403
