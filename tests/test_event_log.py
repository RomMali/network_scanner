import os

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["IPS_DB_PATH"] = "file:ips_pytest?mode=memory&cache=shared"
os.environ["IPS_DB_URI"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic.event_log import clear_events, flush, log_event, query_events
from main import app


def setup_function():
    clear_events()


def test_log_event_reaches_sqlite_via_queue():
    log_event(
        {
            "src": "10.1.1.1",
            "dst": "10.1.1.2",
            "proto": "tcp",
            "action": "DROP",
            "rule_id": "heuristic:syn_flood",
            "reason": "syn_flood",
        }
    )
    assert flush()
    items, total = query_events()
    assert total >= 1
    row = next(i for i in items if i["src_ip"] == "10.1.1.1")
    assert row["dst_ip"] == "10.1.1.2"
    assert row["protocol"] == "tcp"
    assert row["action"] == "DROP"
    assert row["rule_id"] == "heuristic:syn_flood"


def test_api_logs_filter_and_pagination():
    for i in range(5):
        log_event(
            {
                "src": "192.0.2.10",
                "dst": "192.0.2.1",
                "proto": "tcp",
                "action": "DROP",
                "rule_id": f"r{i}",
            }
        )
    log_event(
        {
            "src": "192.0.2.20",
            "dst": "192.0.2.1",
            "proto": "udp",
            "action": "ACCEPT",
            "rule_id": None,
        }
    )
    assert flush()
    client = app.test_client()

    drops = client.get("/api/logs?action=DROP&src_ip=192.0.2.10")
    assert drops.status_code == 200
    body = drops.get_json()
    assert body["total"] == 5
    assert all(item["action"] == "DROP" and item["src_ip"] == "192.0.2.10" for item in body["items"])

    allow = client.get("/api/logs?action=ALLOW&src_ip=192.0.2.20")
    assert allow.status_code == 200
    allow_body = allow.get_json()
    assert allow_body["total"] == 1
    assert allow_body["items"][0]["action"] == "ALLOW"

    page = client.get("/api/logs?action=DROP&src_ip=192.0.2.10&limit=2&offset=0")
    page2 = client.get("/api/logs?action=DROP&src_ip=192.0.2.10&limit=2&offset=2")
    assert page.status_code == 200 and page2.status_code == 200
    p1, p2 = page.get_json(), page2.get_json()
    assert p1["limit"] == 2 and p1["offset"] == 0
    assert len(p1["items"]) == 2
    assert len(p2["items"]) == 2
    ids = [i["id"] for i in p1["items"] + p2["items"]]
    assert len(ids) == len(set(ids))
    timestamps = [i["timestamp"] for i in p1["items"]]
    assert timestamps == sorted(timestamps, reverse=True)
