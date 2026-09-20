import os

os.environ["NFQUEUE_MOCK"] = "1"

from main import app
from backend.logic.nfqueue_worker import worker
from backend.logic.packet_parse import build_ipv4_packet
from backend.logic.verdict import ACCEPT, add_drop_source, clear_drop_sources


def setup_function():
    worker.stop()
    clear_drop_sources()


def teardown_function():
    worker.stop()
    clear_drop_sources()


def test_start_stop_status_legacy_and_api():
    client = app.test_client()
    stopped = client.get("/status")
    assert stopped.status_code == 200
    assert b"running" not in stopped.data.lower() or b"stopped" in stopped.data.lower()
    assert stopped.get_json()["status"] == "stopped"

    started = client.get("/start")
    assert started.status_code == 200
    status = client.get("/status")
    assert b"running" in status.data
    assert client.get("/api/status").get_json()["status"] == "running"

    api_stop = client.post("/api/stop")
    assert api_stop.status_code == 200
    assert client.get("/status").get_json()["status"] == "stopped"

    api_start = client.post("/api/start")
    assert api_start.status_code == 200
    assert client.get("/api/status").get_json()["status"] == "running"
    client.get("/stop")
    assert client.get("/status").get_json()["status"] == "stopped"


def test_worker_process_payload_drop():
    add_drop_source("198.51.100.9")
    raw = build_ipv4_packet("198.51.100.9", "198.51.100.1")
    from backend.logic.verdict import DROP

    assert worker.process_payload(raw) == DROP
    clear_drop_sources()
    assert worker.process_payload(build_ipv4_packet("198.51.100.8", "198.51.100.1")) == ACCEPT
