import os

os.environ["NFQUEUE_MOCK"] = "1"

from backend.logic.ml_pipeline import enqueue_meta, get_alerts, reset_ml, start_ml, stop_ml
from backend.logic.packet_parse import PacketMeta
from main import app
import time


def test_alerts_endpoint_and_nonblocking_enqueue():
    reset_ml()
    start_ml()
    meta = PacketMeta("192.0.2.50", "10.0.0.8", 6, 1, 22, 40)
    enqueue_meta(meta)
    time.sleep(0.3)
    client = app.test_client()
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)
    logs = client.get("/api/logs")
    assert logs.status_code == 200
    stop_ml()
