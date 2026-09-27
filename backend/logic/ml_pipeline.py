"""Async feature logging and baseline anomaly alerts. Never issues DROP."""
from __future__ import annotations

import json
import math
import os
import queue
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from backend.logic.event_log import record
from backend.logic.packet_parse import PacketMeta

EVENTS_PATH = Path(__file__).resolve().parents[2] / "logs" / "events.jsonl"
ALERTS: Deque[Dict[str, Any]] = deque(maxlen=500)
_alert_lock = threading.Lock()

_q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=10000)
_started = False
_stop = threading.Event()
_thread: Optional[threading.Thread] = None

_src_rates: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=256))
_src_dsts: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=256))
_src_ports: Dict[str, Deque[int]] = defaultdict(lambda: deque(maxlen=256))


def _zscore(values: List[float], current: float) -> float:
    if len(values) < 8:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((x - mean) ** 2 for x in values) / len(values)
    std = math.sqrt(var)
    if std < 1e-9:
        return 0.0
    return abs(current - mean) / std


def _entropy(items: List[Any]) -> float:
    if not items:
        return 0.0
    counts: Dict[Any, int] = {}
    for i in items:
        counts[i] = counts.get(i, 0) + 1
    n = float(len(items))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log(p, 2)
    return ent


def _score_isolation(features: List[float]) -> Optional[float]:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except Exception:
        return None
    # Tiny online buffer stored on function
    buf = getattr(_score_isolation, "_buf", [])
    buf.append(features)
    if len(buf) > 256:
        buf = buf[-256:]
    _score_isolation._buf = buf
    if len(buf) < 16:
        return None
    model = IsolationForest(n_estimators=32, contamination=0.1, random_state=0)
    model.fit(np.array(buf))
    pred = model.decision_function(np.array([features]))[0]
    return float(pred)


def _handle(item: Dict[str, Any]) -> None:
    src = item["src"]
    now = item.get("now") or 0.0
    _src_rates[src].append(now)
    _src_dsts[src].append(item.get("dst") or "")
    if item.get("dport") is not None:
        _src_ports[src].append(int(item["dport"]))
    window = [t for t in _src_rates[src] if t > now - 5.0]
    rate = len(window) / 5.0
    unique_dsts = len(set(_src_dsts[src]))
    port_ent = _entropy(list(_src_ports[src]))
    hist_rates = []
    for s, times in _src_rates.items():
        if s == src:
            continue
        hist_rates.append(len([t for t in times if t > now - 5.0]) / 5.0)
    z = _zscore(hist_rates or [rate], rate)
    iso = _score_isolation([rate, float(unique_dsts), port_ent, float(item.get("length") or 0)])
    anomaly = z >= 3.0 or (iso is not None and iso < 0)
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src": src,
        "dst": item.get("dst"),
        "proto": item.get("proto"),
        "rate_5s": rate,
        "unique_dsts": unique_dsts,
        "port_entropy": port_ent,
        "zscore": z,
        "isolation_score": iso,
        "anomaly": anomaly,
        "action": "ALERT" if anomaly else "FEATURE",
        "reason": "ml_anomaly" if anomaly else "ml_feature",
    }
    try:
        EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass
    if anomaly:
        with _alert_lock:
            ALERTS.append(row)
        record(
            {
                "action": "ALERT",
                "src": src,
                "dst": item.get("dst"),
                "proto": item.get("proto"),
                "reason": "ml_anomaly",
                "zscore": z,
                "isolation_score": iso,
            }
        )
        _maybe_propose_signature(src)


def _maybe_propose_signature(src: str) -> None:
    with _alert_lock:
        count = sum(1 for a in ALERTS if a.get("src") == src and a.get("anomaly"))
    if count < 5:
        return
    from backend.logic.rules import list_rules, upsert_rule

    for r in list_rules():
        if r.get("src") == f"{src}/32" and r.get("enabled") is False and r.get("proposed"):
            return
    upsert_rule(
        {
            "priority": 50,
            "action": "deny",
            "src": f"{src}/32",
            "dst": "any",
            "proto": "any",
            "enabled": False,
            "proposed": True,
            "reason": "ml_proposed_signature",
        }
    )


def _loop() -> None:
    while not _stop.is_set():
        try:
            item = _q.get(timeout=0.25)
        except queue.Empty:
            continue
        if item is None:
            break
        try:
            _handle(item)
        except Exception:
            pass


def start_ml() -> None:
    global _started, _thread
    if _started:
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="ml-pipeline", daemon=True)
    _thread.start()
    _started = True


def stop_ml() -> None:
    global _started
    _stop.set()
    try:
        _q.put_nowait(None)
    except queue.Full:
        pass
    _started = False


def enqueue_meta(meta: PacketMeta) -> None:
    start_ml()
    item = {
        "src": meta.src,
        "dst": meta.dst,
        "proto": meta.proto_name,
        "sport": meta.sport,
        "dport": meta.dport,
        "length": meta.length,
        "now": datetime.now(timezone.utc).timestamp(),
    }
    try:
        _q.put_nowait(item)
    except queue.Full:
        pass


def get_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    with _alert_lock:
        return list(ALERTS)[-limit:]


def reset_ml() -> None:
    with _alert_lock:
        ALERTS.clear()
    _src_rates.clear()
    _src_dsts.clear()
    _src_ports.clear()
    if hasattr(_score_isolation, "_buf"):
        _score_isolation._buf = []
