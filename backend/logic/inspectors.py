"""Heuristic inspectors. DoS can DROP; others alert-only (no L2 on FORWARD)."""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from backend.logic.event_log import record
from backend.logic.packet_parse import PacketMeta

DOS_THRESHOLD = int(os.environ.get("DOS_THRESHOLD", "100"))
HEURISTIC_DROP = os.environ.get("HEURISTIC_DROP", "1") == "1"

_lock = threading.Lock()
_windows: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20000))


def reset_inspectors() -> None:
    with _lock:
        _windows.clear()


def inspect_dos(meta: PacketMeta) -> Optional[str]:
    now = time.time()
    with _lock:
        q = _windows[meta.src]
        q.append(now)
        rate = sum(1 for t in q if t > now - 1.0)
    if rate > DOS_THRESHOLD:
        record(
            {
                "action": "ALERT",
                "src": meta.src,
                "dst": meta.dst,
                "proto": meta.proto_name,
                "reason": "dos_rate",
                "rate": rate,
            }
        )
        if os.environ.get("HEURISTIC_DROP", "1") == "1":
            return "dos_rate"
    return None


def default_inspectors():
    return [inspect_dos]
