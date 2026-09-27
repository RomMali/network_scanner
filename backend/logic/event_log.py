"""In-memory structured IPS event log for the control-plane API."""
from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from backend.helpers.logger import log_attack_blocked, log_system_event

_MAX = 2000
_events: Deque[Dict[str, Any]] = deque(maxlen=_MAX)
_lock = threading.Lock()

_JSONL = Path(__file__).resolve().parents[2] / "logs" / "events.jsonl"


def _ensure_log_dir() -> None:
    _JSONL.parent.mkdir(parents=True, exist_ok=True)


def record(event: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(event)
    event.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with _lock:
        _events.append(event)
    _ensure_log_dir()
    try:
        with open(_JSONL, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        pass
    action = str(event.get("action", "")).upper()
    src = event.get("src")
    if action == "DROP" and src:
        log_attack_blocked(src)
    else:
        log_system_event(
            f"verdict={action} src={src} dst={event.get('dst')} "
            f"proto={event.get('proto')} rule_id={event.get('rule_id')}"
        )
    return event


def get_events(limit: int = 200, action: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock:
        items = list(_events)
    if action:
        want = action.upper()
        items = [e for e in items if str(e.get("action", "")).upper() == want]
    return items[-limit:]


def clear_events() -> None:
    with _lock:
        _events.clear()


def format_text(limit: int = 200) -> str:
    lines = []
    for e in get_events(limit=limit):
        lines.append(
            f"{e.get('ts')} {e.get('action')} src={e.get('src')} dst={e.get('dst')} "
            f"proto={e.get('proto')} sport={e.get('sport')} dport={e.get('dport')} "
            f"rule_id={e.get('rule_id')} reason={e.get('reason')}"
        )
    return "\n".join(lines) if lines else "No IPS events yet.\n"
