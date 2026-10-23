"""SQLite-backed IPS event log with a non-blocking NFQUEUE writer queue."""
from __future__ import annotations

import atexit
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.helpers.logger import log_attack_blocked, log_system_event

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB = _ROOT / "data" / "ips.db"
_MAX_QUEUE = 10000
_BATCH_SIZE = 50
_PRUNE_INTERVAL = 30.0
_KEEP_ROWS = 10000
_KEEP_DAYS = 7
_FLUSH = object()
_STOP = object()

_queue: "queue.Queue[Any]" = queue.Queue(maxsize=_MAX_QUEUE)
_started = False
_start_lock = threading.Lock()
_thread: Optional[threading.Thread] = None
_writer_conn: Optional[sqlite3.Connection] = None
_read_lock = threading.Lock()


def _use_uri(path: str) -> bool:
    if os.environ.get("IPS_DB_URI", "").strip() in ("1", "true", "TRUE", "yes"):
        return True
    return path.startswith("file:") or path == ":memory:"


def db_path() -> str:
    env = os.environ.get("IPS_DB_PATH", "").strip()
    if env:
        return env
    if os.environ.get("NFQUEUE_MOCK", "").strip() in ("1", "true", "TRUE", "yes"):
        os.environ.setdefault("IPS_DB_URI", "1")
        return "file:ips_test?mode=memory&cache=shared"
    return str(_DEFAULT_DB)


def _connect() -> sqlite3.Connection:
    path = db_path()
    uri = _use_uri(path)
    if not uri and path not in (":memory:",):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, uri=uri, check_same_thread=False, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error:
        pass
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            action TEXT,
            rule_id TEXT,
            reason TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_network_events_src_ip ON network_events(src_ip)"
    )
    conn.commit()


def _normalize_action(value: Any) -> str:
    action = str(value or "").upper()
    if action == "ACCEPT":
        return "ALLOW"
    return action or "ALLOW"


def _normalize(event: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(event)
    ts = event.get("timestamp") or event.get("ts")
    if not ts:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(ts, str) and "T" in ts:
        ts = ts.replace("T", " ").split("+")[0].split("Z")[0][:19]
    return {
        "timestamp": ts,
        "src_ip": event.get("src_ip") or event.get("src"),
        "dst_ip": event.get("dst_ip") or event.get("dst"),
        "protocol": event.get("protocol") or event.get("proto"),
        "action": _normalize_action(event.get("action")),
        "rule_id": None if event.get("rule_id") is None else str(event.get("rule_id")),
        "reason": event.get("reason"),
    }


def _insert_batch(conn: sqlite3.Connection, rows: List[Dict[str, Any]]) -> None:
    conn.executemany(
        """
        INSERT INTO network_events
            (timestamp, src_ip, dst_ip, protocol, action, rule_id, reason)
        VALUES
            (:timestamp, :src_ip, :dst_ip, :protocol, :action, :rule_id, :reason)
        """,
        rows,
    )
    conn.commit()
    for row in rows:
        log_system_event(
            f"verdict={row['action']} src={row['src_ip']} dst={row['dst_ip']} "
            f"proto={row['protocol']} rule_id={row['rule_id']}"
        )
        if row["action"] == "DROP" and row["src_ip"]:
            log_attack_blocked(row["src_ip"], row["rule_id"])


def _prune(conn: sqlite3.Connection) -> None:
    conn.execute(
        "DELETE FROM network_events WHERE timestamp < datetime('now', ?)",
        (f"-{_KEEP_DAYS} days",),
    )
    conn.execute(
        """
        DELETE FROM network_events
        WHERE id NOT IN (
            SELECT id FROM network_events ORDER BY timestamp DESC, id DESC LIMIT ?
        )
        """,
        (_KEEP_ROWS,),
    )
    conn.commit()


def _db_writer_thread() -> None:
    global _writer_conn
    conn = _connect()
    _init_schema(conn)
    _writer_conn = conn
    batch: List[Dict[str, Any]] = []
    last_prune = time.time()

    def flush_batch() -> None:
        nonlocal batch
        if batch:
            _insert_batch(conn, batch)
            batch = []

    while True:
        try:
            item = _queue.get(timeout=0.2)
        except queue.Empty:
            flush_batch()
            if time.time() - last_prune >= _PRUNE_INTERVAL:
                _prune(conn)
                last_prune = time.time()
            continue
        try:
            if item is _STOP:
                flush_batch()
                break
            if isinstance(item, tuple) and item and item[0] is _FLUSH:
                flush_batch()
                item[1].set()
                continue
            batch.append(item)
            if len(batch) >= _BATCH_SIZE:
                flush_batch()
        finally:
            _queue.task_done()
    try:
        conn.close()
    except sqlite3.Error:
        pass
    _writer_conn = None


def _ensure_started() -> None:
    global _started, _thread
    if _started:
        return
    with _start_lock:
        if _started:
            return
        path = db_path()
        if not _use_uri(path) and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        _thread = threading.Thread(target=_db_writer_thread, name="ips-db-writer", daemon=True)
        _thread.start()
        _started = True


def log_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Enqueue an event and return immediately (NFQUEUE-safe)."""
    row = _normalize(event)
    _ensure_started()
    try:
        _queue.put_nowait(row)
    except queue.Full:
        pass
    return row


def record(event: Dict[str, Any]) -> Dict[str, Any]:
    return log_event(event)


def flush(timeout: float = 2.0) -> bool:
    """Block until queued events are committed (tests / API reads)."""
    _ensure_started()
    done = threading.Event()
    try:
        _queue.put((_FLUSH, done), timeout=timeout)
    except queue.Full:
        return False
    return done.wait(timeout)


def stop(timeout: float = 2.0) -> None:
    global _started
    if not _started:
        return
    try:
        _queue.put(_STOP, timeout=timeout)
    except queue.Full:
        pass
    if _thread is not None:
        _thread.join(timeout=timeout)
    _started = False


def query_events(
    action: Optional[str] = None,
    src_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    _ensure_started()
    flush(timeout=1.0)
    try:
        limit = min(max(int(limit), 1), 1000)
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(int(offset), 0)
    except (TypeError, ValueError):
        offset = 0
    clauses = []
    params: List[Any] = []
    if action:
        clauses.append("action = ?")
        params.append(_normalize_action(action))
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(str(rule_id))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _read_lock:
        conn = _connect()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM network_events {where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, timestamp, src_ip, dst_ip, protocol, action, rule_id, reason
                FROM network_events
                {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        finally:
            conn.close()
    items = [dict(r) for r in rows]
    return items, int(total)


def get_events(
    limit: int = 200,
    action: Optional[str] = None,
    src_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    items, _ = query_events(
        action=action, src_ip=src_ip, rule_id=rule_id, limit=limit, offset=offset
    )
    return items


def clear_events() -> None:
    _ensure_started()
    flush(timeout=1.0)
    with _read_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM network_events")
            conn.commit()
        finally:
            conn.close()


def format_text(limit: int = 200) -> str:
    items, _ = query_events(limit=limit, offset=0)
    if not items:
        return "No IPS events yet.\n"
    lines = []
    for e in items:
        lines.append(
            f"{e.get('timestamp')} {e.get('action')} src={e.get('src_ip')} dst={e.get('dst_ip')} "
            f"proto={e.get('protocol')} rule_id={e.get('rule_id')} reason={e.get('reason')}"
        )
    return "\n".join(lines)


atexit.register(stop)
