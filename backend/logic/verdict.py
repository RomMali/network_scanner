"""Inline verdict: allow/deny rules, blacklist, drop_sources, then default ACCEPT."""
from __future__ import annotations

from typing import Any, Dict, Optional, Set, Tuple

from backend.logic.heuristics import engine as heuristics_engine
from backend.logic.packet_parse import PacketMeta
from backend.logic.rules import match_rule

ACCEPT = "ACCEPT"
DROP = "DROP"

drop_sources: Set[str] = set()


def add_drop_source(ip: str) -> None:
    drop_sources.add(ip)


def clear_drop_sources() -> None:
    drop_sources.clear()


def _blacklist_ips() -> Set[str]:
    try:
        from db.json_storage import json_storage

        return set(json_storage.iter_blacklist_ips())
    except Exception:
        return set()


def decide(
    meta: PacketMeta,
    inspectors=None,
    raw: Optional[bytes] = None,
    hw_addr: Any = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Return (ACCEPT|DROP, details).
    Static JSON rules (and blacklist / drop_sources) run first.
    Heuristics see the raw payload only when no static match returned.
    ML must not be passed here for blocking.
    """
    details: Dict[str, Any] = {
        "src": meta.src,
        "dst": meta.dst,
        "proto": meta.proto_name,
        "sport": meta.sport,
        "dport": meta.dport,
        "rule_id": None,
        "reason": "default_accept",
    }

    rule = match_rule(meta)
    if rule is not None:
        details["rule_id"] = rule.id
        details["reason"] = f"rule_{rule.action}"
        action = ACCEPT if rule.action == "allow" else DROP
        details["action"] = action
        return action, details

    if meta.src in _blacklist_ips():
        details["reason"] = "blacklist"
        details["action"] = DROP
        return DROP, details

    if meta.src in drop_sources:
        details["reason"] = "drop_sources"
        details["action"] = DROP
        return DROP, details

    if raw:
        heuristic_id = heuristics_engine.evaluate(raw, hw_addr=hw_addr)
        if heuristic_id:
            details["rule_id"] = heuristic_id
            details["reason"] = heuristic_id
            details["action"] = DROP
            return DROP, details

    if inspectors:
        for inspect in inspectors:
            reason = inspect(meta)
            if reason:
                details["reason"] = str(reason)
                details["action"] = DROP
                return DROP, details

    details["action"] = ACCEPT
    return ACCEPT, details
