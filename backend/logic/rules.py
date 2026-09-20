"""Priority rule matcher with file hot-reload."""
from __future__ import annotations

import ipaddress
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.logic.packet_parse import PacketMeta
from backend.utils.json_handler import load_json, save_json

RULES_FILE = "rules.json"
_lock = threading.RLock()
_compiled: List["CompiledRule"] = []
_mtime: Optional[float] = None
_loaded = False


def _rules_path() -> str:
    from backend.utils.json_handler import DATA_DIR

    return str(DATA_DIR / RULES_FILE)


@dataclass
class CompiledRule:
    id: int
    priority: int
    action: str
    enabled: bool
    src: Optional[ipaddress._BaseNetwork]
    dst: Optional[ipaddress._BaseNetwork]
    proto: Optional[int]
    sport: Optional[int]
    dport: Optional[int]
    raw: Dict[str, Any] = field(default_factory=dict)

    def matches(self, meta: PacketMeta) -> bool:
        if not self.enabled:
            return False
        if self.src and ipaddress.ip_address(meta.src) not in self.src:
            return False
        if self.dst and ipaddress.ip_address(meta.dst) not in self.dst:
            return False
        if self.proto is not None and meta.proto != self.proto:
            return False
        if self.sport is not None and meta.sport != self.sport:
            return False
        if self.dport is not None and meta.dport != self.dport:
            return False
        return True


_PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1, "6": 6, "17": 17, "1": 1}


def _parse_proto(value: Any) -> Optional[int]:
    if value is None or value == "" or value == "any":
        return None
    if isinstance(value, int):
        return value
    return _PROTO_MAP.get(str(value).lower())


def _parse_net(value: Any) -> Optional[ipaddress._BaseNetwork]:
    if not value or value in ("any", "*", "0.0.0.0/0"):
        return None
    return ipaddress.ip_network(str(value), strict=False)


def compile_rule(entry: Dict[str, Any]) -> CompiledRule:
    action = str(entry.get("action", "deny")).lower()
    if action not in ("allow", "deny"):
        action = "deny"
    return CompiledRule(
        id=int(entry.get("id") or 0),
        priority=int(entry.get("priority") or 0),
        action=action,
        enabled=bool(entry.get("enabled", True)),
        src=_parse_net(entry.get("src")),
        dst=_parse_net(entry.get("dst")),
        proto=_parse_proto(entry.get("proto")),
        sport=int(entry["sport"]) if entry.get("sport") not in (None, "", "any") else None,
        dport=int(entry["dport"]) if entry.get("dport") not in (None, "", "any") else None,
        raw=entry,
    )


def load_rules(force: bool = False) -> List[CompiledRule]:
    global _compiled, _mtime, _loaded
    path = _rules_path()
    try:
        mt = os.path.getmtime(path) if os.path.exists(path) else None
    except OSError:
        mt = None
    with _lock:
        if not force and _loaded and mt == _mtime:
            return list(_compiled)
        data = load_json(RULES_FILE)
        if not isinstance(data, list):
            data = []
        compiled = [compile_rule(e) for e in data if isinstance(e, dict)]
        compiled.sort(key=lambda r: r.priority, reverse=True)
        _compiled = compiled
        _mtime = mt
        _loaded = True
        return list(_compiled)


def match_rule(meta: PacketMeta) -> Optional[CompiledRule]:
    for rule in load_rules():
        if rule.matches(meta):
            return rule
    return None


def list_rules() -> List[Dict[str, Any]]:
    data = load_json(RULES_FILE)
    return data if isinstance(data, list) else []


def save_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    save_json(RULES_FILE, rules)
    load_rules(force=True)
    return rules


def upsert_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    rules = list_rules()
    rid = payload.get("id")
    if rid is None:
        rid = (max((int(r.get("id") or 0) for r in rules), default=0) + 1)
        payload["id"] = rid
        payload.setdefault("enabled", True)
        payload.setdefault("priority", 100)
        payload.setdefault("action", "deny")
        rules.append(payload)
    else:
        rid = int(rid)
        payload["id"] = rid
        found = False
        for i, r in enumerate(rules):
            if int(r.get("id") or 0) == rid:
                merged = dict(r)
                merged.update(payload)
                rules[i] = merged
                payload = merged
                found = True
                break
        if not found:
            payload.setdefault("enabled", True)
            rules.append(payload)
    save_rules(rules)
    return payload


def delete_rule(rule_id: int) -> Optional[Dict[str, Any]]:
    rules = list_rules()
    kept = []
    deleted = None
    for r in rules:
        if int(r.get("id") or 0) == int(rule_id):
            deleted = r
        else:
            kept.append(r)
    if deleted is None:
        return None
    save_rules(kept)
    return deleted
