"""Stateful NFQUEUE heuristics: SYN flood, DNS poisoning, IP-MAC spoofing.

Uses only the Python standard library for packet parsing (no Scapy).
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

PROTO_TCP = 6
PROTO_UDP = 17
TCP_SYN = 0x02
TCP_ACK = 0x10
DNS_QR = 0x8000

PendingKey = Tuple[str, str, int]


def normalize_mac(hw_addr: Any) -> Optional[str]:
    if hw_addr is None:
        return None
    if isinstance(hw_addr, str):
        text = hw_addr.strip().lower().replace("-", ":")
        if not text:
            return None
        parts = [p for p in text.split(":") if p]
        if len(parts) >= 6:
            try:
                return ":".join(f"{int(p, 16):02x}" for p in parts[:6])
            except ValueError:
                return None
        return text
    raw = bytes(hw_addr)
    if len(raw) < 6:
        return None
    return ":".join(f"{b:02x}" for b in raw[:6])


def _parse_ipv4(payload: bytes) -> Optional[dict]:
    if payload is None or len(payload) < 20:
        return None
    version_ihl = payload[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    src = socket.inet_ntoa(payload[12:16])
    dst = socket.inet_ntoa(payload[16:20])
    return {"ihl": ihl, "proto": proto, "src": src, "dst": dst, "l4": payload[ihl:]}


class StatefulHeuristicsEngine:
    def __init__(self, arp_table_path: Optional[str] = "/proc/net/arp"):
        self._lock = threading.RLock()
        self._last_prune = 0.0
        self.syn_flood_enabled = True
        self.syn_window_seconds = 5.0
        self.syn_max = 50
        self.dns_enabled = True
        self.dns_query_ttl = 5.0
        self.dns_mismatch_window = 5.0
        self.dns_max_mismatches = 20
        self.arp_enabled = True
        self._syn_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._dns_pending: Dict[PendingKey, float] = {}
        self._dns_mismatches: Dict[str, Deque[float]] = defaultdict(deque)
        self._ip_mac: Dict[str, str] = {}
        if arp_table_path:
            self._seed_arp_table(arp_table_path)

    def _seed_arp_table(self, path: str) -> None:
        arp_path = Path(path)
        if not arp_path.is_file():
            return
        try:
            lines = arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip, mac = parts[0], normalize_mac(parts[3])
            if ip and mac and mac != "00:00:00:00:00:00":
                self._ip_mac[ip] = mac

    def reset(self) -> None:
        with self._lock:
            self._syn_times.clear()
            self._dns_pending.clear()
            self._dns_mismatches.clear()
            self._ip_mac.clear()
            self._last_prune = 0.0

    def prune(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._prune_unlocked(now)

    def _prune_unlocked(self, now: float) -> None:
        syn_cut = now - self.syn_window_seconds
        stale_syn = []
        for ip, times in self._syn_times.items():
            while times and times[0] <= syn_cut:
                times.popleft()
            if not times:
                stale_syn.append(ip)
        for ip in stale_syn:
            del self._syn_times[ip]

        expired = [key for key, exp in self._dns_pending.items() if exp <= now]
        for key in expired:
            del self._dns_pending[key]

        mis_cut = now - self.dns_mismatch_window
        stale_mis = []
        for ip, times in self._dns_mismatches.items():
            while times and times[0] <= mis_cut:
                times.popleft()
            if not times:
                stale_mis.append(ip)
        for ip in stale_mis:
            del self._dns_mismatches[ip]
        self._last_prune = now

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune >= 1.0:
            self._prune_unlocked(now)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            self._prune_unlocked(now)
            return {
                "syn_flood": {
                    "enabled": self.syn_flood_enabled,
                    "max_syn": self.syn_max,
                    "window_seconds": self.syn_window_seconds,
                    "tracked_sources": len(self._syn_times),
                },
                "dns_poisoning": {
                    "enabled": self.dns_enabled,
                    "query_ttl": self.dns_query_ttl,
                    "max_mismatches": self.dns_max_mismatches,
                    "mismatch_window": self.dns_mismatch_window,
                    "pending_queries": len(self._dns_pending),
                    "mismatch_sources": len(self._dns_mismatches),
                },
                "arp_spoofing": {
                    "enabled": self.arp_enabled,
                    "bindings": len(self._ip_mac),
                },
            }

    def update_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        with self._lock:
            syn = payload.get("syn_flood")
            if isinstance(syn, dict):
                if "enabled" in syn:
                    self.syn_flood_enabled = bool(syn["enabled"])
                if "max_syn" in syn:
                    self.syn_max = max(1, int(syn["max_syn"]))
                if "window_seconds" in syn:
                    self.syn_window_seconds = float(syn["window_seconds"])
            dns = payload.get("dns_poisoning")
            if isinstance(dns, dict):
                if "enabled" in dns:
                    self.dns_enabled = bool(dns["enabled"])
                if "query_ttl" in dns:
                    self.dns_query_ttl = float(dns["query_ttl"])
                if "max_mismatches" in dns:
                    self.dns_max_mismatches = max(1, int(dns["max_mismatches"]))
                if "mismatch_window" in dns:
                    self.dns_mismatch_window = float(dns["mismatch_window"])
            arp = payload.get("arp_spoofing")
            if isinstance(arp, dict) and "enabled" in arp:
                self.arp_enabled = bool(arp["enabled"])
        return self.snapshot()

    def evaluate(self, raw_bytes: bytes, hw_addr: Any = None) -> Optional[str]:
        parsed = _parse_ipv4(raw_bytes)
        if parsed is None:
            return None
        now = time.time()
        with self._lock:
            self._maybe_prune(now)
            if self.syn_flood_enabled:
                hit = self._check_syn_flood(parsed, now)
                if hit:
                    return hit
            if self.dns_enabled:
                hit = self._check_dns(parsed, now)
                if hit:
                    return hit
            if self.arp_enabled:
                hit = self._check_arp(parsed["src"], hw_addr)
                if hit:
                    return hit
        return None

    def _check_syn_flood(self, parsed: dict, now: float) -> Optional[str]:
        if parsed["proto"] != PROTO_TCP:
            return None
        l4 = parsed["l4"]
        if len(l4) < 14:
            return None
        flags = l4[13]
        if not (flags & TCP_SYN) or (flags & TCP_ACK):
            return None
        src = parsed["src"]
        times = self._syn_times[src]
        times.append(now)
        cut = now - self.syn_window_seconds
        while times and times[0] <= cut:
            times.popleft()
        if len(times) > self.syn_max:
            return "heuristic:syn_flood"
        return None

    def _check_dns(self, parsed: dict, now: float) -> Optional[str]:
        if parsed["proto"] != PROTO_UDP:
            return None
        l4 = parsed["l4"]
        if len(l4) < 8 + 12:
            return None
        sport, dport = struct.unpack("!HH", l4[0:4])
        dns = l4[8:]
        txid, dns_flags = struct.unpack("!HH", dns[0:4])
        is_response = bool(dns_flags & DNS_QR)
        src, dst = parsed["src"], parsed["dst"]
        if not is_response and dport == 53:
            self._dns_pending[(src, dst, txid)] = now + self.dns_query_ttl
            return None
        if is_response and sport == 53:
            key = (dst, src, txid)
            expiry = self._dns_pending.get(key)
            if expiry is not None and expiry > now:
                del self._dns_pending[key]
                return None
            mismatches = self._dns_mismatches[src]
            mismatches.append(now)
            cut = now - self.dns_mismatch_window
            while mismatches and mismatches[0] <= cut:
                mismatches.popleft()
            if expiry is None or expiry <= now:
                return "heuristic:dns_poisoning"
            if len(mismatches) > self.dns_max_mismatches:
                return "heuristic:dns_poisoning"
        return None

    def _check_arp(self, src_ip: str, hw_addr: Any) -> Optional[str]:
        mac = normalize_mac(hw_addr)
        if mac is None:
            return None
        trusted = self._ip_mac.get(src_ip)
        if trusted is None:
            self._ip_mac[src_ip] = mac
            return None
        if trusted != mac:
            return "heuristic:arp_spoofing"
        return None


engine = StatefulHeuristicsEngine()
