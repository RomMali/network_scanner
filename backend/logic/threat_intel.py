"""Public malicious-IP feeds with O(1) set lookup for the NFQUEUE path."""
from __future__ import annotations

import ipaddress
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

DEFAULT_FEED = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
REFRESH_INTERVAL_SECONDS = 24 * 60 * 60
EXPAND_PREFIXLEN_MIN = 24
_USER_AGENT = "network_scanner-ips/1.0"


def _auto_refresh_default() -> bool:
    mock = os.environ.get("NFQUEUE_MOCK", "0").strip().lower() in ("1", "true", "yes", "on")
    env = os.environ.get("THREAT_INTEL_AUTO_REFRESH", "").strip().lower()
    if env in ("0", "false", "no"):
        return False
    if env in ("1", "true", "yes"):
        return True
    return not mock


class ThreatIntelManager:
    def __init__(
        self,
        feed_url: str = DEFAULT_FEED,
        auto_refresh: Optional[bool] = None,
        timeout: float = 15.0,
    ):
        self.feed_url = feed_url
        self.timeout = timeout
        self.enabled = True
        self.malicious_ips: Set[str] = set()
        self._nets: List[ipaddress.IPv4Network] = []
        self.last_updated: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._auto_refresh = _auto_refresh_default() if auto_refresh is None else auto_refresh
        if self._auto_refresh:
            self._schedule()

    def _schedule(self) -> None:
        self._cancel_timer()
        timer = threading.Timer(REFRESH_INTERVAL_SECONDS, self._timer_refresh)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _timer_refresh(self) -> None:
        try:
            self.refresh_feeds()
        except Exception:
            pass
        if self._auto_refresh:
            self._schedule()

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def stop(self) -> None:
        self._auto_refresh = False
        self._cancel_timer()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            last = self.last_updated.isoformat() if self.last_updated else None
            return {
                "enabled": self.enabled,
                "ip_count": len(self.malicious_ips),
                "last_updated": last,
            }

    def is_malicious(self, ip: str) -> bool:
        if not self.enabled or not ip:
            return False
        with self._lock:
            if ip in self.malicious_ips:
                return True
            if not self._nets:
                return False
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in net for net in self._nets)

    def load_text(self, text: str) -> int:
        ips: Set[str] = set()
        nets: List[ipaddress.IPv4Network] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            token = line.split()[0]
            try:
                if "/" in token:
                    net = ipaddress.ip_network(token, strict=False)
                    if not isinstance(net, ipaddress.IPv4Network):
                        continue
                    if net.prefixlen >= EXPAND_PREFIXLEN_MIN:
                        ips.update(str(host) for host in net.hosts())
                        if net.prefixlen == 32:
                            ips.add(str(net.network_address))
                    else:
                        nets.append(net)
                else:
                    addr = ipaddress.ip_address(token)
                    if addr.version == 4:
                        ips.add(str(addr))
            except ValueError:
                continue
        with self._lock:
            self.malicious_ips = ips
            self._nets = nets
            self.last_updated = datetime.now(timezone.utc)
            self.last_error = None
            return len(ips)

    def refresh_feeds(self) -> Dict[str, Any]:
        req = urllib.request.Request(
            self.feed_url,
            headers={"User-Agent": _USER_AGENT},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            with self._lock:
                self.last_error = str(exc)
            raise
        text = body.decode("utf-8", errors="ignore")
        self.load_text(text)
        return self.status()


manager = ThreatIntelManager()
