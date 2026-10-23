"""NFQUEUE worker: parse payload, decide, ACCEPT/DROP. Mock mode for tests."""
from __future__ import annotations

import os
import signal
import threading
from typing import Optional

from backend.helpers.logger import log_system_event
from backend.logic import nft_hook
from backend.logic.event_log import record
from backend.logic.ml_pipeline import enqueue_meta
from backend.logic.packet_parse import parse_ipv4_5tuple
from backend.logic.verdict import ACCEPT, DROP, decide

try:
    from netfilterqueue import NetfilterQueue  # type: ignore
except Exception:  # pragma: no cover - optional native dep
    NetfilterQueue = None


def _use_mock() -> bool:
    if os.environ.get("NFQUEUE_MOCK", "").strip() in ("1", "true", "TRUE", "yes"):
        return True
    if os.environ.get("NETFILTERQUEUE_MOCK", "").strip() in ("1", "true", "TRUE", "yes"):
        return True
    return NetfilterQueue is None


class IpsWorker:
    def __init__(self, queue_num: Optional[int] = None):
        self.queue_num = int(os.environ.get("NFQUEUE_NUM", queue_num if queue_num is not None else 0))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._nfq = None
        self.running = False
        self.mock = False
        self._lock = threading.Lock()
        self._signals_bound = False

    def process_payload(self, payload: bytes, hw_addr=None) -> str:
        meta = parse_ipv4_5tuple(payload)
        if meta is None:
            return ACCEPT
        action, details = decide(meta, raw=payload, hw_addr=hw_addr)
        details["action"] = action
        record(details)
        try:
            enqueue_meta(meta)
        except Exception:
            pass
        return action

    def _on_packet(self, pkt) -> None:
        try:
            payload = pkt.get_payload()
            hw_addr = None
            getter = getattr(pkt, "get_hw", None)
            if callable(getter):
                try:
                    hw_addr = getter()
                except Exception:
                    hw_addr = None
            action = self.process_payload(payload, hw_addr=hw_addr)
            if action == DROP:
                pkt.drop()
            else:
                pkt.accept()
        except Exception:
            try:
                pkt.accept()
            except Exception:
                pass

    def _run_real(self) -> None:
        nfq = NetfilterQueue()
        self._nfq = nfq
        nfq.bind(self.queue_num, self._on_packet)
        try:
            nfq.run()
        finally:
            try:
                nfq.unbind()
            except Exception:
                pass
            self._nfq = None

    def _run_mock(self) -> None:
        while not self._stop.wait(0.2):
            pass

    def _loop(self) -> None:
        try:
            if self.mock:
                self._run_mock()
            else:
                self._run_real()
        except Exception as exc:
            log_system_event(f"NFQUEUE worker error: {exc}")
        finally:
            nft_hook.remove(self.queue_num)
            self.running = False
            log_system_event("IPS worker stopped (fail-open: NFQUEUE rules removed)")

    def _bind_signals(self) -> None:
        if self._signals_bound:
            return

        def _handler(signum, frame):
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
            self._signals_bound = True
        except ValueError:
            # Not in main thread
            pass

    def start(self) -> dict:
        with self._lock:
            if self.running:
                return {"status": "already running", "ok": False}
            self.mock = _use_mock()
            self._stop.clear()
            self._bind_signals()
            if not self.mock:
                nft_hook.install(self.queue_num)
            else:
                log_system_event("IPS worker starting in NFQUEUE_MOCK mode")
            self.running = True
            self._thread = threading.Thread(target=self._loop, name="nfqueue-worker", daemon=True)
            self._thread.start()
            log_system_event(f"IPS worker started mock={self.mock} queue={self.queue_num}")
            return {"status": "running", "ok": True, "mock": self.mock}

    def stop(self) -> dict:
        with self._lock:
            if not self.running:
                nft_hook.remove(self.queue_num)
                return {"status": "stopped", "ok": False}
            self._stop.set()
            if self._nfq is not None:
                try:
                    self._nfq.unbind()
                except Exception:
                    pass
            nft_hook.remove(self.queue_num)
            self.running = False
            log_system_event("IPS worker stop requested")
            return {"status": "stopped", "ok": True}

    def status(self) -> dict:
        return {
            "status": "running" if self.running else "stopped",
            "mock": self.mock,
            "queue_num": self.queue_num,
            "fail_open": True,
        }


worker = IpsWorker()
