"""Install/remove FORWARD NFQUEUE hooks. Fail-open: purge on teardown."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Sequence

from backend.helpers.logger import log_system_event

COMMENT = "network_scanner-nfqueue"
DEFAULT_QUEUE = int(os.environ.get("NFQUEUE_NUM", "0"))
_ops: List[List[str]] = []


def _env_flag_on(name: str, default: str = "0") -> bool:
    val = os.environ.get(name, default)
    if val is None:
        val = default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def hooks_mocked() -> bool:
    return _env_flag_on("NFQUEUE_MOCK") or _env_flag_on("NETFILTERQUEUE_MOCK")


def _bin(name: str, env_key: str) -> str:
    return os.environ.get(env_key) or shutil.which(name) or name


def _iptables() -> str:
    return _bin("iptables", "IPTABLES_BIN")


def _run(args: Sequence[str]) -> subprocess.CompletedProcess:
    argv = list(args)
    _ops.append(argv)
    if hooks_mocked():
        # Do not touch the host. -A succeeds; -D / unknown stop the delete loop.
        action = argv[1] if len(argv) > 1 else ""
        code = 0 if action in ("-A", "-L", "-n", "--line-numbers") or "-L" in argv else 1
        return subprocess.CompletedProcess(argv, code, stdout="", stderr="")
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _forward_nfqueue_args(queue_num: int, action: str) -> List[str]:
    return [
        _iptables(),
        action,
        "FORWARD",
        "-m",
        "comment",
        "--comment",
        COMMENT,
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(queue_num),
    ]


def install(queue_num: int = DEFAULT_QUEUE) -> bool:
    """Attach NFQUEUE on FORWARD (NAT/routed path). Not INPUT."""
    remove_rules(queue_num)
    result = _run(_forward_nfqueue_args(queue_num, "-A"))
    if result.returncode != 0:
        log_system_event(
            f"nft_hook install skipped/failed: {result.stderr.strip() or result.stdout.strip()}"
        )
        return False
    log_system_event(f"FORWARD NFQUEUE installed queue-num={queue_num}")
    return True


def remove_rules(queue_num: int = DEFAULT_QUEUE) -> None:
    """Delete every FORWARD rule tagged network_scanner-nfqueue (idempotent)."""
    listed = _run(
        [_iptables(), "-L", "FORWARD", "--line-numbers", "-n", "--verbose"]
    )
    line_nums = []
    for raw in (listed.stdout or "").splitlines():
        if COMMENT not in raw:
            continue
        first = raw.split(None, 1)[0] if raw.strip() else ""
        if first.isdigit():
            line_nums.append(int(first))
    for num in sorted(line_nums, reverse=True):
        _run([_iptables(), "-D", "FORWARD", str(num)])
    while True:
        result = _run(_forward_nfqueue_args(queue_num, "-D"))
        if result.returncode != 0:
            break
    log_system_event(f"FORWARD NFQUEUE removed queue-num={queue_num}")


def remove(queue_num: int = DEFAULT_QUEUE) -> None:
    remove_rules(queue_num)


def recorded_ops() -> List[List[str]]:
    return list(_ops)


def clear_ops() -> None:
    _ops.clear()
