"""Install/remove FORWARD NFQUEUE hooks. Fail-open: remove rules on teardown."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Sequence

from backend.helpers.logger import log_system_event

COMMENT = "network_scanner-nfqueue"
DEFAULT_QUEUE = int(os.environ.get("NFQUEUE_NUM", "0"))


def _bin(name: str, env_key: str) -> str:
    return os.environ.get(env_key) or shutil.which(name) or name


def _run(args: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        check=False,
    )


def _iptables() -> str:
    return _bin("iptables", "IPTABLES_BIN")


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
    remove(queue_num)
    result = _run(_forward_nfqueue_args(queue_num, "-A"))
    if result.returncode != 0:
        log_system_event(
            f"nft_hook install skipped/failed: {result.stderr.strip() or result.stdout.strip()}"
        )
        return False
    log_system_event(f"FORWARD NFQUEUE installed queue-num={queue_num}")
    return True


def remove(queue_num: int = DEFAULT_QUEUE) -> None:
    """Delete all matching FORWARD NFQUEUE rules (fail-open)."""
    while True:
        result = _run(_forward_nfqueue_args(queue_num, "-D"))
        if result.returncode != 0:
            break
    log_system_event(f"FORWARD NFQUEUE removed queue-num={queue_num}")
