import os
import signal
from unittest.mock import patch

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic import nft_hook
from backend.logic.nft_hook import COMMENT, hooks_mocked, remove_rules
from backend.logic.nfqueue_worker import worker
from main import reset_shutdown_guard, shutdown


def setup_function():
    os.environ["NFQUEUE_MOCK"] = "1"
    nft_hook.clear_ops()
    reset_shutdown_guard()
    worker.stop()


def test_hooks_mocked_skips_real_subprocess():
    assert hooks_mocked()
    with patch("backend.logic.nft_hook.subprocess.run") as run:
        nft_hook.install(0)
        nft_hook.remove_rules(0)
        run.assert_not_called()


def test_remove_rules_issues_forward_delete_with_comment():
    nft_hook.clear_ops()
    remove_rules(0)
    deletes = [op for op in nft_hook.recorded_ops() if len(op) > 1 and op[1] == "-D"]
    assert deletes
    tagged = [op for op in deletes if COMMENT in op]
    assert tagged
    assert all("FORWARD" in op for op in tagged)
    assert all("NFQUEUE" in op for op in tagged)
    assert all("INPUT" not in op for op in tagged)


def test_shutdown_stops_worker_and_calls_remove_rules():
    worker.start()
    assert worker.running
    with patch("backend.logic.nft_hook.remove_rules") as remover:
        with patch("backend.logic.event_log.stop") as stop_logs:
            shutdown(signum=signal.SIGINT, exit_process=False)
            stop_logs.assert_called()
            remover.assert_called()
    assert worker.running is False
