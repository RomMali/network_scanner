import os

import pytest

os.environ.setdefault("NFQUEUE_MOCK", "1")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-must-be-32bytes!")
os.environ.setdefault("HEURISTIC_DROP", "0")
os.environ.setdefault("IPS_DB_PATH", "file:ips_pytest?mode=memory&cache=shared")
os.environ.setdefault("IPS_DB_URI", "1")
os.environ.setdefault("THREAT_INTEL_AUTO_REFRESH", "0")


@pytest.fixture(autouse=True)
def _reset_threat_intel():
    from backend.logic.threat_intel import manager

    manager.enabled = True
    manager.malicious_ips.clear()
    manager._nets.clear()
    manager.last_updated = None
    manager.last_error = None
    yield
