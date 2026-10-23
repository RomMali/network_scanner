import os

os.environ.setdefault("NFQUEUE_MOCK", "1")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-must-be-32bytes!")
os.environ.setdefault("HEURISTIC_DROP", "0")
os.environ.setdefault("IPS_DB_PATH", "file:ips_pytest?mode=memory&cache=shared")
os.environ.setdefault("IPS_DB_URI", "1")
