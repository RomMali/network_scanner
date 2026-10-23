import atexit
import os
import signal

from flask import Flask
from flask_jwt_extended import JWTManager
from backend.auth.routes import auth_bp
from backend.core.routes import core_bp

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-only-change-me")
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
jwt = JWTManager(app)

app.register_blueprint(core_bp)
app.register_blueprint(auth_bp, url_prefix="/auth")

_shutdown_done = False


def shutdown(signum=None, frame=None, exit_process=True):
    """Stop NFQUEUE + log writer and purge FORWARD hooks (fail-open)."""
    global _shutdown_done
    if _shutdown_done:
        return
    _shutdown_done = True
    from backend.logic.event_log import stop as stop_event_log
    from backend.logic.nft_hook import remove_rules
    from backend.logic.nfqueue_worker import worker
    from backend.logic.threat_intel import manager as threat_intel

    try:
        worker.stop()
    except Exception:
        pass
    try:
        stop_event_log()
    except Exception:
        pass
    try:
        threat_intel.stop()
    except Exception:
        pass
    try:
        remove_rules()
    except Exception:
        pass
    if exit_process and signum is not None:
        # Bypass Werkzeug waiting on non-daemon threads after SIGINT.
        os._exit(0)


def reset_shutdown_guard():
    global _shutdown_done
    _shutdown_done = False


def _install_signal_handlers():
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)


atexit.register(lambda: shutdown(exit_process=False))


if __name__ == "__main__":
    from backend.logic import nft_hook, nfqueue_worker

    print("[*] Initializing Network Scanner IPS...")

    nft_hook.install()
    nfqueue_worker.worker.start()
    # Worker may bind SIGINT/SIGTERM; reclaim them so teardown can os._exit.
    _install_signal_handlers()

    print("[*] IPS Engine Active. Starting API...")
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    app.run(
        host=host,
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
        threaded=True,
        use_reloader=False,
    )