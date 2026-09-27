# backend/helpers/logging_config.py
import logging
from pathlib import Path

base_dir = Path(__file__).resolve().parents[2]
log_dir = base_dir / "logs"
log_dir.mkdir(parents=True, exist_ok=True)


def setup_logger(name, log_filename):
    log_path = log_dir / log_filename
    handler = logging.FileHandler(log_path)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        logger.addHandler(handler)
        logger.addHandler(logging.StreamHandler())

    return logger


attack_logger = setup_logger("AttackLogger", "attacks.log")
system_logger = setup_logger("SystemLogger", "ips_app.log")
user_logger = setup_logger("UserLogger", "user_actions.log")
