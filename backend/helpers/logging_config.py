# backend/helpers/logging_config.py
import logging
import os

# Set log path relative to the project root
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
log_dir = os.path.join(base_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)


def setup_logger(name, log_filename):
    log_path = os.path.join(log_dir, log_filename)
    handler = logging.FileHandler(log_path)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        logger.addHandler(handler)
        logger.addHandler(logging.StreamHandler())

    return logger


# Define separate loggers for different purposes
attack_logger = setup_logger("AttackLogger", "attacks.log")
system_logger = setup_logger("SystemLogger", "ips_app.log")
user_logger = setup_logger("UserLogger", "user_actions.log")
