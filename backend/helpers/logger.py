# backend/helpers/logger.py
from .logging_config import attack_logger, system_logger, user_logger


def log_message(message):
    system_logger.info(message)


def log_attack_detected(source_ip, attack_type, severity=None):
    attack_logger.error(f"Attack detected from {source_ip} - Type: {attack_type} - Severity: {severity or 'Unknown'}")


def log_attack_blocked(source_ip):
    attack_logger.info(f"Attack from {source_ip} was blocked successfully.")


def log_system_event(message):
    system_logger.info(f"System: {message}")


def log_user_action(user_id, action):
    user_logger.info(f"User {user_id} performed action: {action}")
