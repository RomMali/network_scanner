import os
import time
from backend.helpers.logger import log_attack_blocked

LOG_FILE = "logs/attacks.log"
blocked_ips = set()


def block_ip(ip):
    """
    Blocks the given IP using iptables.
    """
    if ip not in blocked_ips:
        print(f"[BLOCKING] IP: {ip}")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"Blocked IP: {ip} at {time.ctime()}\n")
        log_attack_blocked(ip)
