from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP
from collections import deque
import time

# Log file for attacks
LOG_FILE = "logs/attacks.log"

# Thresholds
DOS_THRESHOLD = 100  # packets per second
ARP_THRESHOLD = 5  # ARP replies per second

# Data structures
packet_counter = deque(maxlen=10000)
arp_cache = {}


def detect_dos(pkt):
    """
    Detects DoS (Denial of Service) attacks based on packet rate.
    - Appends the current timestamp to a buffer.
    - Calculates the number of packets in the last second.
    - Raises an alert if the packet rate exceeds the DOS_THRESHOLD.
    """
    global packet_counter
    packet_counter.append(time.time())

    # Count packets in the last second
    one_second_window = [t for t in packet_counter if t > time.time() - 1]
    packet_rate = len(one_second_window)

    if packet_rate > DOS_THRESHOLD:
        # Extract the source IP address if available
        src_ip = pkt[0][1].src if pkt.haslayer("IP") else None
        if src_ip:
            log_event(f"[ALERT] DoS attack detected from {src_ip}! Rate: {packet_rate}")


def detect_dns_poisoning(pkt):
    """
    Detects DNS poisoning attacks by comparing DNS responses.
    - Verifies if the packet is a DNS response (QR=1).
    - Checks if the DNS response has conflicting IP addresses for the same domain.
    """
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # QR=1 means response
        dns_id = pkt[DNS].id
        domain = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else None
        ip_list = [rdata.rdata for rdata in pkt[DNS].an] if pkt[DNS].an else []

        # Compare against cache
        if domain in arp_cache:
            cached_ips = arp_cache[domain]
            if set(cached_ips) != set(ip_list):  # IPs mismatch - possible poisoning
                log_event(f"[ALERT] DNS poisoning detected for {domain}! Previous: {cached_ips}, Current: {ip_list}")
        # Update cache
        arp_cache[domain] = ip_list


def detect_dhcp_spoofing(pkt):
    """
    Detects DHCP spoofing attacks by identifying conflicting DHCP servers.
    - Monitors DHCP offer messages and logs alerts if multiple servers offer conflicting IPs.
    """
    if pkt.haslayer(DHCP) and pkt[DHCP].options:
        dhcp_opts = dict(pkt[DHCP].options)
        if dhcp_opts.get("message-type") == 2:  # DHCP Offer
            offered_ip = pkt[BOOTP].yiaddr
            server_ip = pkt[IP].src
            if "dhcp_servers" in arp_cache:
                if server_ip not in arp_cache["dhcp_servers"]:
                    log_event(f"[ALERT] DHCP spoofing detected! Conflicting DHCP server: {server_ip}")
            else:
                arp_cache["dhcp_servers"] = [server_ip]


def detect_arp_spoofing(pkt):
    """
    Detects ARP spoofing by identifying conflicting ARP replies.
    - Compares MAC addresses associated with the same IP address.
    - Logs an alert if multiple MAC addresses claim the same IP.
    """
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip in arp_cache:
            if arp_cache[src_ip] != src_mac:  # MAC address mismatch
                log_event(
                    f"[ALERT] ARP spoofing detected! IP {src_ip} is claimed by multiple MACs: {arp_cache[src_ip]} and {src_mac}")
        # Update cache
        arp_cache[src_ip] = src_mac


def log_event(message):
    """
    Logs and prints detection alerts.
    - Appends the alert message to a log file.
    - Prints the alert message to the console.
    """
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{message}\n")
    print(message)


# Packet handler
def handle_packet(pkt):
    """
    Central handler for all detection mechanisms.
    """
    detect_dos(pkt)
    detect_dns_poisoning(pkt)
    detect_dhcp_spoofing(pkt)
    detect_arp_spoofing(pkt)


if __name__ == "__main__":
    print("Starting detection engine...")
    sniff(prn=handle_packet, store=False)  # Start packet sniffing
