import os
import socket
import struct

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-must-be-32bytes!"

from backend.logic.heuristics import StatefulHeuristicsEngine, engine as global_engine
from backend.logic.packet_parse import parse_ipv4_5tuple
from backend.logic.verdict import ACCEPT, DROP, decide
from main import app

PROTO_TCP = 6
PROTO_UDP = 17
TCP_SYN = 0x02
TCP_ACK = 0x10


def _ipv4_header(src: str, dst: str, proto: int, l4_len: int) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        20 + l4_len,
        0,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )


def build_tcp(src, dst, sport=12345, dport=80, flags=TCP_ACK) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        0,
        0,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    return _ipv4_header(src, dst, PROTO_TCP, len(tcp)) + tcp


def build_dns(src, dst, sport, dport, txid, qr: bool) -> bytes:
    flags = 0x8000 if qr else 0
    dns = struct.pack("!HHHHHH", txid, flags, 0, 0, 0, 0)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(dns), 0) + dns
    return _ipv4_header(src, dst, PROTO_UDP, len(udp)) + udp


def test_syn_flood_burst_drops_normal_tcp_passes():
    heur = StatefulHeuristicsEngine(arp_table_path=None)
    ack = build_tcp("198.51.100.10", "198.51.100.1", flags=TCP_ACK)
    assert heur.evaluate(ack) is None
    syn = build_tcp("198.51.100.10", "198.51.100.1", flags=TCP_SYN)
    for _ in range(50):
        assert heur.evaluate(syn) is None
    assert heur.evaluate(syn) == "heuristic:syn_flood"


def test_syn_flood_via_verdict_pipeline():
    global_engine.reset()
    global_engine.syn_max = 50
    src = "203.0.113.40"
    syn = build_tcp(src, "203.0.113.1", flags=TCP_SYN)
    meta = parse_ipv4_5tuple(syn)
    for _ in range(50):
        action, _ = decide(meta, raw=syn)
        assert action == ACCEPT
    action, details = decide(meta, raw=syn)
    assert action == DROP
    assert details["rule_id"] == "heuristic:syn_flood"
    global_engine.reset()


def test_dns_solicited_pass_unsolicited_drop():
    heur = StatefulHeuristicsEngine(arp_table_path=None)
    client, resolver = "192.0.2.10", "192.0.2.53"
    query = build_dns(client, resolver, sport=53000, dport=53, txid=0x4242, qr=False)
    reply = build_dns(resolver, client, sport=53, dport=53000, txid=0x4242, qr=True)
    assert heur.evaluate(query) is None
    assert heur.evaluate(reply) is None

    mismatch = build_dns(resolver, client, sport=53, dport=53000, txid=0x1111, qr=True)
    assert heur.evaluate(mismatch) == "heuristic:dns_poisoning"

    unsolicited = build_dns("198.51.100.9", client, sport=53, dport=53000, txid=0x4242, qr=True)
    assert heur.evaluate(unsolicited) == "heuristic:dns_poisoning"


def test_arp_spoofing_conflicting_mac():
    heur = StatefulHeuristicsEngine(arp_table_path=None)
    pkt = build_tcp("10.0.0.8", "10.0.0.1", flags=TCP_ACK)
    assert heur.evaluate(pkt, hw_addr="aa:bb:cc:dd:ee:ff") is None
    assert heur.evaluate(pkt, hw_addr="aa:bb:cc:dd:ee:ff") is None
    assert heur.evaluate(pkt, hw_addr="00:11:22:33:44:55") == "heuristic:arp_spoofing"


def test_heuristics_api_get_and_put():
    global_engine.reset()
    client = app.test_client()
    listed = client.get("/api/heuristics")
    assert listed.status_code == 200
    body = listed.get_json()
    assert "syn_flood" in body and "dns_poisoning" in body and "arp_spoofing" in body
    assert body["syn_flood"]["enabled"] is True

    client.post(
        "/auth/register",
        json={"username": "heur_adv", "password": "secret12", "advanced_mode": True},
    )
    token = client.post(
        "/auth/login", json={"username": "heur_adv", "password": "secret12"}
    ).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    updated = client.put(
        "/api/heuristics",
        json={"syn_flood": {"enabled": False, "max_syn": 10}},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.get_json()["syn_flood"]["enabled"] is False
    assert updated.get_json()["syn_flood"]["max_syn"] == 10

    client.post(
        "/auth/register",
        json={"username": "heur_std", "password": "secret12", "advanced_mode": False},
    )
    std_token = client.post(
        "/auth/login", json={"username": "heur_std", "password": "secret12"}
    ).get_json()["token"]
    denied = client.put(
        "/api/heuristics",
        json={"syn_flood": {"enabled": True}},
        headers={"Authorization": f"Bearer {std_token}"},
    )
    assert denied.status_code == 403
    global_engine.update_config({"syn_flood": {"enabled": True, "max_syn": 50}})
    global_engine.reset()
