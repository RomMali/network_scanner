import os

os.environ["NFQUEUE_MOCK"] = "1"
os.environ["HEURISTIC_DROP"] = "0"

from backend.logic.packet_parse import PacketMeta, build_ipv4_packet, parse_ipv4_5tuple
from backend.logic.verdict import ACCEPT, DROP, add_drop_source, clear_drop_sources, decide


def test_parse_ipv4_5tuple():
    raw = build_ipv4_packet("10.0.0.2", "10.0.0.1", proto=6, sport=1111, dport=80)
    meta = parse_ipv4_5tuple(raw)
    assert meta is not None
    assert meta.src == "10.0.0.2"
    assert meta.dst == "10.0.0.1"
    assert meta.proto == 6
    assert meta.sport == 1111
    assert meta.dport == 80


def test_default_accept():
    clear_drop_sources()
    meta = PacketMeta("8.8.8.8", "1.1.1.1", 6, 1234, 443, 40)
    action, details = decide(meta)
    assert action == ACCEPT
    assert details["reason"] == "default_accept"


def test_drop_listed_source():
    clear_drop_sources()
    add_drop_source("192.0.2.10")
    meta = PacketMeta("192.0.2.10", "192.0.2.1", 6, 1, 80, 40)
    action, details = decide(meta)
    assert action == DROP
    assert details["reason"] == "drop_sources"
    other = PacketMeta("192.0.2.11", "192.0.2.1", 6, 1, 80, 40)
    action2, _ = decide(other)
    assert action2 == ACCEPT
    clear_drop_sources()
