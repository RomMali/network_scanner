"""IPv4 5-tuple parser for NFQUEUE payloads (no sniffing)."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional


PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}


@dataclass(frozen=True)
class PacketMeta:
    src: str
    dst: str
    proto: int
    sport: Optional[int]
    dport: Optional[int]
    length: int

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.proto, str(self.proto))


def parse_ipv4_5tuple(payload: bytes) -> Optional[PacketMeta]:
    if payload is None or len(payload) < 20:
        return None
    version_ihl = payload[0]
    version = version_ihl >> 4
    if version != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    src = socket.inet_ntoa(payload[12:16])
    dst = socket.inet_ntoa(payload[16:20])
    total_len = struct.unpack("!H", payload[2:4])[0]
    sport = dport = None
    if proto in (PROTO_TCP, PROTO_UDP) and len(payload) >= ihl + 4:
        sport, dport = struct.unpack("!HH", payload[ihl : ihl + 4])
    return PacketMeta(
        src=src,
        dst=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        length=total_len or len(payload),
    )


def build_ipv4_packet(
    src: str,
    dst: str,
    proto: int = PROTO_TCP,
    sport: int = 12345,
    dport: int = 80,
) -> bytes:
    """Minimal IPv4+TCP/UDP header for tests (checksums omitted)."""
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    ihl = 5
    total_len = 20 + 8
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        total_len,
        0,
        0,
        64,
        proto,
        0,
        src_b,
        dst_b,
    )
    l4 = struct.pack("!HH", sport, dport) + b"\x00\x00\x00\x00"
    return ip + l4
