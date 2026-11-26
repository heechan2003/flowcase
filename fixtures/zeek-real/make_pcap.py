# /// script
# requires-python = ">=3.12"
# dependencies = ["scapy==2.6.1"]
# ///
"""Write `trace.pcap`: a few minutes of synthetic traffic for real Zeek to read.

Run it with `make zeek-fixture` from the repository root, which then runs Zeek on the capture (see
`README.md`). The capture is byte-stable: every address, port, sequence number, payload and
timestamp below is fixed.

Each exchange exercises one loader rule, and
`packages/triage/tests/integration/source/test_zeek_real.py` restates what it should produce:

| exchange           | what the loader should make of it                                  |
|--------------------|--------------------------------------------------------------------|
| DNS answered       | a complete DNS session; the address carries the name to the client |
| TLS with SNI       | `sni` from ssl.log, `dns` from the earlier answer                  |
| HTTP after DNS     | outbound TCP named only by DNS                                     |
| inbound SSH-like   | the remote side opened it: `initiator` is `server`                 |
| long upload        | one long flow of exactly `UPLOAD_BYTES`, split over three minutes  |
| DNS unanswered     | an unanswered DNS session                                          |
| lone DNS reply     | Zeek's `dns_unmatched_reply` weird: an unsolicited reply           |

Addresses are documentation ranges (servers) and 10.0.0.0/8 (local hosts); names end in `.test`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

OUT = Path(__file__).resolve().parent / "trace.pcap"
DAY_START = datetime(2026, 3, 2, tzinfo=UTC).timestamp()

LAPTOP = "10.1.0.10"
WORKSTATION = "10.1.0.20"
BACKUP_CLIENT = "10.1.0.30"
RESOLVER = "198.51.100.53"
SHOP = "203.0.113.10"
FILES = "203.0.113.30"
VAULT = "203.0.113.40"
SCANNER = "192.0.2.25"

SHOP_NAME = "www.shop.test"
FILES_NAME = "files.shop.test"
UPLOAD_BYTES = 1_200_000
SEGMENT = 1_200

LOCAL_MAC = "02:00:00:00:00:01"
GATEWAY_MAC = "02:00:00:00:00:02"


def at(clock: str) -> float:
    """Seconds since the epoch for `HH:MM:SS[.fff]` on the capture's day (UTC)."""
    hours, minutes, seconds = clock.split(":")
    return DAY_START + int(hours) * 3600 + int(minutes) * 60 + float(seconds)


@dataclass
class Capture:
    packets: list[Any] = field(default_factory=list)

    def add(self, when: float, src: str, dst: str, layer: Any) -> None:
        local_src = src.startswith("10.")
        frame = Ether(
            src=LOCAL_MAC if local_src else GATEWAY_MAC,
            dst=GATEWAY_MAC if local_src else LOCAL_MAC,
        )
        packet = frame / IP(src=src, dst=dst, ttl=64, id=len(self.packets) & 0xFFFF) / layer
        packet.time = round(when, 6)
        self.packets.append(packet)

    def write(self, path: Path) -> None:
        self.packets.sort(key=lambda packet: float(packet.time))
        writer = PcapWriter(str(path), linktype=1, sync=False)
        try:
            for packet in self.packets:
                writer.write(packet)
        finally:
            writer.close()


@dataclass
class TcpSession:
    """One TCP connection with honest sequence numbers, so Zeek counts exact byte totals."""

    capture: Capture
    client: str
    client_port: int
    server: str
    server_port: int
    client_seq: int = 1_000
    server_seq: int = 5_000

    def send(self, when: float, from_client: bool, flags: str, payload: bytes = b"") -> None:
        if from_client:
            src, dst, sport, dport = self.client, self.server, self.client_port, self.server_port
            seq, ack = self.client_seq, self.server_seq
        else:
            src, dst, sport, dport = self.server, self.client, self.server_port, self.client_port
            seq, ack = self.server_seq, self.client_seq
        layer = TCP(sport=sport, dport=dport, flags=flags, seq=seq, window=65535)
        if "A" in flags:
            layer.ack = ack
        self.capture.add(when, src, dst, layer / payload if payload else layer)
        advance = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        if from_client:
            self.client_seq += advance
        else:
            self.server_seq += advance

    def open(self, when: float) -> None:
        self.send(when, True, "S")
        self.send(when + 0.010, False, "SA")
        self.send(when + 0.020, True, "A")

    def data(self, when: float, from_client: bool, payload: bytes) -> None:
        self.send(when, from_client, "PA", payload)
        self.send(when + 0.005, not from_client, "A")

    def close(self, when: float) -> None:
        self.send(when, True, "FA")
        self.send(when + 0.010, False, "FA")
        self.send(when + 0.020, True, "A")


def client_hello(server_name: str) -> bytes:
    """A TLS 1.2 ClientHello record carrying `server_name`, with a fixed random."""
    name = server_name.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    extensions = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    ciphers = struct.pack("!HHH", 0xC02F, 0xC030, 0x009C)
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _record(0x16, _handshake(0x01, body))


def server_hello() -> bytes:
    """A TLS 1.2 ServerHello record choosing ECDHE-RSA-AES128-GCM-SHA256, with a fixed random."""
    body = b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + struct.pack("!H", 0xC02F) + b"\x00"
    return _record(0x16, _handshake(0x02, body))


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _record(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def dns_query(capture: Capture, when: float, client: str, port: int, txid: int, name: str) -> None:
    query = DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype="A"))
    capture.add(when, client, RESOLVER, UDP(sport=port, dport=53) / query)


def dns_answer(
    capture: Capture, when: float, client: str, port: int, txid: int, name: str, address: str
) -> None:
    answer = DNS(
        id=txid,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=name, qtype="A"),
        an=DNSRR(rrname=name, type="A", ttl=300, rdata=address),
    )
    capture.add(when, RESOLVER, client, UDP(sport=53, dport=port) / answer)


def build() -> Capture:
    capture = Capture()

    # 12:00:00 The laptop resolves the shop, then opens TLS to it with the same name in the SNI.
    dns_query(capture, at("12:00:00.000"), LAPTOP, 53001, 0x1001, SHOP_NAME)
    dns_answer(capture, at("12:00:00.020"), LAPTOP, 53001, 0x1001, SHOP_NAME, SHOP)
    tls = TcpSession(capture, LAPTOP, 50001, SHOP, 443)
    tls.open(at("12:00:01.000"))
    tls.data(at("12:00:01.100"), True, client_hello(SHOP_NAME))
    tls.data(at("12:00:01.200"), False, server_hello())
    tls.close(at("12:00:02.000"))

    # 12:00:10 The laptop resolves a second name and fetches over plain HTTP: no SNI, DNS only.
    dns_query(capture, at("12:00:10.000"), LAPTOP, 53002, 0x1002, FILES_NAME)
    dns_answer(capture, at("12:00:10.020"), LAPTOP, 53002, 0x1002, FILES_NAME, FILES)
    http = TcpSession(capture, LAPTOP, 50002, FILES, 80)
    http.open(at("12:00:11.000"))
    request = f"GET /readme.txt HTTP/1.1\r\nHost: {FILES_NAME}\r\nUser-Agent: fixture\r\n\r\n"
    http.data(at("12:00:11.100"), True, request.encode("ascii"))
    content = b"synthetic fixture file\n" * 40
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(content)}\r\n\r\n".encode("ascii")
        + content
    )
    http.data(at("12:00:11.200"), False, response)
    http.close(at("12:00:12.000"))

    # 12:00:20 A remote address opens a session to the workstation's port 22.
    inbound = TcpSession(capture, SCANNER, 51515, WORKSTATION, 22)
    inbound.open(at("12:00:20.000"))
    inbound.data(at("12:00:20.100"), False, b"SSH-2.0-OpenSSH_9.6\r\n")
    inbound.data(at("12:00:20.200"), True, b"SSH-2.0-fixture\r\n")
    inbound.close(at("12:00:21.000"))

    # 12:00:40 to 12:02:10 The backup client uploads UPLOAD_BYTES, crossing two minute boundaries.
    upload = TcpSession(capture, BACKUP_CLIENT, 50100, VAULT, 8443)
    upload.open(at("12:00:40.000"))
    segments = UPLOAD_BYTES // SEGMENT
    pattern = bytes(range(256)) * (SEGMENT // 256 + 1)
    for index in range(segments):
        when = at("12:00:40.100") + index * (90.0 / segments)
        upload.send(when, True, "PA", pattern[:SEGMENT])
        if index % 10 == 9 or index == segments - 1:
            upload.send(when + 0.002, False, "A")
    upload.close(at("12:02:10.200"))

    # 12:03:00 A query that is never answered.
    dns_query(capture, at("12:03:00.000"), LAPTOP, 53003, 0x1003, "gone.shop.test")

    # 12:04:00 A reply nobody asked for.
    dns_answer(capture, at("12:04:00.000"), WORKSTATION, 53004, 0x1004, SHOP_NAME, SHOP)

    return capture


def main() -> None:
    capture = build()
    capture.write(OUT)
    print(f"wrote {OUT.name}: {len(capture.packets)} packets")


if __name__ == "__main__":
    main()
