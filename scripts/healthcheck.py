#!/usr/bin/env python3
"""Health check: DNS over PROXY v2 + Prometheus metrics."""

import socket
import struct
import sys
import urllib.request

PP2_SIG = b"\r\n\r\n\0\r\nQUIT\n"


def pp2_header() -> bytes:
    src = socket.inet_aton("203.0.113.50")
    dst = socket.inet_aton("127.0.0.1")
    payload = src + dst + struct.pack("!HH", 54321, 53)
    return PP2_SIG + bytes([0x21, 0x11]) + struct.pack("!H", len(payload)) + payload


def dns_ping(host: str, port: int) -> None:
    labels = b"\x06google\x03com\x00"
    msg = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(pp2_header())
    sock.sendall(struct.pack("!H", len(msg)) + msg)
    hdr = sock.recv(2)
    if len(hdr) < 2:
        raise SystemExit("dns: short response")
    ln = struct.unpack("!H", hdr)[0]
    data = sock.recv(ln)
    sock.close()
    if len(data) < 4:
        raise SystemExit("dns: truncated response")


def metrics_ok(url: str) -> None:
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = resp.read(200)
        if b"hickory" not in body.lower() and b"#" not in body[:1:]:
            raise SystemExit("metrics: unexpected body")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 53
    metrics_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9000
    dns_ping(host, port)
    metrics_ok(f"http://{host}:{metrics_port}/metrics")


if __name__ == "__main__":
    main()
