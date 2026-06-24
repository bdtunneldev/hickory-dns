#!/usr/bin/env python3
"""DNS over TCP with optional PROXY v2; prints structured results."""

import json
import socket
import struct
import sys

PP2_SIG = b"\r\n\r\n\0\r\nQUIT\n"
QTYPES = {1: "A", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}


def build_pp2_v4(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    payload = src + dst + struct.pack("!HH", src_port, dst_port)
    return PP2_SIG + bytes([0x21, 0x11]) + struct.pack("!H", len(payload)) + payload


def build_query(name: str, qtype: int = 1) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def skip_name(data: bytes, off: int) -> int:
    if data[off] & 0xC0 == 0xC0:
        return off + 2
    while data[off] != 0:
        off += 1 + data[off]
    return off + 1


def parse_response(data: bytes, qname: str, qtype: int) -> dict:
    if len(data) < 12:
        return {"query": qname, "qtype": QTYPES.get(qtype, qtype), "error": "short response"}
    rcode = data[3] & 0xF
    ancount = struct.unpack("!H", data[6:8])[0]
    result = {
        "query": qname,
        "qtype": QTYPES.get(qtype, str(qtype)),
        "rcode": {0: "NOERROR", 3: "NXDOMAIN", 5: "REFUSED"}.get(rcode, str(rcode)),
        "answers": [],
    }
    off = 12
    off = skip_name(data, off) + 4  # question
    for _ in range(ancount):
        off = skip_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off : off + 10])
        off += 10
        rdata = data[off : off + rdlen]
        off += rdlen
        entry = {"type": QTYPES.get(rtype, str(rtype)), "ttl": ttl}
        if rtype == 1 and rdlen == 4:
            entry["data"] = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:
            entry["data"] = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            entry["data"] = "<CNAME>"
        else:
            entry["data"] = rdata.hex()
        result["answers"].append(entry)
    return result


def dns_tcp_query(host: str, port: int, name: str, qtype: int = 1, proxy: bool = False) -> dict:
    sock = socket.create_connection((host, port), timeout=15)
    if proxy:
        sock.sendall(build_pp2_v4("203.0.113.50", 54321, host, port))
    msg = build_query(name, qtype)
    sock.sendall(struct.pack("!H", len(msg)) + msg)
    ln = struct.unpack("!H", sock.recv(2))[0]
    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data))
        if not chunk:
            break
        data += chunk
    sock.close()
    out = parse_response(data, name, qtype)
    out["via"] = f"{host}:{port}" + ("+PROXY" if proxy else "")
    return out


if __name__ == "__main__":
    mode = sys.argv[1]  # hickory | bd | google
    name = sys.argv[2]
    qtype = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    if mode == "hickory":
        r = dns_tcp_query("127.0.0.1", 53, name, qtype, proxy=True)
    elif mode == "bd":
        r = dns_tcp_query("103.187.22.195", 53, name, qtype, proxy=False)
    elif mode == "google":
        r = dns_tcp_query("8.8.8.8", 53, name, qtype, proxy=False)
    else:
        sys.exit(f"unknown mode: {mode}")
    print(json.dumps(r))
