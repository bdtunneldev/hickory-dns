#!/usr/bin/env python3
"""Send many DNS queries over TCP via HAProxy (PROXY v2 is added by HAProxy)."""

import argparse
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

PP2_SIG = b"\r\n\r\n\0\r\nQUIT\n"
RCODES = {0: "NOERROR", 3: "NXDOMAIN", 5: "REFUSED", 2: "SERVFAIL"}


def pp2_header(src_ip: str = "203.0.113.50", src_port: int = 54321) -> bytes:
    src, dst = socket.inet_aton(src_ip), socket.inet_aton("127.0.0.1")
    payload = src + dst + struct.pack("!HH", src_port, 53)
    return PP2_SIG + bytes([0x21, 0x11]) + struct.pack("!H", len(payload)) + payload


def build_query(name: str, qid: int) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\0"
    return struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def one_query(host: str, port: int, name: str, qid: int, send_proxy: bool = False) -> tuple[str, float]:
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if send_proxy:
            sock.sendall(pp2_header())
        msg = build_query(name, qid)
        sock.sendall(struct.pack("!H", len(msg)) + msg)
        hdr = sock.recv(2)
        if len(hdr) < 2:
            sock.close()
            return "error:short", (time.perf_counter() - t0) * 1000
        ln = struct.unpack("!H", hdr)[0]
        data = b""
        while len(data) < ln:
            chunk = sock.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        sock.close()
        if len(data) < 4:
            return "error:truncated", (time.perf_counter() - t0) * 1000
        rcode = data[3] & 0xF
        return RCODES.get(rcode, f"rcode:{rcode}"), (time.perf_counter() - t0) * 1000
    except OSError as e:
        return f"error:OSError:{e.errno}", (time.perf_counter() - t0) * 1000
    except Exception as e:
        return f"error:{type(e).__name__}", (time.perf_counter() - t0) * 1000


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def main():
    parser = argparse.ArgumentParser(description="TCP DNS load test via HAProxy")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=53)
    parser.add_argument("total", nargs="?", type=int, default=10000)
    parser.add_argument("workers", nargs="?", type=int, default=50)
    parser.add_argument(
        "--send-proxy",
        action="store_true",
        help="Send PROXY v2 header (direct Hickory testing only)",
    )
    args = parser.parse_args()
    names = ["google.com", "bkash.com", "wikipedia.org", "example.com"]

    counts: dict[str, int] = {}
    latencies: list[float] = []
    ok_latencies: list[float] = []
    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(one_query, args.host, args.port, names[i % len(names)], i, args.send_proxy)
            for i in range(args.total)
        ]
        for fut in as_completed(futures):
            result, latency_ms = fut.result()
            counts[result] = counts.get(result, 0) + 1
            latencies.append(latency_ms)
            if result == "NOERROR":
                ok_latencies.append(latency_ms)

    elapsed = time.perf_counter() - start
    qps = args.total / elapsed if elapsed else 0
    latencies.sort()
    ok_latencies.sort()
    ok = counts.get("NOERROR", 0)
    fail = args.total - ok

    print(f"queries={args.total} elapsed={elapsed:.2f}s qps={qps:.0f} workers={args.workers}")
    print(f"  success={ok} ({100*ok/args.total:.1f}%) fail={fail} ({100*fail/args.total:.1f}%)")
    for k in sorted(counts, key=lambda x: (-counts[x], x)):
        print(f"  {k}: {counts[k]} ({100*counts[k]/args.total:.1f}%)")
    print(
        f"  latency_ms (all): min={latencies[0]:.1f} avg={sum(latencies)/len(latencies):.1f} "
        f"p50={percentile(latencies, 50):.1f} p95={percentile(latencies, 95):.1f} "
        f"p99={percentile(latencies, 99):.1f} max={latencies[-1]:.1f}"
    )
    if ok_latencies:
        print(
            f"  latency_ms (ok):  min={ok_latencies[0]:.1f} avg={sum(ok_latencies)/len(ok_latencies):.1f} "
            f"p50={percentile(ok_latencies, 50):.1f} p95={percentile(ok_latencies, 95):.1f} "
            f"p99={percentile(ok_latencies, 99):.1f} max={ok_latencies[-1]:.1f}"
        )


if __name__ == "__main__":
    main()
