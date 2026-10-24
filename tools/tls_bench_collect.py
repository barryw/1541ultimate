#!/usr/bin/env python3
"""Collect verified Nios TLS timings from temporary benchmark firmware."""
import argparse
import json
import statistics
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="192.168.1.148")
parser.add_argument("--runs", type=int, default=30)
parser.add_argument("--output", type=Path, default=Path("/tmp/nios-tls-results.json"))
args = parser.parse_args()
base = f"http://{args.host}"


def request(method, path):
    with urllib.request.urlopen(urllib.request.Request(base + path, method=method), timeout=10) as response:
        return json.load(response)


info = request("GET", "/v1/info")
assert info["product"] == "Ultimate 64 Elite", info
runs = []
warmup = None
artifact = {"firmware": info, "peer": "192.168.1.3:18443",
            "payload_bytes": 256 * 1024, "warmup": None,
            "runs": runs,
            "conditions": {"tls": "1.2 ECDHE-ECDSA CHACHA20-POLY1305",
                           "authenticated": True,
                           "entropy": "deterministic test fixture; no secrets",
                           "time": "RTC local time converted to UTC",
                           "client": "Nios II/f, -Os -mno-hw-mul, FreeRTOS task priority 1"}}
for index in range(args.runs + 1):
    started = request("PUT", "/v1/machine:tls_bench")
    assert started["state"] == "running", started
    deadline = time.monotonic() + 360
    while True:
        outcome = request("GET", "/v1/machine:tls_bench")
        if outcome["state"] == "complete":
            break
        assert time.monotonic() < deadline, f"benchmark timeout on run {index}"
        time.sleep(0.25)
    time.sleep(2)
    outcome["idle_heap_free"] = request("GET", "/v1/machine:heap")["free"]
    if index:
        runs.append(outcome)
    else:
        warmup = outcome
        artifact["warmup"] = warmup
    args.output.write_text(json.dumps(artifact, indent=2) + "\n")
    assert outcome["error"] == 0 and outcome["verify_flags"] == 0, outcome
    assert outcome["bytes"] == 256 * 1024, outcome
    assert outcome["plain_bytes"] == 256 * 1024, outcome
    print(f"{'warmup' if index == 0 else index}: "
          f"handshake={outcome['handshake_ms']}ms "
          f"transfer={outcome['transfer_ms']}ms "
          f"plain={outcome['plain_transfer_ms']}ms "
          f"heap={outcome['heap_before']}/{outcome['heap_after']} "
          f"idle={outcome['idle_heap_free']}", flush=True)

summary = {}
for field in ("tcp_ms", "setup_ms", "handshake_ms", "transfer_ms",
              "plain_tcp_ms", "plain_transfer_ms", "stack_free_words", "idle_heap_free"):
    values = sorted(run[field] for run in runs)
    summary[field] = {"min": values[0], "median": statistics.median(values),
                      "p95": values[int(0.95 * (len(values) - 1))], "max": values[-1]}

artifact["summary"] = summary
args.output.write_text(json.dumps(artifact, indent=2) + "\n")
print(json.dumps(summary, indent=2), flush=True)
