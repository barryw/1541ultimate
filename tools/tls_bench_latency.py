#!/usr/bin/env python3
"""Measure REST responsiveness during separate Nios TLS benchmark run."""
import argparse
import json
import statistics
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="192.168.1.148")
parser.add_argument("--output", type=Path, default=Path("nios-latency.json"))
args = parser.parse_args()
BASE = f"http://{args.host}"
OUT = args.output


def sample():
    started = time.monotonic()
    try:
        with urllib.request.urlopen(BASE + "/v1/info", timeout=5) as response:
            assert response.status == 200
            json.load(response)
        error = None
    except Exception as exc:
        error = str(exc)
    return {"elapsed_ms": round((time.monotonic() - started) * 1000, 3), "error": error}


def summary(samples):
    ok = sorted(s["elapsed_ms"] for s in samples if s["error"] is None)
    return {"count": len(samples), "failures": len(samples) - len(ok),
            "median_ms": statistics.median(ok) if ok else None,
            "p95_ms": ok[int(0.95 * (len(ok) - 1))] if ok else None,
            "max_ms": ok[-1] if ok else None}


idle = []
for _ in range(30):
    idle.append(sample())
    time.sleep(0.5)
with urllib.request.urlopen(urllib.request.Request(BASE + "/v1/machine:tls_bench", method="PUT"),
                            timeout=5) as response:
    assert json.load(response)["state"] == "running"
started = time.monotonic()
busy = []
while time.monotonic() - started < 46:
    s = sample()
    s["since_start_ms"] = round((time.monotonic() - started) * 1000)
    busy.append(s)
    time.sleep(0.5)
with urllib.request.urlopen(BASE + "/v1/machine:tls_bench", timeout=5) as response:
    run = json.load(response)
assert run["state"] == "complete" and run["error"] == 0, run
artifact = {"idle": idle, "busy": busy, "run": run,
            "summary": {"idle": summary(idle), "busy": summary(busy)}}
OUT.write_text(json.dumps(artifact, indent=2) + "\n")
print(json.dumps(artifact["summary"], indent=2))
