#!/usr/bin/env python3
"""Deterministic local TLS peer for Nios/ESP comparison."""
import json
import socket
import ssl
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = bytes(range(256)) * 1024

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.options |= ssl.OP_NO_TICKET
context.set_ciphers("ECDHE-ECDSA-CHACHA20-POLY1305")
context.set_ecdh_curve("prime256v1")
context.load_cert_chain(HERE / "server.pem", HERE / "server.key")

listener = socket.create_server(("0.0.0.0", 18443), backlog=5)
print("listening on 18443", flush=True)
while True:
    raw, address = listener.accept()
    raw.settimeout(180)
    started = time.monotonic()
    try:
        with context.wrap_socket(raw, server_side=True) as connection:
            marker = connection.recv(1)
            if marker != b"B":
                raise ValueError(f"unexpected marker: {marker!r}")
            version = connection.version()
            cipher = connection.cipher()[0]
            resumed = connection.session_reused
            connection.sendall(PAYLOAD)
            connection.unwrap()  # emits authenticated close_notify
            print(json.dumps({"peer": address[0], "version": version,
                              "cipher": cipher, "resumed": resumed,
                              "bytes": len(PAYLOAD),
                              "elapsed_ms": round((time.monotonic() - started) * 1000)}),
                  flush=True)
    except Exception as exc:
        print(json.dumps({"peer": address[0], "error": str(exc),
                          "elapsed_ms": round((time.monotonic() - started) * 1000)}),
              flush=True)
