#!/usr/bin/env python3
"""Plain TCP control: same bytes and peer as TLS benchmark."""
import json
import socket
import time

payload = bytes(range(256)) * 1024
listener = socket.create_server(("0.0.0.0", 18444), backlog=5)
print("listening on 18444", flush=True)
while True:
    connection, address = listener.accept()
    connection.settimeout(180)
    started = time.monotonic()
    try:
        with connection:
            marker = connection.recv(1)
            if marker != b"B":
                raise ValueError(f"unexpected marker: {marker!r}")
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            print(json.dumps({"peer": address[0], "bytes": len(payload),
                              "elapsed_ms": round((time.monotonic() - started) * 1000)}),
                  flush=True)
    except Exception as exc:
        print(json.dumps({"peer": address[0], "error": str(exc)}), flush=True)
