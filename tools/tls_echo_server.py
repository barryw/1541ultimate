#!/usr/bin/env python3
import argparse
import socket
import ssl
import time


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS 1.2 binary echo server")
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6464)
    parser.add_argument("--http", action="store_true")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    context.set_ecdh_curve("prime256v1")
    context.load_cert_chain(args.cert, args.key)

    with socket.create_server((args.host, args.port)) as listener:
        print(f"listening on {args.host}:{args.port}", flush=True)
        while True:
            connection, address = listener.accept()
            started = time.monotonic()
            try:
                with context.wrap_socket(connection, server_side=True) as secure:
                    elapsed = time.monotonic() - started
                    print(f"connected: {address[0]} {secure.cipher()[0]} {elapsed:.3f}s", flush=True)
                    if args.http:
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            data = secure.recv(4096)
                            if not data:
                                break
                            request.extend(data)
                        body = b"Ultimate HTTPS works\n"
                        secure.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            + f"Content-Length: {len(body)}\r\n".encode()
                            + b"Connection: close\r\n\r\n"
                            + body
                        )
                        continue
                    while data := secure.recv(4096):
                        secure.sendall(data)
            except (ConnectionError, ssl.SSLError) as error:
                print(f"connection failed: {address[0]}: {error}", flush=True)


if __name__ == "__main__":
    main()
