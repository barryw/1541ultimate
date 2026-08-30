#!/usr/bin/env python3
import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT_MAGIC = b"UTLS"


def request(url: str, password: str, data: bytes | None = None, method: str | None = None) -> bytes:
    headers = {"X-Password": password} if password else {}
    if data is not None:
        headers["Content-Type"] = "application/octet-stream"
    with urllib.request.urlopen(
        urllib.request.Request(url, data=data, headers=headers, method=method), timeout=10
    ) as response:
        return response.read()


def build_program(output: Path, interface: int, http: bool, server: str, port: int) -> None:
    subprocess.run(
        [
            str(ROOT / "tools/64tass/64tass"),
            "-D", f"INTERFACE={interface}",
            "-D", f"HTTP_TEST={int(http)}",
            "-D", f"SERVER_PORT={port}",
            "-D", f'SERVER_NAME="{server}"',
            "-o", str(output),
            str(ROOT / "tools/tls_echo_test.tas"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def run_case(args: argparse.Namespace, interface: int, http: bool) -> None:
    mode = "HTTPS" if http else "binary TLS"
    with tempfile.TemporaryDirectory(prefix="ultimate-tls-hw-") as directory:
        program = Path(directory) / "test.prg"
        build_program(program, interface, http, args.server_name, args.port)
        server_command = [
            sys.executable,
            os.fspath(ROOT / "tools/tls_echo_server.py"),
            args.cert,
            args.key,
            "--port", str(args.port),
        ]
        if http:
            server_command.append("--http")
        server = subprocess.Popen(
            server_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        try:
            assert "listening on" in server.stdout.readline()
            base = f"http://{args.ultimate}/v1"
            request(
                f"{base}/machine:writemem?address=c000&data=00000000000000000000",
                args.password,
                method="PUT",
            )
            request(
                f"{base}/runners:run_prg",
                args.password,
                data=program.read_bytes(),
                method="POST",
            )
            deadline = time.monotonic() + args.timeout
            result = b""
            while time.monotonic() < deadline:
                result = request(
                    f"{base}/machine:readmem?address=c000&length=10", args.password
                )
                if result[:4] == RESULT_MAGIC and result[4] != 0:
                    break
                time.sleep(0.25)
            assert result[:4] == RESULT_MAGIC, "test program did not start"
            assert result[4] == 1, f"{mode} failed on interface {interface}"
            assert result[5] == interface
            interface_ip = socket.inet_ntoa(result[6:10])
        finally:
            server.terminate()
            try:
                output = server.communicate(timeout=3)[0]
            except subprocess.TimeoutExpired:
                server.kill()
                output = server.communicate()[0]

        peers = [line.split()[1] for line in output.splitlines() if line.startswith("connected:")]
        assert peers == [interface_ip], (
            f"selected interface {interface} has {interface_ip}, server observed {peers}"
        )
        print(f"PASS interface {interface} ({interface_ip}): {mode}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Ultimate TLS and HTTPS tests over both Ethernet and Wi-Fi"
    )
    parser.add_argument("--ultimate", required=True, help="Ultimate REST API address")
    parser.add_argument("--server-name", required=True, help="certificate hostname or IP")
    parser.add_argument("--cert", required=True, help="publicly trusted server certificate chain")
    parser.add_argument("--key", required=True, help="server private key")
    parser.add_argument("--password", default=os.environ.get("U64_PASS", ""))
    parser.add_argument("--port", type=int, default=6464)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--interfaces", type=int, nargs="+", default=(0, 1))
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9.-]+", args.server_name):
        parser.error("--server-name must be an IPv4 address or DNS hostname")

    for interface in args.interfaces:
        run_case(args, interface, False)
        run_case(args, interface, True)


if __name__ == "__main__":
    main()
