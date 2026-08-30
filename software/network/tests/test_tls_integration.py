#!/usr/bin/env python3
import contextlib
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class TLSIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="ultimate-tls-test-")
        cls.work = Path(cls.temp.name)
        cls.mbedtls_build = cls.work / "mbedtls"
        source = ROOT / "software/mbedtls"
        for directory in ("include", "library", "3rdparty", "scripts"):
            shutil.copytree(source / directory, cls.mbedtls_build / directory)
        subprocess.run(
            [
                "make", "-C", str(cls.mbedtls_build / "library"), "-j2",
                "-o", "ssl_debug_helpers_generated.c",
                "libmbedtls.a", "libmbedx509.a", "libmbedcrypto.a",
            ],
            check=True,
        )

        cls.client = cls.work / "tls_coprocessor_host_test"
        library = cls.mbedtls_build / "library"
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-D_DEFAULT_SOURCE",
                "-D_POSIX_C_SOURCE=200112L",
                "-D_DARWIN_C_SOURCE",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "software/network/tests/stubs"),
                "-I",
                str(ROOT / "software/io/uart"),
                "-I",
                str(ROOT / "software/wifi/raw_u64/main"),
                "-I",
                str(ROOT / "software/wifi"),
                "-I",
                str(cls.mbedtls_build / "include"),
                str(ROOT / "software/network/tests/tls_coprocessor_host_test.c"),
                str(ROOT / "software/wifi/tls_coprocessor.c"),
                str(library / "libmbedtls.a"),
                str(library / "libmbedx509.a"),
                str(library / "libmbedcrypto.a"),
                "-pthread",
                "-o",
                str(cls.client),
            ],
            check=True,
        )

        cls.root, cls.cert, cls.key = cls._make_certificates("trusted")
        cls.wrong_root, _, _ = cls._make_certificates("untrusted")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    @classmethod
    def _make_certificates(cls, name: str) -> tuple[Path, Path, Path]:
        directory = cls.work / name
        directory.mkdir()
        root_key = directory / "root.key"
        root = directory / "root.pem"
        key = directory / "server.key"
        request = directory / "server.csr"
        cert = directory / "server.pem"
        extensions = directory / "server.ext"
        extensions.write_text(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        )
        commands = [
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", root_key],
            [
                "openssl", "req", "-x509", "-new", "-sha256", "-days", "3650",
                "-key", root_key, "-subj", f"/CN=Ultimate {name} Test Root", "-out", root,
            ],
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key],
            ["openssl", "req", "-new", "-sha256", "-key", key, "-subj", "/CN=localhost", "-out", request],
            [
                "openssl", "x509", "-req", "-sha256", "-days", "30",
                "-in", request, "-CA", root, "-CAkey", root_key, "-CAcreateserial",
                "-extfile", extensions, "-out", cert,
            ],
        ]
        for command in commands:
            subprocess.run([str(item) for item in command], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return root, cert, key

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    @contextlib.contextmanager
    def _server(self, http: bool = False):
        port = self._free_port()
        command = [
            sys.executable,
            str(ROOT / "tools/tls_echo_server.py"),
            str(self.cert),
            str(self.key),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ]
        if http:
            command.append("--http")
        server = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            line = server.stdout.readline()
            self.assertIn("listening on", line)
            yield port
        finally:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            server.stdout.close()

    def _run_client(self, port: int, ca: Path, hostname: str, mode: str) -> str:
        result = subprocess.run(
            [
                str(self.client),
                "127.0.0.1",
                str(port),
                str(ca),
                hostname,
                mode,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.stdout

    def test_binary_tls_and_three_fresh_connections(self) -> None:
        with self._server() as port:
            output = self._run_client(port, self.root, "localhost", "echo")
        self.assertIn("TLS binary and reconnect passed", output)

    def test_https_request(self) -> None:
        with self._server(http=True) as port:
            output = self._run_client(port, self.root, "localhost", "http")
        self.assertIn("HTTPS passed", output)

    def test_untrusted_ca_is_rejected(self) -> None:
        with self._server() as port:
            output = self._run_client(port, self.wrong_root, "localhost", "reject")
        self.assertIn("certificate rejection passed", output)

    def test_wrong_hostname_is_rejected(self) -> None:
        with self._server() as port:
            output = self._run_client(port, self.root, "wrong.invalid", "reject")
        self.assertIn("certificate rejection passed", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
