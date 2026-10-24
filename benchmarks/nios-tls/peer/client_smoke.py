import socket
import ssl
from pathlib import Path

here = Path(__file__).resolve().parent
context = ssl.create_default_context(cafile=str(here / "ca.pem"))
# Original test CA lacks AKI; keep Python 3.13's other chain/hostname checks.
context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers("ECDHE-ECDSA-CHACHA20-POLY1305")
with socket.create_connection(("127.0.0.1", 18443), timeout=10) as raw:
    with context.wrap_socket(raw, server_hostname="bench.local") as stream:
        assert stream.version() == "TLSv1.2"
        assert stream.cipher()[0] == "ECDHE-ECDSA-CHACHA20-POLY1305"
        stream.sendall(b"B")
        data = bytearray()
        while len(data) < 256 * 1024:
            chunk = stream.recv(4096)
            assert chunk
            data.extend(chunk)
        assert data == bytes(range(256)) * 1024
        assert stream.recv(1) == b""
        stream.unwrap()
print("TLS peer smoke: verified 262144 bytes and close_notify")
