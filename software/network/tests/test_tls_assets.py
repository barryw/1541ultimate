#!/usr/bin/env python3
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
def main() -> None:
    mozilla_bundle = (ROOT / "software/network/mozilla-ca.pem").read_bytes()
    assert hashlib.sha256(mozilla_bundle).hexdigest() == (
        "f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9"
    )
    assert mozilla_bundle.count(b"-----BEGIN CERTIFICATE-----") == 121
    assert b"Certificate data from Mozilla as of: Thu Aug 13 03:12:01 2026 GMT" in mozilla_bundle

    tls_source = (ROOT / "software/network/tls_socket.cc").read_text()
    coprocessor = (ROOT / "software/wifi/tls_coprocessor.c").read_text()
    assert '#define CA_FILENAME "custom-ca.pem"' in tls_source
    assert "ca_bundle_sha256" not in tls_source
    assert '#include "esp_crt_bundle.h"' in coprocessor
    assert "esp_crt_bundle_attach(NULL)" in coprocessor
    assert coprocessor.index("esp_crt_bundle_attach(&config)") < coprocessor.index(
        "mbedtls_ssl_conf_ca_chain(&config, &ca_roots, NULL)"
    )
    assert "if (ca_length == 0)" in coprocessor

    tls_doc = (ROOT / "software/network/tls.md").read_text()
    assert "/flash/data/custom-ca.pem" in tls_doc
    assert "augment" in tls_doc
    assert "Mozilla NSS" in tls_doc

    for sdkconfig in ("software/wifi/raw_u64/sdkconfig", "software/u64ctrl/sdkconfig"):
        config = (ROOT / sdkconfig).read_text()
        assert "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y" in config
        assert "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y" in config
        assert "mozilla-ca.pem" in config
        assert "CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y" in config
        assert "CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_EPHEMERAL=y" in config
        assert "# CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_PSK is not set" in config
        assert "CONFIG_MBEDTLS_HKDF_C=y" in config
        assert "CONFIG_MBEDTLS_TLS_CLIENT_ONLY=y" in config

    c3_config = (ROOT / "software/wifi/raw_c3/sdkconfig").read_text()
    assert "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y" in c3_config
    assert "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y" in c3_config
    assert "mozilla-ca.pem" in c3_config
    assert "# CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 is not set" in c3_config
    assert "CONFIG_MBEDTLS_TLS_CLIENT_ONLY=y" in c3_config

    protocol = (ROOT / "software/io/network/network_target.h").read_text()
    assert "#define NET_CMD_OPEN_TLS            0x12" in protocol

    esp_headers = [
        (ROOT / "software/wifi/raw_u64/main/rpc_calls.h").read_text(),
        (ROOT / "software/wifi/raw_c3/main/rpc_calls.h").read_text(),
        (ROOT / "software/u64ctrl/main/rpc_calls.h").read_text(),
    ]
    tls_abi = re.compile(
        r"typedef struct \{\s*rpc_header_t hdr;\s*uint8_t operation;.*?"
        r"\}\s*rpc_tls_start_data;",
        re.S,
    )
    blocks = []
    for header in esp_headers:
        definitions = tls_abi.search(header).group()
        macros = "\n".join(re.findall(r"^#define (?:CMD_TLS|TLS_[A-Z_]+).*?$", header, re.M))
        blocks.append(re.sub(r"\s+", " ", definitions + macros))
    assert blocks[0] == blocks[1]
    assert re.search(r"#define CMD_TLS\s+0x17\b", blocks[0])
    for operation, value in (
        ("CA", 0), ("START", 1), ("HANDSHAKE", 2), ("PULL", 3),
        ("WRITE", 4), ("READ", 5), ("CLOSE", 6),
    ):
        assert re.search(rf"#define TLS_OP_{operation}\s+{value}\b", blocks[0])

    for target in (
        "software/wifi/raw_u64/main",
        "software/wifi/raw_c3/main",
        "software/u64ctrl/main",
    ):
        assert "tls_coprocessor.c" in (ROOT / target / "CMakeLists.txt").read_text()
        assert "case CMD_TLS:" in (ROOT / target / "rpc_dispatch.c").read_text()
        assert "tls_coprocessor_init()" in (ROOT / target / "wifi_modem.c").read_text()

    for makefile in (
        "target/u64/nios2/ultimate/Makefile",
        "target/u2plus_L/riscv/ultimate/Makefile",
        "target/u64ii/riscv/ultimate/Makefile",
    ):
        source = (ROOT / makefile).read_text()
        assert "tls_socket.cc" in source
        assert "mbedtls" in source
        assert "TLS_COPROCESSOR=1" in source

    for makefile in (
        "target/u2/riscv/ultimate/Makefile",
        "target/u2plus/nios/ultimate/Makefile",
    ):
        source = (ROOT / makefile).read_text()
        assert "tls_socket.cc" not in source
        assert "TLS_COPROCESSOR" not in source

    for target in ("u64", "u64ii"):
        updater = (ROOT / f"software/application/update_u2p/update_{target}.cc").read_text()
        binaries = (ROOT / f"software/application/update_u2p/update_binaries_{target}.s").read_text()
        assert "ca-roots.pem" not in updater
        assert "ca-roots.pem" not in binaries

    network_target = (ROOT / "software/io/network/network_target.cc").read_text()
    assert "#ifdef TLS_COPROCESSOR\n        case NET_CMD_SET_INTERFACE:" in network_target
    assert "case NET_CMD_SET_INTERFACE:" in network_target
    assert "NetworkInterface :: set_default_interface(command->message[2])" in network_target
    assert "NetworkInterface::get_preferred_ip()" in network_target
    assert "bind(socket," in network_target

    network_interface = (ROOT / "software/io/network/network_interface.cc").read_text()
    assert "#ifdef TLS_COPROCESSOR\nstatic int preferredInterface" in network_interface

    time_source = (ROOT / "software/network/time.c").read_text()
    assert "rtc_get_epoch_time()" in time_source
    assert "#ifdef TLS_COPROCESSOR\n    extern time_t rtc_get_epoch_time" in time_source
    for rtc in ("rtc_dummy.cc", "rtc_i2c.cc"):
        rtc_source = (ROOT / "software/io/rtc" / rtc).read_text()
        assert "#ifdef TLS_COPROCESSOR\nextern \"C\" time_t rtc_get_epoch_time" in rtc_source

    https_client = (ROOT / "software/network/assembly.cc").read_text()
    assert "#define HOSTPORT      443" in https_client
    assert "tls_socket_open(sock_fd, HOSTNAME)" in https_client
    assert "#ifdef TLS_COPROCESSOR\nint Assembly :: write_socket" in https_client

    u2pl_updater = (ROOT / "software/application/update_u2pl/update.cc").read_text()
    assert 'create_dir("/flash/data")' in u2pl_updater


if __name__ == "__main__":
    main()
