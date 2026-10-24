# U64 Nios TLS diagnostic fixture

This branch reproduces the U64 Elite Nios II benchmark reported in [report.md](report.md). It is a temporary diagnostic, not production firmware. TLS entropy is deterministic and the CA/server keys are test-only. Never use this client or CA for real traffic.

Base firmware: `GideonZ/1541ultimate` master `99784768a7cb32d1580e7960e9ac96e16595f30d`. `software/mbedtls` is an Mbed TLS 3.6.7 submodule pinned to `068ff080b369adfac81509f9b57b2afabaf82dc5`. Tested on U64 Elite with Nios GCC 5.3.0, Quartus 18.1 Build 625, FreeRTOS 200 Hz. The diagnostic route is U64-only and intentionally absent from published OpenAPI docs.

## Peer

Run both listeners on the same LAN host. Client source uses `192.168.1.3` and ports 18443/18444; change both addresses in `software/api/tls_bench.cc` if your peer differs. Allow those ports in the host firewall.

```sh
python3 benchmarks/nios-tls/peer/server.py
python3 benchmarks/nios-tls/peer/plain_server.py
```

Use separate terminals. `python3 benchmarks/nios-tls/peer/client_smoke.py` checks TLS on the peer host. Smoke script clears Python 3.13's strict AKI requirement because original test CA lacks that extension; it still checks chain, hostname, and dates. Peer pins TLS 1.2, `ECDHE-ECDSA-CHACHA20-POLY1305`, and P-256 ECDHE. Leaf and CA are P-256; hostname is `bench.local`. CA is in both PEM and DER forms. Use `ca.der` for `TLS_TRUST_CA` when comparing PR #997. The test certificate expires 2027-01-22 UTC; regenerate after that date. `server.key` is public test material and must never be trusted for anything else.

The server sends `bytes(range(256)) * 1024` after receiving one `B` byte and then sends TLS `close_notify`. Plain TCP control sends identical bytes on 18444. Peer logs source IP, negotiated version/cipher, resumed state, byte count, and elapsed time. Check `resumed: false` for all trials.

## Build and run Nios firmware

```sh
git submodule update --init --recursive
. ~/quartus18-env.sh
. "$IDF_PATH/export.sh"
export PATH=$HOME/bin:$PATH
make esp32_raw_u64
make u64_no_esp
```

Fresh checkout needs ESP32 blobs once for updater packaging; later `make u64_no_esp` omits ESP32 rebuild and compiles Mbed TLS library before U64 application. Build image is `update.u64`. Flash only on a U64 you can recover. The firmware client uses a fixed peer IP and deterministic entropy; it will refuse an RTC date before 2025. On a device with no REST password:

```sh
python3 tools/tls_bench_collect.py --host 192.168.1.148 --runs 12 --output nios-results.json
python3 tools/tls_bench_latency.py --host 192.168.1.148 --output nios-latency.json
```

Collector warms up once, then records 12 certificate-verified TLS/plain transfer pairs and checks every byte. Latency script samples `GET /v1/info` every 500 ms before and during a separate TLS run. For FTP contention, trigger `PUT /v1/machine:tls_bench` repeatedly while measuring identical FTP downloads on idle and busy firmware. Avoid running other device tests concurrently.

## Optional curve profile

The three-run profile used a separate image. Apply `profile-ecp.patch` to the Mbed TLS submodule, append `-DTLS_BENCH_PROFILE` to `OPTIONS` in both `target/libs/nios2/mbedtls/Makefile` and `target/u64/nios2/ultimate/Makefile`, clean both library and U64 build outputs, then rebuild. Do not compare its wall time directly with the uninstrumented image. The patch tracks `ecp_mul` and `ecp_muladd` in 5 ms FreeRTOS ticks.

## Results

`nios-results.json`, `nios-profile-results.json`, and `nios-latency.json` hold raw measured records. U64 hostname, unique ID and MAC addresses were removed from the copies here; timing and firmware/version fields are unchanged. [report.md](report.md) states hardware conditions, app size delta, summary and limits. Historical Nios peer did not pin or log ECDHE group; this fixture now pins P-256 so a matched ESP32 comparison should repeat Nios runs too. Git metadata and build timestamp make firmware binaries non-reproducible byte for byte.
