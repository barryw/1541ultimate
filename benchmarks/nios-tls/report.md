# Nios II TLS feasibility benchmark

Status: completed on U64 Elite hardware. This is a diagnostic branch, not a firmware PR.

## Fixed conditions

- Source: GideonZ/1541ultimate `master` at `99784768a7cb32d1580e7960e9ac96e16595f30d`.
- Build host: beast, Quartus 18.1 Build 625, Nios GCC 5.3.0, `-Os -mno-hw-mul`. Generated U64 BSP says hardware multiply and divide are absent; benchmark keeps shipping compiler flags. BSP's `ALT_CPU_CPU_FREQ` says 62.5 MHz while application `CLOCK_FREQ` says 66.67 MHz, so this report does not derive cycle counts from either.
- TLS: Mbed TLS 3.6.7 (`068ff080b369adfac81509f9b57b2afabaf82dc5`), TLS 1.2, `ECDHE-ECDSA-CHACHA20-POLY1305` only. Nios build only enables P-256/P-384; matched peer now pins P-256 explicitly.
- Certificate: local ECDSA P-256 CA and `bench.local` ECDSA P-256 server leaf; certificate chain, hostname, purpose and validity dates checked. Peer runs on beast `192.168.1.3:18443`.
- Test CA SHA-256 fingerprint: `A0:8B:54:9B:F4:5F:AF:E6:41:DB:FD:37:38:3B:45:C8:97:72:C9:2D:66:BF:FC:C4:AE:6D:FB:75:37:59:29:89`; valid 2026-10-24 through 2027-01-22 UTC.
- Payload: 262,144 bytes `bytes(range(256)) * 1024`, checked byte for byte. Independent plain TCP peer sends identical payload on port 18444.
- Timing: FreeRTOS 200 Hz tick (5 ms resolution), TCP connection, TLS setup, handshake and payload transfer measured separately inside U64 task at priority 1. First run is warmup; 12 recorded runs follow. Results below use uninstrumented firmware; profile firmware is a separate build.
- Entropy: test-only deterministic callback, mixed with current tick to vary client ephemeral keys. No secrets sent. This measures Nios cryptographic computation, **not** a viable production entropy source.
- UTC: RTC local time converted to UTC; run refuses dates before 2025. Do not claim production authenticated time provisioning from this fixture.
- Hardware: Ultimate 64 Elite, wired address `192.168.1.148`. Test peer logs actual source address, negotiated cipher, session resumption and payload count.

## Build size

| Image | `.app` bytes | Free application flash |
|---|---:|---:|
| Clean master, same compiler and stack watermark option | 1,261,704 | 239.9 KiB |
| TLS diagnostic | 1,359,784 | 144.1 KiB |

Diagnostic increase: **98,080 bytes** (`.text` +97,548, `.data` +532, `.bss` +64). Includes TLS library, diagnostic route, local CA, and stack watermark code. Worker reserves 8,192 FreeRTOS stack words at runtime. Firmware builds and passes application-space gate.

Diagnostic update SHA-256: `9ce0367aeb05cbfd5d3cf327d79f62da48bc6b0bca0f3968894e48f2d7df2327`. Uploaded copy on `/USB1/update_nios_tls_bench.u64` matches byte for byte. `/USB1/update_pr871_4402a806.u64` is available as current-firmware rollback.

## Hardware results

All 12 recorded TLS handshakes verified certificate chain, hostname, date and peer identity (`verify_flags=0`); each TLS and plain TCP transfer matched all 262,144 expected bytes. No TLS session was resumed. Peer logs showed U64 wired source `192.168.1.148`. Raw outcomes and firmware metadata: `nios-results.json`.

| Metric | Min | Median | Max |
|---|---:|---:|---:|
| TLS handshake | 35.965 s | **35.980 s** | 35.995 s |
| TLS transfer, 256 KiB | 7.335 s | **7.355 s** | 7.385 s |
| Plain TCP transfer, same 256 KiB | 0.295 s | **0.298 s** | 0.305 s |
| Idle heap free after each run | 5,301,044 B | 5,301,044 B | 5,301,044 B |

Median TLS throughput: **34.8 KiB/s**. Plain TCP control: **860 KiB/s**. TLS payload transfer took about **24.7×** longer. Worker stack minimum free: 7,233 of 8,192 words, or 959 words (3,836 bytes) used. Stable idle heap across this short series rules out a visible per-run leak; it does not prove long-term leak freedom.

Separate REST latency probe (`nios-latency.json`) sampled `GET /v1/info` every 500 ms. Idle: 30/30 succeeded, median 8.85 ms, max 19.93 ms. During one concurrent TLS benchmark: 88/88 succeeded, median 24.83 ms, max 39.09 ms. This shows measurable contention without complete service loss in this workload.

## Curve-operation profile

Separate build instrumented `mbedtls_ecp_mul_restartable` and `mbedtls_ecp_muladd_restartable` with same 5 ms tick clock. These paths do not nest in this Mbed TLS version: `muladd` calls `ecp_mul_restartable_internal` directly. Profile build application size: 1,360,292 bytes; update SHA-256 `06a94d2ae552c6d4f178ff2f716dafd5394620dfb8c7cbe1d92c1dbaf0386a3a`. Three recorded verified runs after warmup (`nios-profile-results.json`):

| Metric | Median | Range |
|---|---:|---:|
| Handshake | 35.745 s | 35.740–35.750 s |
| `ecp_mul` (2 calls) | 11.770 s | 11.765–11.770 s |
| `ecp_muladd` (2 calls) | 23.695 s | 23.690–23.695 s |
| Combined curve operations | **35.465 s** | 35.460–35.465 s |

Curve operations consumed **99.2%** of profile-build handshake time. Remaining ~280 ms includes protocol, parsing, certificate handling outside point math, network, and timer quantization. Profile build ran ~0.235 s faster than uninstrumented median; exact percentages therefore describe this profile build, not a precise cycle breakdown of uninstrumented code. Both builds demonstrate point math dominates handshake.

## Cleanup

U64 restored from `/USB1/update_pr871_4402a806.u64`. `GET /v1/info` after cold boot reports firmware 3.15, commit `4402a806`, FPGA 126, core 1.50. Temporary peer listeners stopped and all four beast UFW allow rules for ports 18443/18444 removed.

## Limits on interpretation

This one profile is a realistic authenticated TLS 1.2 best case for a CPU without AES hardware. It does not measure RSA certificate verification, AES-GCM, TLS 1.3, public CA bundles, DNS, production entropy, server TLS, or other Ultimate CPUs. PR #997 uses ESP-IDF 6 / Mbed TLS 4.1.1, so its results must use the same negotiated TLS version and cipher, peer, payload and network path before comparing elapsed time. A U64 result cannot establish feasibility on U2 or U2+.
