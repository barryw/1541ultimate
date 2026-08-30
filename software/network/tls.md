# TLS client support

TLS uses `mozilla-ca.pem`, the full Mozilla NSS trust store published by curl
on August 13, 2026. Its SHA-256 is
`f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`.
It is initialized with the ESP hardware RNG at coprocessor boot. Public trust
changes only when this pinned bundle is updated and new firmware is installed.
The PEM conversion does not preserve Firefox-only name constraints; this is
the same limitation documented for curl's Mozilla extract.

## Custom certificate authorities

To add private or otherwise unlisted certificate authorities, upload a PEM
bundle to `/flash/data/custom-ca.pem` and reboot the Ultimate. The file may
contain one or more CA certificates and must be smaller than 4096 bytes.
Custom roots augment the public bundle; they do not replace it. Removing the
file and rebooting removes the custom trust.

## Hardware

| Hardware | TLS | Network paths |
| --- | --- | --- |
| Ultimate 64 / Ultimate 64 Elite | TLS 1.2 and 1.3 | Ethernet and WiFi |
| Ultimate 64 Elite-II | TLS 1.2 and 1.3 | Ethernet and WiFi |
| Commodore 64 Ultimate | TLS 1.2 and 1.3 | Ethernet and WiFi |
| Ultimate-II+L | TLS 1.2 | Ethernet and WiFi |
| Ultimate-II+ | Not supported | No ESP cryptographic coprocessor |
| Ultimate-II | Not supported | No ESP cryptographic coprocessor |

TLS is compiled only into the first four targets above. Ultimate-II+ and
Ultimate-II builds contain none of the TLS socket, custom-CA, or TLS-only
interface-selection code.

TLS 1.3 is deliberately disabled on the Ultimate-II+L: it leaves only 16 KiB
free in the ESP32-C3 application partition. TLS 1.2 leaves about 81 KiB free.

TLS requires a working ESP WiFi module even when the connection itself uses
Ethernet, because that module performs the cryptography. The module is optional
on the Ultimate-II+L and may be absent from some older Ultimate 64 boards.

## Limits

- Client connections only; no TLS or HTTPS server.
- One TLS socket at a time. Plain TCP and UDP sockets remain available.
- Server authentication only; client certificates and PSK modes are not exposed.
- Certificate hostname and validity dates are always verified. The clock must
  be valid, normally through NTP after Ethernet or WiFi connects.
- No TLS session resumption. Each new connection performs a new handshake.
- No ALPN selection, so HTTP/2 is not negotiated. HTTPS uses HTTP/1.1.
- ChaCha20-Poly1305-only servers are not supported. AES-GCM is supported.
- Servers must send any required intermediate certificates. Private,
  self-signed, or Mozilla-untrusted roots require `custom-ca.pem`.
