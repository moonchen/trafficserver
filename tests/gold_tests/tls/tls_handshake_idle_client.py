#!/usr/bin/env python3
"""Repro client for TLS-refactor finding #3.

Opens a TCP connection, sends a *partial* TLS ClientHello record (a record
header claiming more bytes than are actually sent, plus a truncated handshake
message), then goes completely idle. Measures how long the server takes to
close the connection.

With proxy.config.ssl.handshake_timeout_in set short and all other timeouts
long, a correct server closes at ~handshake_timeout_in. If the handshake timer
was never installed (#3), the connection survives until some looser backstop.
"""
import socket
import sys
import time

port = int(sys.argv[1])
hs_timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0

# Record: handshake(0x16), TLS1.0 version(0x0301), length 0x0200 (claims 512 bytes),
# then a truncated ClientHello (handshake type 0x01, length 0x0001fc) and a few bytes.
# Far fewer than 512 bytes follow, so the server's SSL_accept waits for the rest.
partial = bytes([0x16, 0x03, 0x01, 0x02, 0x00]) + bytes([0x01, 0x00, 0x01, 0xfc, 0x03, 0x03]) + b"\x00" * 8

s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(partial)

start = time.time()
s.settimeout(60)
try:
    while True:
        b = s.recv(4096)
        if not b:
            break  # server sent FIN
except (socket.timeout, ConnectionResetError, OSError):
    pass
elapsed = time.time() - start

# Allow for InactivityCop poll granularity (~1s) plus margin. A close within the
# handshake-timeout window means the handshake timer fired; a much later close means
# it did not and some looser timeout collected the connection instead.
if elapsed < hs_timeout + 5:
    print(f"HANDSHAKE_TIMEOUT_FIRED server_closed_after={elapsed:.2f}s")
else:
    print(f"HANDSHAKE_TIMEOUT_MISSED server_closed_after={elapsed:.2f}s")
