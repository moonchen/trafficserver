#!/usr/bin/env python3

import socket
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>", file=sys.stderr)
        return 2

    port = int(sys.argv[1])

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", port))
    listen_sock.listen(1)
    print(f"LISTENING {port}", flush=True)

    listen_sock.settimeout(5.0)

    data = b""
    conn = None
    try:
        while len(data) == 0:
            conn, _ = listen_sock.accept()
            conn.settimeout(2.0)
            try:
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass

            if len(data) == 0:
                conn.close()
                conn = None
    except socket.timeout:
        pass

    print(f"READ {len(data)} BYTES", flush=True)
    if conn is not None:
        conn.close()
    listen_sock.close()
    print("CLOSED WITHOUT RESPONSE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
