#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
'''
Trickle origin for io_uring_timeout_variants scenario (a).

Accepts a connection, reads the request, sends a 200 + a large Content-Length,
then trickles the body a few bytes at a time forever (well under the advertised
length). ATS keeps an io_uring recvmsg armed for the rest of the origin body,
so the outbound transaction_active_timeout_out cap fires with that recv in
flight. Handles each connection in its own thread so several transactions can
be driven across the test.
'''
import socket
import sys
import threading
import time

# Far larger than anything ATS can pull in the 3s active-timeout window, so the
# recv is always armed for more body when the active timeout fires.
CONTENT_LENGTH = 2_000_000
CHUNK = b"x" * 200
INTERVAL = 0.5


def handle(conn):
    try:
        conn.settimeout(30)
        # Drain (at least the) request headers so ATS's request write completes
        # and it moves on to reading our response body.
        try:
            conn.recv(65536)
        except OSError:
            pass
        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                     b"Content-Length: " + str(CONTENT_LENGTH).encode() + b"\r\n"
                     b"\r\n")
        sent = 0
        while sent < CONTENT_LENGTH:
            conn.sendall(CHUNK)
            sent += len(CHUNK)
            time.sleep(INTERVAL)
    except OSError:
        # ATS closed the connection at the active timeout -- expected.
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(128)
    print("trickle origin ready", flush=True)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
