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
Idle inbound client for io_uring_timeout_variants scenario (b).

Connects to the ATS port, sends only a partial request line (no terminating
CRLFCRLF), then blocks in recv(). ATS accepts the connection, arms an io_uring
recvmsg for the rest of the request, and after transaction_no_activity_timeout_in
the inbound inactivity timeout fires with that recv still in flight. ATS closes
the connection, so our recv() returns EOF. Print a marker + how long it took so
the test can confirm the close was the idle timeout (a second or two), not an
immediate reject or a 30s fall-through default.
'''
import socket
import sys
import time


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Partial request: enough to start the HTTP read (recv armed), never completed.
    s.sendall(b"GET /")
    s.settimeout(20)
    start = time.monotonic()
    try:
        data = s.recv(65536)
    except socket.timeout:
        print("NO_CLOSE ATS did not close within the read window", flush=True)
        return 1
    elapsed = time.monotonic() - start
    if data == b"":
        print("SERVER_CLOSED elapsed={0:.2f}".format(elapsed), flush=True)
        return 0
    # ATS returned something (e.g. a 408); still an ATS-initiated close follows.
    print("SERVER_SENT elapsed={0:.2f} bytes={1}".format(elapsed, len(data)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
