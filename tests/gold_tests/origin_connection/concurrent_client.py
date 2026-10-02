'''
Send requests to Traffic Server at the same moment, each on its own connection.
'''
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

import argparse
import collections
import socket
import sys
import time

# Time for Traffic Server to accept every connection, and later to read the first part of the early
# request, so that the rest of the requests arrive together and it reads them in one pass of its
# event loop.
SETTLE_SECONDS: float = 0.5


def make_request(index: int) -> bytes:
    return f'GET /request-{index} HTTP/1.1\r\nHost: www.example.com\r\n\r\n'.encode()


def read_status(sock: socket.socket) -> int:
    """Read one response and return its status code."""
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('The connection closed before the response header was complete.')
        data += chunk
    header, body = data.split(b'\r\n\r\n', 1)
    lines = header.decode('latin-1').split('\r\n')
    status = int(lines[0].split()[1])
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(':')
        if name.strip().lower() == 'content-length':
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', type=int, help='The Traffic Server port.')
    parser.add_argument('--count', type=int, default=6, help='The number of requests and connections.')
    parser.add_argument('--timeout', type=float, default=30.0, help='Seconds to wait for each response.')
    args = parser.parse_args()

    sockets = [socket.create_connection(('127.0.0.1', args.port), timeout=args.timeout) for _ in range(args.count)]
    time.sleep(SETTLE_SECONDS)

    # Traffic Server starts the state machine for a request when the first bytes of the request
    # arrive. When several requests queue behind one new origin connection, it gives the connection
    # to the queued state machine with the highest address, not to the request that opened it. The
    # first request starts early and completes last, so the request that opens the connection is
    # neither the first nor the last state machine started. Whether addresses rise or fall in
    # allocation order, a different request then gets the connection.
    early_request = make_request(0)
    split = early_request.index(b'\r\n') + 2
    sockets[0].sendall(early_request[:split])
    time.sleep(SETTLE_SECONDS)
    for index in range(1, args.count):
        sockets[index].sendall(make_request(index))
    sockets[0].sendall(early_request[split:])

    statuses = collections.Counter()
    for index, sock in enumerate(sockets):
        status = read_status(sock)
        print(f'request-{index}: status {status}')
        statuses[status] += 1
        sock.close()
    for status, count in sorted(statuses.items()):
        print(f'status {status}: {count} responses')
    return 0


if __name__ == '__main__':
    sys.exit(main())
