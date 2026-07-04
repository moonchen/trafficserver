#!/usr/bin/env python3
'''
POST a large request body through ATS and measure how long ATS takes to fail
the transaction after the origin aborts the connection mid-body.
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
import select
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description='POST through ATS; time how fast the transaction fails.')
    parser.add_argument('-p', '--proxy-port', type=int, required=True, help='ATS HTTP port')
    parser.add_argument('-s', '--size', type=int, default=64 * 1024 * 1024, help='request body size in bytes')
    parser.add_argument(
        '-t', '--threshold', type=float, default=8.0, help='maximum seconds from request start until ATS fails the transaction')
    parser.add_argument('--timeout', type=float, default=60.0, help='give up entirely after this many seconds')
    parser.add_argument(
        '--pause-after', type=int, default=0, help='stop sending body bytes after this many (0: keep sending until done)')
    args = parser.parse_args()

    start = time.monotonic()
    sock = socket.create_connection(('127.0.0.1', args.proxy_port), timeout=10)
    request = (f'POST /post HTTP/1.1\r\n'
               f'Host: origin\r\n'
               f'Content-Length: {args.size}\r\n'
               f'Connection: close\r\n'
               f'\r\n').encode()
    sock.sendall(request)
    sock.setblocking(False)

    chunk = b'x' * 65536
    sent = 0
    response = b''
    outcome = None
    while time.monotonic() - start < args.timeout:
        want_write = sent < args.size and not (args.pause_after and sent >= args.pause_after)
        readable, writable, _ = select.select([sock], [sock] if want_write else [], [], 1.0)
        if readable:
            try:
                data = sock.recv(65536)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                outcome = f'connection error while reading: {e.__class__.__name__}'
                break
            if not data:
                outcome = 'connection closed by ATS'
                break
            response += data
            if b'\r\n\r\n' in response:
                outcome = 'response received'
                break
        if writable:
            try:
                sent += sock.send(chunk[:min(len(chunk), args.size - sent)])
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                outcome = f'connection error while sending: {e.__class__.__name__}'
                break
            if sent >= args.size:
                outcome = 'entire body sent'
                break

    elapsed = time.monotonic() - start
    if outcome is None:
        outcome = 'gave up waiting'
    status = response.split(b'\r\n', 1)[0].decode(errors='replace') if response else '<none>'
    print(f'outcome: {outcome}')
    print(f'status-line: {status}')
    print(f'body-bytes-sent: {sent}')
    print(f'elapsed: {elapsed:.3f}')

    if outcome == 'entire body sent' or outcome == 'gave up waiting':
        print('FAIL: transaction did not fail at all')
        return 2
    if elapsed > args.threshold:
        print(f'FAIL: transaction failed only after {elapsed:.3f}s (threshold {args.threshold}s)')
        return 1
    print('PASS: transaction failed promptly')
    return 0


if __name__ == '__main__':
    sys.exit(main())
