#!/usr/bin/env python3
'''
Origin for the cache write lead tests.

Serves /<rate_kib>/<name>/<size> with Range support, sending the body at rate_kib KiB/s (0 for no limit). Byte i of
every body is the same, so a client can check any part of it: see write_lead_helpers.body(). The socket send buffer is
small, so the bytes the origin has sent are close to the bytes the proxy has read. Each request is logged as JSON lines:
"start", "sent" after every 64 KiB, and "end".

usage: paced_origin.py <port> <log file>
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

import http.server
import itertools
import json
import re
import socket
import sys
import threading
import time

PIECE = 1 << 16
LINE = 16
SEND_BUFFER = 1 << 16

lock = threading.Lock()
ids = itertools.count(1)
log_path = ''


def body(beg: int, end: int) -> bytes:
    '''Return the body bytes [beg, end): every 16-byte line holds its own offset.'''

    first = beg - beg % LINE
    lines = b''.join(b'%015x\n' % offset for offset in range(first, end, LINE))
    return lines[beg - first:end - first]


def log(record: dict) -> None:
    with lock:
        with open(log_path, 'a') as f:
            f.write(json.dumps({**record, 't': time.time()}) + '\n')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SEND_BUFFER)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        m = re.fullmatch(r'/(\d+)/([a-z][a-z0-9-]*)/(\d+)', self.path)
        if m is None:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        rate, size = int(m.group(1)) * 1024, int(m.group(3))
        rid = next(ids)
        value = self.headers.get('Range')
        log({'ev': 'start', 'id': rid, 'path': self.path, 'range': value})

        beg, end, status = 0, size, 200
        r = re.fullmatch(r'bytes=(\d+)-(\d*)', value or '')
        if r is not None:
            beg = int(r.group(1))
            end = min(int(r.group(2)) + 1 if r.group(2) else size, size)
            status = 206
        self.send_response(status)
        self.send_header('Cache-Control', 'max-age=3600')
        self.send_header('ETag', '"v1"')
        self.send_header('Last-Modified', 'Mon, 01 Jan 2024 00:00:00 GMT')
        if status == 206:
            self.send_header('Content-Range', f'bytes {beg}-{end - 1}/{size}')
        self.send_header('Content-Length', str(end - beg))
        self.end_headers()

        sent = 0
        complete = False
        start = time.monotonic()
        try:
            for pos in range(beg, end, PIECE):
                self.wfile.write(body(pos, min(pos + PIECE, end)))
                sent += min(PIECE, end - pos)
                log({'ev': 'sent', 'id': rid, 'sent': sent})
                if rate > 0:
                    delay = start + sent / rate - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
            self.wfile.flush()
            complete = True
        except OSError:
            self.close_connection = True
        finally:
            log({'ev': 'end', 'id': rid, 'sent': sent, 'complete': complete})


def main():
    global log_path
    port, log_path = int(sys.argv[1]), sys.argv[2]
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == '__main__':
    main()
