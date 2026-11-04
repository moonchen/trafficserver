#!/usr/bin/env python3
'''
Origin for the slice collapse and prefetch tests.

Serves /<delay_ms>/<name>/<size> with Range support, after waiting delay_ms before the response header. A name
that starts with "cut" makes the first response that starts at byte 0 send half of its body and then close the
connection. A name that starts with "gate<n>" holds the first response that starts at byte 0 until n requests for
that range have arrived, or 30 seconds have passed. Every request is appended to the log file as a JSON line.

usage: delay_origin.py <port> <log file>
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
import json
import re
import sys
import threading
import time

ALPHABET = b'abcdefghijklmnopqrstuvwxyz0123456789'

lock = threading.Lock()
arrived = threading.Condition(lock)
counts: dict[tuple[str, str | None], int] = {}
log_path = ''


def body_for(size: int) -> bytes:
    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        m = re.fullmatch(r'/(\d+)/([a-z][a-z0-9-]*)/(\d+)', self.path)
        if m is None:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        delay, name, size = int(m.group(1)), m.group(2), int(m.group(3))
        value = self.headers.get('Range')
        with lock:
            counts[(self.path, value)] = counts.get((self.path, value), 0) + 1
            count = counts[(self.path, value)]
            with open(log_path, 'a') as f:
                f.write(json.dumps({'path': self.path, 'range': value}) + '\n')
            arrived.notify_all()

        time.sleep(delay / 1000)
        body = body_for(size)
        beg, end, status = 0, size, 200
        r = re.fullmatch(r'bytes=(\d+)-(\d*)', value or '')
        if r is not None:
            beg = int(r.group(1))
            end = min(int(r.group(2)) + 1 if r.group(2) else size, size)
            status = 206
        gate = re.match(r'gate(\d+)', name)
        if gate is not None and beg == 0 and count == 1:
            with lock:
                arrived.wait_for(lambda: counts[(self.path, value)] >= int(gate.group(1)), timeout=30)
        self.send_response(status)
        self.send_header('Cache-Control', 'max-age=3600')
        self.send_header('ETag', '"v1"')
        if status == 206:
            self.send_header('Content-Range', f'bytes {beg}-{end - 1}/{size}')
        self.send_header('Content-Length', str(end - beg))
        self.end_headers()
        if name.startswith('cut') and beg == 0 and count == 1:
            self.wfile.write(body[beg:beg + (end - beg) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(body[beg:end])


def main():
    global log_path
    port, log_path = int(sys.argv[1]), sys.argv[2]
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == '__main__':
    main()
