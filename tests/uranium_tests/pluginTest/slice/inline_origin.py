#!/usr/bin/env python3
'''
Origin for the slice inline first block test.

Each path selects one server behavior: /<mode>/<size>. Every request is appended to the log file
as a JSON line, so the test can see which ranges reached the origin. A held response ("hold" for a
block, "holdwhole" for an origin that ignores Range) also logs event lines, and resumes once the
file <log file>.release exists.

usage: inline_origin.py <port> <log file>
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
import os
import re
import sys
import threading
import time

ALPHABET = b'abcdefghijklmnopqrstuvwxyz0123456789'

lock = threading.Lock()
counts: dict[str, int] = {}
log_path = ''


def body_for(size: int) -> bytes:
    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


def write_record(record: dict) -> None:
    with open(log_path, 'a') as f:
        f.write(json.dumps(record) + '\n')


def log_record(record: dict) -> None:
    with lock:
        write_record(record)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def _send(self, status: int, headers: dict[str, str], body: bytes = b'') -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _send_held(self, status: int, headers: dict[str, str], body: bytes) -> None:
        '''Send the first 5/8 of a body, then the rest once the release file exists.'''
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        split = len(body) * 5 // 8
        self.wfile.write(body[:split])
        log_record({'event': 'held', 'path': self.path})
        deadline = time.monotonic() + 30
        while not os.path.exists(log_path + '.release') and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            self.wfile.write(body[split:])
            log_record({'event': 'sent', 'path': self.path})
        except OSError:
            log_record({'event': 'cut', 'path': self.path})

    def _range(self, size: int) -> tuple[int, int] | None:
        '''Return the requested half-open range, clipped to the object, or None without a Range.'''
        m = re.fullmatch(r'bytes=(\d+)-(\d*)', self.headers.get('Range', ''))
        if m is None:
            return None
        beg = int(m.group(1))
        end = int(m.group(2)) + 1 if m.group(2) else size
        return beg, min(end, size)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        m = re.fullmatch(r'/([a-z]+)/(\d+)', self.path)
        if m is None:
            self._send(404, {})
            return
        mode, size = m.group(1), int(m.group(2))
        with lock:
            counts[self.path] = counts.get(self.path, 0) + 1
            count = counts[self.path]
            write_record(
                {
                    'method': self.command,
                    'path': self.path,
                    'range': self.headers.get('Range'),
                    'slicer': self.headers.get('X-Slicer-Info'),
                    'ident': self.headers.get('X-Crr-Ident'),
                })

        if mode == 'changing':
            etag = f'"v{count}"'
        elif mode == 'bump':
            etag = '"v1"' if count == 1 else '"v2"'
        else:
            etag = '"v1"'
        headers = {
            'Cache-Control': 'max-age=1' if mode in ('stale', 'cond') else 'max-age=3600',
            'ETag': etag,
            'Last-Modified': 'Mon, 01 Jan 2024 00:00:00 GMT'
        }
        if mode == 'grow' and count > 1:
            size *= 2
        body = body_for(size)

        if mode == 'status':
            extra = {'Location': 'http://elsewhere/'} if size in (301, 302) else {}
            self._send(size, {'Cache-Control': 'no-store', **extra}, f'status {size}\n'.encode())
            return

        if mode == 'cond' and self.headers.get('If-None-Match') == etag:
            self._send(304, headers)
            return

        if mode == 'holdwhole' and count == 1:
            self._send_held(200, headers, body)
            return

        wanted = self._range(size)
        if wanted is None or mode in ('ignore', 'holdwhole'):
            self._send(200, headers, body)
            return

        beg, end = wanted
        if mode == 'empty' or beg >= size:
            self._send(416, {**headers, 'Content-Range': f'bytes */{size}'}, b'range not satisfiable\n')
            return
        if mode == 'short' and count == 1:
            end = beg + max((end - beg) // 2, 1)
        if mode == 'badcr':
            self._send(206, {**headers, 'Content-Range': f'bytes {beg}-{end - 1}'}, body[beg:end])
            return
        if mode == 'star':
            self._send(206, {**headers, 'Content-Range': f'bytes {beg}-{end - 1}/*'}, body[beg:end])
            return
        if mode == 'nocr':
            self._send(206, headers, body[beg:end])
            return
        if mode == 'wrongstart':
            beg = min(beg + 3, end - 1)
        if mode == 'hold' and count == 1 and beg == 0:
            self._send_held(206, {**headers, 'Content-Range': f'bytes {beg}-{end - 1}/{size}'}, body[beg:end])
            return
        self._send(206, {**headers, 'Content-Range': f'bytes {beg}-{end - 1}/{size}'}, body[beg:end])


def main():
    global log_path
    port, log_path = int(sys.argv[1]), sys.argv[2]
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == '__main__':
    main()
