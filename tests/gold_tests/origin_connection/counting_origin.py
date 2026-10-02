'''
An origin that delays each response and reports how many connections are open to it. It serves
HTTP/1.1, or HTTP/2 over TLS.
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
import os
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import h2.config
import h2.connection
import h2.events

RESPONSE: bytes = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'


class ConnectionCounter:
    """Count the open connections and the largest number open at once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._open = 0
        self._peak = 0

    def opened(self) -> None:
        with self._lock:
            self._open += 1
            self._peak = max(self._peak, self._open)
            print(f'connection opened: open={self._open} peak={self._peak}', flush=True)

    def closed(self) -> None:
        with self._lock:
            self._open -= 1
            print(f'connection closed: open={self._open} peak={self._peak}', flush=True)


def make_tls_context(name: str) -> ssl.SSLContext:
    """Create a TLS context that offers HTTP/2, with a self-signed certificate for name."""
    directory = tempfile.mkdtemp(dir='.')
    cert = os.path.join(directory, 'origin.crt')
    key = os.path.join(directory, 'origin.key')
    subprocess.run(
        [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '3', '-subj',
            f'/CN={name}'
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(['h2'])
    return context


class DelayedResponseHandler(socketserver.BaseRequestHandler):
    """Answer each request on a keep-alive connection after a delay."""

    counter: ConnectionCounter
    delay: float
    # Serve HTTP/2 over TLS when set, otherwise HTTP/1.1.
    tls_context: ssl.SSLContext | None = None

    def handle(self) -> None:
        self.counter.opened()
        try:
            if self.tls_context is None:
                self._serve()
            else:
                self._serve_h2()
        except OSError:
            pass
        finally:
            self.counter.closed()

    def _serve(self) -> None:
        pending = b''
        while True:
            while b'\r\n\r\n' not in pending:
                data = self.request.recv(4096)
                if not data:
                    return
                pending += data
            header, pending = pending.split(b'\r\n\r\n', 1)
            request_line = header.split(b'\r\n', 1)[0].decode('latin-1')
            print(f'request: {request_line}', flush=True)
            time.sleep(self.delay)
            self.request.sendall(RESPONSE)

    def _serve_h2(self) -> None:
        sock = self.tls_context.wrap_socket(self.request, server_side=True)
        connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())
        paths: dict[int, str] = {}
        while True:
            data = sock.recv(65535)
            if not data:
                return
            for event in connection.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    paths[event.stream_id] = dict(event.headers).get(b':path', b'').decode('latin-1')
                elif isinstance(event, h2.events.StreamEnded):
                    print(f'request: GET {paths.pop(event.stream_id, "")} HTTP/2', flush=True)
                    time.sleep(self.delay)
                    connection.send_headers(event.stream_id, [(':status', '200'), ('content-length', '2')])
                    connection.send_data(event.stream_id, b'ok', end_stream=True)
            sock.sendall(connection.data_to_send())


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', type=int, help='The port to listen on.')
    parser.add_argument('--delay', type=float, default=2.0, help='Seconds to wait before each response.')
    parser.add_argument(
        '--h2', metavar='NAME', help='Serve HTTP/2 over TLS, with a self-signed certificate for NAME, instead of HTTP/1.1.')
    args = parser.parse_args()

    DelayedResponseHandler.counter = ConnectionCounter()
    DelayedResponseHandler.delay = args.delay
    if args.h2:
        DelayedResponseHandler.tls_context = make_tls_context(args.h2)
    with ThreadedServer(('127.0.0.1', args.port), DelayedResponseHandler) as server:
        server.serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
