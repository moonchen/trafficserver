#!/usr/bin/env python3
'''
An HTTP/2 client that aborts a request while the origin response is still in
flight, exercising the proxy-side session teardown path (do_io_close/destroy)
with a stream still attached.
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
import socket
import ssl
import struct
import time

import h2.connection
import h2.events


def get_socket(port: int) -> socket.socket:
    """Create a TLS-wrapped, ALPN-h2 socket to the proxy."""
    socket.setdefaulttimeout(15)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    tls_socket = socket.create_connection(('localhost', port))
    return ctx.wrap_socket(tls_socket, server_hostname='localhost')


def send_request(port: int, path: str) -> (socket.socket, h2.connection.H2Connection):
    """Open an H2 connection and send a single GET, returning the socket+conn."""
    tls_socket = get_socket(port)
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    tls_socket.sendall(conn.data_to_send())
    headers = [
        (':method', 'GET'),
        (':path', path),
        (':authority', 'localhost'),
        (':scheme', 'https'),
    ]
    conn.send_headers(1, headers, end_stream=True)
    tls_socket.sendall(conn.data_to_send())
    return tls_socket, conn


def abort(port: int, path: str, iterations: int, wait: float) -> None:
    """Repeatedly send a request, then drop the connection while the slow origin
    response is still outstanding. This drives the proxy to tear the client
    session down with a stream still in flight."""
    for i in range(iterations):
        tls_socket, _ = send_request(port, path)
        # Give the proxy time to accept the stream and dispatch to origin, but
        # close well before the (slow) origin responds.
        time.sleep(wait)
        # Abort hard with a TCP RST so the proxy observes an inbound EOS/ERROR
        # mid-response rather than a graceful shutdown.
        tls_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        tls_socket.close()
        print(f"aborted connection {i + 1}/{iterations}")


def complete(port: int, path: str) -> None:
    """Send a request and read the full response, proving the proxy still serves
    traffic after the abort storm (i.e. it did not crash during teardown)."""
    tls_socket, conn = send_request(port, path)
    status = None
    ended = False
    body = b''
    while not ended:
        data = tls_socket.recv(65536)
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                for name, value in event.headers:
                    if name == b':status':
                        status = value.decode()
            elif isinstance(event, h2.events.DataReceived):
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                body += event.data
            elif isinstance(event, h2.events.StreamEnded):
                ended = True
                break
        tls_socket.sendall(conn.data_to_send())
    print(f"status={status} body_len={len(body)}")
    conn.close_connection()
    tls_socket.sendall(conn.data_to_send())
    tls_socket.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("path")
    parser.add_argument("mode", choices=["abort", "complete"])
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--wait", type=float, default=0.3)
    args = parser.parse_args()

    if args.mode == "abort":
        abort(args.port, args.path, args.iterations, args.wait)
    else:
        complete(args.port, args.path)


if __name__ == '__main__':
    main()
