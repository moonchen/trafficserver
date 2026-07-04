#!/usr/bin/env python3
'''
Open a TCP connection to an ATS TLS port, begin a TLS handshake with a partial
ClientHello, stall past the configured handshake timeout, then send one more
byte to re-drive the handshake. ATS should time the handshake out and close.
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
import sys
import time


def main():
    parser = argparse.ArgumentParser(description='Stall a TLS handshake against ATS.')
    parser.add_argument('-p', '--ats-port', type=int, dest='ats_port', required=True, help='ATS TLS port number')
    parser.add_argument('-w', '--wait', type=float, dest='wait', default=3.0, help='seconds to stall mid-handshake')
    args = parser.parse_args()

    # A TLS record header announcing a 512-byte handshake message, followed by
    # only the first few ClientHello bytes: SSL_accept consumes these and asks
    # for more (WANT_READ), leaving the handshake in progress.
    partial_client_hello = bytes([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03])

    sock = socket.create_connection(('127.0.0.1', args.ats_port), timeout=10)
    try:
        sock.sendall(partial_client_hello)
        # Stall past the handshake timeout.
        time.sleep(args.wait)
        # One more byte produces a transport read event that re-drives the
        # handshake; ATS notices the deadline has passed and errors the VC.
        sock.sendall(b'\x00')
        sock.settimeout(10)
        # ATS closes the connection: recv returns empty (EOF) or raises.
        try:
            data = sock.recv(64)
            print('peer closed' if data == b'' else f'unexpected data: {data!r}')
        except (socket.timeout, ConnectionResetError, OSError) as e:
            print(f'connection ended: {e.__class__.__name__}')
    finally:
        sock.close()

    exit(0)


if __name__ == '__main__':
    main()
