#!/usr/bin/env python3
'''
Open a TLS blind tunnel through ATS, complete the handshake against the origin,
then sit idle so ATS's tunnel inactivity timeout fires. Exit 0 once ATS closes
the connection (the expected timeout teardown).
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
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('-p', '--port', type=int, required=True, help='ATS TLS port')
    ap.add_argument('-s', '--sni', default='tunnel.test', help='SNI selecting the blind tunnel route')
    ap.add_argument('-w', '--wait', type=float, default=15.0, help='max idle seconds to wait for ATS to close')
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection(('127.0.0.1', args.port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.sni) as s:
            # The handshake terminates at the origin (raw bytes are blind-tunnelled).
            print(f"handshake complete via {s.version()}; idling up to {args.wait}s", flush=True)
            s.settimeout(args.wait)
            try:
                data = s.recv(4096)
            except socket.timeout:
                print("FAIL: idle wait elapsed without ATS closing the tunnel", flush=True)
                return 1
            except (ssl.SSLError, OSError) as e:
                print(f"OK: ATS ended the idle tunnel: {type(e).__name__}: {e}", flush=True)
                return 0
            if data == b'':
                print("OK: ATS closed the idle tunnel (clean EOF)", flush=True)
                return 0
            print(f"FAIL: unexpected data on an idle tunnel: {data[:64]!r}", flush=True)
            return 1


if __name__ == '__main__':
    sys.exit(main())
