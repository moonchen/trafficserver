'''
A minimal TCP server that accepts connections and immediately closes them
without sending any data. Used to test ATS behavior when the origin server
closes the connection without responding.
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

import socket
import sys


def main():
    port = int(sys.argv[1])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    srv.settimeout(30)

    # Accept a few connections to handle retries, then exit.
    for _ in range(5):
        try:
            conn, _ = srv.accept()
            # Read the request so the client doesn't get a RST.
            try:
                conn.recv(4096)
            except Exception:
                pass
            # Close without sending any response.
            conn.close()
        except socket.timeout:
            break

    srv.close()


if __name__ == '__main__':
    main()
