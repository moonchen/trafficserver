#!/usr/bin/env python3
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
'''
A no-root TCP blackhole origin: further connects never complete the handshake.

Bind + listen with a tiny accept queue (backlog=1), then overfill that queue with
our own never-accepted self-connections. Once the accept queue is full the kernel
silently drops incoming SYNs (no SYN-ACK, no RST), so any *new* connection -- e.g.
ATS's outbound origin connect -- hangs in the handshake forever. This is a
deterministic blackhole that needs no iptables/root, unlike a refused port (which
sends a prompt RST) or a hung-after-accept origin (which completes the handshake).

argv[1] = port to listen on.
'''
import socket
import sys
import time

port = int(sys.argv[1])

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(1)  # tiny accept queue; effective capacity is a couple of slots

# Overfill the accept queue with our own connections that we never accept. The
# first couple complete the handshake and sit in the (never-drained) accept queue;
# the rest have their SYNs dropped and linger in SYN_SENT. Either way the queue
# stays full, so every subsequent SYN (including ATS's) is dropped.
fillers = []
for _ in range(64):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setblocking(False)
    try:
        c.connect(("127.0.0.1", port))
    except (BlockingIOError, OSError):
        pass
    fillers.append(c)

# Give the handshakes that will land a moment to occupy the queue.
time.sleep(0.5)
print("blackhole origin ready on {0}".format(port), flush=True)

# Never accept; hold the listen socket and fillers open so the queue stays full.
while True:
    time.sleep(3600)
