#!/usr/bin/env python3
"""Minimal dual-port origin harness for ATS 502/504 timeout testing.

Port behavior:
- 19002: accept TCP and never progress TLS handshake (drives connect/handshake timeout -> 502).
- 19004: accept TCP, read request bytes, never send a response (drives inactivity timeout -> 504).
"""

from __future__ import annotations

import argparse
import signal
import socket
import threading
import time
from collections import defaultdict
from typing import DefaultDict


def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


class Harness:
    def __init__(self, host: str, port_502: int, port_504: int) -> None:
        self.host = host
        self.port_502 = port_502
        self.port_504 = port_504
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts: DefaultDict[int, int] = defaultdict(int)
        self.listeners: list[socket.socket] = []

    def _log(self, msg: str) -> None:
        print(f"{ts()} {msg}", flush=True)

    def _handle_502(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        with conn:
            self._log(f"stall_tls peer={peer[0]}:{peer[1]}")
            while not self.stop.is_set():
                time.sleep(1.0)

    def _handle_504(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                _ = conn.recv(4096)
            except (TimeoutError, socket.timeout):
                pass
            except OSError:
                return
            self._log(f"stall_ttfb peer={peer[0]}:{peer[1]}")
            while not self.stop.is_set():
                time.sleep(1.0)

    def _accept_loop(self, port: int, fn) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, port))
        srv.listen(256)
        srv.settimeout(0.5)
        self.listeners.append(srv)
        self._log(f"listening {self.host}:{port}")

        while not self.stop.is_set():
            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.counts[port] += 1
                n = self.counts[port]
            self._log(f"accept port={port} attempt={n} peer={peer[0]}:{peer[1]}")
            t = threading.Thread(target=fn, args=(conn, peer), daemon=True)
            t.start()

    def summary(self) -> None:
        with self.lock:
            c502 = self.counts[self.port_502]
            c504 = self.counts[self.port_504]
        self._log(f"summary port={self.port_502} attempts={c502}")
        self._log(f"summary port={self.port_504} attempts={c504}")

    def shutdown(self, *_args) -> None:
        self.stop.set()
        for srv in self.listeners:
            try:
                srv.close()
            except OSError:
                pass
        self.summary()

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        t1 = threading.Thread(target=self._accept_loop, args=(self.port_502, self._handle_502), daemon=True)
        t2 = threading.Thread(target=self._accept_loop, args=(self.port_504, self._handle_504), daemon=True)
        t1.start()
        t2.start()
        while not self.stop.is_set():
            time.sleep(0.5)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port-502", type=int, default=19002)
    p.add_argument("--port-504", type=int, default=19004)
    args = p.parse_args()

    h = Harness(args.host, args.port_502, args.port_504)
    h.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
