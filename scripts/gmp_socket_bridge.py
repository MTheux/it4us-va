#!/usr/bin/env python3
"""Loopback-only TCP bridge for the manager's Docker Unix socket.

The Compose port mapping is restricted to host 127.0.0.1. This process logs
neither GMP commands nor credentials; authentication remains with gvmd.
"""
from __future__ import annotations

import socket
import socketserver
import threading


SOCKET_PATH = "/run/gvmd/gvmd.sock"


def copy(source: socket.socket, destination: socket.socket) -> None:
    try:
        while data := source.recv(65536):
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as manager:
            manager.connect(SOCKET_PATH)
            upstream = threading.Thread(target=copy, args=(self.request, manager), daemon=True)
            upstream.start()
            copy(manager, self.request)
            upstream.join(timeout=2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8


if __name__ == "__main__":
    with Server(("0.0.0.0", 9390), Handler) as server:
        server.serve_forever(poll_interval=0.5)
