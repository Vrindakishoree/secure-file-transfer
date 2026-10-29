"""Minimal TCP transport. The package is already encrypted + signed, so the
socket itself needs no extra security (add TLS in production for metadata privacy)."""
import socket
import struct
from pathlib import Path

MAX_PACKAGE = 512 * 1024 * 1024  # 512 MB safety cap


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed early.")
        buf += chunk
    return buf


def send_package(path, host, port):
    data = Path(path).read_bytes()
    with socket.create_connection((host, port), timeout=15) as s:
        s.sendall(struct.pack(">Q", len(data)) + data)
        return _recv_exact(s, 2)  # b"OK"


def receive_package(dst, host="0.0.0.0", port=5001):
    """Listen for ONE incoming package and save it to `dst`."""
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        print(f"[receiver] listening on {host}:{port} ...")
        conn, addr = srv.accept()
        with conn:
            (n,) = struct.unpack(">Q", _recv_exact(conn, 8))
            if n > MAX_PACKAGE:
                raise ValueError("Package too large.")
            Path(dst).write_bytes(_recv_exact(conn, n))
            conn.sendall(b"OK")
        print(f"[receiver] got {n} bytes from {addr[0]}")
