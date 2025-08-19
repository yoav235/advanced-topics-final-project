# server/transport_tls.py
# -*- coding: utf-8 -*-
"""
TLS transport for inter-server hops, with NOPE enforcement on the sender side.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .server_logging import get_server_logger
from .nope_enforcer import verify_peer_on_socket


def _port_for(server_id: str) -> int:
    try:
        idx = int(server_id[1:])
    except Exception:
        raise ValueError(f"Bad server_id: {server_id!r}")
    return 9440 + idx


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed while receiving")
        buf.extend(chunk)
    return bytes(buf)


@dataclass
class TLSPeerTransport:
    server_id: str

    # accept both naming styles (compat)
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None

    # NEW: where to look for NOPE tokens (e.g., nope/tokens)
    tokens_dir: Optional[Path] = None

    host: str = "127.0.0.1"
    logger: Optional[logging.Logger] = None

    # internal
    _listen_thread: Optional[threading.Thread] = field(default=None, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _on_message: Optional[Callable[[bytes], None]] = field(default=None, init=False)

    def __post_init__(self) -> None:
        # logger adapter with {server: ...}
        if self.logger is None:
            self.log = get_server_logger(self.server_id, "mixnet.server")
        else:
            if isinstance(self.logger, logging.Logger):
                self.log = logging.LoggerAdapter(self.logger, {"server": self.server_id})
            else:
                self.log = self.logger

        # normalize cert/key paths; support both param names
        cp = self.cert_path or self.tls_cert
        kp = self.key_path or self.tls_key
        if not cp or not kp:
            raise ValueError("cert/key paths not provided (need tls_cert/tls_key or cert_path/key_path)")
        self.cert_path = Path(cp)
        self.key_path = Path(kp)

        # normalize tokens_dir if provided
        if self.tokens_dir is not None:
            self.tokens_dir = Path(self.tokens_dir)

    # ------------------------------------------------------------------ API
    def start(self, on_message: Callable[[bytes], None]) -> None:
        if self._listen_thread and self._listen_thread.is_alive():
            return
        self._on_message = on_message
        self._stop_event.clear()
        t = threading.Thread(target=self._server_loop, name=f"tls-listen-{self.server_id}", daemon=True)
        t.start()
        self._listen_thread = t
        self.log.info("[TLS %s] listener started on %s:%d", self.server_id, self.host, _port_for(self.server_id))

    def stop(self) -> None:
        self._stop_event.set()

    def send_to_peer(self, peer_id: str, payload: bytes, *, timeout: float = 3.0) -> bool:
        """Open TLS to peer, enforce NOPE on the peer cert, then send a length-prefixed frame."""
        addr = (self.host, _port_for(peer_id))
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # our auth is NOPE, not CA

            with socket.create_connection(addr, timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as ssock:
                    ok = verify_peer_on_socket(
                        ssock,
                        server_id=peer_id,
                        mode="return_false",
                        tokens_dir=self.tokens_dir,  # <-- pass through
                    )
                    if not ok:
                        self.log.warning("🚫 TLS denied for %s: invalid/missing NOPE.", peer_id)
                        return False
                    hdr = struct.pack(">I", len(payload))
                    ssock.sendall(hdr + payload)
                    return True
        except Exception as e:
            self.log.warning("Forward TLS send to %s failed: %s", peer_id, e)
            return False

    # Backward-compat shim (older code called .send)
    def send(self, peer_id: str, payload: bytes, *, timeout: float = 3.0) -> bool:
        return self.send_to_peer(peer_id, payload, timeout=timeout)

    # ------------------------------------------------------------ internals
    def _server_loop(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.cert_path), str(self.key_path))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as base:
            base.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            base.bind((self.host, _port_for(self.server_id)))
            base.listen(8)
            base.settimeout(0.3)

            while not self._stop_event.is_set():
                try:
                    conn, _ = base.accept()
                except TimeoutError:
                    continue
                except OSError:
                    continue

                try:
                    with ctx.wrap_socket(conn, server_side=True) as ssock:
                        hdr = _recv_exact(ssock, 4)
                        (n,) = struct.unpack(">I", hdr)
                        if n < 0 or n > (10 * 1024 * 1024):
                            raise ValueError(f"bad frame length: {n}")
                        data = _recv_exact(ssock, n)
                        if self._on_message:
                            self._on_message(data)
                except Exception as e:
                    self.log.debug("TLS recv error: %s", e, exc_info=False)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
