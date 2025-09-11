# server/transport_tls.py
# -*- coding: utf-8 -*-
"""
TLS transport for inter-server hops, with NOPE enforcement on the sender side.
Hardened:
- TLS >= 1.2 enforced (both client & server contexts)
- Consistent timeouts
- Clear DENY logs (peer, domain, reason)
- Graceful stop() that unblocks accept()
- Safer framing (size checks) and robust close paths
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .server_logging import get_server_logger
from .nope_enforcer import verify_peer_on_socket, expected_domain_for


# ---- constants / limits -----------------------------------------------------

_BASE_PORT = 9440          # S1->9441, S2->9442, ...
_MAX_FRAME = 10 * 1024 * 1024  # 10 MiB upper bound for a single frame
_ACCEPT_TIMEOUT = 0.3         # seconds
_IO_TIMEOUT = 5.0             # seconds for client connect / server IO


def _port_for(server_id: str) -> int:
    try:
        idx = int(server_id[1:])
    except Exception:
        raise ValueError(f"Bad server_id: {server_id!r}")
    return _BASE_PORT + idx


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Receive exactly n bytes or raise ConnectionError."""
    if n < 0:
        raise ValueError("negative length not allowed")
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed while receiving")
        buf.extend(chunk)
    return bytes(buf)


def _make_client_ctx() -> ssl.SSLContext:
    # One-way TLS: we do not trust a CA — NOPE authenticates the peer post-handshake.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Harden TLS version
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        # Fallback for very old Python, still OK since PROTOCOL_TLS_CLIENT disallows SSLv3.
        pass
    # Do not check hostname / CA — our auth is NOPE, not PKI
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Reasonable socket defaults; ciphers left to system defaults (modern OpenSSL is fine)
    return ctx


def _make_server_ctx(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


@dataclass
class TLSPeerTransport:
    server_id: str

    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None

    tokens_dir: Optional[Path] = None

    host: str = "127.0.0.1"
    logger: Optional[logging.Logger] = None

    _listen_thread: Optional[threading.Thread] = field(default=None, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _on_message: Optional[Callable[[bytes], None]] = field(default=None, init=False)

    # local “poke” socket info to break accept() on stop()
    _listen_port: Optional[int] = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.logger is None:
            self.log = get_server_logger(self.server_id, "mixnet.server")
        else:
            if isinstance(self.logger, logging.Logger):
                self.log = logging.LoggerAdapter(self.logger, {"server": self.server_id})
            else:
                self.log = self.logger

        cp = self.cert_path or self.tls_cert
        kp = self.key_path or self.tls_key
        if not cp or not kp:
            raise ValueError("cert/key paths not provided (need tls_cert/tls_key or cert_path/key_path)")
        self.cert_path = Path(cp)
        self.key_path = Path(kp)

        if self.tokens_dir is not None:
            self.tokens_dir = Path(self.tokens_dir)

    # ------------------------------------------------------------------ API
    def start(self, on_message: Callable[[bytes], None]) -> None:
        """Start background TLS server loop."""
        if self._listen_thread and self._listen_thread.is_alive():
            return
        self._on_message = on_message
        self._stop_event.clear()
        self._listen_port = _port_for(self.server_id)
        t = threading.Thread(target=self._server_loop, name=f"tls-listen-{self.server_id}", daemon=True)
        t.start()
        self._listen_thread = t
        self.log.info("[TLS %s] listener started on %s:%d", self.server_id, self.host, self._listen_port)

    def stop(self) -> None:
        """Signal server loop to stop and poke the accept() so it unblocks quickly."""
        self._stop_event.set()
        # Poke accept() by connecting once to our own port; ignore errors.
        try:
            if self._listen_port is not None:
                with socket.create_connection((self.host, self._listen_port), timeout=0.2) as s:
                    pass
        except Exception:
            pass

    def send_to_peer(self, peer_id: str, payload: bytes, *, timeout: float = _IO_TIMEOUT) -> bool:
        """
        Open TLS to peer, enforce NOPE on the peer cert, then send a length-prefixed frame.
        Returns True on success, False on deny/error.
        """
        addr = (self.host, _port_for(peer_id))
        try:
            ctx = _make_client_ctx()

            t0 = time.perf_counter()
            with socket.create_connection(addr, timeout=timeout) as raw:
                raw.settimeout(timeout)
                with ctx.wrap_socket(raw, server_hostname=self.host) as ssock:
                    t_hs = time.perf_counter()
                    dom = expected_domain_for(peer_id, fallback=None)
                    ok = verify_peer_on_socket(
                        ssock,
                        server_id=peer_id,
                        mode="return_false",
                        tokens_dir=self.tokens_dir,
                        expected_domain=dom,
                    )
                    t_nv = time.perf_counter()
                    if not ok:
                        self.log.warning(
                            "DENY tls=%s peer=%s domain=%s reason=%s",
                            "client", peer_id, dom or "n/a", "NOPE verification failed"
                        )
                        return False
                    if not isinstance(payload, (bytes, bytearray)):
                        self.log.warning("DENY tls=client peer=%s reason=%s", peer_id, "payload not bytes")
                        return False
                    n = len(payload)
                    if n > _MAX_FRAME:
                        self.log.warning("DENY tls=client peer=%s reason=%s size=%d", peer_id, "frame too large", n)
                        return False

                    hdr = struct.pack(">I", n)
                    ssock.sendall(hdr + payload)
                    self.log.debug(
                        "hop=%s timings: tls=%.1fms, nope=%.1fms, total=%.1fms",
                        peer_id,
                        (t_hs - t0) * 1e3,
                        (t_nv - t_hs) * 1e3,
                        (time.perf_counter() - t0) * 1e3,
                    )
                    return True
        except Exception as e:
            self.log.warning("DENY tls=client peer=%s reason=%s", peer_id, f"send failed: {e}")
            return False

    # Backward-compat shim (older code called .send)
    def send(self, peer_id: str, payload: bytes, *, timeout: float = _IO_TIMEOUT) -> bool:
        return self.send_to_peer(peer_id, payload, timeout=timeout)

    # ------------------------------------------------------------ internals
    def _server_loop(self) -> None:
        """Single-process, iterative TLS accept loop (length-prefixed frames)."""
        ctx = _make_server_ctx(self.cert_path, self.key_path)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as base:
            base.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                base.bind((self.host, self._listen_port or _port_for(self.server_id)))
            except OSError as e:
                self.log.error("DENY tls=server reason=bind-failed port=%s err=%s",
                               self._listen_port, e)
                return
            base.listen(8)
            base.settimeout(_ACCEPT_TIMEOUT)

            while not self._stop_event.is_set():
                try:
                    try:
                        conn, _ = base.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        # Listener may be closing; re-check stop flag next iteration
                        continue

                    conn.settimeout(_IO_TIMEOUT)

                    try:
                        with ctx.wrap_socket(conn, server_side=True) as ssock:
                            # Simple length-prefixed frame
                            hdr = _recv_exact(ssock, 4)
                            (n,) = struct.unpack(">I", hdr)
                            if n < 0 or n > _MAX_FRAME:
                                raise ValueError(f"bad frame length: {n}")
                            data = _recv_exact(ssock, n)
                            if self._on_message:
                                try:
                                    self._on_message(data)
                                except Exception as cb_err:
                                    self.log.warning("handler error: %s", cb_err)
                    except Exception as e:
                        self.log.debug("TLS recv/handle error: %s", e, exc_info=False)
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass

                except Exception as loop_err:
                    # Do not crash the loop on sporadic errors
                    self.log.debug("server loop warn: %s", loop_err, exc_info=False)

        self.log.info("[TLS %s] listener stopped", self.server_id)
