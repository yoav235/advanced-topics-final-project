# server/mixnet_tls_transport.py
# -*- coding: utf-8 -*-
"""
Mixnet TLS Transport (NOPE-only)
--------------------------------
A minimal transport layer that performs TLS + NOPE attestation only (no CA).
- Server: requests a client certificate (mTLS), performs TLS handshake, then enforces NOPE on the peer.
- Client: presents a certificate, connects, and enforces NOPE on the server.

This module provides:
- server_once(): accept a single TLS connection, enforce NOPE, receive one request and send one reply.
- client_request(): open a TLS connection, enforce NOPE, send one request and receive one reply.
- send_msg()/recv_msg(): length-prefixed binary framing (4-byte big-endian length + body).
- send_json()/recv_json(): JSON sugar over the same framing.

Prerequisites:
- Files tls/cert.pem and tls/key.pem exist (created by init_tls.py).
- NOPE tokens live under nope/tokens/ (created by init_nope.py).
- server/nope_enforcer.py is present (uses server/nope_utils.py).

Typical usage:

    # Server:
    from server.mixnet_tls_transport import server_once
    def handler(body: bytes) -> bytes:
        return b"ACK:" + body
    reply = server_once(
        bind=("0.0.0.0", 9443),
        expected_peer_id="S1",
        expected_domain="mix1.local",
        handle_request=handler,
    )

    # Client:
    from server.mixnet_tls_transport import client_request
    resp = client_request(
        remote=("127.0.0.1", 9443),
        expected_peer_id="S2",
        expected_domain="mix2.local",
        payload=b"hello",
    )

By default we do mTLS (server requests client cert; client presents).
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import time
from typing import Callable, Optional, Tuple

from server.tls_runtime import (
    make_server_context,
    make_client_context,
    accept_once_with_nope,
    connect_with_nope,
)
from server.nope_enforcer import expected_domain_for

log = logging.getLogger(__name__)

# Framing: 4-byte big-endian length prefix, then the message body.
_LEN = struct.Struct(">I")
_MAX_MSG = 1 << 20  # 1 MiB max message size (tweak as needed)

__all__ = [
    "send_msg",
    "recv_msg",
    "send_json",
    "recv_json",
    "server_once",
    "client_request",
]


# -----------------------------
# Binary framing & JSON helpers
# -----------------------------

def send_msg(sock: socket.socket, body: bytes) -> None:
    """Send a single message with a 4-byte length prefix followed by the body."""
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    n = len(body)
    if n < 0 or n > _MAX_MSG:
        raise ValueError(f"message too large (>{_MAX_MSG} bytes)")
    sock.sendall(_LEN.pack(n) + body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise if the peer closes early."""
    if n < 0:
        raise ValueError("negative length not allowed")
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        r = sock.recv_into(view[got:], n - got)
        if r == 0:
            raise ConnectionError("peer closed during recv")
        got += r
    return bytes(buf)


def recv_msg(sock: socket.socket) -> bytes:
    """Receive one framed message (4-byte length + body)."""
    header = _recv_exact(sock, _LEN.size)
    (length,) = _LEN.unpack(header)
    if length < 0 or length > _MAX_MSG:
        raise ValueError(f"declared length too large ({length} > {_MAX_MSG})")
    return _recv_exact(sock, length)


def send_json(sock: socket.socket, obj) -> None:
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    send_msg(sock, data)


def recv_json(sock: socket.socket):
    data = recv_msg(sock)
    return json.loads(data.decode("utf-8"))


# -----------------------------
# Server-side API
# -----------------------------

def server_once(
    bind: Tuple[str, int],
    *,
    expected_peer_id: Optional[str],
    expected_domain: Optional[str],
    handle_request: Callable[[bytes], bytes] | None = None,
    request_client_cert: bool = True,
    timeout: Optional[float] = 10.0,
) -> bytes:
    """
    Accept a single TLS connection:
      1) build server TLS context (requesting client cert if request_client_cert=True)
      2) perform TLS handshake
      3) enforce NOPE on the peer (expected_peer_id/domain)
      4) read one request, pass through handle_request (if provided), and send a single reply

    Returns the bytes reply (useful in tests).
    """
    ctx = make_server_context(request_client_cert=request_client_cert)

    # Resolve domain precedence (expected_domains.json > explicit arg > token > mixN.local)
    dom = expected_domain
    if expected_peer_id:
        dom = dom or expected_domain_for(expected_peer_id, fallback=None)

    # Enforce NOPE at accept time; if it fails, print a canonical DENY line.
    try:
        ssock, addr = accept_once_with_nope(
            bind,
            ctx,
            expected_peer_id=expected_peer_id,
            expected_domain=dom,
            enforce=True,
            timeout=timeout,
        )
    except Exception:
        # Canonical line used by tests and diagnostics:
        print(
            f"DENY peer_id={expected_peer_id or 'unknown'} "
            f"domain={dom or 'unknown'} reason=nope-verify-failed",
            flush=True,
        )
        raise

    # If we are here, NOPE is already enforced successfully (when expected_peer_id is provided).
    try:
        try:
            req = recv_msg(ssock)
        except Exception:
            # If peer tears down after NOPE failure on their side, surface a clear DENY as well.
            print(
                f"DENY peer_id={expected_peer_id or 'unknown'} "
                f"domain={dom or 'unknown'} reason=nope-verify-failed",
                flush=True,
            )
            raise

        if handle_request:
            resp = handle_request(req)
            if not isinstance(resp, (bytes, bytearray, memoryview)):
                raise TypeError("handle_request() must return bytes-like")
        else:
            # default: echo
            resp = req
        send_msg(ssock, resp)
        return bytes(resp)
    finally:
        try:
            ssock.close()
        except Exception:
            pass


# -----------------------------
# Client-side API
# -----------------------------

def _is_conn_refused_oserror(err: OSError) -> bool:
    """Return True if the OSError represents a connection refused condition."""
    # Windows: 10061, Linux: 111
    return isinstance(err, ConnectionRefusedError) or getattr(err, "errno", None) in (10061, 111)


def client_request(
    remote: Tuple[str, int],
    *,
    expected_peer_id: Optional[str],
    expected_domain: Optional[str],
    payload: bytes | bytearray | memoryview,
    present_client_cert: bool = True,
    timeout: Optional[float] = 5.0,
    connect_attempts: int = 10,
    connect_delay: float = 0.05,
) -> bytes:
    """
    Send one request and receive one reply:
      1) build client TLS context (present client cert if present_client_cert=True)
      2) perform TLS handshake (with small retries to absorb startup races)
      3) enforce NOPE on the server (expected_peer_id/domain)
      4) send payload and receive a single reply
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    if not expected_peer_id:
        # for client-side we *must* know who we expect to talk to
        raise ValueError("expected_peer_id is required on client_request()")

    ctx = make_client_context(present_client_cert=present_client_cert)

    # Resolve domain precedence (expected_domains.json > explicit arg > token > mixN.local)
    dom = expected_domain or expected_domain_for(expected_peer_id, fallback=None)

    # Small connection retry loop to avoid races where the peer listener thread
    # has bound the port but is not yet accepting connections.
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max(1, connect_attempts) + 1):
        try:
            ss = connect_with_nope(
                remote,
                ctx,
                expected_peer_id=expected_peer_id,
                expected_domain=dom,
                enforce=True,
                timeout=timeout,
            )
            break  # success
        except OSError as e:
            if _is_conn_refused_oserror(e) and attempt < connect_attempts:
                if attempt == 1:
                    log.warning(
                        "TLS connect to %s:%s refused; will retry up to %d times (%.0f ms interval).",
                        remote[0], remote[1], connect_attempts, connect_delay * 1000.0
                    )
                time.sleep(connect_delay)
                last_exc = e
                continue
            # Any other OSError (or exhausted retries) -> re-raise
            raise
        except Exception:
            # Non-OSError exceptions (e.g., NOPE enforcement failures).
            print(
                f"DENY peer_id={expected_peer_id} domain={dom or 'unknown'} reason=nope-verify-failed",
                flush=True,
            )
            raise
    else:
        # Should not reach here, but keep a safeguard.
        if last_exc is not None:
            raise last_exc  # pragma: no cover
        raise RuntimeError("connect_with_nope failed unexpectedly")  # pragma: no cover

    try:
        try:
            send_msg(ss, payload)
            resp = recv_msg(ss)
        except Exception:
            # If server denies (e.g., because *its* NOPE check failed), make denial explicit in logs.
            print(
                f"DENY peer_id={expected_peer_id} domain={dom or 'unknown'} reason=nope-verify-failed",
                flush=True,
            )
            raise
        return resp
    finally:
        try:
            ss.close()
        except Exception:
            pass


# -----------------------------
# Demo (optional)
# -----------------------------
if __name__ == "__main__":
    # Manual smoke test:
    # Terminal 1:  python -m server.mixnet_tls_transport server
    # Terminal 2:  python -m server.mixnet_tls_transport client
    import sys

    def _demo_handler(b: bytes) -> bytes:
        return b"ACK:" + b

    if len(sys.argv) >= 2 and sys.argv[1] == "server":
        print("Starting demo server on 127.0.0.1:9443 (expects S1@mix1.local)...")
        server_once(
            ("127.0.0.1", 9443),
            expected_peer_id="S1",
            expected_domain="mix1.local",
            handle_request=_demo_handler,
        )
        print("Server handled one request.")
    elif len(sys.argv) >= 2 and sys.argv[1] == "client":
        print("Starting demo client to 127.0.0.1:9443 (expects S2@mix2.local)...")
        r = client_request(
            ("127.0.0.1", 9443),
            expected_peer_id="S2",
            expected_domain="mix2.local",
            payload=b"hello",
        )
        print("Client got:", r)
    else:
        print("Usage:\n  python -m server.mixnet_tls_transport server\n  python -m server.mixnet_tls_transport client")
