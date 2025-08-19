# server/mixnet_tls_transport.py
# -*- coding: utf-8 -*-
"""
Mixnet TLS Transport (NOPE-only):
---------------------------------
שכבת תעבורה פשוטה שמבצעת TLS + אימות NOPE בלבד, בלי CA.
- בצד השרת: מבקשים תעודת לקוח (mTLS), מבצעים TLS handshake, ואז מאמתים NOPE על ה-peer.
- בצד הלקוח: מציגים תעודה, מתחברים, ומבצעים אימות NOPE על השרת.

המודול מספק:
- server_once(): מאזין לחיבור אחד, עושה אימות NOPE, מקבל בקשה ומחזיר תשובה.
- client_request(): יוצר חיבור TLS, מאמת NOPE על השרת, שולח בקשה ומחזיר תשובה.
- send_msg()/recv_msg(): פריימינג בינארי (אורך 4 בתים big-endian + גוף).
- send_json()/recv_json(): סוכר ל-JSON מעל אותו פריימינג.

כדי שהאימות יעבוד:
- קבצי tls/cert.pem ו-tls/key.pem קיימים (init_tls.py כבר יוצר).
- קבצי NOPE tokens נמצאים תחת nope/tokens/ (init_nope.py כבר יוצר).
- server/nope_enforcer.py קיים (משתמש ב-server/nope_utils.py).

שימוש טיפוסי:

    # שרת:
    from server.mixnet_tls_transport import server_once
    def handler(body: bytes) -> bytes:
        # כאן שמים את הלוגיקה של המיקס (פילטרים, ערבובים, וכו')
        return b"ACK:" + body
    reply = server_once(
        bind=("0.0.0.0", 9443),
        expected_peer_id="S1",
        expected_domain="mix1.local",
        handle_request=handler,
    )

    # לקוח:
    from server.mixnet_tls_transport import client_request
    resp = client_request(
        remote=("127.0.0.1", 9443),
        expected_peer_id="S2",
        expected_domain="mix2.local",
        payload=b"hello",
    )

הערה: בדיפולט אנחנו מבצעים mTLS (השרת מבקש תעודה; הלקוח מציג).
"""

from __future__ import annotations
import json
import socket
import struct
import logging
from typing import Tuple, Optional, Callable

from server.tls_runtime import (
    make_server_context,
    make_client_context,
    accept_once_with_nope,
    connect_with_nope,
)

log = logging.getLogger(__name__)

# פריימינג: 4 בתים (big-endian) של האורך, ואז גוף ההודעה
_LEN = struct.Struct(">I")
_MAX_MSG = 1 << 20  # 1MB מקסימום להודעה (ניתן להתאים לפי צרכי המיקס)

# -----------------------------
# פריימינג בינארי ו-JSON
# -----------------------------

def send_msg(sock: socket.socket, body: bytes) -> None:
    """שולח הודעה עם כותרת אורך (4 בתים) + גוף."""
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    if len(body) > _MAX_MSG:
        raise ValueError(f"message too large (>{_MAX_MSG} bytes)")
    sock.sendall(_LEN.pack(len(body)) + body)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """קורא בדיוק n בתים או זורק חריגה אם הסשן נסגר לפני הזמן."""
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
    """מקבל הודעה עם פריימינג (4 בתים אורך + גוף)."""
    header = recv_exact(sock, _LEN.size)
    (length,) = _LEN.unpack(header)
    if length > _MAX_MSG:
        raise ValueError(f"declared length too large ({length} > {_MAX_MSG})")
    return recv_exact(sock, length)


def send_json(sock: socket.socket, obj) -> None:
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    send_msg(sock, data)


def recv_json(sock: socket.socket):
    data = recv_msg(sock)
    return json.loads(data.decode("utf-8"))


# -----------------------------
# API צד שרת
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
    מאזין לחיבור יחיד:
      1) יוצר הקשר TLS לשרת (מבקש תעודת לקוח אם request_client_cert=True)
      2) עושה TLS handshake
      3) מאמת NOPE על ה-peer (expected_peer_id/domain)
      4) קורא בקשה אחת, מפעיל handle_request (אם נתון), ושולח תשובה
    מחזיר את התשובה שנשלחה (לנוחות בדיקות).
    """
    ctx = make_server_context(request_client_cert=request_client_cert)
    ssock, addr = accept_once_with_nope(
        bind, ctx,
        expected_peer_id=expected_peer_id,
        expected_domain=expected_domain,
        enforce=True,
        timeout=timeout,
    )
    # אם הגענו לכאן — ה-NOPE עבר בהצלחה
    try:
        req = recv_msg(ssock)
        if handle_request:
            resp = handle_request(req)
            if not isinstance(resp, (bytes, bytearray, memoryview)):
                raise TypeError("handle_request() must return bytes")
        else:
            # דיפולט: echo
            resp = req
        send_msg(ssock, resp)
        return bytes(resp)
    finally:
        try:
            ssock.close()
        except Exception:
            pass


# -----------------------------
# API צד לקוח
# -----------------------------

def client_request(
    remote: Tuple[str, int],
    *,
    expected_peer_id: Optional[str],
    expected_domain: Optional[str],
    payload: bytes | bytearray | memoryview,
    present_client_cert: bool = True,
    timeout: Optional[float] = 5.0,
) -> bytes:
    """
    שולח בקשה אחת ומחזיר תשובה:
      1) יוצר הקשר TLS ללקוח (מציג תעודה אם present_client_cert=True)
      2) עושה TLS handshake
      3) מאמת NOPE על השרת (expected_peer_id/domain)
      4) שולח payload ומקבל תשובה אחת
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")

    ctx = make_client_context(present_client_cert=present_client_cert)
    ss = connect_with_nope(
        remote, ctx,
        expected_peer_id=expected_peer_id,
        expected_domain=expected_domain,
        enforce=True,
        timeout=timeout,
    )
    try:
        send_msg(ss, payload)
        resp = recv_msg(ss)
        return resp
    finally:
        try:
            ss.close()
        except Exception:
            pass


# -----------------------------
# דוגמת שימוש (אופציונלי)
# -----------------------------
if __name__ == "__main__":
    # הרצה ידנית לבדיקת עשן:
    # טרמינל 1:  python -m server.mixnet_tls_transport server
    # טרמינל 2:  python -m server.mixnet_tls_transport client
    import sys, threading, time

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
        # שימו לב: בדמו הזה זה סתם ערכים — התאימו לשרשרת היעד שלכם
        r = client_request(
            ("127.0.0.1", 9443),
            expected_peer_id="S2",
            expected_domain="mix2.local",
            payload=b"hello",
        )
        print("Client got:", r)
    else:
        print("Usage:\n  python -m server.mixnet_tls_transport server\n  python -m server.mixnet_tls_transport client")
