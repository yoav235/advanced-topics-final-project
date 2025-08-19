# server/tls_runtime.py
# -*- coding: utf-8 -*-
"""
TLS runtime helpers for the project (no ZK).
- בונה הקשרי TLS לשרת/לקוח משימוש ב-tls/cert.pem + tls/key.pem
- תומך ב-mTLS אופציונלי (השרת מבקש תעודת לקוח)
- מבצע אימות NOPE מעל הסוקט לאחר ה-handshake באמצעות server/nope_enforcer.py

שימוש טיפוסי (שרת):
    from server.tls_runtime import make_server_context, accept_once_with_nope
    ctx = make_server_context(request_client_cert=True)
    ssock, addr = accept_once_with_nope(("0.0.0.0", 9443), ctx,
                                        expected_peer_id="S2", expected_domain="mix2.local",
                                        enforce=True)
    # אם הגענו לכאן — האימות עבר. אפשר לקרוא/לכתוב על ssock.

שימוש טיפוסי (לקוח):
    from server.tls_runtime import make_client_context, connect_with_nope
    ctx = make_client_context(present_client_cert=True)  # אם עושים mTLS
    ssock = connect_with_nope(("127.0.0.1", 9443), ctx,
                               expected_peer_id="S1", expected_domain="mix1.local",
                               enforce=True)

הערות:
- "expected_peer_id" הוא S1/S2/S3 בהתאם למי שמתחברים אליו.
- "expected_domain" צריך להתאים לשדה domain שב-token (e.g., mix1.local).
- אין צורך ב-ZK; verify_peer_on_socket משתמש ב-nope_utils שמאמתים את ה-token בלבד.
"""

from __future__ import annotations
import ssl
import socket
import pathlib
import logging
from typing import Optional, Tuple

from server.nope_enforcer import verify_peer_on_socket

log = logging.getLogger(__name__)
ROOT = pathlib.Path(__file__).resolve().parents[1]
TLS_DIR = ROOT / "tls"
CERT_PATH = TLS_DIR / "cert.pem"
KEY_PATH  = TLS_DIR / "key.pem"


# --------------------------
# Context builders
# --------------------------

def make_server_context(
    cert_path: pathlib.Path | str = CERT_PATH,
    key_path: pathlib.Path | str  = KEY_PATH,
    *,
    request_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    יוצר SSLContext לשרת. כברירת מחדל יבקש תעודת לקוח (CERT_OPTIONAL),
    כדי שנוכל לאחזר את ה-cert של ה-peer ולבצע אימות NOPE עליו.
    """
    cert_path = pathlib.Path(cert_path)
    key_path  = pathlib.Path(key_path)
    if not cert_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"missing TLS materials under {TLS_DIR} (cert.pem/key.pem)")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    if request_client_cert:
        # מבקש תעודת לקוח; לא דורש שרשרת CA — האימות יעשה ב-NOPE
        ctx.verify_mode = ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE
    # קשיחות סבירה
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
    return ctx


def make_client_context(
    *,
    verify_server_cert: bool = False,
    present_client_cert: bool = False,
    cert_path: pathlib.Path | str = CERT_PATH,
    key_path: pathlib.Path | str  = KEY_PATH,
) -> ssl.SSLContext:
    """
    יוצר SSLContext ללקוח.
    - verify_server_cert=False כי אנחנו עושים אימות NOPE ייעודי במקום PKI של CA.
    - present_client_cert=True אם רוצים mTLS (הלקוח מציג תעודה לשרת).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify_server_cert:
        # אם תרצו בעתיד לאמת מול CA/Anchor — לטעון כאן trust store.
        raise NotImplementedError("PKI verification is disabled in this project (using NOPE)")
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if present_client_cert:
        cert_path = pathlib.Path(cert_path)
        key_path  = pathlib.Path(key_path)
        if not cert_path.exists() or not key_path.exists():
            raise FileNotFoundError(f"missing client cert/key under {TLS_DIR}")
        ctx.load_cert_chain(str(cert_path), str(key_path))

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
    return ctx


# --------------------------
# Server accept helpers
# --------------------------

def listen_tcp(bind: Tuple[str, int]) -> socket.socket:
    """יוצר ומחזיר סוקט האזנה רגיל (TCP)."""
    host, port = bind
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    return srv


def accept_once_with_nope(
    bind: Tuple[str, int],
    server_ctx: ssl.SSLContext,
    *,
    expected_peer_id: Optional[str] = None,
    expected_domain: Optional[str] = None,
    enforce: bool = True,
    timeout: Optional[float] = 10.0,
) -> Tuple[ssl.SSLSocket, Tuple[str, int]]:
    """
    מאזין פעם אחת, מבצע TLS handshake, ואז אימות NOPE על ה-peer.
    אם enforce=True והאימות נכשל — תיזרק חריגה.
    מחזיר (ssock, addr) במידה והכל תקין.
    """
    with listen_tcp(bind) as ls:
        ls.settimeout(timeout)
        conn, addr = ls.accept()
    ssock = server_ctx.wrap_socket(conn, server_side=True)
    try:
        if expected_peer_id:
            ok = verify_peer_on_socket(
                ssock,
                server_id=expected_peer_id,
                expected_domain=expected_domain or "mix.local",
                mode="raise" if enforce else "return",
            )
            if not ok and enforce:
                raise RuntimeError("NOPE peer verification failed")
        return ssock, addr
    except Exception:
        try:
            ssock.close()
        finally:
            raise


# --------------------------
# Client connect helpers
# --------------------------

def connect_with_nope(
    remote: Tuple[str, int],
    client_ctx: ssl.SSLContext,
    *,
    expected_peer_id: Optional[str] = None,
    expected_domain: Optional[str] = None,
    enforce: bool = True,
    timeout: Optional[float] = 5.0,
) -> ssl.SSLSocket:
    """
    מתחבר כ-Client, מבצע TLS handshake, ואז אימות NOPE על השרת המרוחק.
    אם enforce=True והאימות נכשל — תיזרק חריגה.
    מחזיר את ה-SSLSocket המחובר לשימוש ישיר בקריאה/כתיבה.
    """
    host, port = remote
    s = socket.create_connection((host, port), timeout=timeout)
    ss = client_ctx.wrap_socket(s, server_hostname=host)
    try:
        if expected_peer_id:
            ok = verify_peer_on_socket(
                ss,
                server_id=expected_peer_id,
                expected_domain=expected_domain or "mix.local",
                mode="raise" if enforce else "return",
            )
            if not ok and enforce:
                raise RuntimeError("NOPE server verification failed")
        return ss
    except Exception:
        try:
            ss.close()
        finally:
            raise
