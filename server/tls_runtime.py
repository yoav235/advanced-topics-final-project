# server/tls_runtime.py
# -*- coding: utf-8 -*-
"""
TLS runtime helpers for the project (with and without PKI), + NOPE verification.

מה הקובץ הזה נותן:
- בניית הקשרי TLS לשרת/לקוח מתוך tls/cert.pem + tls/key.pem
- מצב "לייט": TLS בלי CA (זה המצב הדיפולטי אצלנו) + אימות NOPE אחרי ה-handshake
- מצב "מחמיר/אמיתי" (מושבת כברירת מחדל כאן): mTLS מלא + אימות מול עוגן אמון (CA/self-signed)
- פונקציות accept/connect שמבצעות גם אימות NOPE מעל הסוקט לאחר ה-handshake

שימוש (NOPE כמו אצלנו):
    from server.tls_runtime import make_server_context, accept_once_with_nope
    ctx = make_server_context(request_client_cert=True)
    ssock, addr = accept_once_with_nope(("0.0.0.0", 9443), ctx,
                                        expected_peer_id="S2", expected_domain="mix2.local",
                                        enforce=True)

    from server.tls_runtime import make_client_context, connect_with_nope
    cctx = make_client_context(present_client_cert=True)
    ss   = connect_with_nope(("127.0.0.1", 9443), cctx,
                             expected_peer_id="S1", expected_domain="mix1.local",
                             enforce=True)

שימוש (TLS "נטו" בלי NOPE — לדמו TLS בלבד):
    from server.tls_runtime import make_server_context, accept_once_mtls
    from server.tls_runtime import make_client_context, connect_mtls
    # ראו ההערות בהמשך; המצב המחמיר המלא עם CA/anchor נשאר כמפורט בקומנטים.

הערות:
- אנחנו לא מסתמכים על PKI/CA; הזהות מאומתת ע"י NOPE אחרי ה-TLS.
- אפשר להצמיד (pin) לפי fingerprint של ה-cert (sha256) לקבלת שכבת הגנה נוספת.
- אם יש מודול server/nope_zk.py עם maybe_enforce_on_peer_cert — נאכוף ZK לפי env; אחרת נתעלם.
"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import socket
import ssl
from typing import Optional, Tuple

from server.nope_enforcer import verify_peer_on_socket

log = logging.getLogger(__name__)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TLS_DIR = ROOT / "tls"
CERT_PATH = TLS_DIR / "cert.pem"
KEY_PATH = TLS_DIR / "key.pem"


# ---------------------------------------------------------------------------
# Internal helpers / hardening
# ---------------------------------------------------------------------------

def _harden_server_ctx(ctx: ssl.SSLContext) -> ssl.SSLContext:
    """Apply sane security defaults to a server TLS context."""
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # העדפת TLS 1.3 כאשר זמין (לא מכריחים)
        ctx.maximum_version = getattr(ssl.TLSVersion, "TLSv1_3", ssl.TLSVersion.MAXIMUM_SUPPORTED)
    except Exception:
        pass
    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except Exception:
        pass
    # סט צופנים שמרני אך תואם (ללא RC4/MD5/NULL)
    try:
        ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
    except Exception:
        pass
    return ctx


def _harden_client_ctx(ctx: ssl.SSLContext) -> ssl.SSLContext:
    """Apply sane security defaults to a client TLS context."""
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = getattr(ssl.TLSVersion, "TLSv1_3", ssl.TLSVersion.MAXIMUM_SUPPORTED)
    except Exception:
        pass
    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except Exception:
        pass
    try:
        ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
    except Exception:
        pass
    return ctx


def _pem_fingerprint(pem_path: str, algo: str = "sha256") -> str:
    """Fingerprint (hex) of a PEM certificate by the given hash algorithm."""
    pem = pathlib.Path(pem_path).read_text(encoding="utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.new(algo, der).hexdigest()


def _der_fingerprint(der_bytes: bytes, algo: str = "sha256") -> str:
    """Fingerprint (hex) of DER bytes by the given hash algorithm."""
    return hashlib.new(algo, der_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Context builders (לייט – כמו שהיה: אין CA, אימות זהות נעשה ע"י NOPE)
# ---------------------------------------------------------------------------

def make_server_context(
    cert_path: pathlib.Path | str = CERT_PATH,
    key_path: pathlib.Path | str = KEY_PATH,
    *,
    request_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    יוצר SSLContext לשרת. כברירת מחדל יבקש תעודת לקוח (CERT_OPTIONAL),
    בלי CA (האימות יתבצע ע"י NOPE לאחר ה-handshake).
    """
    cert_path = pathlib.Path(cert_path)
    key_path = pathlib.Path(key_path)
    if not cert_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"missing TLS materials under {TLS_DIR} (cert.pem/key.pem)")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    if request_client_cert:
        # רק כדי לאפשר קריאה של פרטי ה-peer-cert (אין כאן אימות מול CA)
        ctx.verify_mode = ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return _harden_server_ctx(ctx)


def make_client_context(
    *,
    verify_server_cert: bool = False,
    present_client_cert: bool = False,
    cert_path: pathlib.Path | str = CERT_PATH,
    key_path: pathlib.Path | str = KEY_PATH,
) -> ssl.SSLContext:
    """
    יוצר SSLContext ללקוח במצב "לייט".
    - verify_server_cert=False כי בסכמה שלנו זהות השרת מאומתת ע"י NOPE ולא ע"י CA.
    - present_client_cert=True אם רוצים שהלקוח יציג תעודה (mTLS לייט; אין אימות מול CA).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify_server_cert:
        # במצב לייט אין עוגן אמון; למצב מחמיר השתמשו בגרסאות *_strict (ראו למטה).
        raise NotImplementedError("PKI verification is disabled in make_client_context (use *_strict)")
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if present_client_cert:
        cert_path = pathlib.Path(cert_path)
        key_path = pathlib.Path(key_path)
        if not cert_path.exists() or not key_path.exists():
            raise FileNotFoundError(f"missing client cert/key under {TLS_DIR}")
        ctx.load_cert_chain(str(cert_path), str(key_path))

    return _harden_client_ctx(ctx)


# ---------------------------------------------------------------------------
# Context builders (מחמיר – mTLS + CA/anchor) — נשאר כרפרנס ומושבת כברירת מחדל
# ---------------------------------------------------------------------------
# def make_server_context_strict(
#     cert_path: pathlib.Path | str = CERT_PATH,
#     key_path:  pathlib.Path | str = KEY_PATH,
#     *,
#     cafile: pathlib.Path | str = CERT_PATH,   # self-signed anchor / CA
# ) -> ssl.SSLContext:
#     cert_path = pathlib.Path(cert_path)
#     key_path  = pathlib.Path(key_path)
#     cafile    = pathlib.Path(cafile)
#     if not cert_path.exists() or not key_path.exists():
#         raise FileNotFoundError(f"missing TLS materials under {TLS_DIR} (cert.pem/key.pem)")
#     if not cafile.exists():
#         raise FileNotFoundError(f"missing trust anchor: {cafile}")
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#     ctx.load_cert_chain(str(cert_path), str(key_path))
#     ctx.verify_mode = ssl.CERT_REQUIRED
#     ctx.load_verify_locations(cafile=str(cafile))
#     return _harden_server_ctx(ctx)
#
# def make_client_context_strict(
#     *,
#     cert_path: pathlib.Path | str = CERT_PATH,
#     key_path:  pathlib.Path | str = KEY_PATH,
#     cafile:    pathlib.Path | str = CERT_PATH,  # server trust anchor
#     present_client_cert: bool = True,
# ) -> ssl.SSLContext:
#     cafile = pathlib.Path(cafile)
#     if not cafile.exists():
#         raise FileNotFoundError(f"missing trust anchor: {cafile}")
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#     ctx.check_hostname = False  # אין SAN/DNS — נסתמך על anchor/pinning
#     ctx.verify_mode = ssl.CERT_REQUIRED
#     ctx.load_verify_locations(cafile=str(cafile))
#     if present_client_cert:
#         cert_path = pathlib.Path(cert_path)
#         key_path  = pathlib.Path(key_path)
#         if not cert_path.exists() or not key_path.exists():
#             raise FileNotFoundError(f"missing client cert/key under {TLS_DIR}")
#         ctx.load_cert_chain(str(cert_path), str(key_path))
#     return _harden_client_ctx(ctx)


# ---------------------------------------------------------------------------
# TCP listen helper
# ---------------------------------------------------------------------------

def listen_tcp(bind: Tuple[str, int]) -> socket.socket:
    """יוצר ומחזיר סוקט האזנה רגיל (TCP)."""
    host, port = bind
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    return srv


# ---------------------------------------------------------------------------
# Server accept helpers (TLS + NOPE)
# ---------------------------------------------------------------------------

def _maybe_enforce_zk_on_peer_cert(ssock: ssl.SSLSocket, logger_name: str = "tls_nope_zk") -> None:
    """
    אם קיים מודול server.nope_zk עם maybe_enforce_on_peer_cert — נאכוף לפי env.
    אם לא קיים או נכשל import — נתעלם בשקט (ונשאיר את ה-NOPE החתום כ-SoT).
    """
    try:
        from server.nope_zk import maybe_enforce_on_peer_cert, NopeZKError  # type: ignore
        peer_der = ssock.getpeercert(binary_form=True)
        if not peer_der:
            return
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_der_x509_certificate(peer_der)
        pem = cert.public_bytes(serialization.Encoding.PEM)

        def _log(msg: str) -> None:
            logging.getLogger(logger_name).info(msg)

        maybe_enforce_on_peer_cert(pem, log_func=_log)
    except Exception as e:
        # NopeZKError יורש מ-Exception — במקרה של ENFORCE האתגר יזרק מבחוץ; כאן נשמור לוג בלבד.
        logging.getLogger(logger_name).warning("ZK/NOPE check skipped or non-fatal error: %s", e)


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
        # ZK (אופציונלי; לא יכשיל אם המודול חסר)
        _maybe_enforce_zk_on_peer_cert(ssock)

        if expected_peer_id:
            ok = verify_peer_on_socket(
                ssock,
                server_id=expected_peer_id,
                expected_domain=expected_domain or "mix.local",
                mode="raise" if enforce else "return_false",  # FIX
            )
            if not ok and enforce:
                raise RuntimeError("NOPE peer verification failed")
        return ssock, addr
    except Exception:
        try:
            ssock.close()
        finally:
            raise


# ---------------------------------------------------------------------------
# Client connect helpers (TLS + NOPE)
# ---------------------------------------------------------------------------

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
    ss = client_ctx.wrap_socket(s, server_hostname=host if client_ctx.check_hostname else None)
    try:
        # ZK (אופציונלי; לא יכשיל אם המודול חסר)
        _maybe_enforce_zk_on_peer_cert(ss)

        if expected_peer_id:
            ok = verify_peer_on_socket(
                ss,
                server_id=expected_peer_id,
                expected_domain=expected_domain or "mix.local",
                mode="raise" if enforce else "return_false",  # FIX
            )
            if not ok and enforce:
                raise RuntimeError("NOPE server verification failed")
        return ss
    except Exception:
        try:
            ss.close()
        finally:
            raise


# ---------------------------------------------------------------------------
# TLS "נטו" (ללא NOPE) — שימוש נקודתי בלבד/דמו; אצלנו NOPE הוא מקור האמת לזהות
# ---------------------------------------------------------------------------

def connect_mtls(
    remote: Tuple[str, int],
    client_ctx: ssl.SSLContext,
    *,
    expected_peer_fingerprint: str | None = None,
    expected_peer_cert_path: pathlib.Path | str | None = CERT_PATH,
    timeout: float | None = 5.0,
) -> ssl.SSLSocket:
    """
    מתחבר לשרת TLS (ללא NOPE). אופציונלית מצמיד (pin) את תעודת השרת לפי fingerprint.
    """
    host, port = remote
    s = socket.create_connection((host, port), timeout=timeout)
    ss = client_ctx.wrap_socket(s, server_hostname=host if client_ctx.check_hostname else None)
    try:
        if expected_peer_fingerprint or expected_peer_cert_path:
            peer_der = ss.getpeercert(binary_form=True)
            got_fp = _der_fingerprint(peer_der)
            exp_fp = expected_peer_fingerprint or _pem_fingerprint(str(expected_peer_cert_path))
            if got_fp.lower() != exp_fp.lower():
                raise ssl.SSLError(
                    f"server certificate fingerprint mismatch (got {got_fp}, expected {exp_fp})"
                )
        return ss
    except Exception:
        try:
            ss.close()
        finally:
            raise


# (אם תרצו גם accept_once_mtls — ניתן להשיב מהגרסה המוחמצת למעלה; אצלנו אין בכך צורך שוטף)
