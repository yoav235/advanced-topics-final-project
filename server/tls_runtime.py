# server/tls_runtime.py
# -*- coding: utf-8 -*-
"""
TLS runtime helpers for the project (with and without PKI), + NOPE verification.

מה הקובץ הזה נותן:
- בניית הקשרי TLS לשרת/לקוח מתוך tls/cert.pem + tls/key.pem (שנוצרים ע"י NOPE server.sh)
- מצב "לייט": TLS בלי CA (כבעבר) + אימות NOPE אחרי ה-handshake
- מצב "מחמיר/אמיתי": mTLS מלא + אימות תעודות מול עוגן אמון (CA/self-signed anchor) + אופציונלי pinning
- פונקציות accept/connect שמבצעות גם אימות NOPE מעל הסוקט לאחר ה-handshake

שימוש (NOPE כמו שהיה):
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

שימוש (TLS "אמיתי" + NOPE):
    from server.tls_runtime import make_server_context_strict, accept_once_with_nope
    sctx = make_server_context_strict()  # CERT_REQUIRED + trust anchor (tls/cert.pem)
    ssock, addr = accept_once_with_nope(("0.0.0.0", 9443), sctx,
                                        expected_peer_id="S2", expected_domain="mix2.local",
                                        enforce=True)

    from server.tls_runtime import make_client_context_strict, connect_with_nope
    cctx = make_client_context_strict(present_client_cert=True)  # mTLS + verify server
    ss   = connect_with_nope(("127.0.0.1", 9443), cctx,
                             expected_peer_id="S1", expected_domain="mix1.local",
                             enforce=True)

שימוש (TLS "נטו" בלי NOPE — אם רוצים דמו נקי של TLS בלבד):
    from server.tls_runtime import make_server_context_strict, accept_once_mtls
    sctx = make_server_context_strict()
    ssock, addr = accept_once_mtls(("0.0.0.0", 9443), sctx)

    from server.tls_runtime import make_client_context_strict, connect_mtls
    cctx = make_client_context_strict(present_client_cert=True)
    ss   = connect_mtls(("127.0.0.1", 9443), cctx)

הערות:
- ברירת המחדל לעוגן האמון (CA / self-signed anchor) היא tls/cert.pem, כפי שנוצר ע"י NOPE.
- אפשר להצמיד (pin) לפי fingerprint של ה-cert (sha256) לקבלת הגנה נוספת.
- אימות NOPE נשאר זהה (verify_peer_on_socket) ופועל מעל TLS.
"""

from __future__ import annotations
import ssl
import socket
import pathlib
import logging
import hashlib
from typing import Optional, Tuple

from server.nope_enforcer import verify_peer_on_socket

log = logging.getLogger(__name__)
ROOT = pathlib.Path(__file__).resolve().parents[1]
TLS_DIR = ROOT / "tls"
CERT_PATH = TLS_DIR / "cert.pem"
KEY_PATH  = TLS_DIR / "key.pem"


# --------------------------
# Context builders (לייט – כמו שהיה)
# --------------------------

def make_server_context(
    cert_path: pathlib.Path | str = CERT_PATH,
    key_path: pathlib.Path | str  = KEY_PATH,
    *,
    request_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    יוצר SSLContext לשרת. כברירת מחדל יבקש תעודת לקוח (CERT_OPTIONAL),
    בלי CA (האימות יתבצע ע"י NOPE לאחר ה-handshake).
    """
    cert_path = pathlib.Path(cert_path)
    key_path  = pathlib.Path(key_path)
    if not cert_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"missing TLS materials under {TLS_DIR} (cert.pem/key.pem)")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    if request_client_cert:
        ctx.verify_mode = ssl.CERT_OPTIONAL  # רק כדי לגשת ל-cert של ה-peer; אין CA פה
    else:
        ctx.verify_mode = ssl.CERT_NONE
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
    - verify_server_cert=False כי בזרימה הזו אנו סומכים על NOPE ולא על CA.
    - present_client_cert=True אם רוצים שהלקוח יציג תעודה (mTLS לייט).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify_server_cert:
        # לא נתמך ב"מצב לייט"
        raise NotImplementedError("PKI verification is disabled in make_client_context (use *_strict)")
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
# Context builders (מחמיר – mTLS + CA/anchor)
# --------------------------

# def make_server_context_strict(
#     cert_path: pathlib.Path | str = CERT_PATH,
#     key_path:  pathlib.Path | str = KEY_PATH,
#     *,
#     cafile: pathlib.Path | str = CERT_PATH,   # עוגן אמון (למשל self-signed anchor מ-NOPE)
# ) -> ssl.SSLContext:
#     """
#     שרת TLS מחמיר: דורש תעודת לקוח (CERT_REQUIRED) ומאמת אותה מול CA/anchor.
#     """
#     cert_path = pathlib.Path(cert_path)
#     key_path  = pathlib.Path(key_path)
#     cafile    = pathlib.Path(cafile)
#     if not cert_path.exists() or not key_path.exists():
#         raise FileNotFoundError(f"missing TLS materials under {TLS_DIR} (cert.pem/key.pem)")
#     if not cafile.exists():
#         raise FileNotFoundError(f"missing trust anchor: {cafile}")
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#     ctx.load_cert_chain(str(cert_path), str(key_path))
#     ctx.minimum_version = ssl.TLSVersion.TLSv1_2
#     ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
#     ctx.verify_mode = ssl.CERT_REQUIRED
#     ctx.load_verify_locations(cafile=str(cafile))
#     return ctx
#
#
# def make_client_context_strict(
#     *,
#     cert_path: pathlib.Path | str = CERT_PATH,
#     key_path:  pathlib.Path | str = KEY_PATH,
#     cafile:    pathlib.Path | str = CERT_PATH,  # עוגן האמון לשרת
#     present_client_cert: bool = True,
# ) -> ssl.SSLContext:
#     """
#     לקוח TLS מחמיר: מאמת את השרת מול העוגן, ואופציונלית מציג תעודת לקוח (mTLS).
#     """
#     cafile = pathlib.Path(cafile)
#     if not cafile.exists():
#         raise FileNotFoundError(f"missing trust anchor: {cafile}")
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#     ctx.minimum_version = ssl.TLSVersion.TLSv1_2
#     ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
#     ctx.check_hostname = False               # אין לנו DNS SAN; נאמת מול העוגן/פינינג
#     ctx.verify_mode = ssl.CERT_REQUIRED
#     ctx.load_verify_locations(cafile=str(cafile))
#
#     if present_client_cert:
#         cert_path = pathlib.Path(cert_path)
#         key_path  = pathlib.Path(key_path)
#         if not cert_path.exists() or not key_path.exists():
#             raise FileNotFoundError(f"missing client cert/key under {TLS_DIR}")
#         ctx.load_cert_chain(str(cert_path), str(key_path))
#     return ctx


# --------------------------
# Pinning helpers (אופציונלי)
# --------------------------

# todo: understand these 2 functions
def _pem_fingerprint(pem_path: str, algo: str = "sha256") -> str:
    """מחזיר fingerprint (hex) של תעודת PEM לפי האלגוריתם הנתון (sha256 כברירת מחדל)."""
    pem = pathlib.Path(pem_path).read_text(encoding="utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.new(algo, der).hexdigest()

def _der_fingerprint(der_bytes: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, der_bytes).hexdigest()


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


# todo: is it really uses NOPE verification?
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

    # --- NEW: בדיקת NOPE-ZK על תעודת הצד השני (אם הופעלה בסביבה) ---
    try:
        from server.nope_zk import maybe_enforce_on_peer_cert, NopeZKError
        peer_der = ssock.getpeercert(binary_form=True)
        if peer_der:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            cert = x509.load_der_x509_certificate(peer_der)
            pem = cert.public_bytes(serialization.Encoding.PEM)
            def _log(msg: str):
                import logging; logging.getLogger("tls_nope_smoke").info(msg)
            maybe_enforce_on_peer_cert(pem, log_func=_log)
    except NopeZKError:
        try:
            ssock.close()
        finally:
            raise
    except Exception as _e:
        import logging; logging.getLogger("tls_nope_smoke").warning("ZK/NOPE check error: %s", _e)
    # --- END NEW ---

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



# def accept_once_mtls(
#     bind: Tuple[str, int],
#     server_ctx: ssl.SSLContext,
#     *,
#     expected_peer_fingerprint: str | None = None,
#     expected_peer_cert_path: pathlib.Path | str | None = CERT_PATH,
#     timeout: float | None = 10.0,
# ) -> Tuple[ssl.SSLSocket, Tuple[str, int]]:
#     """
#     מאזין פעם אחת (TLS מחמיר). אופציונלית מצמיד (pin) את תעודת הלקוח לפי fingerprint.
#     """
#     with listen_tcp(bind) as ls:
#         ls.settimeout(timeout)
#         conn, addr = ls.accept()
#     ssock = server_ctx.wrap_socket(conn, server_side=True)
#     try:
#         if expected_peer_fingerprint or expected_peer_cert_path:
#             peer_der = ssock.getpeercert(binary_form=True)
#             got_fp = _der_fingerprint(peer_der)
#             exp_fp = expected_peer_fingerprint or _pem_fingerprint(str(expected_peer_cert_path))
#             if got_fp.lower() != exp_fp.lower():
#                 raise ssl.SSLError(
#                     f"peer certificate fingerprint mismatch (got {got_fp}, expected {exp_fp})"
#                 )
#         return ssock, addr
#     except Exception:
#         try:
#             ssock.close()
#         finally:
#             raise


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
    ss = client_ctx.wrap_socket(s, server_hostname=host if client_ctx.check_hostname else None)

    # --- NEW: בדיקת NOPE-ZK על תעודת השרת (אם הופעלה בסביבה) ---
    try:
        from server.nope_zk import maybe_enforce_on_peer_cert, NopeZKError
        peer_der = ss.getpeercert(binary_form=True)
        if peer_der:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            cert = x509.load_der_x509_certificate(peer_der)
            pem = cert.public_bytes(serialization.Encoding.PEM)
            def _log(msg: str):
                import logging; logging.getLogger("tls_nope_smoke").info(msg)
            maybe_enforce_on_peer_cert(pem, log_func=_log)
    except NopeZKError:
        try:
            ss.close()
        finally:
            raise
    except Exception as _e:
        import logging; logging.getLogger("tls_nope_smoke").warning("ZK/NOPE check error: %s", _e)
    # --- END NEW ---

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



def connect_mtls(
    remote: Tuple[str, int],
    client_ctx: ssl.SSLContext,
    *,
    expected_peer_fingerprint: str | None = None,
    expected_peer_cert_path: pathlib.Path | str | None = CERT_PATH,
    timeout: float | None = 5.0,
) -> ssl.SSLSocket:
    """
    מתחבר לשרת TLS מחמיר. אופציונלית מצמיד (pin) את תעודת השרת לפי fingerprint.
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
