# server/mix_tls.py
import os
import ssl
from typing import Optional

TLS_DIR = os.environ.get("TLS_DIR", "tls")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", os.path.join(TLS_DIR, "cert.pem"))
TLS_KEY_PATH  = os.environ.get("TLS_KEY_PATH",  os.path.join(TLS_DIR, "key.pem"))
TLS_CA_PATH   = os.environ.get("TLS_CA_PATH",   None)  # אופציונלי: קובץ CA לאימות בצד לקוח

def create_tls_context(server_side: bool = True, require_cert: bool = False) -> ssl.SSLContext:
    """
    יוצר הקשר TLS.
    - server_side=True: מטעין cert/key (Self-Signed נתמך).
    - server_side=False: מצב לקוח; אם require_cert=True ו-TLS_CA_PATH מוגדר וקיים,
      נטען CA ונאכוף אימות; אחרת נכבה אימות (נוח לפיתוח מקומי).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)

    if server_side:
        context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    else:
        if require_cert and TLS_CA_PATH and os.path.exists(TLS_CA_PATH):
            context.load_verify_locations(cafile=TLS_CA_PATH)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False  # אין לנו DNS אמין בסביבה המקומית
        else:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

    # הקשחות בסיסיות
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("HIGH:@SECLEVEL=2")
    return context

def wrap_tls_socket(sock, server_side: bool = True, require_cert: bool = False):
    """עוטף socket קיים ב-TLS."""
    ctx = create_tls_context(server_side=server_side, require_cert=require_cert)
    return ctx.wrap_socket(sock, server_side=server_side)
