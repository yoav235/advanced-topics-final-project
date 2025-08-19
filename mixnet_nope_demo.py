# server/mixnet_nope_demo.py
# -*- coding: utf-8 -*-
"""
Demo: three-hop mixnet-style flow over TLS with NOPE-only authentication.
- S1 is a client -> connects to S2 (expects S2@mix2.local)
- S2 is a server (expects S1@mix1.local) and a client to S3 (expects S3@mix3.local)
- S3 is a server (expects S2@mix2.local)

Relies on:
  - tls/cert.pem, tls/key.pem
  - nope/tokens/S1.nope.json, S2.nope.json, S3.nope.json
  - server/tls_runtime.py, server/nope_enforcer.py, server/mixnet_tls_transport.py

Run (from project root):
  python -m server.mixnet_nope_demo
"""

from __future__ import annotations
import threading
import time
import sys

from server.mixnet_tls_transport import (
    server_once,
    client_request,
)

# פורטים מקומיים לדמו
PORT_S2 = 9442
PORT_S3 = 9443

def s3_server():
    """
    S3: מאזין ל-S2, מאמת NOPE של S2, ומחזיר תשובת OK.
    expected_peer_id/domain הם של S2.
    """
    def handle(body: bytes) -> bytes:
        # כאן הייתה לוגיקת מיקס; כרגע נענה קצר וברור
        return b"S3_OK:" + body

    server_once(
        ("127.0.0.1", PORT_S3),
        expected_peer_id="S2",
        expected_domain="mix2.local",
        handle_request=handle,
        request_client_cert=True,
        timeout=10.0,
    )

def s2_server():
    """
    S2: מאזין ל-S1, מאמת NOPE של S1; בתוך הטיפול בבקשה הוא עצמו פונה ל-S3
    כ'לקוח' עם אימות NOPE על S3, ומחזיר את התשובה מטה-מעלה.
    """
    def handle(body: bytes) -> bytes:
        # hop אל S3 כלקוח, עם אימות NOPE על S3
        resp3 = client_request(
            ("127.0.0.1", PORT_S3),
            expected_peer_id="S3",
            expected_domain="mix3.local",
            payload=body,
            present_client_cert=True,
            timeout=5.0,
        )
        return b"S2<-"+ resp3

    server_once(
        ("127.0.0.1", PORT_S2),
        expected_peer_id="S1",
        expected_domain="mix1.local",
        handle_request=handle,
        request_client_cert=True,
        timeout=10.0,
    )

def run_demo():
    # נרים קודם את S3 ואז את S2, ואז S1 כלקוח
    t3 = threading.Thread(target=s3_server, daemon=True)
    t3.start()
    time.sleep(0.2)

    t2 = threading.Thread(target=s2_server, daemon=True)
    t2.start()
    time.sleep(0.3)

    # S1: לקוח שפונה ל-S2, ומאמת NOPE על S2
    try:
        resp = client_request(
            ("127.0.0.1", PORT_S2),
            expected_peer_id="S2",
            expected_domain="mix2.local",
            payload=b"hello-mix",
            present_client_cert=True,
            timeout=5.0,
        )
        sys.stdout.write(f"DEMO_RESPONSE: {resp!r}\n")
        return 0
    except Exception as e:
        sys.stdout.write(f"DEMO_FAIL: {e}\n")
        return 2
    finally:
        # נותן קצת זמן לסגירה נקייה של הסשנים
        time.sleep(0.2)

if __name__ == "__main__":
    exit(run_demo())
