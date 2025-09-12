# simulate.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from server.server import MixServer
from server.server_logging import get_server_logger

ROOT = Path(__file__).resolve().parent
TLS_DIR = ROOT / "tls"
TOK_DIR = ROOT / "nope" / "tokens"
CERT = TLS_DIR / "cert.pem"
KEY = TLS_DIR / "key.pem"

def _have_tls() -> bool:
    return CERT.exists() and KEY.exists()

def _have_tokens() -> bool:
    # דרוש שלושת הטוקנים לדמו (S1,S2,S3)
    need = ["S1.nope.json", "S2.nope.json", "S3.nope.json"]
    return TOK_DIR.exists() and all((TOK_DIR / n).exists() for n in need)

def _maybe_init_artifacts() -> None:
    """
    כברירת מחדל *לא* מאתחלים אם קיימים קבצים (כדי לא לדרוס טוקנים משובשים בבדיקות התקפה).
    אם חסר—נאתחל.
    אפשר לאלץ אתחול מלא עם NOPE_FORCE_INIT=1.
    אפשר גם לאלץ דילוג עם NOPE_SKIP_INIT=1.
    """
    force = os.environ.get("NOPE_FORCE_INIT", "").strip() == "1"
    skip = os.environ.get("NOPE_SKIP_INIT", "").strip() == "1"

    if skip and not force:
        return

    need_tls = force or not _have_tls()
    need_tok = force or not _have_tokens()

    if not (need_tls or need_tok):
        # הכול קיים – לא נוגעים (מגן על תרחישי התקפה)
        return

    # נאתחל רק את מה שחסר בפועל, כדי להיות מינימליסטיים
    if need_tls:
        from init_tls import main as tls_main
        tls_main()

    if need_tok:
        from init_nope import main as nope_main
        nope_main()

def _build_servers() -> tuple[MixServer, MixServer, MixServer]:
    # שלושת השרתים (S1,S2,S3) מאזינים ב־127.0.0.1:9441/9442/9443
    s1 = MixServer("S1", tls_cert=CERT, tls_key=KEY, tokens_dir=TOK_DIR, host="127.0.0.1")
    s2 = MixServer("S2", tls_cert=CERT, tls_key=KEY, tokens_dir=TOK_DIR, host="127.0.0.1")
    s3 = MixServer("S3", tls_cert=CERT, tls_key=KEY, tokens_dir=TOK_DIR, host="127.0.0.1")
    return s1, s2, s3

def _demo_client_send(origin_client_id: str, path: list[str], message: dict[str, str]) -> None:
    """
    שולח הודעה “דרך” המסלול – בדמו: קורא ל־receive_message של ה־hop הראשון (S1),
    והשרתים מעבירים ביניהם ב־TLS (עם אימות NOPE בצד השולח).
    """
    print(f"[Client {origin_client_id}] Sending message via path {path}: {message}")
    first = path[0]
    if first != "S1":
        raise RuntimeError("demo expects first hop to be S1")
    # בדמו אנחנו מעבירים ciphertext כטקסט (כמו שהיה).
    ciphertext = json.dumps(message)
    _SERVERS["S1"].receive_message(ciphertext, origin_client_id=origin_client_id, use_tls=True)

def _shutdown(servers: tuple[MixServer, MixServer, MixServer]) -> None:
    for s in servers:
        try:
            s.stop()
        except Exception:
            pass

_SERVERS: dict[str, MixServer] = {}

def main() -> int:
    # לוג כללי
    log = get_server_logger("simulate")

    # אל תדרוס טוקנים אם קיימים (כדי שהתקפות token-corruption יצליחו לעורר DENY)
    _maybe_init_artifacts()

    # הרם שרתים
    s1, s2, s3 = _build_servers()
    global _SERVERS
    _SERVERS = {"S1": s1, "S2": s2, "S3": s3}

    try:
        # תן רגע מאזינים להתרומם
        time.sleep(0.2)

        # שני “לקוחות” לדוגמה – כמו בלוגים שצירפת
        _demo_client_send("C1", ["S1", "S2", "S3"], {"to": "C1", "message": "Hello, Mixnet!"})
        _demo_client_send("C2", ["S1", "S2", "S3"], {"to": "C1", "message": "Hello, Mixnet!"})

        # תן רגע לעיבוד/לוגים
        time.sleep(0.2)
        return 0
    except Exception as e:
        log.error("simulate failed: %s", e)
        return 1
    finally:
        _shutdown((s1, s2, s3))

if __name__ == "__main__":
    sys.exit(main())
