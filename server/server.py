# server/server.py
# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
import logging

from .transport_tls import TLSPeerTransport
from .server_logging import get_server_logger

@dataclass
class MixServer:
    """
    שרת מיקס מינימלי המדגים:
    - האזנה ב-TLS (עם cert/key מקומיים)
    - שליחת הודעות TLS לשרת הבא
    - אכיפת NOPE מתבצעת בשכבת ה-TLSPeerTransport בזמן ה-handshake
    - לוגים עם LoggerAdapter שמספק תמיד extra['server'] כדי למנוע שגיאות formatter
    """
    server_id: str

    # נתיבי TLS וקבצי NOPE (ברירות מחדל יחסיות לשורש הפרויקט)
    tls_cert: Path = Path("tls/cert.pem")
    tls_key: Path = Path("tls/key.pem")
    tokens_dir: Path = Path("nope/tokens")

    # כתובת הקשבה מקומית
    host: str = "127.0.0.1"

    # פנימיים
    transport: TLSPeerTransport = field(init=False)
    log: logging.LoggerAdapter = field(init=False)
    _started: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        # logger עם extra {'server': <server_id>} כדי להתאים לפורמט הלוג הכללי
        self.log = get_server_logger(self.server_id)

        # ודא נתיבים (יחסיים לקובץ הרצה)
        self.tls_cert = Path(self.tls_cert)
        self.tls_key = Path(self.tls_key)
        self.tokens_dir = Path(self.tokens_dir)

        # בנה transport עם הלוגר של השרת הזה
        self.transport = TLSPeerTransport(
            server_id=self.server_id,
            tls_cert=self.tls_cert,
            tls_key=self.tls_key,
            tokens_dir=self.tokens_dir,
            host=self.host,
            logger=self.log,  # חשוב: כדי שלוגים פנימיים ב-transport יהיו עם extra['server']
        )

        # אתחול מיידי (כמו שהיה במקור אצלך)
        self.start()

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------
    def start(self) -> None:
        if self._started:
            return
        # חיווי למשתמש על קבצי TLS ונתיב טוקנים
        self.log.info("TLS files found (cert=%s, key=%s)", str(self.tls_cert).replace("\\", "/"), str(self.tls_key).replace("\\", "/"))
        self.log.info("NOPE: expecting tokens in '%s'", str(self.tokens_dir).replace("\\", "/"))

        # הפעלת האזנת TLS; הקולבק יקבל bytes + מזהה-peer
        self.transport.start(self._on_tls_message)
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        try:
            self.transport.stop()
        finally:
            self._started = False

    # ---------------------------------------------------------------------
    # Routing (דמו נתיבי S1->S2->S3)
    # ---------------------------------------------------------------------
    def _next_hop(self) -> Optional[str]:
        """בחירה דטרמיניסטית פשוטה למסלול ההדגמה: S1→S2→S3 (ו-S3 הוא hop אחרון)."""
        if self.server_id == "S1":
            return "S2"
        if self.server_id == "S2":
            return "S3"
        return None  # S3 הוא האחרון

    # ---------------------------------------------------------------------
    # API שהלקוח קורא אליה ישירות על ה-hop הראשון (ללא אכיפת NOPE בצד השרת הראשון)
    # ---------------------------------------------------------------------
    def receive_message(self, ciphertext: str, origin_client_id: str, use_tls: bool = True) -> None:
        """
        קריאה "מלקוח" אל השרת הראשון בשרשרת.
        בדמו: מדלגים על NOPE ב-hop הראשון (כי המקור הוא לקוח), ומעבירים הלאה ב-TLS ל-hop הבא.
        """
        self.log.info("Origin is client %s -> skipping NOPE on first hop.", origin_client_id)

        nxt = self._next_hop()
        if not nxt:
            # אם במקרה S3 קיבל ישירות מהלקוח – נמסור כיעד סופי
            self._deliver_final(ciphertext)
            return

        # מעבירים הלאה ב-TLS; ה-TLSPeerTransport יוודא NOPE על היעד
        try:
            self.transport.send(nxt, ciphertext.encode("utf-8"))
        except Exception as e:
            self.log.warning("Forward TLS send to %s failed: %s", nxt, e)

    # ---------------------------------------------------------------------
    # Callback from transport when a TLS message arrives from a peer
    # ---------------------------------------------------------------------
    def _on_tls_message(self, data: bytes) -> None:
        """
        Called by TLSPeerTransport when a TLS-framed message arrives from a peer.
        """
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)

        nxt = self._next_hop()
        if nxt is None:
            # last hop (S3) — deliver
            self._deliver_final(text)
            return

        # otherwise forward to next hop over TLS (NOPE enforced in transport.send)
        try:
            self.transport.send(nxt, text.encode("utf-8"))
        except Exception as e:
            self.log.warning("Forward TLS send to %s failed: %s", nxt, e)

    # ---------------------------------------------------------------------
    # "מסירה" סופית (לוג בלבד בדמו)
    # ---------------------------------------------------------------------
    def _deliver_final(self, text: str) -> None:
        self.log.info('Delivered to final hop: "%s"', text)
