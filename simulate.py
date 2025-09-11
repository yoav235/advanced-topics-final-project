# simulate.py
# -*- coding: utf-8 -*-

import time

from client.client import Client
from server.server import MixServer

NUM_CLIENTS = 2
NUM_SERVERS = 3

def main() -> int:
    # הקם שרתים S1..S{NUM_SERVERS} וחבר ביניהם בשרשרת
    servers = [MixServer(f"S{i}") for i in range(1, NUM_SERVERS + 1)]
    for i in range(NUM_SERVERS - 1):
        servers[i].next_server = servers[i + 1]

    # במימושים מסוימים השרתים מתחילים מאזינים ברגע היצירה;
    # בכל מקרה נחכה רגע קטן כדי לוודא שהפורט מאזין לפני שליחת הודעות.
    time.sleep(0.15)

    # הקם לקוחות C1..C{NUM_CLIENTS}
    clients = [Client(f"C{i}", servers) for i in range(1, NUM_CLIENTS + 1)]

    # שלח הודעה מכל לקוח. עוטפים ב־try/except כדי שגם אם יש DENY במורד,
    # התהליך לא יקרוס לפני שהלוגים יודפסו והמבחנים ילכדו אותם.
    for client in clients:
        try:
            client.send_message({"to": "C1", "message": "Hello, Mixnet!"})
        except Exception:
            # הכשל (למשל NOPE deny) כבר יודפס ע"י שכבת ה־TLS/NOPE
            # ואנחנו רק מונעים מהסקריפט לסיים ב־non-zero.
            pass

    # המתן מעט כדי לאפשר להופ S1→S2→S3 (כולל דחיות) להשלים ולהדפיס לוגים.
    time.sleep(0.8)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
