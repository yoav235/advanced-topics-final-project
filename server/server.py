# server/server.py
import os
import base64
import json
import logging
from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import crypto_utils

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TLS_DIR = os.environ.get("TLS_DIR", "tls")
TLS_CERT_PATH = os.path.join(TLS_DIR, "cert.pem")
TLS_KEY_PATH  = os.path.join(TLS_DIR, "key.pem")

NOPE_DIR     = os.environ.get("NOPE_DIR", "nope")
NOPE_TOKENS  = os.path.join(NOPE_DIR, "tokens")  # e.g., S1.nope.json
KEYS_DIR     = os.environ.get("KEYS_DIR", "keys")

# חשוב: ליישר לדומיינים ש-init_nope.py יצר (mix1.local/2/3)
SERVER_DOMAINS = {"S1": "mix1.local", "S2": "mix2.local", "S3": "mix3.local"}


def _load_pubkey(server_id: str):
    path = os.path.join(KEYS_DIR, f"{server_id}_pub.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _pub_fingerprint(pub) -> str:
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    h = hashes.Hash(hashes.SHA256())
    h.update(der)
    return h.finalize().hex()


class MixServer:
    # רג’יסטרי גלובלי כדי שנוכל למצוא את השרת הבא לפי מזהה
    REGISTRY: dict[str, "MixServer"] = {}

    def __init__(self, server_id, server_list: Optional[list] = None, num_clients: int = 2):
        self.server_id = server_id
        self.server_list = {"S1": "S1", "S2": "S2", "S3": "S3"}  # לוגי בלבד בסימולציה הזו
        self.num_clients = num_clients
        self.next_server = None

        # רישום ברג’יסטרי
        MixServer.REGISTRY[self.server_id] = self

        # מפתחות
        self.private_key = crypto_utils.load_private_keys([server_id])[server_id]
        self.public_key  = crypto_utils.load_public_key(server_id)

        # TLS (דיווח בלבד כרגע)
        try:
            with open(TLS_CERT_PATH, "rb") as cert_file:
                self.cert = cert_file.read()
            with open(TLS_KEY_PATH, "rb") as key_file:
                self.key = key_file.read()
            logging.info(f"[Server {self.server_id}] TLS files found (cert={TLS_CERT_PATH}, key={TLS_KEY_PATH})")
        except FileNotFoundError:
            logging.warning(f"[Server {self.server_id}] TLS files missing. NOPE will still be required for TLS.")
            self.cert = self.key = None

        logging.info(f"[Server {self.server_id}] NOPE: expecting tokens in '{NOPE_TOKENS}'")

    # --- אימות NOPE ---
    def _verify_sender_nope(self, sender_id: str) -> bool:
        """
        לקוחות (C*) – דולג בהופ הראשון.
        שרתים (S*) – מאומתים נגד הטוקן שלהם ב-nope/tokens/S*.nope.json
          (פורמט JSON חתום RSA-PSS כפי שמייצר init_nope.py).
        """
        if not sender_id.startswith("S"):
            logging.info(f"[Server {self.server_id}] Origin is client {sender_id} -> skipping NOPE on first hop.")
            return True

        tok_path = os.path.join(NOPE_TOKENS, f"{sender_id}.nope.json")
        if not os.path.exists(tok_path):
            logging.warning(f"[Server {self.server_id}] Missing NOPE token for {sender_id} at {tok_path}")
            return False

        # אימות החתימה ושדות ה-payload
        try:
            with open(tok_path, "r", encoding="utf-8") as f:
                token = json.load(f)
            payload = token["payload"]
            sig_b64 = token["signature_b64"]
            domain_expected = SERVER_DOMAINS.get(sender_id)
            if payload.get("server_id") != sender_id or payload.get("domain") != domain_expected:
                return False

            sender_pub = _load_pubkey(sender_id)
            if payload.get("pubkey_fingerprint") != _pub_fingerprint(sender_pub):
                return False

            msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            signature = base64.b64decode(sig_b64)
            sender_pub.verify(
                signature,
                msg,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            logging.warning(f"[Server {self.server_id}] ❌ NOPE verification failed for {sender_id}: {e}")
            return False

    # --- קבלת הודעה והעברה להופ הבא ---
    def receive_message(self, message_b64: str, sender_id: str, use_tls: bool = True):
        # אכיפת NOPE על מקור החיבור
        if use_tls and not self._verify_sender_nope(sender_id):
            logging.warning(f"[Server {self.server_id}] 🚫 TLS denied for {sender_id}: invalid/missing NOPE.")
            return
        if use_tls and sender_id.startswith("S"):
            logging.info(f"[Server {self.server_id}] 🔐 TLS accepted from {sender_id} (NOPE OK).")

        # פענוח שכבת הבצל לשרת הנוכחי
        try:
            decrypted = crypto_utils.decrypt_hybrid(self.private_key, base64.b64decode(message_b64))
            data = json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            logging.error(f"[Server {self.server_id}] Failed to decrypt/parse message: {e}")
            return

        # data חייב להכיל: {"from": client_id, "next": <S* או 'DEST'>, "payload": <base64|dict>}
        nxt = data.get("next")
        inner_payload = data.get("payload")
        if nxt == "DEST":
            logging.info(f"[Server {self.server_id}] 🎉 Final destination reached. Message: {inner_payload}")
            return

        # שלח להופ הבא (S*) – כאן האכיפה תהיה S→S
        next_server = MixServer.REGISTRY.get(nxt)
        if not next_server:
            logging.error(f"[Server {self.server_id}] Next hop '{nxt}' not found in registry.")
            return

        if not isinstance(inner_payload, str):
            logging.error(f"[Server {self.server_id}] Inner payload is not base64 string.")
            return

        # העברה: השולח כעת הוא השרת הנוכחי
        next_server.receive_message(inner_payload, sender_id=self.server_id, use_tls=True)
