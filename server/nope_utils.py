# server/nope_utils.py
# -*- coding: utf-8 -*-
"""
NOPE utils — no-ZK edition

מה יש כאן:
1) תמיכה בשני פורמטים של טוקן
   a) JSON חתום (RSA-PSS-SHA256) — הפורמט החדש:
      File: nope/tokens/<SID>.nope.json
      {
        "payload": {
          "server_id": "...",
          "domain": "...",
          "pubkey_fingerprint": "<hex sha256(SPKI)>",
          "alg": "RSA-PSS-SHA256",
          "ts": <unix>
        },
        "signature_b64": "<base64(signature)>"
      }
      החתימה היא על JSON קנוני של payload (sort_keys + separators).

   b) Legacy HMAC (תאימות לאחור):
      token_b64 = base64(JSON{payload, mac_b64})
      payload   = {"domain": "...", "pubkey_b64": base64(DER(SPKI))}
      mac       = HMAC-SHA256(secret(domain), canonical_json(payload))
      secret    = nope/authority_secrets/<domain>.key (נוצר אם חסר)

2) פונקציות עיקריות לשימוש:
   - find_token_for_server(server_id, ...)
   - verify_nope_token_file(token_path, server_id, domain, public_key)
   - verify_peer_nope(server_id, domain, public_key)  # עטיפת נוחות
   - verify_nope_and_optional_zk(...)                 # shim: מאמת רק טוקן

אין יותר תלות ב-ZK/‏snarkjs/‏VK/‏Proofs. אם קיימים קריאות ישנות
ל־verify_nope_and_optional_zk, הן ימשיכו לעבוד—הפונקציה מתעלמת מפרמטרי ZK.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --------------------------------------------------------------------------------------
# תצורה בסיסית של לוגינג (לא כופה פורמט; ישתלב בלוגינג של האפליקציה אם מוגדר)
# --------------------------------------------------------------------------------------
log = logging.getLogger(__name__)

# --------------------------------------------------------------------------------------
# נתיבים
# --------------------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
NOPE_DIR     = Path(os.environ.get("NOPE_DIR", PROJECT_ROOT / "nope"))
AUTH_DIR     = NOPE_DIR / "authority_secrets"
TOKENS_DIR   = NOPE_DIR / "tokens"

AUTH_DIR.mkdir(parents=True, exist_ok=True)
TOKENS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------------------
# עזר: JSON קנוני לבייטים (לחתימה/אימות)
# --------------------------------------------------------------------------------------
def _canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ======================================================================================
#                                 Legacy HMAC token
# ======================================================================================

def _auth_key_path(domain: str) -> Path:
    safe = domain.replace("/", "_")
    return AUTH_DIR / f"{safe}.key"


def ensure_domain_secret(domain: str) -> bytes:
    """יוצר/טוען סוד פר-דומיין (מדמה מנפיק תלוי-DNSSEC)."""
    p = _auth_key_path(domain)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


def make_nope_proof(domain: str, server_pubkey_der: bytes) -> str:
    """יוצר טוקן HMAC ישן (לשמירת תאימות לאחור)."""
    secret = ensure_domain_secret(domain)
    payload = {
        "domain": domain,
        "pubkey_b64": base64.b64encode(server_pubkey_der).decode("ascii"),
    }
    mac = hmac.new(secret, _canonical_json_bytes(payload), hashlib.sha256).digest()
    token = {"payload": payload, "mac_b64": base64.b64encode(mac).decode("ascii")}
    return base64.b64encode(json.dumps(token).encode("utf-8")).decode("ascii")


def verify_nope_proof(token_b64: str, expected_domain: str, server_pubkey_der: bytes) -> bool:
    """מאמת טוקן HMAC ישן."""
    try:
        token = json.loads(base64.b64decode(token_b64).decode("utf-8"))
        payload = token["payload"]
        mac_b64 = token["mac_b64"]

        if payload.get("domain") != expected_domain:
            return False
        if payload.get("pubkey_b64") != base64.b64encode(server_pubkey_der).decode("ascii"):
            return False

        secret = ensure_domain_secret(expected_domain)
        expected_mac = hmac.new(secret, _canonical_json_bytes(payload), hashlib.sha256).digest()
        return hmac.compare_digest(expected_mac, base64.b64decode(mac_b64))
    except Exception:
        return False


# ======================================================================================
#                             JSON token (RSA-PSS, current)
# ======================================================================================

def pubkey_fingerprint(public_key) -> str:
    """SHA-256 על SPKI (DER) של המפתח הציבורי."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def verify_nope_json(token_obj: dict, expected_sid: str, expected_domain: str, server_public_key) -> bool:
    """אימות טוקן JSON חתום RSA-PSS-SHA256, כולל בדיקת טריות (ts/exp) אופציונלית.
       ניתן לקבוע מקס' גיל בשניות דרך env: NOPE_TOKEN_MAX_AGE_SEC (ברירת מחדל 90 יום).
       אם יש payload['exp'] – נבדוק אותו; אחרת אם יש 'ts' – נבדוק now-ts <= max_age.
       אם אין ts/exp – לא נפיל, כדי לשמור תאימות לאחור.
    """
    import os, time
    try:
        payload = token_obj["payload"]
        sig_b64 = token_obj["signature_b64"]

        if payload.get("server_id") != expected_sid:
            return False
        if payload.get("domain") != expected_domain:
            return False
        if payload.get("pubkey_fingerprint") != pubkey_fingerprint(server_public_key):
            return False

        payload_bytes = _canonical_json_bytes(payload)
        signature = base64.b64decode(sig_b64)

        server_public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        # --- freshness ---
        max_age = int(os.environ.get("NOPE_TOKEN_MAX_AGE_SEC", str(90 * 24 * 3600)))
        now = int(time.time())
        exp = payload.get("exp")
        ts  = payload.get("ts")
        if isinstance(exp, int):
            if now > exp:
                return False
        elif isinstance(ts, int) and max_age > 0:
            if now - ts > max_age:
                return False

        return True
    except Exception:
        return False


# ======================================================================================
#                           טעינת טוקן מאחסון ואימותו
# ======================================================================================

PathLike = Union[str, Path]

def verify_nope_token_file(token_path: PathLike,
                           server_id: str,
                           expected_domain: str,
                           server_public_key) -> bool:
    """
    מזהה אוטומטית את סוג הטוקן (JSON חתום / HMAC ישן) ומאמת בהתאם.
    מחזיר True אם הטוקן תואם ל-(server_id, expected_domain, server_public_key).
    """
    p = Path(token_path)
    if not p.exists():
        log.debug("Token file not found: %s", p)
        return False

    # ניסיון ראשון: JSON חדש
    try:
        text = p.read_text(encoding="utf-8").strip()
        obj = json.loads(text)
        if isinstance(obj, dict) and "payload" in obj and "signature_b64" in obj:
            return verify_nope_json(obj, server_id, expected_domain, server_public_key)
    except Exception:
        pass

    # נפילה לאחור: Base64 של טוקן HMAC
    try:
        token_b64 = p.read_text(encoding="utf-8").strip()
        server_pub_der = server_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return verify_nope_proof(token_b64, expected_domain, server_pub_der)
    except Exception:
        return False


def find_token_for_server(server_id: str,
                          prefer_json: bool = True,
                          tokens_dir: Path | None = None) -> Optional[Path]:
    """
    מחפש nope/tokens/<SID>.nope.json (מועדף) או nope/tokens/<SID>.tok.
    """
    tdir = Path(tokens_dir) if tokens_dir else TOKENS_DIR
    json_path = tdir / f"{server_id}.nope.json"
    b64_path  = tdir / f"{server_id}.tok"
    if prefer_json and json_path.exists():
        return json_path
    if b64_path.exists():
        return b64_path
    if json_path.exists():
        return json_path
    return None


def verify_peer_nope(server_id: str,
                     expected_domain: str,
                     server_public_key,
                     tokens_dir: Path | None = None) -> bool:
    """
    עטיפת נוחות: מאתר את הטוקן עבור השרת ומאמת אותו.
    """
    token_path = find_token_for_server(server_id, tokens_dir=tokens_dir)
    if not token_path:
        log.warning("Token for %s not found under %s", server_id, tokens_dir or TOKENS_DIR)
        return False
    ok = verify_nope_token_file(token_path, server_id, expected_domain, server_public_key)
    if ok:
        log.info("NOPE token OK for %s (domain=%s)", server_id, expected_domain)
    else:
        log.warning("NOPE token FAILED for %s (domain=%s)", server_id, expected_domain)
    return ok


# ======================================================================================
#         Shim תואם-לאחור: verify_nope_and_optional_zk — מאמת טוקן בלבד
# ======================================================================================

def verify_nope_and_optional_zk(server_id: str,
                                expected_domain: str,
                                server_public_key,
                                token_path: PathLike | None = None,
                                *_, **__) -> bool:
    """
    שמירה על תאימות לקוד ישן: מתעלם מכל פרמטרי ZK/נתיבי VK/Proofs/Env.
    מבצע אך ורק אימות טוקן NOPE.
    """
    p = Path(token_path) if token_path else find_token_for_server(server_id)
    if not p:
        log.warning("Token for %s not found under %s", server_id, TOKENS_DIR)
        return False
    return verify_nope_token_file(p, server_id, expected_domain, server_public_key)


__all__ = [
    # legacy HMAC
    "make_nope_proof", "verify_nope_proof",
    # JSON token
    "pubkey_fingerprint", "verify_nope_json",
    # storage/lookup
    "find_token_for_server", "verify_nope_token_file", "verify_peer_nope",
    # shim
    "verify_nope_and_optional_zk",
]
