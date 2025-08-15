# init_nope.py
import os
import json
import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---- הגדרות ----
SERVERS = ["S1", "S2", "S3"]         # ניתן להרחיב בהמשך
KEYS_DIR = Path("keys")
TOKENS_DIR = Path("nope") / "tokens"

# מיפוי דומיינים (בינתיים placeholder – תשנה בהמשך אם יש לכם מיפוי אמיתי)
DOMAIN_MAP = {
    "S1": "mix1.local",
    "S2": "mix2.local",
    "S3": "mix3.local",
}


def ensure_dirs():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    TOKENS_DIR.mkdir(parents=True, exist_ok=True)


def load_private_key(server_id: str):
    priv_path = KEYS_DIR / f"{server_id}_priv.pem"
    with priv_path.open("rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(server_id: str):
    pub_path = KEYS_DIR / f"{server_id}_pub.pem"
    with pub_path.open("rb") as f:
        return serialization.load_pem_public_key(f.read())


def pubkey_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def sign_payload(private_key, payload_bytes: bytes) -> bytes:
    # חתימה עם RSA-PSS + SHA256 (בחירה מומלצת)
    return private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, payload_bytes: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def make_nope_token(server_id: str) -> Path:
    """
    בונה טוקן NOPE לשרת נתון, חותם עליו ושומר אותו כ-JSON.
    מחזיר את הנתיב לקובץ הטוקן.
    """
    # טעינת מפתחות
    priv = load_private_key(server_id)
    pub = load_public_key(server_id)

    # הכנת המטען (payload)
    data = {
        "server_id": server_id,
        "domain": DOMAIN_MAP.get(server_id, "localhost"),
        "pubkey_fingerprint": pubkey_fingerprint(pub),
        "alg": "RSA-PSS-SHA256",
        "ts": int(time.time()),
        # אפשר להוסיף בהמשך: dnssec_chain, nope_params וכו'
    }
    payload_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # חתימה
    sig = sign_payload(priv, payload_bytes)
    token_obj = {
        "payload": data,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

    # כתיבה לדיסק
    out_path = TOKENS_DIR / f"{server_id}.nope.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(token_obj, f, ensure_ascii=False, indent=2)

    return out_path


def verify_nope_token(path: Path) -> bool:
    """
    מאמת טוקן NOPE לפי המפתח הציבורי של השרת שבתוך ה-payload (לפי server_id).
    """
    with path.open("r", encoding="utf-8") as f:
        token = json.load(f)

    payload = token["payload"]
    server_id = payload["server_id"]
    signature = base64.b64decode(token["signature_b64"])

    # שחזור payload בתצורה מדויקת לחתימה
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # טוענים מפתח ציבורי לאימות
    pub = load_public_key(server_id)
    return verify_signature(pub, payload_bytes, signature)


def main():
    print("[init_nope] Starting…")
    ensure_dirs()

    # בדיקה שהמפתחות קיימים
    missing = []
    for sid in SERVERS:
        if not (KEYS_DIR / f"{sid}_priv.pem").exists() or not (KEYS_DIR / f"{sid}_pub.pem").exists():
            missing.append(sid)

    if missing:
        for sid in missing:
            print(f"[init_nope] WARNING: missing keys for {sid} "
                  f"(expected {KEYS_DIR / (sid + '_priv.pem')} and {KEYS_DIR / (sid + '_pub.pem')}). "
                  f"Run generate_keys.py first.")
        # לא מפסיקים את הריצה לגמרי – נמשיך עם אלה שכן קיימים.

    # יצירה ואימות לכל שרת שיש לו מפתחות
    for sid in SERVERS:
        priv_exists = (KEYS_DIR / f"{sid}_priv.pem").exists()
        pub_exists = (KEYS_DIR / f"{sid}_pub.pem").exists()
        if not (priv_exists and pub_exists):
            continue

        out = make_nope_token(sid)
        ok = verify_nope_token(out)
        status = "Verified OK" if ok else "VERIFICATION FAILED"
        print(f"[init_nope] {sid}: wrote {out} -> {status}")

    # סיכום קבצים
    print("\n[init_nope] Tokens folder content:")
    for p in sorted(TOKENS_DIR.glob("*.nope.json")):
        print(f" - {p} ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
