# init_nope.py
"""
יוצר טוקני NOPE חתומים במפתח ה-TLS עצמו, כך שהאימות יתבצע מול ה-public key שבתוך tls/cert.pem.

תלויות:
- tls/cert.pem + tls/key.pem (הריצו לפני כן: python init_tls.py)
- ספריית היעד לטוקנים: nope/tokens

פלט:
- nope/tokens/S1.nope.json, S2.nope.json, S3.nope.json
"""

import json
import base64
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---- הגדרות ----
SERVERS = ["S1", "S2", "S3"]  # ניתן להרחיב בהמשך
BASE_DIR = Path(__file__).resolve().parent

TLS_DIR  = BASE_DIR / "tls"
TLS_CERT = TLS_DIR / "cert.pem"
TLS_KEY  = TLS_DIR / "key.pem"

TOKENS_DIR = BASE_DIR / "nope" / "tokens"
TOKENS_DIR.mkdir(parents=True, exist_ok=True)

# מיפוי דומיינים (placeholder – עדכנו אם יש לכם מיפוי אמיתי)
DOMAIN_MAP = {
    "S1": "mix1.local",
    "S2": "mix2.local",
    "S3": "mix3.local",
}


# ---------- עזר ----------
def load_tls_keypair():
    """טוען את זוג המפתחות של TLS: מפתח פרטי + public מתוך התעודה."""
    if not TLS_CERT.exists() or not TLS_KEY.exists():
        raise FileNotFoundError(
            f"TLS missing: expected {TLS_CERT} and {TLS_KEY}. Run init_tls.py first."
        )

    cert = x509.load_pem_x509_certificate(TLS_CERT.read_bytes())
    tls_public_key = cert.public_key()

    tls_private_key = serialization.load_pem_private_key(
        TLS_KEY.read_bytes(), password=None
    )
    return tls_private_key, tls_public_key


def pubkey_fingerprint(public_key) -> str:
    """SHA-256 fingerprint של SubjectPublicKeyInfo (DER)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def sign_payload(private_key, payload_bytes: bytes) -> bytes:
    """חתימה עם RSA-PSS + SHA256."""
    return private_key.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key, payload_bytes: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------- יצירה ואימות טוקן ----------
def make_nope_token(server_id: str, tls_priv, tls_pub) -> Path:
    """
    בונה טוקן NOPE לשרת נתון:
      - pubkey_fingerprint מחושב מהמפתח הציבורי של TLS
      - חתימה נעשית עם המפתח הפרטי של TLS
    """
    payload = {
        "server_id": server_id,
        "domain": DOMAIN_MAP.get(server_id, "localhost"),
        "pubkey_fingerprint": pubkey_fingerprint(tls_pub),
        "alg": "RSA-PSS-SHA256",
        "ts": int(time.time()),
        # בהמשך אפשר לצרף לכאן הוכחת ZK דחוסה/שרשרת DNSSEC וכד'
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = sign_payload(tls_priv, payload_bytes)

    token_obj = {
        "payload": payload,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

    out_path = TOKENS_DIR / f"{server_id}.nope.json"
    out_path.write_text(json.dumps(token_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


def verify_nope_token(path: Path, tls_pub) -> bool:
    """אימות עצמי (sanity) מול המפתח הציבורי של TLS."""
    token = json.loads(path.read_text(encoding="utf-8"))
    payload = token["payload"]
    sig = base64.b64decode(token["signature_b64"])

    # fingerprint חייב להתאים ל-TLS public key
    if payload.get("pubkey_fingerprint") != pubkey_fingerprint(tls_pub):
        return False

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return verify_signature(tls_pub, payload_bytes, sig)


# ---------- main ----------
def main():
    print("[init_nope] Starting…")

    tls_priv, tls_pub = load_tls_keypair()

    for sid in SERVERS:
        out = make_nope_token(sid, tls_priv, tls_pub)
        ok = verify_nope_token(out, tls_pub)
        status = "Verified OK" if ok else "VERIFICATION FAILED"
        print(f"[init_nope] {sid}: wrote {out} -> {status}")

    print("\n[init_nope] Tokens folder content:")
    for p in sorted(TOKENS_DIR.glob("*.nope.json")):
        print(f" - {p} ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
