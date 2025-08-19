# init_nope.py  — bind NOPE tokens to the TLS key (no ZK)
import json
import base64
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---- הגדרות כלליות ----
SERVERS = ["S1", "S2", "S3"]
TOKENS_DIR = Path("nope") / "tokens"
TLS_DIR    = Path("tls")
TLS_CERT   = TLS_DIR / "cert.pem"
TLS_KEY    = TLS_DIR / "key.pem"

# מיפוי דומיינים (לפי הדמו)
DOMAIN_MAP = {
    "S1": "mix1.local",
    "S2": "mix2.local",
    "S3": "mix3.local",
}

def ensure_dirs():
    TOKENS_DIR.mkdir(parents=True, exist_ok=True)

# ---- טעינת מפתחות/תעודה של TLS ----
def load_tls_public_key():
    cert = x509.load_pem_x509_certificate(TLS_CERT.read_bytes())
    return cert.public_key()

def load_tls_private_key():
    return serialization.load_pem_private_key(TLS_KEY.read_bytes(), password=None)

# ---- עזרים ----
def pubkey_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()

def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_payload(priv, payload_bytes: bytes) -> bytes:
    return priv.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def verify_signature(pub, payload_bytes: bytes, sig: bytes) -> bool:
    try:
        pub.verify(
            sig,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# ---- קריאה/כתיבה של טוקן ----
def make_token_obj(server_id: str, tls_pub, tls_priv) -> dict:
    payload = {
        "server_id": server_id,
        "domain": DOMAIN_MAP.get(server_id, "localhost"),
        "pubkey_fingerprint": pubkey_fingerprint(tls_pub),  # חשוב: fingerprint של TLS
        "alg": "RSA-PSS-SHA256",
        "ts": int(time.time()),
    }
    sig = sign_payload(tls_priv, canonical_bytes(payload))
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

def token_is_valid_for_tls(token_obj: dict, server_id: str, tls_pub) -> bool:
    try:
        payload = token_obj["payload"]
        sig_b64 = token_obj["signature_b64"]
        if payload.get("server_id") != server_id:
            return False
        if payload.get("domain") != DOMAIN_MAP.get(server_id, "localhost"):
            return False
        if payload.get("pubkey_fingerprint") != pubkey_fingerprint(tls_pub):
            return False
        return verify_signature(tls_pub, canonical_bytes(payload), base64.b64decode(sig_b64))
    except Exception:
        return False

def write_token(server_id: str, obj: dict) -> Path:
    out = TOKENS_DIR / f"{server_id}.nope.json"
    out.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

def maybe_update_token(server_id: str, tls_pub, tls_priv) -> tuple[Path, bool]:
    """
    מחזיר: (path, updated?)
    אם קיים טוקן תקף מול TLS — נשאיר; אחרת ניצור/נעדכן.
    """
    path = TOKENS_DIR / f"{server_id}.nope.json"
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if token_is_valid_for_tls(existing, server_id, tls_pub):
                return path, False
        except Exception:
            pass
    obj = make_token_obj(server_id, tls_pub, tls_priv)
    write_token(server_id, obj)
    return path, True

# ---- main ----
def main():
    print("[init_nope] Starting (TLS-bound tokens)…")
    ensure_dirs()

    # בדיקות קיום
    missing = [p for p in (TLS_CERT, TLS_KEY) if not p.exists()]
    if missing:
        for p in missing:
            print(f"[init_nope] ERROR: missing {p}")
        print("[init_nope] Run init_tls.py first.")
        return

    tls_pub = load_tls_public_key()
    tls_priv = load_tls_private_key()

    touched = 0
    for sid in SERVERS:
        path, updated = maybe_update_token(sid, tls_pub, tls_priv)
        status = "Updated" if updated else "OK (kept)"
        print(f"[init_nope] {sid}: {status} -> {path}")
        touched += int(updated)

    print("\n[init_nope] Tokens folder content:")
    for p in sorted(TOKENS_DIR.glob("*.nope.json")):
        print(f" - {p} ({p.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
