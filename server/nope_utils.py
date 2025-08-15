# server/nope_utils.py
import os
import hmac
import json
import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

"""
NOPE utils (dual-mode):
- Legacy (HMAC): token is base64(JSON{payload, mac_b64}); payload has
  {"domain": ..., "pubkey_b64": base64(DER(pubkey))} and MAC=HMAC-SHA256 over payload
  using per-domain secret in nope/authority_secrets/<domain>.key
- JSON RSA-PSS (current init_nope.py): file *.nope.json with
  {"payload": {..., "server_id", "domain", "pubkey_fingerprint", "alg"}, "signature_b64": ...}
  Signature is RSA-PSS-SHA256 by the server's private key; verified with its public key.
"""

NOPE_DIR = os.environ.get("NOPE_DIR", "nope")
AUTH_DIR = os.path.join(NOPE_DIR, "authority_secrets")
os.makedirs(AUTH_DIR, exist_ok=True)


# ---------- helpers (legacy HMAC) ----------
def _auth_key_path(domain: str) -> str:
    safe = domain.replace("/", "_")
    return os.path.join(AUTH_DIR, f"{safe}.key")


def ensure_domain_secret(domain: str) -> bytes:
    """Create or load per-domain secret (simulating DNSSEC-bound issuer)."""
    path = _auth_key_path(domain)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        secret = os.urandom(32)
        with open(path, "wb") as f:
            f.write(secret)
    else:
        with open(path, "rb") as f:
            secret = f.read()
    return secret


def make_nope_proof(domain: str, server_pubkey_der: bytes) -> str:
    """Legacy HMAC token creation (kept for compatibility)."""
    secret = ensure_domain_secret(domain)
    payload = {
        "domain": domain,
        "pubkey_b64": base64.b64encode(server_pubkey_der).decode("ascii"),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    mac = hmac.new(secret, raw, hashlib.sha256).digest()
    token = {"payload": payload, "mac_b64": base64.b64encode(mac).decode("ascii")}
    return base64.b64encode(json.dumps(token).encode("utf-8")).decode("ascii")


def verify_nope_proof(token_b64: str, expected_domain: str, server_pubkey_der: bytes) -> bool:
    """Legacy HMAC verification (kept for compatibility)."""
    try:
        token = json.loads(base64.b64decode(token_b64).decode("utf-8"))
        payload = token["payload"]
        mac_b64 = token["mac_b64"]
        if payload.get("domain") != expected_domain:
            return False
        if payload.get("pubkey_b64") != base64.b64encode(server_pubkey_der).decode("ascii"):
            return False
        secret = ensure_domain_secret(expected_domain)
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        expected_mac = hmac.new(secret, raw, hashlib.sha256).digest()
        return hmac.compare_digest(expected_mac, base64.b64decode(mac_b64))
    except Exception:
        return False


# ---------- helpers (RSA-PSS JSON) ----------
def pubkey_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def verify_nope_json(token_obj: dict, expected_sid: str, expected_domain: str, server_public_key) -> bool:
    try:
        payload = token_obj["payload"]
        sig_b64 = token_obj["signature_b64"]
        if payload.get("server_id") != expected_sid:
            return False
        if payload.get("domain") != expected_domain:
            return False
        # fingerprint must match the actual server public key
        if payload.get("pubkey_fingerprint") != pubkey_fingerprint(server_public_key):
            return False

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = base64.b64decode(sig_b64)

        server_public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------- main loader that supports both formats ----------
def verify_nope_token_file(token_path: str, server_id: str, expected_domain: str, server_public_key) -> bool:
    """
    Detect token type by content/extension and verify accordingly.
    Returns True if token is valid for (server_id, expected_domain, server_public_key).
    """
    if not os.path.exists(token_path):
        return False

    try:
        # Try JSON first (current format *.nope.json)
        with open(token_path, "r", encoding="utf-8") as f:
            maybe_json = f.read().strip()
        try:
            token_obj = json.loads(maybe_json)
            # JSON token should have "payload" and "signature_b64"
            if isinstance(token_obj, dict) and "payload" in token_obj and "signature_b64" in token_obj:
                return verify_nope_json(token_obj, server_id, expected_domain, server_public_key)
        except json.JSONDecodeError:
            pass

        # Fallback: legacy base64 token
        with open(token_path, "rb") as f_bin:
            raw = f_bin.read().strip()
        token_b64 = raw.decode("utf-8")
        server_pub_der = server_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return verify_nope_proof(token_b64, expected_domain, server_pub_der)
    except Exception:
        return False
