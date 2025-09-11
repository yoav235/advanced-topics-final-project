# init_nope.py  — bind NOPE tokens to the TLS key (no ZK; JSON RSA-PSS tokens)
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --------------------------------------------------------------------------------------
# Paths & constants
# --------------------------------------------------------------------------------------
ROOT       = Path(__file__).resolve().parent
PROJECT    = ROOT
NOPE_DIR   = Path(os.environ.get("NOPE_DIR", PROJECT / "nope"))
TOKENS_DIR = NOPE_DIR / "tokens"

TLS_DIR  = Path(os.environ.get("TLS_DIR", "tls"))
TLS_CERT = TLS_DIR / "cert.pem"
TLS_KEY  = TLS_DIR / "key.pem"

EXPECTED_DOMAINS_PATH = PROJECT / "server" / "expected_domains.json"

SERVERS = ["S1", "S2", "S3"]  # small demo topology

# --------------------------------------------------------------------------------------
# Domains loading (keeps consistency with server/nope_enforcer.expected_domain_for)
# --------------------------------------------------------------------------------------
def _fallback_domain_for_sid(server_id: str) -> str:
    try:
        idx = int(server_id[1:])
    except Exception:
        idx = 0
    return f"mix{idx}.local" if idx > 0 else "localhost"

def _load_domain_map() -> Dict[str, str]:
    """
    Load expected domains from server/expected_domains.json if present.
    Fallback to mixN.local/localhost.
    """
    try:
        if EXPECTED_DOMAINS_PATH.exists():
            mp = json.loads(EXPECTED_DOMAINS_PATH.read_text(encoding="utf-8"))
            if isinstance(mp, dict):
                # normalize keys (S1/S2/..)
                return {str(k): str(v) for k, v in mp.items()}
    except Exception:
        pass
    # fallback demo defaults
    return {sid: _fallback_domain_for_sid(sid) for sid in SERVERS}

# --------------------------------------------------------------------------------------
# TLS key/cert I/O
# --------------------------------------------------------------------------------------
def _ensure_dirs() -> None:
    TOKENS_DIR.mkdir(parents=True, exist_ok=True)

def _load_tls_public_key():
    cert = x509.load_pem_x509_certificate(TLS_CERT.read_bytes())
    return cert.public_key()

def _load_tls_private_key():
    return serialization.load_pem_private_key(TLS_KEY.read_bytes(), password=None)

# --------------------------------------------------------------------------------------
# Helpers: fingerprint, canonical JSON, sign/verify
# --------------------------------------------------------------------------------------
def _pubkey_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()

def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _sign_payload(priv, payload_bytes: bytes) -> bytes:
    return priv.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def _verify_signature(pub, payload_bytes: bytes, sig: bytes) -> bool:
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

# --------------------------------------------------------------------------------------
# Token build/validate/write
# --------------------------------------------------------------------------------------
def _maybe_exp(ts: int) -> int | None:
    """
    If NOPE_TOKEN_TTL_SEC is set (>0), return ts+ttl to embed 'exp' into the token.
    Otherwise return None (token will carry only 'ts').
    """
    try:
        ttl = int(os.environ.get("NOPE_TOKEN_TTL_SEC", "0"))
        if ttl > 0:
            return ts + ttl
    except Exception:
        pass
    return None

def _make_token_obj(server_id: str, domain: str, tls_pub, tls_priv) -> dict:
    now = int(time.time())
    payload = {
        "server_id": server_id,
        "domain": domain,
        "pubkey_fingerprint": _pubkey_fingerprint(tls_pub),  # bind to TLS key
        "alg": "RSA-PSS-SHA256",
        "ts": now,
    }
    exp = _maybe_exp(now)
    if exp is not None:
        payload["exp"] = exp

    sig = _sign_payload(tls_priv, _canonical_bytes(payload))
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

def _token_is_valid_for_tls(token_obj: dict, server_id: str, domain: str, tls_pub) -> bool:
    try:
        payload = token_obj["payload"]
        sig_b64 = token_obj["signature_b64"]
        if payload.get("server_id") != server_id:
            return False
        if payload.get("domain") != domain:
            return False
        if payload.get("pubkey_fingerprint") != _pubkey_fingerprint(tls_pub):
            return False
        return _verify_signature(tls_pub, _canonical_bytes(payload), base64.b64decode(sig_b64))
    except Exception:
        return False

def _write_token(server_id: str, obj: dict) -> Path:
    out = TOKENS_DIR / f"{server_id}.nope.json"
    out.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

def _maybe_update_token(server_id: str, domain: str, tls_pub, tls_priv) -> Tuple[Path, bool]:
    """
    Returns: (path, updated?)
    If an existing token matches (server_id, domain, TLS pubkey), keep as-is; otherwise replace.
    """
    path = TOKENS_DIR / f"{server_id}.nope.json"
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if _token_is_valid_for_tls(existing, server_id, domain, tls_pub):
                return path, False
        except Exception:
            pass
    obj = _make_token_obj(server_id, domain, tls_pub, tls_priv)
    _write_token(server_id, obj)
    return path, True

# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------
def main() -> int:
    print("[init_nope] Starting (TLS-bound tokens)…")
    _ensure_dirs()

    # sanity
    missing = [p for p in (TLS_CERT, TLS_KEY) if not p.exists()]
    if missing:
        for p in missing:
            print(f"[init_nope] ERROR: missing {p}")
        print("[init_nope] Run init_tls.py first.")
        return 2

    domain_map = _load_domain_map()
    tls_pub  = _load_tls_public_key()
    tls_priv = _load_tls_private_key()

    touched = 0
    for sid in SERVERS:
        dom = domain_map.get(sid, _fallback_domain_for_sid(sid))
        path, updated = _maybe_update_token(sid, dom, tls_pub, tls_priv)
        status = "Updated" if updated else "OK (kept)"
        print(f"[init_nope] {sid}: {status} -> {path}")
        touched += int(updated)

    print("\n[init_nope] Tokens folder content:")
    for p in sorted(TOKENS_DIR.glob("*.nope.json")):
        try:
            sz = p.stat().st_size
        except Exception:
            sz = 0
        print(f" - {p} ({sz} bytes)")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
