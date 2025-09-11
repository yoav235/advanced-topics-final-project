# server/nope_utils.py
# -*- coding: utf-8 -*-
"""
NOPE utils — token verification (JSON RSA-PSS & legacy HMAC)

What this module provides:
1) Two token formats (auto-detected):
   a) JSON signed token (RSA-PSS-SHA256) — current format
      File: nope/tokens/<SID>.nope.json
      {
        "payload": {
          "server_id": "...",
          "domain": "...",
          "pubkey_fingerprint": "<hex sha256(SPKI)>",
          "alg": "RSA-PSS-SHA256",          # optional but recommended
          "ts": <unix>,                     # optional
          "exp": <unix>                     # optional (preferred over ts)
        },
        "signature_b64": "<base64(signature over canonical payload JSON)>"
      }

   b) Legacy HMAC token (back-compat):
      token_b64 = base64(JSON{payload, mac_b64})
      payload   = {"domain": "...", "pubkey_b64": base64(DER(SPKI))}
      mac       = HMAC-SHA256(secret(domain), canonical_json(payload))
      secret    = nope/authority_secrets/<domain>.key

2) Main helpers:
   - find_token_for_server(server_id, ...)
   - verify_nope_token_file(token_path, server_id, domain, public_key)
   - verify_peer_nope(server_id, domain, public_key)  # convenience
   - verify_nope_and_optional_zk(...)                 # back-compat shim (token-only)

Notes:
- Freshness policy: if payload.exp exists, require now <= exp.
  Else if payload.ts exists and NOPE_TOKEN_MAX_AGE_SEC > 0, require now - ts <= max_age.
  If neither exists, skip freshness to preserve back-compat.
- This module does NOT decide the expected domain; pass it in.
  Domain precedence (expected_domains.json etc.) is handled in nope_enforcer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ------------------------------------------------------------------------------
# logging
# ------------------------------------------------------------------------------
log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# paths
# ------------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
NOPE_DIR     = Path(os.environ.get("NOPE_DIR", PROJECT_ROOT / "nope"))
AUTH_DIR     = NOPE_DIR / "authority_secrets"
TOKENS_DIR   = NOPE_DIR / "tokens"

AUTH_DIR.mkdir(parents=True, exist_ok=True)
TOKENS_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------------------
# canonical JSON for signing/verifying
# ------------------------------------------------------------------------------
def _canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ==============================================================================
# Legacy HMAC token (back-compat)
# ==============================================================================

def _auth_key_path(domain: str) -> Path:
    safe = domain.replace("/", "_")
    return AUTH_DIR / f"{safe}.key"


def ensure_domain_secret(domain: str) -> bytes:
    """Create/load a per-domain secret (simulates DNSSEC-bound issuer in older demos)."""
    p = _auth_key_path(domain)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


def make_nope_proof(domain: str, server_pubkey_der: bytes) -> str:
    """Create legacy HMAC token (for backward compatibility)."""
    secret = ensure_domain_secret(domain)
    payload = {
        "domain": domain,
        "pubkey_b64": base64.b64encode(server_pubkey_der).decode("ascii"),
    }
    mac = hmac.new(secret, _canonical_json_bytes(payload), hashlib.sha256).digest()
    token = {"payload": payload, "mac_b64": base64.b64encode(mac).decode("ascii")}
    return base64.b64encode(json.dumps(token).encode("utf-8")).decode("ascii")


def verify_nope_proof(token_b64: str, expected_domain: str, server_pubkey_der: bytes) -> bool:
    """Verify legacy HMAC token."""
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


# ==============================================================================
# JSON token (RSA-PSS, current)
# ==============================================================================

def pubkey_fingerprint(public_key) -> str:
    """SHA-256 over DER-encoded SPKI of the public key."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def _get_max_age_seconds() -> int:
    """Read NOPE_TOKEN_MAX_AGE_SEC from env (defaults to 90 days). 0 disables freshness check."""
    try:
        val = int(os.environ.get("NOPE_TOKEN_MAX_AGE_SEC", str(90 * 24 * 3600)))
        return max(val, 0)
    except Exception:
        return 90 * 24 * 3600


def verify_nope_json(token_obj: dict,
                     expected_sid: str,
                     expected_domain: str,
                     server_public_key) -> bool:
    """
    Verify a JSON-signed token (RSA-PSS-SHA256).
    Fields required within payload: server_id, domain, pubkey_fingerprint.
    Optional: alg (recommended "RSA-PSS-SHA256"), ts, exp.
    Freshness policy:
      - If 'exp' present: now <= exp.
      - Else if 'ts' present and max_age>0: now - ts <= max_age.
      - Else: skip freshness (back-compat).
    """
    try:
        payload = token_obj["payload"]
        sig_b64 = token_obj["signature_b64"]

        # Basic binding checks
        if payload.get("server_id") != expected_sid:
            return False
        if payload.get("domain") != expected_domain:
            return False
        if payload.get("pubkey_fingerprint") != pubkey_fingerprint(server_public_key):
            return False

        # Algorithm (optional but recommended)
        alg = payload.get("alg")
        if alg is not None and str(alg).upper() != "RSA-PSS-SHA256":
            # Be strict but compatible: if alg given and not what we expect -> reject
            return False

        # Signature over canonical payload JSON
        payload_bytes = _canonical_json_bytes(payload)
        signature = base64.b64decode(sig_b64)

        server_public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        # Freshness
        now = int(time.time())
        max_age = _get_max_age_seconds()
        exp = payload.get("exp")
        ts  = payload.get("ts")

        if isinstance(exp, int):
            if now > exp:
                return False
        elif isinstance(ts, int) and max_age > 0:
            if (now - ts) > max_age:
                return False

        return True
    except Exception:
        return False


# ==============================================================================
# Loading a token from storage & verifying it
# ==============================================================================

PathLike = Union[str, Path]


def verify_nope_token_file(token_path: PathLike,
                           server_id: str,
                           expected_domain: str,
                           server_public_key) -> bool:
    """
    Auto-detect token format and verify accordingly.
    Returns True iff the token matches (server_id, expected_domain, server_public_key).
    """
    p = Path(token_path)
    if not p.exists():
        log.debug("Token file not found: %s", p)
        return False

    # Try new JSON format first
    try:
        text = p.read_text(encoding="utf-8").strip()
        obj = json.loads(text)
        if isinstance(obj, dict) and "payload" in obj and "signature_b64" in obj:
            return verify_nope_json(obj, server_id, expected_domain, server_public_key)
    except Exception:
        pass

    # Fallback: legacy HMAC (base64 JSON)
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
                          tokens_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Look up nope/tokens/<SID>.nope.json (preferred) or nope/tokens/<SID>.tok
    under tokens_dir (defaults to NOPE_DIR/tokens).
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
                     tokens_dir: Optional[Path] = None) -> bool:
    """
    Convenience: find the token for server_id and verify it.
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


# ==============================================================================
# Back-compat shim: verify_nope_and_optional_zk — verifies token only
# ==============================================================================

def verify_nope_and_optional_zk(server_id: str,
                                expected_domain: str,
                                server_public_key,
                                token_path: Optional[PathLike] = None,
                                *_, **__) -> bool:
    """
    Kept for backward compatibility: ignores any ZK/VK/Proof args and verifies token only.
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
