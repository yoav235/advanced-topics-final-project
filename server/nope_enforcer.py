# server/nope_enforcer.py
# -*- coding: utf-8 -*-
"""
NOPE enforcement helper for TLS sockets.

- Extracts peer cert public key from an SSLSocket
- Loads NOPE token for the given server_id (S1/S2/S3) from nope/tokens
- Prefers expected domain from server/expected_domains.json over the domain written in the token
- Verifies token against (server_id, expected_domain, peer public key)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from cryptography import x509

from .nope_utils import find_token_for_server, verify_nope_token_file

_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_DOMAINS_PATH = _ROOT / "server" / "expected_domains.json"
_expected_cache: dict[str, str] | None = None


def _load_expected_domains() -> dict[str, str]:
    global _expected_cache
    if _expected_cache is not None:
        return _expected_cache
    try:
        _expected_cache = json.loads(_EXPECTED_DOMAINS_PATH.read_text(encoding="utf-8"))
    except Exception:
        _expected_cache = {}
    return _expected_cache


def expected_domain_for(server_id: str, fallback: Optional[str] = None) -> str:
    """Public helper: S1->mix1.local etc., from server/expected_domains.json if present."""
    mp = _load_expected_domains()
    if server_id in mp:
        return mp[server_id]
    return fallback if fallback is not None else _fallback_domain_for_sid(server_id)


def _fallback_domain_for_sid(server_id: str) -> str:
    # S1 -> mix1.local, etc.
    try:
        idx = int(server_id[1:])
    except Exception:
        idx = 0
    return f"mix{idx}.local" if idx > 0 else "mix.local"


def _domain_from_token_file(token_path: Path, fallback: str) -> str:
    try:
        obj = json.loads(token_path.read_text(encoding="utf-8"))
        return obj.get("payload", {}).get("domain", fallback)
    except Exception:
        return fallback


def verify_peer_on_socket(
    ssock,  # ssl.SSLSocket
    server_id: str,
    mode: str = "raise",            # "raise" | "return_false"
    tokens_dir: Optional[Path] = None,
    expected_domain: Optional[str] = None,
) -> bool:
    """
    Verify the NOPE token for `server_id` against the peer TLS certificate on `ssock`.

    Domain precedence:
      1) expected_domain argument (if provided)
      2) server/expected_domains.json
      3) domain embedded in the token (legacy behavior)
      4) mixN.local fallback
    """
    try:
        # 1) peer certificate -> public key
        der = ssock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("TLS peer has no certificate")
        cert = x509.load_der_x509_certificate(der)
        peer_pub = cert.public_key()

        # 2) find the token for this server_id
        tok = find_token_for_server(server_id, tokens_dir=tokens_dir)
        if not tok:
            raise FileNotFoundError(f"NOPE token for {server_id} not found under {tokens_dir or 'nope/tokens'}")

        # 3) pick expected domain by precedence
        dom = expected_domain or expected_domain_for(server_id, fallback=None)
        if dom is None:
            dom = _domain_from_token_file(Path(tok), _fallback_domain_for_sid(server_id))
        # final fallback
        dom = dom or _fallback_domain_for_sid(server_id)

        ok = verify_nope_token_file(tok, server_id, dom, peer_pub)
        if ok:
            return True
        if mode == "raise":
            raise RuntimeError(f"NOPE verification failed for {server_id} (domain={dom})")
        return False

    except Exception:
        if mode == "raise":
            raise
        return False
