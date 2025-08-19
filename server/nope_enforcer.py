# server/nope_enforcer.py
# -*- coding: utf-8 -*-
"""
NOPE enforcement helper for TLS sockets.

- Extracts peer certificate public key from an SSLSocket
- Loads the appropriate NOPE token for the given server_id (S1/S2/S3) from nope/tokens
- Verifies the token against (server_id, domain in token, peer public key)
- Returns True/False or raises (per mode)

Usage:
    ok = verify_peer_on_socket(ssock, server_id="S2", mode="raise", tokens_dir=Path("nope/tokens"))
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cryptography import x509

from .nope_utils import find_token_for_server, verify_nope_token_file


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
) -> bool:
    """
    Verify the NOPE token for `server_id` against the peer TLS certificate on `ssock`.

    - Finds token file under `tokens_dir` (or default nope/tokens) via find_token_for_server
    - Extracts peer public key from the TLS cert (binary_form DER)
    - Uses the domain embedded in the token payload (fallback: mixN.local)
    - Returns True if OK; if mode="raise" and verification fails -> raises, else returns False
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

        # 3) expected domain comes from the token itself (safer); fallback to mixN.local
        expected_domain = _domain_from_token_file(Path(tok), _fallback_domain_for_sid(server_id))

        # 4) verify
        ok = verify_nope_token_file(tok, server_id, expected_domain, peer_pub)
        if ok:
            return True
        if mode == "raise":
            raise RuntimeError(f"NOPE verification failed for {server_id} (domain={expected_domain})")
        return False

    except Exception:
        if mode == "raise":
            raise
        return False
