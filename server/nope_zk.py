# server/nope_zk.py
from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier

_NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")

class NopeZKError(RuntimeError):
    pass

def _load_cert_from_bytes(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def _load_cert_from_file(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return _load_cert_from_bytes(f.read())

def _check_time_valid(cert: x509.Certificate) -> None:
    # משתמשים ב-not_valid_before_utc / not_valid_after_utc אם זמינים; אחרת מתיישרים ל-naive
    try:
        nbf = cert.not_valid_before_utc
        naf = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        if not (nbf <= now <= naf):
            raise NopeZKError("certificate not within validity window (UTC)")
    except AttributeError:
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        if not (cert.not_valid_before <= now_naive <= cert.not_valid_after):
            raise NopeZKError("certificate not within validity window")

def _extract_nope_proof_dict(cert: x509.Certificate) -> dict:
    try:
        ext = cert.extensions.get_extension_for_oid(_NOPE_OID)
    except Exception as e:
        raise NopeZKError(f"missing NOPE OID extension: {e}")
    try:
        proof_json = ext.value.value.decode()
        return json.loads(proof_json)
    except Exception as e:
        raise NopeZKError(f"malformed NOPE OID payload: {e}")

def _verify_with_snarkjs(proof_dict: dict, vk_path: str = "nope/rsa-ecdsa-vk.json") -> None:
    # public signals (לדמו): אותו קובץ שה-issuer שמר לצד ה-proof
    public_path_src = "nope/rsa-ecdsa_public.json"
    if not (os.path.exists(vk_path) and os.path.exists(public_path_src)):
        raise NopeZKError("verification keys/public signals not found under 'nope/'")

    # נעדיף npx.cmd על Windows, אחרת npx
    npx = "npx.cmd" if os.name == "nt" else "npx"

    with tempfile.TemporaryDirectory() as tmp:
        proof_path = os.path.join(tmp, "rsa-ecdsa-proof.json")
        public_path = os.path.join(tmp, "rsa-ecdsa-public.json")
        with open(proof_path, "w", encoding="utf-8") as f:
            json.dump(proof_dict, f)
        shutil.copy(public_path_src, public_path)

        cmd = [npx, "snarkjs", "groth16", "verify", vk_path, public_path, proof_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise NopeZKError("npx/snarkjs not available in PATH")
        if "OK" not in (res.stdout or ""):
            raise NopeZKError(f"snarkjs verify failed: {res.stdout or res.stderr}")

def verify_cert_pem_bytes_has_valid_nope(pem_bytes: bytes) -> bool:
    """
    אימות ZK 'רך': מחזיר True/False, לא מעלה חריגות החוצה.
    """
    try:
        cert = _load_cert_from_bytes(pem_bytes)
        _check_time_valid(cert)
        proof = _extract_nope_proof_dict(cert)
        _verify_with_snarkjs(proof)
        return True
    except Exception:
        return False

def enforce_cert_pem_bytes_has_valid_nope(pem_bytes: bytes) -> None:
    """
    אימות ZK 'אוכף': זורק NopeZKError אם אין/נכשל.
    """
    cert = _load_cert_from_bytes(pem_bytes)
    _check_time_valid(cert)
    proof = _extract_nope_proof_dict(cert)
    _verify_with_snarkjs(proof)

def maybe_enforce_on_peer_cert(
    peer_cert_pem: bytes,
    log_func = None,
) -> None:
    """
    מכבד משתני סביבה:
      - NOPE_ZK_CHECK=1   => בדיקת ZK; אם ENFORCE=0 — לוג אזהרה בלבד על כישלון
      - NOPE_ZK_ENFORCE=1 => זריקת חריגה על כישלון
    """
    check = os.environ.get("NOPE_ZK_CHECK", "0") == "1"
    enforce = os.environ.get("NOPE_ZK_ENFORCE", "0") == "1"
    if not check:
        return
    if enforce:
        enforce_cert_pem_bytes_has_valid_nope(peer_cert_pem)
        if log_func: log_func("ZK/NOPE: enforcement OK")
    else:
        ok = verify_cert_pem_bytes_has_valid_nope(peer_cert_pem)
        if not ok:
            if log_func: log_func("ZK/NOPE: soft-check FAILED (continuing)")
        else:
            if log_func: log_func("ZK/NOPE: soft-check OK")
