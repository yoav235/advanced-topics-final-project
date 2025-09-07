# init_tls.py  — generate TLS cert; embed NOPE proof when ZK is enabled & inputs exist
from __future__ import annotations
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from generate_tls import generate_tls_cert, generate_nope_tls_cert

NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")

def _cert_has_nope_oid(cert_path: Path) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        # if the extension exists — OK
        _ = cert.extensions.get_extension_for_oid(NOPE_OID)
        return True
    except Exception:
        return False

def _nope_inputs_present(root: Path) -> bool:
    # these are the files your verifier expects to exist
    return all([
        (root / "nope" / "rsa-ecdsa_proof.json").exists(),   # proof to embed
        (root / "nope" / "rsa-ecdsa_public.json").exists(),  # public inputs for verify
        (root / "nope" / "rsa-ecdsa-vk.json").exists(),      # verification key for verify
    ])

def main():
    tls_dir = Path(os.environ.get("TLS_DIR", "tls"))
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert = tls_dir / "cert.pem"
    key  = tls_dir / "key.pem"

    root = Path(__file__).resolve().parent

    # Controls: when ZK is desired, prefer embedding NOPE proof
    want_zk  = os.environ.get("NOPE_ZK_CHECK", "0") == "1" or os.environ.get("NOPE_ZK_ENFORCE", "0") == "1"
    have_inp = _nope_inputs_present(root)

    # Optional override to force regeneration
    force_regen = os.environ.get("FORCE_REGEN_TLS", "0") == "1"

    if force_regen:
        # Explicitly regenerate according to mode
        if want_zk and have_inp:
            print("[init_tls] FORCE: generating TLS cert with embedded NOPE proof…")
            generate_nope_tls_cert(str(tls_dir))
        else:
            if want_zk and not have_inp:
                print("[init_tls] WARNING: NOPE inputs not found; falling back to plain TLS.")
            print("[init_tls] FORCE: generating plain TLS cert…")
            generate_tls_cert(str(tls_dir))
        return

    # If cert+key missing — generate (prefer NOPE when requested and possible)
    if not (cert.exists() and key.exists()):
        if want_zk and have_inp:
            print(f"[init_tls] TLS missing in '{tls_dir}' -> generating with NOPE OID…")
            generate_nope_tls_cert(str(tls_dir))
        else:
            if want_zk and not have_inp:
                print("[init_tls] WARNING: NOPE inputs not found; generating plain TLS.")
            print(f"[init_tls] TLS missing in '{tls_dir}' -> generating…")
            generate_tls_cert(str(tls_dir))
        return

    # We have cert/key already
    if want_zk:
        if _cert_has_nope_oid(cert):
            print(f"[init_tls] TLS already present at '{tls_dir}' (NOPE OID found) -> keeping")
        else:
            if have_inp:
                print(f"[init_tls] TLS present but NOPE OID missing -> regenerating with NOPE proof…")
                generate_nope_tls_cert(str(tls_dir))
            else:
                print("[init_tls] WARNING: NOPE inputs not found; keeping existing plain TLS.")
    else:
        print(f"[init_tls] TLS already present at '{tls_dir}' -> cert.pem & key.pem exist")

if __name__ == "__main__":
    main()
