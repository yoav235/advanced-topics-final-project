# init_tls.py  — generate TLS cert; embed NOPE proof when ZK is enabled & inputs exist
from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from generate_tls import generate_tls_cert, generate_nope_tls_cert

# אותו OID שבו אנו מטמיעים את ה־NOPE proof (חייב להתאים ל-nope-verifier.py/generate_tls.py)
NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")


def _cert_has_nope_oid(cert_path: Path) -> bool:
    """בודק אם לתעודה יש הרחבה עם OID של NOPE."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        _ = cert.extensions.get_extension_for_oid(NOPE_OID)
        return True
    except Exception:
        return False


def _nope_inputs_present(root: Path) -> bool:
    """
    בדיקה שהקבצים הדרושים קיימים:
      - הוכחה להטמעה בתעודה (rsa-ecdsa_proof.json)
      - public inputs + verification key כדי שהמאמת ידע לבדוק
    """
    return all(
        [
            (root / "nope" / "rsa-ecdsa_proof.json").exists(),
            (root / "nope" / "rsa-ecdsa_public.json").exists(),
            (root / "nope" / "rsa-ecdsa-vk.json").exists(),
        ]
    )


def _want_zk_from_env() -> bool:
    """
    ZK נדרש אם אחת מהסביבות דולקות:
      NOPE_ZK_CHECK=1  או  NOPE_ZK_ENFORCE=1
    """
    return os.environ.get("NOPE_ZK_CHECK", "0") == "1" or os.environ.get("NOPE_ZK_ENFORCE", "0") == "1"


def main() -> None:
    tls_dir = Path(os.environ.get("TLS_DIR", "tls"))
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert = tls_dir / "cert.pem"
    key = tls_dir / "key.pem"

    root = Path(__file__).resolve().parent

    want_zk = _want_zk_from_env()
    have_inp = _nope_inputs_present(root)
    force_regen = os.environ.get("FORCE_REGEN_TLS", "0") == "1"

    def _gen_plain():
        print("[init_tls] generating plain TLS cert…")
        generate_tls_cert(str(tls_dir))

    def _gen_with_nope():
        print("[init_tls] generating TLS cert with embedded NOPE proof…")
        generate_nope_tls_cert(str(tls_dir))

    # --- FORCE: תמיד מייצרים מחדש לפי המצב המבוקש
    if force_regen:
        if want_zk and have_inp:
            _gen_with_nope()
        else:
            if want_zk and not have_inp:
                print("[init_tls] WARNING: NOPE inputs not found; falling back to plain TLS.")
            _gen_plain()
        return

    # --- אין תעודה/מפתח: יצירה ראשונית
    if not (cert.exists() and key.exists()):
        if want_zk and have_inp:
            print(f"[init_tls] TLS missing in '{tls_dir}' -> generating with NOPE OID…")
            _gen_with_nope()
        else:
            if want_zk and not have_inp:
                print("[init_tls] WARNING: NOPE inputs not found; generating plain TLS.")
            print(f"[init_tls] TLS missing in '{tls_dir}' -> generating…")
            _gen_plain()
        return

    # --- יש כבר cert+key
    if want_zk:
        if _cert_has_nope_oid(cert):
            print(f"[init_tls] TLS already present at '{tls_dir}' (NOPE OID found) -> keeping")
        else:
            if have_inp:
                print("[init_tls] TLS present but NOPE OID missing -> regenerating with NOPE proof…")
                _gen_with_nope()
            else:
                print("[init_tls] WARNING: NOPE inputs not found; keeping existing plain TLS.")
    else:
        print(f"[init_tls] TLS already present at '{tls_dir}' -> cert.pem & key.pem exist")


if __name__ == "__main__":
    main()
