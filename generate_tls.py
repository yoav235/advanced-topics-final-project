# generate_tls.py
# -*- coding: utf-8 -*-
"""
יצירת תעודות TLS:
- generate_tls_cert: תעודת self-signed רגילה (לפיתוח/דמו)
- generate_nope_tls_cert: תעודת self-signed עם הטמעת הוכחת NOPE ב-OID ייעודי

הקבצים נוצרים אל תוך TLS_DIR (ברירת מחדל 'tls'): key.pem, cert.pem
"""

import os
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier  # <-- הייבוא הנכון ל-OID

# אותו OID שמאומת ע"י המאמת שלנו (nope-verifier.py / init_tls.py)
NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")


def _mk_self_signed_cert(private_key) -> x509.CertificateBuilder:
    """בסיס ל-CertificateBuilder עבור self-signed מקומי."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jerusalem"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jerusalem"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdvancedTopics"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
    )


def _write_key_and_cert(tls_dir: str, private_key, certificate: x509.Certificate) -> tuple[str, str]:
    """כותב key.pem ו-cert.pem ומחזיר נתיביהם (cert_path, key_path)."""
    os.makedirs(tls_dir, exist_ok=True)
    key_path = os.path.join(tls_dir, "key.pem")
    cert_path = os.path.join(tls_dir, "cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"✅ TLS: created '{key_path}' and '{cert_path}'")
    return cert_path, key_path


def generate_nope_tls_cert(output_dir: str | None = None) -> tuple[str, str]:
    """
    ייצור key.pem ו-cert.pem עם הרחבת OID המכילה הוכחת NOPE (בפורמט JSON).
    יעד ברירת מחדל: TLS_DIR או 'tls/'.
    מחזיר (cert_path, key_path).

    מצפה שהקובץ nope/rsa-ecdsa_proof.json קיים ותקין (JSON).
    """
    tls_dir = output_dir or os.environ.get("TLS_DIR", "tls")
    os.makedirs(tls_dir, exist_ok=True)

    # מפתח פרטי
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # בניית תעודה
    builder = _mk_self_signed_cert(private_key)

    # קריאת ה-proof (נשמר כטקסט JSON גולמי בתוך UnrecognizedExtension)
    proof_path = os.path.join("nope", "rsa-ecdsa_proof.json")
    try:
        proof_text = open(proof_path, "r", encoding="utf-8").read()
        # אימות שהוא JSON חוקי (לא נשמור object — נשמור את המחרוזת, אבל נוודא תקינות)
        _ = json.loads(proof_text)
    except FileNotFoundError:
        raise FileNotFoundError(f"NOPE proof file not found: {proof_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"NOPE proof file is not valid JSON: {proof_path} ({e})")

    builder = builder.add_extension(
        x509.UnrecognizedExtension(NOPE_OID, proof_text.encode("utf-8")),
        critical=False,
    )

    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    return _write_key_and_cert(tls_dir, private_key, certificate)


def generate_tls_cert(output_dir: str | None = None) -> tuple[str, str]:
    """
    ייצור key.pem ו-cert.pem ללא OID (plain TLS). יעד ברירת מחדל: TLS_DIR או 'tls/'.
    מחזיר (cert_path, key_path).
    """
    tls_dir = output_dir or os.environ.get("TLS_DIR", "tls")
    os.makedirs(tls_dir, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    builder = _mk_self_signed_cert(private_key)
    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    return _write_key_and_cert(tls_dir, private_key, certificate)


if __name__ == "__main__":
    # הרצה ידנית קטנה: מעדיף NOPE אם יש קבצי proof זמינים
    tls_dir = os.environ.get("TLS_DIR", "tls")
    cert_path = os.path.join(tls_dir, "cert.pem")
    key_path = os.path.join(tls_dir, "key.pem")

    have_nope_inputs = os.path.exists(os.path.join("nope", "rsa-ecdsa_proof.json"))

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        if have_nope_inputs:
            print("[generate_tls] generating TLS cert with embedded NOPE proof…")
            generate_nope_tls_cert(tls_dir)
        else:
            print("[generate_tls] generating plain TLS cert…")
            generate_tls_cert(tls_dir)
    else:
        print(f"[generate_tls] TLS already present in '{tls_dir}' — nothing to do.")
