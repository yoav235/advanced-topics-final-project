# generate_tls.py
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_nope_tls_cert(output_dir=None):
    """
    ייצור key.pem ו-cert.pem. יעד ברירת מחדל: משתנה סביבה TLS_DIR או 'tls/'.
    מחזיר (cert_path, key_path).
    """
    tls_dir = output_dir or os.environ.get("TLS_DIR", "tls")
    os.makedirs(tls_dir, exist_ok=True)

    key_path = os.path.join(tls_dir, "key.pem")
    cert_path = os.path.join(tls_dir, "cert.pem")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdvancedTopics"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    now = datetime.now(timezone.utc)
    proof_path = os.path.join("nope", "rsa-ecdsa_proof.json")
    with open(proof_path) as f:
        proof_data = f.read()

    certificate = (
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
        .add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.55555.1.1"),  # OID שרירותי לדמו
                proof_data.encode()
            ),
            critical=False
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

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

def generate_tls_cert(output_dir=None):
    """
    ייצור key.pem ו-cert.pem. יעד ברירת מחדל: משתנה סביבה TLS_DIR או 'tls/'.
    מחזיר (cert_path, key_path).
    """
    tls_dir = output_dir or os.environ.get("TLS_DIR", "tls")
    os.makedirs(tls_dir, exist_ok=True)

    key_path = os.path.join(tls_dir, "key.pem")
    cert_path = os.path.join(tls_dir, "cert.pem")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdvancedTopics"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

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

if __name__ == "__main__":
    tls_dir = os.environ.get("TLS_DIR", "tls")
    cert_path = os.path.join(tls_dir, "cert.pem")
    key_path = os.path.join(tls_dir, "key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        generate_nope_tls_cert()
    else:
        print(f"ℹ️ TLS: files already exist in '{tls_dir}', nothing to do.")
