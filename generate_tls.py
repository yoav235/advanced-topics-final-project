<<<<<<< HEAD
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import os

def generate_tls_cert():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
=======
# generate_tls.py
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_tls_cert(output_dir: str | None = None) -> tuple[str, str]:
    """
    ייצור key.pem ו-cert.pem. יעד ברירת מחדל: TLS_DIR או 'tls/'.
    מחזיר (cert_path, key_path).
    """
    tls_dir = output_dir or os.environ.get("TLS_DIR", "tls")
    os.makedirs(tls_dir, exist_ok=True)

    key_path = os.path.join(tls_dir, "key.pem")
    cert_path = os.path.join(tls_dir, "cert.pem")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)

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
<<<<<<< HEAD
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    os.makedirs("tls", exist_ok=True)

    with open("tls/key.pem", "wb") as f:
=======
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    with open(key_path, "wb") as f:
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

<<<<<<< HEAD
    with open("tls/cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("✅ TLS certificate and key generated in tls/ directory.")

if __name__ == "__main__":
    generate_tls_cert()
=======
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"✅ TLS: created '{key_path}' and '{cert_path}'")
    return cert_path, key_path


if __name__ == "__main__":
    tls_dir = os.environ.get("TLS_DIR", "tls")
    cert_path = os.path.join(tls_dir, "cert.pem")
    key_path = os.path.join(tls_dir, "key.pem")

    # יצור רק אם חסר
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        generate_tls_cert(tls_dir)
    else:
        print(f"ℹ️ TLS: files already exist in '{tls_dir}', nothing to do.")
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
