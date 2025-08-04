from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import os

def generate_tls_cert():
    # יצירת מפתח פרטי (private key)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # הגדרת subject ו-issuer (אותו דבר כאן כי זה self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jerusalem"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdvancedTopics"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    now = datetime.now(timezone.utc)

    # יצירת תעודת X.509
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
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # יצירת תיקיית tls אם לא קיימת
    os.makedirs("tls", exist_ok=True)

    # שמירת המפתח והתעודה לקבצים
    with open("tls/key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("tls/cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("✅ TLS certificate and key generated in tls/ directory.")

if __name__ == "__main__":
    generate_tls_cert()
