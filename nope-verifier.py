from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from cryptography.x509.oid import ObjectIdentifier
import json
import subprocess
import tempfile
import os
import shutil

NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")


def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert

def check_tls_validity(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return cert.not_valid_before <= now <= cert.not_valid_after

def extract_nope_proof(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_oid(NOPE_OID)
        proof_json = ext.value.value.decode()  # המחרוזת ששמרנו
        return json.loads(proof_json)
    except Exception as e:
        print(f"No NOPE proof found: {e}")
        return None

def verify_nope_with_snarkjs(proof_dict: dict, vk_path="nope/rsa-ecdsa-vk.json"):
    with tempfile.TemporaryDirectory() as tmp:
        proof_path = os.path.join(tmp, "rsa-ecdsa-proof.json")
        public_path = os.path.join(tmp, "rsa-ecdsa-public.json")

        with open(proof_path, "w") as f:
            json.dump(proof_dict, f)


        shutil.copy("nope/rsa-ecdsa_public.json", public_path)

        cmd = ["npx.cmd", "snarkjs", "groth16", "verify", vk_path, public_path, proof_path]

        result = subprocess.run(cmd, capture_output=True, text=True)
        return "OK" in result.stdout

def verify_tls_with_nope(cert_path: str) -> bool:
    cert = load_certificate(cert_path)

    if not check_tls_validity(cert):
        print("❌ Certificate expired or not yet valid.")
        return False

    proof = extract_nope_proof(cert)
    if not proof:
        print("❌ Missing NOPE proof.")
        return False

    if not verify_nope_with_snarkjs(proof):
        print("❌ NOPE proof verification failed.")
        return False

    print("✅ TLS certificate is valid and NOPE proof verified.")
    return True

if __name__ == "__main__":
    verify_tls_with_nope("tls/cert.pem")