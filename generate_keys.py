import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair(server_id, output_dir="keys"):
    os.makedirs(output_dir, exist_ok=True)

    # Generate key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save private key
    priv_path = os.path.join(output_dir, f"{server_id}_priv.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    pub_key = private_key.public_key()
    pub_path = os.path.join(output_dir, f"{server_id}_pub.pem")
    with open(pub_path, "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"✅ Keys generated for {server_id}")

if __name__ == "__main__":
    for server_id in ["S1", "S2", "S3"]:
        generate_rsa_key_pair(server_id)
