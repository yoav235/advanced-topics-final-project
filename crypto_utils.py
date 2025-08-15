import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def decrypt_hybrid(private_key, payload: bytes) -> bytes:
    rsa_len = 256
    rsa_encrypted = payload[:rsa_len]
    tag = payload[rsa_len:rsa_len + 16]
    ciphertext = payload[rsa_len + 16:]

    aes_key_nonce = private_key.decrypt(
        rsa_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aes_key = aes_key_nonce[:32]
    nonce = aes_key_nonce[32:]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_hybrid(public_key, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using hybrid encryption:
    - Generates random AES key + nonce.
    - Encrypts message with AES-GCM.
    - Encrypts AES key + nonce with RSA public key.
    - Final message: RSA(cipherkey+nonce) || GCM tag || ciphertext
    """

    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    aes_key_nonce = aes_key + nonce
    rsa_encrypted = public_key.encrypt(
        aes_key_nonce,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return rsa_encrypted + tag + ciphertext


def load_private_keys(server_ids, keys_dir="keys"):
    key_folder = os.path.join(os.getcwd(), keys_dir)
    private_keys = {}
    for server_id in server_ids:
        key_path = os.path.join(key_folder, f"{server_id}_priv.pem")
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            private_keys[server_id] = private_key

    return private_keys


def load_public_key(path):
    """
    Load a public key from a PEM file.
    :param path: Path to the PEM file
    :return: The loaded public key object
    """
    full_path = "./keys/" + path + "_pub.pem"
    with open(full_path, "rb") as key_file:
        key_data = key_file.read()
        public_key = serialization.load_pem_public_key(key_data)
    return public_key
