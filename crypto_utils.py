import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


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