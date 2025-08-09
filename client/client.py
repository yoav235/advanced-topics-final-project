# from server.nope_utils import sign_message_with_nope
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import base64
import os
import crypto_utils
import random

def load_private_keys(server_ids, keys_dir="keys"):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    key_folder = os.path.join(base_dir, keys_dir)

    private_keys = {}
    for server_id in server_ids:
        key_path = os.path.join(key_folder, f"{server_id}_priv.pem")
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            private_keys[server_id] = private_key

    return private_keys


class Client:
    def __init__(self, client_id, server_list):
        self.client_id = client_id
        self.server_list = server_list
        self.public_keys = self.load_public_keys(["S1", "S2", "S3"]) # server_ids is hardcoded for testing!


    def load_public_keys(self, server_ids, keys_dir="keys"):
        """
        Loads RSA public keys for the given server IDs.

        Args:
            server_ids: List of server IDs like ["S1", "S2", "S3"]
            keys_dir: Directory where public key PEM files are stored

        Returns:
            Dict mapping server_id → rsa.RSAPublicKey object
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # goes up one level from client/
        key_folder = os.path.join(base_dir, keys_dir)

        public_keys = {}
        for server_id in server_ids:
            key_path = os.path.join(key_folder, f"{server_id}_pub.pem")
            with open(key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
                public_keys[server_id] = public_key

        return public_keys

    def onion_encrypt(self, message_dict, path_ids):
        """
        message_dict: dict with {"to": client_id, "message": "text"}
        path_ids: list of 3 server IDs, in order of hops [S1, S2, S3]
        public_keys: dict { "S1": rsa_public_key_obj, ... }
        """
        payload = message_dict

        for i, server_id in enumerate(reversed(path_ids)):
            next_hop = path_ids[::-1][i - 1] if i > 0 else "DEST"
            payload = {
                "from": self.client_id,
                "next": next_hop,
                "payload": payload
            }
            serialized = json.dumps(payload).encode()
            encrypted = crypto_utils.encrypt_hybrid(self.public_keys[server_id], serialized)
            payload = base64.b64encode(encrypted).decode()

        return payload


    def send_message(self, message):
        chosen_servers = random.sample(self.server_list, 3)
        message_path = [s.server_id for s in chosen_servers]
        payload = self.onion_encrypt(message, message_path)
        # signed_message = sign_message_with_nope(payload, self.client_id)
        signed_message = payload
        print(f"[Client {self.client_id}] Sending message to {self.server_list}: {message}")

        chosen_servers[0].receive_message(signed_message, self.client_id, use_tls=True)

# testing encryption
if __name__ == "__main__":
    client = Client("client_id", ["S1", "S2", "S3"])
    message = {
        "to": client.client_id,
        "message": "Hello World!"
    }

    path = ["S1", "S2", "S3"]
    encrypted_message = client.onion_encrypt(message, path)
    print("encrypted message: ", encrypted_message)

    # load private keys
    private_keys = load_private_keys(path)

    layer1 = crypto_utils.decrypt_hybrid(private_keys["S1"], base64.b64decode(encrypted_message))
    print("decrypted level 1:", json.loads(layer1.decode()))

    layer2 = crypto_utils.decrypt_hybrid(private_keys["S2"], base64.b64decode(json.loads(layer1.decode())["payload"]))
    print("decrypted level 2:", json.loads(layer2.decode()))

    layer3 = crypto_utils.decrypt_hybrid(private_keys["S3"], base64.b64decode(json.loads(layer2.decode())["payload"]))
    print("final decrypted message:", json.loads(layer3.decode())["payload"]["message"])

