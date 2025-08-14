<<<<<<< HEAD
import base64
import json

import crypto_utils
=======
# import base64
# import json
#
# import crypto_utils
# class MixServer:
#     def __init__(self, server_id, server_list=None, num_clients=2):
#         self.server_id = server_id
#         self.server_list = {"S1": "S1", "S2": "S2", "S3": "S3", "S4": "S4", "S5": "S5"}
#         self.num_clients = num_clients
#         self.next_server = None
#         self.private_key = crypto_utils.load_private_keys([server_id])
#         try:
#             with open("tls/cert.pem", "rb") as cert_file:
#                 self.cert = cert_file.read()
#             with open("tls/key.pem", "rb") as key_file:
#                 self.key = key_file.read()
#             print(f"[Server {self.server_id}] 🔐 TLS initialized.")
#         except FileNotFoundError:
#             print(f"[Server {self.server_id}] ⚠️ TLS files not found. Continuing without TLS.")
#             self.cert = self.key = None
#
#     def receive_message(self, message, sender_id, use_tls=True):
#
#         decrypted_message = crypto_utils.decrypt_hybrid(self.private_key[self.server_id], base64.b64decode(message))
#         decrypted_message = json.loads(decrypted_message.decode('utf-8'))
#         if not use_tls:
#             print(f"[Server {self.server_id}] ❌ Rejected message from {sender_id}: No TLS.")
#             return
#
#         print(f"[Server {self.server_id}] Received message from {sender_id}: {decrypted_message["payload"]}")
#
#         # from server.nope_utils import verify_nope_signature
#         # if not verify_nope_signature(message, sender_id):
#         #     print(f"[Server {self.server_id}] ❌ Invalid NOPE signature! Message dropped.")
#         #     return
#
#         # print(f"[{sender_id}] ✅ NOPE signature verified.")
#         self.next_server = self.server_list[decrypted_message["next"]]
#         # if self.next_server:
#         #     print(f"[Server {self.server_id}] Forwarding message to {self.next_server.server_id}")
#         #     self.next_server.receive_message(message, sender_id, use_tls=use_tls)
#         # else:
#         #     print(f"[Server {self.server_id}] Final destination reached.")
#
#     def send_message(self, message, sender_id, use_tls=True):
#         if not use_tls:
#             return None
#
# server/server.py
import os
import base64
import json
import logging

import crypto_utils

# לוג אחיד
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

TLS_DIR = os.environ.get("TLS_DIR", "tls")
TLS_CERT_PATH = os.path.join(TLS_DIR, "cert.pem")
TLS_KEY_PATH  = os.path.join(TLS_DIR, "key.pem")


>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
class MixServer:
    def __init__(self, server_id, server_list=None, num_clients=2):
        self.server_id = server_id
        self.server_list = {"S1": "S1", "S2": "S2", "S3": "S3", "S4": "S4", "S5": "S5"}
        self.num_clients = num_clients
        self.next_server = None
        self.private_key = crypto_utils.load_private_keys([server_id])
<<<<<<< HEAD
        try:
            with open("tls/cert.pem", "rb") as cert_file:
                self.cert = cert_file.read()
            with open("tls/key.pem", "rb") as key_file:
                self.key = key_file.read()
            print(f"[Server {self.server_id}] 🔐 TLS initialized.")
        except FileNotFoundError:
            print(f"[Server {self.server_id}] ⚠️ TLS files not found. Continuing without TLS.")
            self.cert = self.key = None

    def receive_message(self, message, sender_id, use_tls=True):

        decrypted_message = crypto_utils.decrypt_hybrid(self.private_key[self.server_id], base64.b64decode(message))
        decrypted_message = json.loads(decrypted_message.decode('utf-8'))
        if not use_tls:
            print(f"[Server {self.server_id}] ❌ Rejected message from {sender_id}: No TLS.")
            return

        print(f"[Server {self.server_id}] Received message from {sender_id}: {decrypted_message["payload"]}")

        # from server.nope_utils import verify_nope_signature
        # if not verify_nope_signature(message, sender_id):
        #     print(f"[Server {self.server_id}] ❌ Invalid NOPE signature! Message dropped.")
        #     return

        # print(f"[{sender_id}] ✅ NOPE signature verified.")
        self.next_server = self.server_list[decrypted_message["next"]]
        # if self.next_server:
        #     print(f"[Server {self.server_id}] Forwarding message to {self.next_server.server_id}")
        #     self.next_server.receive_message(message, sender_id, use_tls=use_tls)
        # else:
        #     print(f"[Server {self.server_id}] Final destination reached.")
=======

        # TLS: קבצים קיימים? לוג בהתאם
        try:
            with open(TLS_CERT_PATH, "rb") as cert_file:
                self.cert = cert_file.read()
            with open(TLS_KEY_PATH, "rb") as key_file:
                self.key = key_file.read()
            logging.info(f"[Server {self.server_id}] TLS initialized (cert={TLS_CERT_PATH}, key={TLS_KEY_PATH})")
        except FileNotFoundError:
            logging.warning(f"[Server {self.server_id}] TLS files missing (expected: {TLS_CERT_PATH}, {TLS_KEY_PATH}). Continuing without TLS.")
            self.cert = self.key = None

    def receive_message(self, message, sender_id, use_tls=True):
        decrypted_message = crypto_utils.decrypt_hybrid(self.private_key[self.server_id], base64.b64decode(message))
        decrypted_message = json.loads(decrypted_message.decode('utf-8'))

        if not use_tls:
            logging.warning(f"[Server {self.server_id}] Rejected message from {sender_id}: No TLS.")
            return

        # שים לב לציטוטים כדי לא לשבור f-string
        logging.info(f"[Server {self.server_id}] Received message from {sender_id}: {decrypted_message['payload']}")

        self.next_server = self.server_list[decrypted_message["next"]]
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)

    def send_message(self, message, sender_id, use_tls=True):
        if not use_tls:
            return None
<<<<<<< HEAD

=======
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
