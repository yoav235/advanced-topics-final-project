class MixServer:
    def __init__(self, server_id, next_server=None):
        self.server_id = server_id
        self.next_server = next_server
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
        if not use_tls:
            print(f"[Server {self.server_id}] ❌ Rejected message from {sender_id}: No TLS.")
            return

        print(f"[Server {self.server_id}] Received message from {sender_id}: {message}")

        from server.nope_utils import verify_nope_signature
        if not verify_nope_signature(message, sender_id):
            print(f"[Server {self.server_id}] ❌ Invalid NOPE signature! Message dropped.")
            return

        print(f"[{sender_id}] ✅ NOPE signature verified.")

        if self.next_server:
            print(f"[Server {self.server_id}] Forwarding message to {self.next_server.server_id}")
            self.next_server.receive_message(message, sender_id, use_tls=use_tls)
        else:
            print(f"[Server {self.server_id}] Final destination reached.")
