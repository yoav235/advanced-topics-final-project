class MixClient:
    def __init__(self, client_id, entry_server):
        self.client_id = client_id
        self.entry_server = entry_server

    def send_message(self, message):
        # === שלב 1: חתימה מדומה של NOPE ===
        from server.nope_utils import sign_message_with_nope
        signed_message = sign_message_with_nope(message, self.client_id)

        # === שלב 2: הדפסת השליחה ===
        print(f"[Client {self.client_id}] Sending message to {self.entry_server}: {message}")

        # === שלב 3: שליחת ההודעה (חתומה) לשרת הראשון דרך TLS מדומה ===
        self.entry_server.receive_message(signed_message, self.client_id, use_tls=True)
