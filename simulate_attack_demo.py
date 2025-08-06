from client.client import Client
from server.server import MixServer

NUM_CLIENTS = 2
NUM_SERVERS = 3

class MaliciousClient(Client):
    def send_message(self, message):
        fake_sender_id = "C999"
        signed_message = f"{message}::SIGNED_BY_{fake_sender_id}"
        print(f"[Malicious {self.client_id}] Sending forged message to {self.entry_server}: {signed_message}")
        self.entry_server.receive_message(signed_message, self.client_id)

def main():
    servers = [MixServer(f"S{i}") for i in range(1, NUM_SERVERS + 1)]
    for i in range(NUM_SERVERS - 1):
        servers[i].next_server = servers[i + 1]

    clients = [Client(f"C{i}", entry_server=servers[0]) for i in range(1, NUM_CLIENTS + 1)]
    attacker = MaliciousClient("C_mal", entry_server=servers[0])

    for client in clients:
        client.send_message("Hello, Mixnet!")

    attacker.send_message("I am legit!")

if __name__ == "__main__":
    main()
