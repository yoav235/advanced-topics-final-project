from client.client import Client
from server.server import MixServer

NUM_CLIENTS = 2
NUM_SERVERS = 3

def main():
    servers = [MixServer(f"S{i}") for i in range(1, NUM_SERVERS + 1)]

    for i in range(NUM_SERVERS - 1):
        servers[i].next_server = servers[i + 1]

    clients = [Client(f"C{i}", servers) for i in range(1, NUM_CLIENTS + 1)]

    for client in clients:
        client.send_message({"to": "C1", "message": "Hello, Mixnet!"})

if __name__ == "__main__":
    main()
