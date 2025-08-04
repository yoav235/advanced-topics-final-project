from client.client import MixClient
from server.server import MixServer

NUM_CLIENTS = 2
NUM_SERVERS = 3

def main():
    # יצירת שרתים עם שמות S1, S2, ...
    servers = [MixServer(f"S{i}") for i in range(1, NUM_SERVERS + 1)]

    # קישור בין השרתים (רשת ליניארית)
    for i in range(NUM_SERVERS - 1):
        servers[i].next_server = servers[i + 1]

    # יצירת קליינטים עם שמות C1, C2, ... והגדרת השרת הראשון כ-entry point
    clients = [MixClient(f"C{i}", entry_server=servers[0]) for i in range(1, NUM_CLIENTS + 1)]

    # כל קליינט שולח הודעה לשרת הכניסה
    for client in clients:
        client.send_message("Hello, Mixnet!")

if __name__ == "__main__":
    main()
