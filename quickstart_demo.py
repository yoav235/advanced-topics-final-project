# quickstart_demo.py
import argparse, threading, time, sys
from server.mixnet_tls_transport import server_once, client_request

def main():
    ap = argparse.ArgumentParser(description="Tiny NOPE/TLS demo: one server_once + one client_request")
    ap.add_argument("--port", type=int, default=9551, help="TCP port to listen/connect (default: 9551)")
    ap.add_argument("--peer", default="S1", help="Expected peer_id on client side (default: S1)")
    ap.add_argument("--domain", default="mix1.local", help="Expected domain on client side (default: mix1.local)")
    ap.add_argument("--present-client-cert", action="store_true",
                    help="Present a client certificate (default: off)")
    args = ap.parse_args()

    def handler(b: bytes) -> bytes:
        return b"ACK:" + b

    # start single-shot server in background
    thr = threading.Thread(
        target=lambda: server_once(("127.0.0.1", args.port),
                                   expected_peer_id=None,
                                   expected_domain=None,
                                   handle_request=handler,
                                   request_client_cert=False),
        daemon=True)
    thr.start()
    time.sleep(0.2)

    try:
        resp = client_request(("127.0.0.1", args.port),
                              expected_peer_id=args.peer,
                              expected_domain=args.domain,
                              payload=b"hello",
                              present_client_cert=args.present_client_cert)
        print(f"OK: response={resp!r}")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
