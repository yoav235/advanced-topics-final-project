# tls_strict_smoke.py
from __future__ import annotations
import argparse, logging, threading, time, socket, ssl
from typing import Optional, Tuple
from server.tls_runtime import make_server_context, make_client_context, accept_once_with_nope, connect_with_nope, listen_tcp
from server.mixnet_tls_transport import send_msg, recv_msg

log = logging.getLogger("tls_nope_smoke")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def _make_server_ctx() -> ssl.SSLContext:
    # no mTLS; identity is handled by NOPE after the handshake
    return make_server_context(request_client_cert=False)

def _make_client_ctx() -> ssl.SSLContext:
    # no mTLS
    return make_client_context(present_client_cert=False)

# ---------- TLS ONLY ----------
def server_tls_only(bind: Tuple[str,int]) -> None:
    ctx = _make_server_ctx()
    srv = listen_tcp(bind)
    try:
        conn, _ = srv.accept()
        ssock = ctx.wrap_socket(conn, server_side=True)
        try:
            data = recv_msg(ssock)
            send_msg(ssock, b"ACK:" + data)
        finally:
            ssock.close()
    finally:
        srv.close()

def client_tls_only(remote: Tuple[str,int]) -> bytes:
    ctx = _make_client_ctx()
    s = socket.create_connection(remote, timeout=5.0)
    ss = ctx.wrap_socket(s, server_hostname=remote[0] if ctx.check_hostname else None)
    try:
        send_msg(ss, b"hello")
        return recv_msg(ss)
    finally:
        ss.close()

# ---------- TLS + NOPE ----------
def server_tls_plus_nope(bind: Tuple[str,int], expected_peer_id: Optional[str], expected_domain: Optional[str]) -> None:
    ctx = _make_server_ctx()
    ssock, _ = accept_once_with_nope(
        bind, ctx,
        expected_peer_id=expected_peer_id,  # usually None (do not enforce on client)
        expected_domain=expected_domain,
        enforce=bool(expected_peer_id),
        timeout=10.0
    )
    try:
        data = recv_msg(ssock)
        send_msg(ssock, b"ACK:" + data)
    finally:
        ssock.close()

def client_tls_plus_nope(remote: Tuple[str,int], expected_peer_id: str, expected_domain: str) -> bytes:
    ctx = _make_client_ctx()
    ss = connect_with_nope(
        remote, ctx,
        expected_peer_id=expected_peer_id,
        expected_domain=expected_domain,
        enforce=True,
        timeout=5.0
    )
    try:
        send_msg(ss, b"hello")
        return recv_msg(ss)
    finally:
        ss.close()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["tls-only","tls+nope"], default="tls-only")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9555)
    ap.add_argument("--peer-id", default=None)
    ap.add_argument("--domain", default="mix1.local")
    args = ap.parse_args()

    bind = (args.host, args.port)
    remote = (args.host, args.port)

    if args.mode == "tls-only":
        t = threading.Thread(target=server_tls_only, args=(bind,), daemon=True)
        t.start()
        time.sleep(0.2)
        resp = client_tls_only(remote)
        print(resp)
        t.join(0.5)
        return 0

    if not args.peer_id:
        print("tls+nope requires --peer-id", flush=True)
        return 2

    t = threading.Thread(target=server_tls_plus_nope, args=(bind, None, args.domain), daemon=True)
    t.start()
    time.sleep(0.2)
    resp = client_tls_plus_nope(remote, expected_peer_id=args.peer_id, expected_domain=args.domain)
    print(resp)
    t.join(0.5)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
