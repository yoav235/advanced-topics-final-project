import ssl
import socket

TLS_CERT_PATH = "tls/cert.pem"
TLS_KEY_PATH = "tls/key.pem"

def create_tls_context(server_side=True):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    return context

def wrap_tls_socket(sock, server_side=True):
    context = create_tls_context(server_side)
    return context.wrap_socket(sock, server_side=server_side)
