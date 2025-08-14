<<<<<<< HEAD
import ssl
import socket

TLS_CERT_PATH = "tls/cert.pem"
TLS_KEY_PATH = "tls/key.pem"

def create_tls_context(server_side=True):
=======
# import ssl
# import socket
#
# TLS_CERT_PATH = "tls/cert.pem"
# TLS_KEY_PATH = "tls/key.pem"
#
# def create_tls_context(server_side=True):
#     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
#     context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
#     return context
#
# def wrap_tls_socket(sock, server_side=True):
#     context = create_tls_context(server_side)
#     return context.wrap_socket(sock, server_side=server_side)

# server/mix_tls.py
import os
import ssl

TLS_DIR = os.environ.get("TLS_DIR", "tls")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", os.path.join(TLS_DIR, "cert.pem"))
TLS_KEY_PATH  = os.environ.get("TLS_KEY_PATH",  os.path.join(TLS_DIR, "key.pem"))

def create_tls_context(server_side: bool = True):
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    return context

<<<<<<< HEAD
def wrap_tls_socket(sock, server_side=True):
=======
def wrap_tls_socket(sock, server_side: bool = True):
>>>>>>> d0c2ba6 (feat: automatic TLS generation + server TLS startup check)
    context = create_tls_context(server_side)
    return context.wrap_socket(sock, server_side=server_side)
