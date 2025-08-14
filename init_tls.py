# init_tls.py
import os
from generate_tls import generate_tls_cert

def main():
    tls_dir = os.environ.get("TLS_DIR", "tls")
    cert = os.path.join(tls_dir, "cert.pem")
    key  = os.path.join(tls_dir, "key.pem")

    os.makedirs(tls_dir, exist_ok=True)

    if os.path.exists(cert) and os.path.exists(key):
        print(f"[init_tls] TLS already present at '{tls_dir}' -> cert.pem & key.pem exist")
        return

    print(f"[init_tls] TLS missing in '{tls_dir}' -> generating...")
    generate_tls_cert(tls_dir)

if __name__ == "__main__":
    main()
