from __future__ import annotations
from pathlib import Path
import json
import sys
from cryptography import x509

# Import verifier
try:
    from server.nope_utils import verify_nope_token_file
except Exception as e:
    print("ERROR: could not import verify_nope_token_file from server/nope_utils.py:", e)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent
NOPE_DIR = ROOT / "nope"
TOK_DIR  = NOPE_DIR / "tokens"

TLS_CANDIDATES = [
    ROOT / "tls",
    ROOT / "server" / "tls",
]

def find_token_for_server(server_id: str) -> Path | None:
    p_json = TOK_DIR / f"{server_id}.nope.json"
    if p_json.exists():
        return p_json
    p_tok = TOK_DIR / f"{server_id}.tok"
    if p_tok.exists():
        return p_tok
    return None

def load_server_public_key(server_id: str):
    # Search order:
    #   tls/<SID>/cert.pem -> tls/cert.pem -> server/tls/<SID>/cert.pem -> server/tls/cert.pem
    candidates = []
    for base in TLS_CANDIDATES:
        candidates += [base / server_id / "cert.pem", base / "cert.pem"]
    for p in candidates:
        if p.exists():
            cert = x509.load_pem_x509_certificate(p.read_bytes())
            return cert.public_key(), p
    raise FileNotFoundError(f"TLS cert.pem for {server_id} not found in {TLS_CANDIDATES}")

def read_domain_from_json_token(token_path: Path) -> str | None:
    if token_path.suffix.lower() == ".json":
        try:
            obj = json.loads(token_path.read_text(encoding="utf-8"))
            return obj.get("payload", {}).get("domain")
        except Exception:
            return None
    return None

def check_tokens(server_ids=("S1", "S2", "S3")) -> bool:
    all_ok = True
    for sid in server_ids:
        token_path = find_token_for_server(sid)
        if not token_path:
            print(f"{sid}: MISSING token (nope/tokens/{sid}.nope.json or {sid}.tok)")
            all_ok = False
            continue
        try:
            pubkey, cert_path = load_server_public_key(sid)
        except Exception as e:
            print(f"{sid}: TLS issue - {e}")
            all_ok = False
            continue
        expected_domain = read_domain_from_json_token(token_path) or "mix.local"
        ok = verify_nope_token_file(str(token_path), sid, expected_domain, pubkey)
        mark = "[OK]" if ok else "[BAD]"
        print(f"{mark} {sid}: token={token_path.name}, domain={expected_domain}, cert={cert_path}")
        all_ok &= ok
    return all_ok

def main():
    print("=== NOPE tokens vs TLS check ===")
    ok = check_tokens(("S1", "S2", "S3"))
    print("Summary:", "OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
