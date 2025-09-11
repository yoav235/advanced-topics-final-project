# test_all.py
# Full pytest suite: simulate baseline + attacks, ZK soft/enforce, inline smoke (expired/domain)
import os
import re
import sys
import json
import time
import uuid
import subprocess
from pathlib import Path

# ---------------------------
# Project-root & env helpers
# ---------------------------
def _find_project_root() -> Path:
    p = Path(__file__).resolve().parent
    hallmarks = {"simulate.py", "init_tls.py", "init_nope.py"}
    for _ in range(6):
        if all((p / h).exists() for h in hallmarks):
            return p
        p = p.parent
    return Path(__file__).resolve().parent

ROOT = _find_project_root()
TOK_DIR = ROOT / "nope" / "tokens"

def _base_env(extra=None):
    env = os.environ.copy()
    env["NOPE_LOG_LEVEL"] = "DEBUG"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra:
        env.update(extra)
    return env

def _run_script(py_relpath: str, env=None):
    """Run project python file as a subprocess. Return (code, combined_out)."""
    proc = subprocess.run(
        [sys.executable, "-u", str(ROOT / py_relpath)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=_base_env(env),
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

def _run_inline_py(lines, env=None):
    """
    Create a temporary inline python file that ensures project root on sys.path,
    then run it as a subprocess. Return (code, combined_out).
    """
    name = f"_pytest_inline_{uuid.uuid4().hex}.py"
    path = ROOT / name
    prefix = [
        "import sys, pathlib, os, time",
        "root = pathlib.Path(__file__).resolve().parent",
        "sys.path.insert(0, str(root))",
    ]
    content = "\n".join(prefix + list(lines)) + "\n"
    path.write_text(content, encoding="utf-8")
    try:
        return _run_script(name, env=env)
    finally:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

# -----------------
# Project init I/O
# -----------------
def _ensure_init():
    _run_script("init_tls.py")
    _run_script("init_nope.py")

def _regen_tls_plain():
    code, out = _run_script("init_tls.py", env={"FORCE_REGEN_TLS": "1",
                                                "NOPE_ZK_CHECK": "0",
                                                "NOPE_ZK_ENFORCE": "0"})
    assert code == 0, out

def _regen_tls_with_oid():
    code, out = _run_script("init_tls.py", env={"FORCE_REGEN_TLS": "1",
                                                "NOPE_ZK_CHECK": "1",
                                                "NOPE_ZK_ENFORCE": "1"})
    assert code == 0, out

# -------------------------
# Token tamper helpers
# -------------------------
def _corrupt_token(server_id: str):
    """
    Corrupt the NOPE token by zeroing fingerprint. Return (path, orig_text).
    """
    p = TOK_DIR / f"{server_id}.nope.json"
    original = p.read_text(encoding="utf-8")
    obj = json.loads(original)
    obj["payload"]["pubkey_fingerprint"] = "0" * 64
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return p, original

def _tamper_domain(server_id: str, new_domain: str):
    p = TOK_DIR / f"{server_id}.nope.json"
    original = p.read_text(encoding="utf-8")
    obj = json.loads(original)
    obj["payload"]["domain"] = new_domain
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return p, original

def _restore_token(path: Path, original_text: str):
    path.write_text(original_text, encoding="utf-8")

# ----------------------------
# Log parsing for DENY lines
# ----------------------------
_DENY_RE_TMPL = r"\bDENY\b.*\b(peer_id|peer)={sid}\b"

def _denied_for(sid: str, out: str) -> bool:
    # Accept both legacy and new formats
    if f"TLS denied for {sid}" in out:
        return True
    if re.search(_DENY_RE_TMPL.format(sid=re.escape(sid)), out):
        return True
    return False

# ------------
# The tests
# ------------
def test_00_baseline_simulate_ok():
    _ensure_init()
    code, out = _run_script("simulate.py")
    assert code == 0, f"simulate.py exit={code}\n--- output ---\n{out}"
    # Must NOT deny S2/S3 on clean run
    assert not _denied_for("S2", out), out
    assert not _denied_for("S3", out), out

def test_01_attack_corrupt_S2_denied():
    _ensure_init()
    p, bak = _corrupt_token("S2")
    try:
        code, out = _run_script("simulate.py")
        # Some runners keep exit code 0 but log DENY; assert via logs
        assert _denied_for("S2", out), out
    finally:
        _restore_token(p, bak)

def test_02_attack_corrupt_S3_denied():
    _ensure_init()
    p, bak = _corrupt_token("S3")
    try:
        code, out = _run_script("simulate.py")
        assert _denied_for("S3", out), out
    finally:
        _restore_token(p, bak)

def test_03_expired_tokens_denied_inline_smoke():
    # Short token lifetime -> reinit -> sleep -> inline client should be denied
    env = {
        "NOPE_ZK_CHECK": "0",
        "NOPE_ZK_ENFORCE": "0",
        "NOPE_TOKEN_MAX_AGE_SEC": "1",
    }
    _run_script("init_tls.py", env=env)
    _run_script("init_nope.py", env=env)
    time.sleep(2)  # expire

    lines = [
        "from server.mixnet_tls_transport import server_once, client_request",
        "import threading, time, sys",
        "def handler(b: bytes) -> bytes: return b'ACK:' + b",
        "PORT = 9555",
        "thr = threading.Thread(target=lambda: server_once(('127.0.0.1', PORT), expected_peer_id=None, expected_domain=None, handle_request=handler, request_client_cert=False), daemon=True)",
        "thr.start(); time.sleep(0.2)",
        "try:",
        "    r = client_request(('127.0.0.1', PORT), expected_peer_id='S1', expected_domain='mix1.local', payload=b'hello', present_client_cert=False)",
        "    print('UNEXPECTED_OK:', r); sys.exit(0)",
        "except Exception as e:",
        "    print('EXPECTED_DENY:', e); sys.exit(1)",
    ]
    code, out = _run_inline_py(lines, env=env)
    # We expect a DENY (non-zero). Some envs might flip exit code, so also look for 'DENY' text:
    denied = (code != 0) or ("DENY" in out or "nope-verify-failed" in out or "EXPECTED_DENY" in out)
    assert denied, out

def test_04_domain_tamper_denied_inline_smoke():
    _ensure_init()
    p, bak = _tamper_domain("S1", "evil.local")  # first hop token domain mismatch
    try:
        lines = [
            "from server.mixnet_tls_transport import server_once, client_request",
            "import threading, time, sys",
            "def handler(b: bytes) -> bytes: return b'ACK:' + b",
            "PORT = 9556",
            "thr = threading.Thread(target=lambda: server_once(('127.0.0.1', PORT), expected_peer_id=None, expected_domain=None, handle_request=handler, request_client_cert=False), daemon=True)",
            "thr.start(); time.sleep(0.2)",
            "try:",
            "    r = client_request(('127.0.0.1', PORT), expected_peer_id='S1', expected_domain='mix1.local', payload=b'hello', present_client_cert=False)",
            "    print('UNEXPECTED_OK:', r); sys.exit(0)",
            "except Exception as e:",
            "    print('EXPECTED_DENY:', e); sys.exit(1)",
        ]
        code, out = _run_inline_py(lines)
        denied = (code != 0) or ("DENY" in out or "nope-verify-failed" in out or "EXPECTED_DENY" in out)
        assert denied, out
    finally:
        _restore_token(p, bak)

def test_05_zk_enforce_plain_fails_and_oid_passes():
    # Plain TLS => enforce must fail
    _regen_tls_plain()
    code, out = _run_script("nope-verifier.py", env={})  # soft check first; may fail informationally
    # enforce should fail without OID
    code2, out2 = _run_script("nope-verifier.py", env={})
    # run enforce explicitly
    code2, out2 = _run_script("nope-verifier.py", env={})
    code2, out2 = _run_script("nope-verifier.py", env={})
    code2, out2 = _run_script("nope-verifier.py", env={})
    code2, out2 = subprocess.run(
        [sys.executable, "-u", str(ROOT / "nope-verifier.py"), str(ROOT / "tls" / "cert.pem"), "--enforce"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=_base_env({}),
    ).returncode, ""
    assert code2 != 0, "ZK enforce unexpectedly passed on plain TLS"

    # TLS with OID => enforce must pass
    _regen_tls_with_oid()
    code3, out3 = subprocess.run(
        [sys.executable, "-u", str(ROOT / "nope-verifier.py"), str(ROOT / "tls" / "cert.pem"), "--enforce"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=_base_env({}),
    ).returncode, ""
    assert code3 == 0, "ZK enforce failed despite OID"

def test_06_transport_smoke_ok():
    # Positive sanity: server_once + client_request should ACK when NOPE matches
    _ensure_init()
    lines = [
        "from server.mixnet_tls_transport import server_once, client_request",
        "import threading, time, sys",
        "def handler(b: bytes) -> bytes: return b'ACK:' + b",
        "PORT = 9557",
        "thr = threading.Thread(target=lambda: server_once(('127.0.0.1', PORT), expected_peer_id=None, expected_domain=None, handle_request=handler, request_client_cert=False), daemon=True)",
        "thr.start(); time.sleep(0.2)",
        "r = client_request(('127.0.0.1', PORT), expected_peer_id='S1', expected_domain='mix1.local', payload=b'hello', present_client_cert=False)",
        "print('RESPONSE:', r); sys.exit(0)",
    ]
    code, out = _run_inline_py(lines)
    assert code == 0 and "ACK:hello" in out, out
