# test_mixnet.py
import os
import sys
import json
import subprocess
from pathlib import Path

def _find_project_root() -> Path:
    """
    Robustly locate the project root by walking up until we see hallmark files.
    Falls back to the directory containing this test file.
    """
    p = Path(__file__).resolve().parent
    hallmarks = {"simulate.py", "init_tls.py", "init_nope.py"}
    for _ in range(6):
        if all((p / h).exists() for h in hallmarks):
            return p
        p = p.parent
    return Path(__file__).resolve().parent  # fallback

ROOT = _find_project_root()
TOK_DIR = ROOT / "nope" / "tokens"

def _run(script_relpath: str):
    """
    Run a project script in a subprocess and return (code, combined_output).
    """
    env = os.environ.copy()
    env["NOPE_LOG_LEVEL"] = "DEBUG"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-u", str(ROOT / script_relpath)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

def _ensure_init():
    _run("init_tls.py")
    _run("init_nope.py")

def _corrupt_token(server_id: str):
    """
    Corrupt the NOPE token for a server by zeroing the fingerprint.
    Returns (path, original_text) so caller can restore in finally.
    """
    p = TOK_DIR / f"{server_id}.nope.json"
    original = p.read_text(encoding="utf-8")
    obj = json.loads(original)
    obj["payload"]["pubkey_fingerprint"] = "0" * 64
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return p, original

def _restore_token(path: Path, original_text: str):
    path.write_text(original_text, encoding="utf-8")

def test_baseline_no_tls_denials():
    _ensure_init()
    code, out = _run("simulate.py")
    assert code == 0, f"simulate.py exit={code}\n--- output ---\n{out}"
    assert "TLS denied for S2" not in out
    assert "TLS denied for S3" not in out

def test_attack_corrupt_S2_causes_denial():
    _ensure_init()
    p, bak = _corrupt_token("S2")
    try:
        code, out = _run("simulate.py")
        assert "TLS denied for S2" in out
    finally:
        _restore_token(p, bak)

def test_attack_corrupt_S3_causes_denial():
    _ensure_init()
    p, bak = _corrupt_token("S3")
    try:
        code, out = _run("simulate.py")
        assert "TLS denied for S3" in out
    finally:
        _restore_token(p, bak)
