# run_mixnet_demo.ps1 — offline-friendly
$ErrorActionPreference = "Stop"

# ---- locate project + venv python ----
$proj   = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $proj
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"
if (!(Test-Path $venvPy)) {
  Write-Host "Creating venv..." -ForegroundColor Cyan
  py -3 -m venv .venv
}

# ---- optional deps (skip when offline or NOPE_SKIP_PIP=1) ----
$skipPip = ($env:NOPE_SKIP_PIP -eq "1")
if (-not $skipPip) {
  try {
    & $venvPy -m ensurepip | Out-Null
    & $venvPy -m pip install -q --upgrade pip
    if (Test-Path ".\requirements.txt") {
      # נסיון יחיד בלי להפיל את הסקריפט אם אין רשת
      & $venvPy -m pip install -q -r .\requirements.txt
    }
  } catch {
    Write-Warning "pip install skipped (offline?): $($_.Exception.Message)"
  }
} else {
  Write-Host "Skipping pip (NOPE_SKIP_PIP=1)" -ForegroundColor Yellow
}

# ---- NOPE: בלי ZK ----
$env:NOPE_ZK_CHECK   = "0"
$env:NOPE_ZK_ENFORCE = "0"

# ---- init TLS + tokens ----
& $venvPy .\init_tls.py
& $venvPy .\init_nope.py

# ---- demo run ----
# אם יש simulate.py נשתמש בו; אחרת נעשה smoke TLS קצר שמוודא NOPE
if (Test-Path ".\simulate.py") {
  & $venvPy .\simulate.py
  exit $LASTEXITCODE
} else {
  $py = @'
import ssl, socket, threading, time, sys, pathlib
from server.nope_enforcer import verify_peer_on_socket

ROOT = pathlib.Path(__file__).resolve().parent
CERT = ROOT / "tls" / "cert.pem"
KEY  = ROOT / "tls" / "key.pem"
TOK  = ROOT / "nope" / "tokens" / "S1.nope.json"
for p in (CERT, KEY, TOK):
    assert p.exists(), f"missing {p}"

HOST, PORT = "127.0.0.1", 9443
def serve_once():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1)
        c, _ = s.accept()
        with ctx.wrap_socket(c, server_side=True) as ss:
            _ = ss.recv(1); ss.sendall(b"OK")

t = threading.Thread(target=serve_once, daemon=True); t.start(); time.sleep(0.2)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
with socket.create_connection((HOST, PORT), timeout=3) as s:
    with ctx.wrap_socket(s, server_hostname=HOST) as ss:
        ok = verify_peer_on_socket(ss, server_id="S1", mode="raise")
        ss.sendall(b"x"); _ = ss.recv(2)
        print("✅ MIXNET NOPE/TLS SMOKE: PASS" if ok else "❌ SMOKE: FAIL")
        sys.exit(0 if ok else 2)
'@
  $runner = Join-Path $proj "_nope_tls_smoke_tmp.py"
  Set-Content -Path $runner -Value $py -Encoding UTF8
  & $venvPy $runner
  $code = $LASTEXITCODE
  Remove-Item $runner -Force -ErrorAction SilentlyContinue
  exit $code
}
