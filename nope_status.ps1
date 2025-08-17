# nope_status.ps1  —  מצב הפרויקט (ללא ZK): TLS ✔, טוקנים ✔, Smoke ✔

$ErrorActionPreference = "Stop"
$proj = "C:\Users\DELL\Desktop\advanced-topics-final-project-master"
Set-Location $proj

# Python מ־venv (ללא Activate)
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"
if (!(Test-Path $venvPy)) { py -3 -m venv .venv; $venvPy = Join-Path $proj ".venv\Scripts\python.exe" }
& $venvPy -m ensurepip | Out-Null
& $venvPy -m pip install -q --upgrade pip | Out-Null
if (Test-Path ".\requirements.txt") { & $venvPy -m pip install -q -r .\requirements.txt | Out-Null }

# נכבה ZK לגמרי
$env:NOPE_ZK_CHECK   = "0"
$env:NOPE_ZK_ENFORCE = "0"

# --- בדיקת TLS (קבצים קיימים) ---
$tlsOK = (Test-Path ".\tls\cert.pem") -and (Test-Path ".\tls\key.pem")
Write-Host ("TLS cert+key    : " + ($(if($tlsOK){"✅ PASS"}else{"❌ FAIL"})))

# --- בדיקת טוקנים S1/S2/S3 מול cert.pem ---
$tokPy = @'
from pathlib import Path
import json, sys
from cryptography import x509
from server.nope_utils import find_token_for_server, verify_nope_token_file

ROOT = Path(__file__).resolve().parent
certp = ROOT / "tls" / "cert.pem"
if not certp.exists():
    print("TOKENS: ❌ FAIL (missing tls/cert.pem)")
    sys.exit(2)
pub = x509.load_pem_x509_certificate(certp.read_bytes()).public_key()

def dom(tok, fb):
    try: return json.loads(Path(tok).read_text(encoding="utf-8")).get("payload",{}).get("domain", fb)
    except: return fb

ok_all = True
for sid in ("S1","S2","S3"):
    tok = find_token_for_server(sid)
    if not tok:
        print(f"{sid}: ❌ missing token")
        ok_all = False
        continue
    d = dom(tok, f"mix{sid[-1]}.local")
    ok = verify_nope_token_file(tok, sid, d, pub)
    print(f"{sid}: {'✅ OK' if ok else '❌ BAD'} (token={Path(tok).name}, domain={d})")
    ok_all &= ok

print("TOKENS:", "✅ PASS" if ok_all else "❌ FAIL")
sys.exit(0 if ok_all else 2)
'@
$tokTmp = Join-Path $proj "_tok_check.py"
Set-Content -Path $tokTmp -Value $tokPy -Encoding UTF8
& $venvPy $tokTmp
$tokCode = $LASTEXITCODE
Remove-Item $tokTmp -Force -ErrorAction SilentlyContinue

# --- Smoke: שרת TLS מקומי + לקוח עם verify_peer_on_socket('S1') ---
$smkPy = @'
import ssl, socket, threading, time, sys, pathlib
from server.nope_enforcer import verify_peer_on_socket

R = pathlib.Path(__file__).resolve().parent
if not (R/"tls"/"cert.pem").exists() or not (R/"tls"/"key.pem").exists() or not (R/"nope"/"tokens"/"S1.nope.json").exists():
    print("SMOKE: ❌ FAIL (missing tls or token)")
    sys.exit(2)

HOST, PORT = "127.0.0.1", 9443
def serve_once():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(R/"tls"/"cert.pem"), str(R/"tls"/"key.pem"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(1)
        c,_ = s.accept()
        with ctx.wrap_socket(c, server_side=True) as ss:
            _ = ss.recv(1); ss.sendall(b"OK")

t = threading.Thread(target=serve_once, daemon=True); t.start(); time.sleep(0.2)

try:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
    with socket.create_connection((HOST, PORT), timeout=3) as s:
        with c.wrap_socket(s, server_hostname=HOST) as ss:
            ok = verify_peer_on_socket(ss, server_id="S1", mode="raise")
            ss.sendall(b"x"); _ = ss.recv(2)
            print("SMOKE:", "✅ PASS" if ok else "❌ FAIL")
            sys.exit(0 if ok else 2)
except Exception as e:
    print("SMOKE: ❌ FAIL", e); sys.exit(2)
'@
$smkTmp = Join-Path $proj "_smoke.py"
Set-Content -Path $smkTmp -Value $smkPy -Encoding UTF8
& $venvPy $smkTmp
$smkCode = $LASTEXITCODE
Remove-Item $smkTmp -Force -ErrorAction SilentlyContinue

# --- סיכום קצר ---
Write-Host ("Summary          : " + ($(if($tlsOK -and ($tokCode -eq 0) -and ($smkCode -eq 0)){"✅ ALL GOOD"}else{"❌ CHECK FAILED"})))
if (-not $tlsOK)   { exit 2 }
if ($tokCode -ne 0){ exit 2 }
if ($smkCode -ne 0){ exit 2 }
exit 0
