param(
  [string]$PeerId = "S1",
  [string]$Domain = "mix1.local"
)

# ----------------- Setup (ASCII only) -----------------
$here = $PSScriptRoot; if (-not $here) { $here = (Get-Location).Path }
Set-Location $here

function Section($t){ Write-Host ("`n== {0} ==" -f $t) -ForegroundColor Cyan }
function Note($t){ Write-Host ("  -> {0}" -f $t) -ForegroundColor DarkGray }
function Pass($t){ Write-Host ("PASS: {0}" -f $t) -ForegroundColor Green }
function Fail($t){ Write-Host ("FAIL: {0}" -f $t) -ForegroundColor Red }

# pick python like you ran manually
$py = Join-Path $here ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

# env like your manual runs
if (-not $env:NOPE_LOG_LEVEL) { $env:NOPE_LOG_LEVEL = "DEBUG" }
$env:PYTHONIOENCODING = "utf-8"

# sanity
if (-not (Test-Path ".\tls_strict_smoke.py")) { Fail "tls_strict_smoke.py not found"; exit 2 }
if (-not (Test-Path ".\tls\cert.pem") -or -not (Test-Path ".\tls\key.pem")) { Fail "missing tls/cert.pem or tls/key.pem"; exit 2 }
if (-not (Test-Path ".\nope\tokens")) { Fail "missing nope/tokens directory"; exit 2 }

# small helper
function New-FreePort { Get-Random -Minimum 30000 -Maximum 39999 }

# ----------------- Test 1: TLS only -----------------
Section "Test 1: TLS only (no mTLS, NOPE not enforced)"
Note "WHAT THIS CHECKS: Basic TLS with self-signed server cert + framing echo."

$port1 = New-FreePort
$out1 = & $py .\tls_strict_smoke.py --mode tls-only --port $port1 2>&1
$code1 = $LASTEXITCODE
$out1 | Out-Host
if ($code1 -eq 0 -and ($out1 -match "ACK:hello")) {
  Pass "TLS-only handshake+echo"
} else {
  Fail ("TLS-only failed (exit={0})" -f $code1)
}

# ----------------- Test 2: TLS + NOPE (good) -----------------
Section "Test 2: TLS + NOPE (expected OK)"
Note ("WHAT THIS CHECKS: After TLS, client verifies server NOPE token (peer-id={0}, domain={1})." -f $PeerId, $Domain)

$port2 = New-FreePort
$out2 = & $py .\tls_strict_smoke.py --mode tls+nope --peer-id $PeerId --domain $Domain --port $port2 2>&1
$code2 = $LASTEXITCODE
$out2 | Out-Host
if ($code2 -eq 0 -and ($out2 -match "ACK:hello")) {
  Pass "TLS+NOPE good peer/domain"
} else {
  Fail ("TLS+NOPE (good) failed (exit={0})" -f $code2)
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host ("TLS only  : " + ($(if($out1 -match "ACK:hello"){"OK"}else{"FAIL"})))
Write-Host ("TLS+NOPE  : " + ($(if($out2 -match "ACK:hello"){"OK"}else{"FAIL"})))
