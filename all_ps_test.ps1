# ==== all_ps_test.ps1 (all-in-one; no external .ps1 dependencies) ====
$ErrorActionPreference = "Stop"; Set-StrictMode -Version Latest

function Section($t){ Write-Host ("`n== {0} ==" -f $t) -ForegroundColor Cyan }
function Note($t){ Write-Host ("  -> {0}" -f $t) -ForegroundColor DarkGray }
function Ok($t){ Write-Host ("OK: {0}" -f $t) -ForegroundColor Green }
function PassMsg($title,$msg){ Write-Host ("PASS: {0}" -f $title) -ForegroundColor Green; Write-Host ("     ✔ {0}" -f $msg) -ForegroundColor Green }
function Warn($t){ Write-Host ("WARN: {0}" -f $t) -ForegroundColor Yellow }
function Fail($t){ Write-Host ("FAIL: {0}" -f $t) -ForegroundColor Red }

function Run-Cmd([string]$label, [string]$exe, [string[]]$argList){
  Section $label
  $tmpOut = [System.IO.Path]::GetTempFileName()
  $tmpErr = [System.IO.Path]::GetTempFileName()
  try {
    $p = Start-Process -FilePath $exe -ArgumentList $argList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
    $out = Get-Content $tmpOut -Raw
    $err = Get-Content $tmpErr -Raw
  } catch {
    $out = ""
    $err = $_.Exception.Message
    $p = [pscustomobject]@{ ExitCode = 1 }
  } finally { Remove-Item $tmpOut,$tmpErr -Force -ErrorAction SilentlyContinue }
  ($out -split "`r?`n" | Select-Object -First 120) | Out-Host
  if ($err) {
    Write-Host "[stderr] (first lines)" -ForegroundColor DarkGray
    ($err -split "`r?`n" | Select-Object -First 20) | Out-Host
  }
  return @{ code=$p.ExitCode; out=$out; err=$err }
}

# Run inline Python from project root (so `import server` works)
function Run-PyLines([string]$label, [string[]]$lines){
  $py = ".\.venv\Scripts\python.exe"
  $tmp = [System.IO.Path]::GetTempFileName().Replace(".tmp",".py")
  $prefix = @(
    "import sys, pathlib, os"
    "root = pathlib.Path(os.getcwd()).resolve()"
    "sys.path.insert(0, str(root))"
  )
  $all = $prefix + $lines
  $all | Set-Content -Path $tmp -Encoding UTF8
  try { return Run-Cmd $label $py @("-u", $tmp) }
  finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

# Helper: check OID presence on tls/cert.pem  (exit 0=HAS_OID, 1=NO_OID, 2=MISSING)
function Check-CertHasNope {
  $pyLocal = ".\.venv\Scripts\python.exe"
  $code = @(
    "from pathlib import Path"
    "from cryptography import x509"
    "from cryptography.x509.oid import ObjectIdentifier"
    "NOPE_OID = ObjectIdentifier('1.3.6.1.4.1.55555.1.1')"
    "cert = Path('tls/cert.pem')"
    "if not cert.exists(): print('MISSING'); raise SystemExit(2)"
    "c = x509.load_pem_x509_certificate(cert.read_bytes())"
    "try: _ = c.extensions.get_extension_for_oid(NOPE_OID); print('HAS_OID'); raise SystemExit(0)"
    "except Exception: print('NO_OID'); raise SystemExit(1)"
  )
  $tmp = "_check_oid_tmp.py"
  $code | Set-Content -Path $tmp -Encoding UTF8
  & $pyLocal -u $tmp | Out-Host
  $rc = $LASTEXITCODE
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  return $rc
}

function Pause-At-End{ Write-Host ""; Write-Host "Done. Press ENTER to continue..." -ForegroundColor Yellow; Read-Host | Out-Null }

# --- sanity: must run in project root ---
$need = @("requirements.txt","server","init_tls.py","init_nope.py","simulate.py","nope-verifier.py")
$missing = @(); foreach($n in $need){ if(-not (Test-Path $n)){ $missing += $n } }
if($missing.Count -gt 0){ Fail ("Please cd into the project root. Missing: " + ($missing -join ", ")); Pause-At-End; return }

# --- env & venv ---
Section "Environment (venv + base env)"
Write-Host ("OS: " + [System.Environment]::OSVersion.VersionString)
Write-Host ("PowerShell: " + $PSVersionTable.PSVersion)
$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Note "Creating venv (.venv)"; py -3 -m venv .venv }
& $py -m ensurepip | Out-Null
try {
  if (Test-Path ".\requirements.txt") {
    & $py -m pip install -q --upgrade pip setuptools wheel
    & $py -m pip install -q -r .\requirements.txt
  } else {
    & $py -m pip install -q --upgrade pip setuptools wheel cryptography pytest
  }
  Ok "Python deps ensured"
} catch { Warn "pip install issue (continuing): $($_.Exception.Message)" }
$env:PYTHONIOENCODING = "utf-8"
$env:NOPE_LOG_LEVEL  = "DEBUG"
$env:NOPE_ZK_CHECK   = "0"
$env:NOPE_ZK_ENFORCE = "0"
$env:NOPE_SKIP_INIT  = ""

# --- Step 1: TLS ---
$r1 = Run-Cmd "Init TLS (generate or reuse cert.pem/key.pem)" $py @("-u",".\init_tls.py")
if($r1.code -eq 0){ PassMsg "TLS init" "יש לנו cert.pem/key.pem תקינים - שכבת TLS זמינה לבדיקות" } else { Fail "TLS init failed" }

# --- Step 2: NOPE tokens ---
$r2 = Run-Cmd "Init NOPE tokens (bind to TLS key)" $py @("-u",".\init_nope.py")
if($r2.code -eq 0){ PassMsg "NOPE tokens init" "טוקני NOPE נוצרו/עודכנו ונקשרו למפתח ה-TLS - זהות מפתח↔דומיין נאכפת" } else { Fail "NOPE tokens init failed" }

# --- Step 3: Artifacts ---
Section "Artifacts (TLS files and tokens present?)"
Get-ChildItem -Force .\tls -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table
Write-Host ""
Get-ChildItem -Force .\nope\tokens -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table
Ok "Artifacts listed"

# --- Step 4: Inline smoke (TLS+NOPE) using mixnet_tls_transport ---
$smokeLines = @(
  "import threading, time, sys"
  "from server.mixnet_tls_transport import server_once, client_request"
  "def handler(b: bytes) -> bytes: return b'ACK:' + b"
  "PORT = 9551"
  "thr = threading.Thread(target=lambda: server_once(('127.0.0.1', PORT), expected_peer_id=None, expected_domain=None, handle_request=handler, request_client_cert=False), daemon=True)"
  "thr.start()"
  "time.sleep(0.2)"
  "try:"
  "    r = client_request(('127.0.0.1', PORT), expected_peer_id='S1', expected_domain='mix1.local', payload=b'hello', present_client_cert=False)"
  "    print('RESPONSE:', r)"
  "    sys.exit(0)"
  "except Exception as e:"
  "    print('ERROR:', e); sys.exit(1)"
)
$r4 = Run-PyLines "Inline smoke: client NOPE->S1@mix1.local" $smokeLines
if($r4.code -eq 0){ PassMsg "TLS+NOPE handshake & echo" "הלקוח אימת NOPE מול השרת והעברנו הודעה (ACK) - שרשרת TLS→NOPE→אפליקציה תקינה" } else { Fail "Inline TLS+NOPE smoke failed" }

# --- Step 5: Realtime baseline (self-contained) -> run simulate.py once ---
$r5 = Run-Cmd "Realtime baseline (simulate.py)" $py @("-u",".\simulate.py")
if($r5.code -eq 0){ PassMsg "Realtime baseline" "מסלול end-to-end של המיקסנט עובד תחת אכיפת NOPE (simulate.py)" } else { Fail "Realtime baseline failed" }

# --- Step 6: Realtime attacks (self-contained; no external ps1) ---
function Corrupt-Token([string]$sid){
  $tok = ".\nope\tokens\$sid.nope.json"
  if (!(Test-Path $tok)) { throw "Token not found: $tok" }
  $bak = "$tok.bak"; Copy-Item $tok $bak -Force
  $j = Get-Content $tok -Raw | ConvertFrom-Json
  $j.payload.pubkey_fingerprint = ("0"*64)
  $j | ConvertTo-Json -Depth 8 | Set-Content -Path $tok -Encoding UTF8
  return @{ tok=$tok; bak=$bak }
}
function Restore-Token($info){ if ($info -and (Test-Path $info.bak)) { Move-Item -Force $info.bak $info.tok } }

# Attack S2
$corS2 = $null
try {
  $corS2 = Corrupt-Token "S2"
  $atkS2 = Run-Cmd "Attack: corrupt S2 (expect DENY)" $py @("-u",".\simulate.py")
} finally { Restore-Token $corS2 }
# Attack S3
$corS3 = $null
try {
  $corS3 = Corrupt-Token "S3"
  $atkS3 = Run-Cmd "Attack: corrupt S3 (expect DENY)" $py @("-u",".\simulate.py")
} finally { Restore-Token $corS3 }

# Determine attack PASS based on denial lines (check stdout+stderr; allow both peer_id= and peer=)
$denS2 = ($atkS2.out + "`n" + $atkS2.err)
$denS3 = ($atkS3.out + "`n" + $atkS3.err)
$attacks_pass = ($denS2 -match 'DENY.*(peer_id=S2|peer=S2)') -and ($denS3 -match 'DENY.*(peer_id=S3|peer=S3)')
if($attacks_pass){
  PassMsg "Attack simulation (token corruption)" "ניסיונות התחזות באמצעות שינוי טוקן נחסמים - NOPE מגן על השרשרת"
} else {
  Fail "Realtime attacks did not behave as expected"
}

# --- Step 7: pytest ---
$r8 = Run-Cmd "pytest -q (if any tests)" $py @("-m","pytest","-q")
if($r8.code -eq 0){ PassMsg "pytest" "בדיקות היחידה/רגרסיה עברו - התנהגות המערכת יציבה ושחזורית" } else { Fail "pytest reported failures" }

# --- Step 8: ZK verifier (soft/enforce) + OID checks ---
$r9a = Run-Cmd "ZK verifier (soft) on current cert" $py @("-u",".\nope-verifier.py",".\tls\cert.pem")
if($r9a.code -eq 0){ PassMsg "ZK (soft) on current cert" "ה-OID/הוכחה תקינים במצב מידע - תאימות לדרישות ZK (ללא אכיפה)" } else { Warn "ZK soft => informational FAIL (not blocking)" }

$env:FORCE_REGEN_TLS = "1"; $env:NOPE_ZK_CHECK="0"; $env:NOPE_ZK_ENFORCE="0"
Run-Cmd "Regenerate PLAIN TLS cert (no OID)" $py @("-u",".\init_tls.py") | Out-Null
Section "Check TLS cert OID state (expect NO_OID)"; $null = Check-CertHasNope
$r9b = Run-Cmd "ZK verifier --enforce on PLAIN TLS (should FAIL)" $py @("-u",".\nope-verifier.py",".\tls\cert.pem","--enforce")
if($r9b.code -ne 0){ PassMsg "ZK enforce on plain TLS" "ללא OID - האכיפה נכשלת כמצופה; תעודה בלי הוכחת NOPE נדחית" } else { Fail "ZK enforce unexpectedly passed on plain TLS" }

$env:FORCE_REGEN_TLS = "1"; $env:NOPE_ZK_CHECK="1"; $env:NOPE_ZK_ENFORCE="1"
Run-Cmd "Regenerate TLS WITH NOPE OID" $py @("-u",".\init_tls.py") | Out-Null
Section "Check TLS cert OID state (expect HAS_OID)"; $null = Check-CertHasNope
$r9c = Run-Cmd "ZK verifier --enforce on TLS with OID (should PASS)" $py @("-u",".\nope-verifier.py",".\tls\cert.pem","--enforce")
if($r9c.code -eq 0){ PassMsg "ZK enforce with OID" "עם הוכחה/OID - האכיפה עוברת; עומדים בדרישות ZK ההרחבתיות" } else { Fail "ZK enforce failed despite OID" }

# --- Step 9: Negative - expired tokens ---
Section "Negative: token freshness (expire tokens -> expect DENY)"
$env:NOPE_ZK_CHECK="0"; $env:NOPE_ZK_ENFORCE="0"; $env:NOPE_TOKEN_MAX_AGE_SEC="1"
Run-Cmd "Re-init TLS (plain ok)" $py @("-u",".\init_tls.py") | Out-Null
Run-Cmd "Re-init NOPE tokens (fresh ts)" $py @("-u",".\init_nope.py") | Out-Null
Write-Host "Sleeping 2s to expire tokens..."; Start-Sleep -Seconds 2
$r10 = Run-PyLines "Inline negative: expired tokens => should DENY" $smokeLines
if($r10.code -ne 0){ PassMsg "Expired tokens denied" "טוקנים שפג תוקפם נחסמים - אוכפים טריות ו-rekey" } else { Fail "Expired tokens were unexpectedly accepted" }

# --- Step 10: Negative - domain tamper ---
Section "Negative: domain tamper (S1 token domain -> expect DENY)"
$tokS1 = Join-Path (Get-Location) "nope\tokens\S1.nope.json"
if (Test-Path $tokS1) {
  $bakS1 = "$tokS1.bak"; Copy-Item $tokS1 $bakS1 -Force
  try {
    $j = Get-Content $tokS1 -Raw | ConvertFrom-Json
    $j.payload.domain = "evil.local"
    $j | ConvertTo-Json -Depth 8 | Set-Content -Path $tokS1 -Encoding UTF8
    $r11 = Run-PyLines "Inline negative: domain tamper => should DENY" $smokeLines
  } finally { Move-Item -Force $bakS1 $tokS1 }
} else {
  $r11 = @{ code=0; out="(skipped: S1 token not found)"; err="" }
}
if($r11.out -match 'skipped'){ Warn "Domain tamper => N/A (S1 token missing?)" }
elseif($r11.code -ne 0){ PassMsg "Domain binding enforced" "טוקן עם דומיין שונה נחסם - קישור זהות↔דומיין נאכף" } else { Fail "Domain-tampered token was unexpectedly accepted" }

# --- Summary rollup ---
Section "Summary"
function Mark-Pos($code){ if($null -eq $code){"N/A"} elseif($code -eq 0){"PASS"}else{"FAIL($code)"} }
function Mark-Neg($code){ if($null -eq $code){"N/A"} elseif($code -ne 0){"PASS"}else{"FAIL(should deny)"} }

$summary = [ordered]@{
  "init_tls (positive)"                          = Mark-Pos $r1.code
  "init_nope (positive)"                         = Mark-Pos $r2.code
  "inline_smoke_tls_nope (positive)"             = Mark-Pos $r4.code
  "realtime_baseline_simulate (positive)"        = Mark-Pos $r5.code
  "realtime_attacks_token_corruption (negative)" = if($attacks_pass){"PASS"}else{"FAIL(1)"}
  "pytest (positive)"                            = Mark-Pos $r8.code
  "zk_enforce_plain_tls_should_fail (negative)"  = if($r9b.code -ne 0){"PASS"}else{"FAIL(should deny)"}
  "zk_enforce_with_oid_should_pass (positive)"   = Mark-Pos $r9c.code
  "expired_tokens_should_deny (negative)"        = Mark-Neg $r10.code
  "domain_tamper_should_deny (negative)"         = if($r11.out -match 'skipped'){"N/A"} else { Mark-Neg $r11.code }
}
foreach($k in $summary.Keys){
  $v = $summary[$k]
  if ($v -like "PASS") { Ok "$k => $v" }
  elseif ($v -like "N/A") { Warn "$k => $v" }
  else { Fail "$k => $v" }
}
$vals=@($summary.Values)
$failCount=($vals|?{$_ -like "FAIL*"}|Measure-Object).Count
$passCount=($vals|?{$_ -eq "PASS"}|Measure-Object).Count
$naCount=($vals|?{$_ -eq "N/A"}|Measure-Object).Count
Write-Host ("Totals => PASS: {0} | FAIL: {1} | N/A: {2}" -f $passCount,$failCount,$naCount) -ForegroundColor DarkGray
if ($failCount -gt 0) { Warn ("Overall result: FAIL (" + $failCount + " failing checks)") } else { PassMsg "Overall result" "כל הבדיקות עברו במצב המצופה - הפרויקט עומד בדרישות" }

Pause-At-End
# ==== end ====
