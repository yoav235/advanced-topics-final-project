# nope_attack_demo.ps1  -  דמו התקפה: דחיית TLS כש-NOPE לא תואם

$ErrorActionPreference = "Stop"

$proj   = "C:\Users\DELL\Desktop\advanced-topics-final-project-master"
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"

Set-Location $proj
$env:NOPE_SKIP_PIP = "1"   # לא מתקין חבילות שוב

# --- 1) ריצת בסיס (אמורה לעבור) ---
Write-Host "== Baseline run (should PASS) ==" -ForegroundColor Cyan
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mixnet_demo.ps1

# --- 2) פוגמים זמנית את S2.nope.json ---
$tok = Join-Path $proj "nope\tokens\S2.nope.json"
$bak = "$tok.bak"
Copy-Item $tok $bak -Force

# משנים fingerprint לערך בלתי-תקף (אפשר גם domain אם רוצים)
$json = Get-Content $tok -Raw | ConvertFrom-Json
$json.payload.pubkey_fingerprint = ("00" * 64)
$json | ConvertTo-Json -Depth 8 | Set-Content -Path $tok -Encoding UTF8

# --- 3) מריצים רק את הסימולציה כדי לראות דחייה ---
Write-Host "`n== Attack run (should show TLS denied / failed) ==" -ForegroundColor Cyan
# מריצים ישירות את הסימולציה (ללא init)
& $venvPy .\simulate.py

# --- 4) שיחזור ---
Move-Item -Force $bak $tok
Write-Host "`nRestored S2.nope.json" -ForegroundColor DarkGray
