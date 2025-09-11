# nope-verifier.py
from __future__ import annotations
import json
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier

# OID שבו מוטמן ה-proof בתעודה (תואם generate_tls.py)
NOPE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")

# קבצי ברירת מחדל ל-public inputs ו-verification key
DEFAULT_PUBLIC_INPUTS = Path("nope") / "rsa-ecdsa_public.json"
DEFAULT_VKEY          = Path("nope") / "rsa-ecdsa-vk.json"

class NopeVerifyError(RuntimeError):
    """נזרקת כאשר ENFORCE פעיל והאימות נכשל/חסר."""

# ---------- עזרי טעינת תעודה ----------
def _load_cert_from_bytes(cert_bytes: bytes) -> x509.Certificate:
    """
    מנסה PEM תחילה (כמו אצלכם), ואם נכשל — DER.
    """
    try:
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())
    except Exception:
        return x509.load_der_x509_certificate(cert_bytes, default_backend())

def _load_cert_from_file(path: str | Path) -> x509.Certificate:
    data = Path(path).read_bytes()
    return _load_cert_from_bytes(data)

def _check_tls_validity(cert: x509.Certificate) -> bool:
    """
    אימות תוקף התעודה בשעון UTC, תוך שימוש במאפיינים *_utc החדשים
    כדי להימנע מהתראות deprecation.
    """
    now = datetime.now(timezone.utc)
    try:
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
    except AttributeError:
        # תאימות לאחור (ספריות ישנות יותר) — נשווה מול not_valid_* הישנים עם aware now
        nvb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        nva = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nvb <= now <= nva

def _extract_nope_proof(cert: x509.Certificate) -> Optional[dict]:
    """
    מחלץ JSON של הוכחה מתוך הרחבת ה-OID.
    ב-generate_tls.py שמרתם מחרוזת JSON, לכן נפענח כ-utf-8.
    """
    try:
        ext = cert.extensions.get_extension_for_oid(NOPE_OID)
        raw = ext.value.value  # bytes (UnrecognizedExtension)
        if isinstance(raw, (bytes, bytearray)):
            txt = raw.decode("utf-8", errors="strict")
            return json.loads(txt)
        if isinstance(raw, str):
            return json.loads(raw)
        return None
    except Exception:
        return None

# ---------- הרצת snarkjs ----------
def _pick_npx() -> Optional[str]:
    """
    מאתר npx (גם ב-Windows). מחזיר נתיב או None אם לא נמצא.
    ניתן לעקוף עם משתנה סביבה NOPE_NPX.
    """
    env = os.environ.get("NOPE_NPX")
    if env:
        return env
    if platform.system().lower().startswith("win"):
        return shutil.which("npx.cmd")
    return shutil.which("npx")

def verify_nope_proof_with_snarkjs(
    proof_dict: dict,
    public_inputs: Path = DEFAULT_PUBLIC_INPUTS,
    vkey_path: Path = DEFAULT_VKEY,
    extra_env: Optional[dict] = None,
) -> bool:
    """
    snarkjs groth16 verify <vk> <public> <proof>
    מחזיר True כשהאימות הצליח. מחזיר False אם snarkjs לא זמין או אם האימות נכשל.
    """
    npx = _pick_npx()
    if not npx:
        # npx/snarkjs לא זמין ב-PATH — נחזיר False (הקריאה העוטפת תחליט מה לעשות)
        return False

    with tempfile.TemporaryDirectory() as tmpd:
        tmpd = Path(tmpd)
        proof_path  = tmpd / "nope-proof.json"
        public_path = tmpd / "nope-public.json"

        proof_path.write_text(json.dumps(proof_dict), encoding="utf-8")

        if not public_inputs.exists() or not vkey_path.exists():
            return False
        shutil.copy2(public_inputs, public_path)

        cmd = [npx, "snarkjs", "groth16", "verify", str(vkey_path), str(public_path), str(proof_path)]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, **(extra_env or {})},
            )
        except FileNotFoundError:
            # npx/snarkjs לא זמין בזמן ריצה
            return False

        out = f"{res.stdout or ''}\n{res.stderr or ''}"
        # snarkjs כותב "OK" בהצלחה ומחזיר 0
        return (res.returncode == 0) and ("OK" in out)

# ---------- API עיקרי ----------
def verify_nope_cert_bytes(
    cert_bytes: bytes,
    enforce: bool = False,
    public_inputs: Path = DEFAULT_PUBLIC_INPUTS,
    vkey_path: Path = DEFAULT_VKEY,
) -> bool:
    """
    מאמת תעודה: תוקף TLS + הוכחת NOPE.
    אם enforce=True — יזרוק NopeVerifyError על כישלון.
    """
    cert = _load_cert_from_bytes(cert_bytes)

    if not _check_tls_validity(cert):
        if enforce:
            raise NopeVerifyError("TLS certificate expired or not yet valid")
        return False

    proof = _extract_nope_proof(cert)
    if not proof:
        if enforce:
            raise NopeVerifyError("Missing NOPE proof in certificate OID")
        return False

    ok = verify_nope_proof_with_snarkjs(proof, public_inputs=public_inputs, vkey_path=vkey_path)
    if not ok and enforce:
        raise NopeVerifyError("NOPE proof verification failed (snarkjs)")
    return ok

def verify_nope_cert_file(
    cert_path: str | Path,
    enforce: bool = False,
    public_inputs: Path = DEFAULT_PUBLIC_INPUTS,
    vkey_path: Path = DEFAULT_VKEY,
) -> bool:
    data = Path(cert_path).read_bytes()
    return verify_nope_cert_bytes(data, enforce=enforce, public_inputs=public_inputs, vkey_path=vkey_path)

def verify_nope_env(cert_bytes: bytes) -> bool:
    """
    עטיפה מכבדת משתני סביבה:
      NOPE_ZK_CHECK   = "1" → מבצע בדיקה ומחזיר True/False
      NOPE_ZK_ENFORCE = "1" → זורק NopeVerifyError על כישלון/חסר
    אם שניהם מכובים/ריקים — מחזיר True (בדיקה כבויה).
    """
    check   = os.environ.get("NOPE_ZK_CHECK", "0") == "1"
    enforce = os.environ.get("NOPE_ZK_ENFORCE", "0") == "1"

    if not check and not enforce:
        return True  # ZK כבוי לגמרי

    return verify_nope_cert_bytes(cert_bytes, enforce=enforce)

# ---------- CLI לבדיקה ידנית ----------
def _main_cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Verify TLS certificate with embedded NOPE proof (snarkjs).")
    ap.add_argument("cert", help="Path to cert.pem (PEM or DER)")
    ap.add_argument("--enforce", action="store_true", help="Raise on failure (exit 2)")
    ap.add_argument("--public", default=str(DEFAULT_PUBLIC_INPUTS), help="Path to NOPE public inputs JSON")
    ap.add_argument("--vk", default=str(DEFAULT_VKEY), help="Path to NOPE verification key JSON")
    args = ap.parse_args()

    try:
        ok = verify_nope_cert_file(
            args.cert,
            enforce=args.enforce,
            public_inputs=Path(args.public),
            vkey_path=Path(args.vk),
        )
        # שומרים פלט ASCII פשוט כדי להימנע מבעיות קונסול/קוד־דף
        print("OK: NOPE ZK verification passed" if ok else "FAIL: NOPE ZK verification failed")
        return 0 if ok else 1
    except NopeVerifyError as e:
        print(f"FAIL: {e}")
        return 2

if __name__ == "__main__":
    raise SystemExit(_main_cli())
