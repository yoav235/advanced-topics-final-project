# server/nope_enforcer.py
# -*- coding: utf-8 -*-
"""
NOPE enforcement helper for TLS sockets.

מה הקובץ הזה עושה:
- מחלץ את מפתח ה־public של ה־peer מתוך SSLSocket לאחר ה-handshake.
- מאתר את טוקן ה-NOPE עבור server_id נתון (S1/S2/S3) מתיקיית nope/tokens
  או מתיקיה חלופית אם הועברה (tokens_dir).
- קובע דומיין צפוי לפי קדימויות:
    1) expected_domain שהועבר לפונקציה (אם ניתן)
    2) server/expected_domains.json (אם קיים)
    3) הדומיין הכתוב בתוך הטוקן (תאימות לאחור)
    4) נפילה ל־mixN.local לפי ה־server_id
- מאמת את הטוקן מול (server_id, expected_domain, מפתח ה־TLS של ה־peer).

הערות:
- האכיפה על תוקף/גיל הטוקן מבוצעת בפועל בתוך verify_nope_token_file (ב־nope_utils),
  אשר מכבד את NOPE_TOKEN_MAX_AGE_SEC (אם מוגדר בסביבה).
- מצב ההחזרה:
    mode="raise"         -> זורק חריגה על כשל
    mode="return_false"  -> לא זורק, מחזיר False על כשל
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography import x509

# אנו נשענים על היישום הקיים ב-nope_utils לאימות חתימות/חישוב fingerprint וכו'
from .nope_utils import verify_nope_token_file  # type: ignore

# שימו לב: לא בכל גרסת הפרויקט קיים find_token_for_server עם tokens_dir.
# לכן נממש לוקלית חיפוש בטוח, ובמידה ואין tokens_dir ננסה לייבא את הפונקציה הקיימת.
try:
    from .nope_utils import find_token_for_server as _find_token_default  # type: ignore
except Exception:  # pragma: no cover - תאימות
    _find_token_default = None  # type: ignore

log = logging.getLogger("nope.enforcer")

_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_DOMAINS_PATH = _ROOT / "server" / "expected_domains.json"
_expected_cache: Optional[dict[str, str]] = None


# ---------------------------------------------------------------------------
# Expected domain resolution
# ---------------------------------------------------------------------------

def _load_expected_domains() -> dict[str, str]:
    """טוען פעם אחת map של server_id->domain מקובץ JSON אם קיים."""
    global _expected_cache
    if _expected_cache is not None:
        return _expected_cache
    try:
        _expected_cache = json.loads(_EXPECTED_DOMAINS_PATH.read_text(encoding="utf-8"))
    except Exception:
        _expected_cache = {}
    return _expected_cache


def _fallback_domain_for_sid(server_id: str) -> str:
    """S1 -> mix1.local; אם הפורמט אינו S<number>, ניפול ל-mix.local."""
    try:
        idx = int(server_id[1:])
    except Exception:
        idx = 0
    return f"mix{idx}.local" if idx > 0 else "mix.local"


def expected_domain_for(server_id: str, fallback: Optional[str] = None) -> str:
    """
    Public helper: מחזיר דומיין צפוי עבור server_id בהתאם לקובץ
    server/expected_domains.json אם קיים; אחרת משתמש ב-fallback או ב-mixN.local.
    """
    mp = _load_expected_domains()
    if server_id in mp:
        return mp[server_id]
    return fallback if fallback is not None else _fallback_domain_for_sid(server_id)


def _domain_from_token_file(token_path: Union[str, Path], fallback: str) -> str:
    """קורא את הדומיין מתוך JSON token (אם זמין); אחרת מחזיר fallback."""
    try:
        p = Path(token_path)
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj.get("payload", {}).get("domain", fallback)
    except Exception:
        return fallback


# ---------------------------------------------------------------------------
# Token discovery
# ---------------------------------------------------------------------------

def _find_token_for_server(server_id: str, tokens_dir: Optional[Path]) -> Optional[str]:
    """
    חיפוש טוקן עבור שרת. אם סופקה תיקיה, נחפש בה; אחרת ננסה את היישום הדיפולטי.
    תומך גם בקבצי *.nope.json וגם *.tok (תאימות).
    """
    if tokens_dir:
        d = Path(tokens_dir)
        for candidate in (d / f"{server_id}.nope.json", d / f"{server_id}.tok"):
            if candidate.exists():
                return str(candidate)
        return None

    # אין tokens_dir — ננסה את הפונקציה מהמודול אם קיימת
    if _find_token_default:
        try:
            tok = _find_token_default(server_id)  # type: ignore[arg-type]
            return str(tok) if tok else None
        except TypeError:
            # גרסה ישנה שאולי לא מתאימה; ננסה לחפש ידנית בתיקיה הסטנדרטית
            pass

    # חיפוש ידני בתיקיית ברירת המחדל
    dflt = _ROOT / "nope" / "tokens"
    for candidate in (dflt / f"{server_id}.nope.json", dflt / f"{server_id}.tok"):
        if candidate.exists():
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_peer_on_socket(
    ssock,                          # ssl.SSLSocket
    server_id: str,
    mode: str = "raise",            # "raise" | "return_false"
    tokens_dir: Optional[Path] = None,
    expected_domain: Optional[str] = None,
) -> bool:
    """
    מאמת את NOPE token של `server_id` מול תעודת ה־TLS של ה־peer על הסוקט `ssock`.

    קדימויות קביעת דומיין:
      1) expected_domain (אם הועבר)
      2) server/expected_domains.json (אם קיים)
      3) הדומיין בתוך הטוקן (תאימות לאחור)
      4) mixN.local לפי ה־server_id

    החזרה:
      - אם mode="raise": זורק חריגה במקרה של כשל; אחרת מחזיר True/False.
      - אם אין תעודת peer (למשל כשהשרת לא ביקש תעודת לקוח) — זוית השימוש קובעת:
          במקרה כזה אין משמעות ל-NOPE על ה-peer ולכן תיזרק חריגה/יוחזר False לפי mode.
    """
    try:
        # --- 1) TLS peer certificate -> public key
        der = ssock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("TLS peer presented no certificate")
        cert = x509.load_der_x509_certificate(der)
        peer_pub = cert.public_key()

        # --- 2) Locate NOPE token for server_id
        tok_path = _find_token_for_server(server_id, tokens_dir=tokens_dir)
        if not tok_path:
            where = str(tokens_dir) if tokens_dir else "nope/tokens"
            raise FileNotFoundError(f"NOPE token for {server_id} not found under {where}")

        # --- 3) Domain resolution
        dom = expected_domain or expected_domain_for(server_id, fallback=None)
        if dom is None:
            dom = _domain_from_token_file(tok_path, _fallback_domain_for_sid(server_id))
        dom = dom or _fallback_domain_for_sid(server_id)  # ביטחון כפול

        # --- 4) Verify token against (server_id, domain, peer_pub)
        ok = verify_nope_token_file(tok_path, server_id, dom, peer_pub)
        if ok:
            return True

        # --- 5) Failure path / logging
        msg = f"NOPE verification failed for {server_id} (domain={dom})"
        log.warning("DENY peer_id=%s domain=%s reason=nope-verify-failed", server_id, dom)
        if mode == "raise":
            raise RuntimeError(msg)
        return False

    except Exception as e:
        if mode == "raise":
            raise
        # return_false mode
        log.debug("verify_peer_on_socket(mode=return_false) -> False due to: %s", e, exc_info=False)
        return False
