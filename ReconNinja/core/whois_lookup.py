"""
core/whois_lookup.py — ReconNinja v5.0.0
WHOIS data retrieval — no API key needed.
Uses whois CLI or python-whois fallback.
"""
from __future__ import annotations

import subprocess
import re
from typing import Optional

from utils.logger import safe_print, log


def _whois_cli(target: str, timeout: int = 15) -> str:
    """Run system whois command."""
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _whois_python(target: str) -> str:
    """Fallback: use python-whois library if installed."""
    try:
        import whois
        w = whois.whois(target)
        return str(w)
    except ImportError:
        return ""
    except Exception:
        return ""


def _extract_field(text: str, patterns: list[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    return ""


def whois_lookup(target: str) -> dict:
    """
    Perform WHOIS lookup on domain or IP.
    Returns parsed dict with key fields.
    """
    raw = _whois_cli(target) or _whois_python(target)
    if not raw:
        log.warning(f"WHOIS: no data for {target}")
        return {"target": target, "raw": "", "error": "No WHOIS data returned"}

    result = {
        "target":       target,
        "raw":          raw[:3000],
        "registrar":    _extract_field(raw, [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"]),
        "registered":   _extract_field(raw, [
            r"Creation Date:\s*(.+)", r"created:\s*(.+)",
            r"Registered On:\s*(.+)", r"Registration Time:\s*(.+)",
        ]),
        "expires":      _extract_field(raw, [
            r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)",
            r"expires:\s*(.+)", r"Expiration Time:\s*(.+)",
        ]),
        "updated":      _extract_field(raw, [
            r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)",
            r"Last Updated On:\s*(.+)",
        ]),
        "name_servers": re.findall(r"Name Server:\s*(.+)", raw, re.I)[:4],
        "status":       re.findall(r"Domain Status:\s*(.+)", raw, re.I)[:3],
        "registrant":   _extract_field(raw, [
            r"Registrant Organization:\s*(.+)", r"org-name:\s*(.+)",
            r"Organisation:\s*(.+)",
        ]),
        "country":      _extract_field(raw, [
            r"Registrant Country:\s*(.+)", r"country:\s*(.+)",
        ]),
        "emails":       list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw
        )))[:5],
    }

    safe_print(
        f"  [info]WHOIS:[/] {target} — "
        f"registrar=[cyan]{result['registrar'][:40] or 'unknown'}[/] "
        f"expires=[dim]{result['expires'][:20] or 'unknown'}[/]"
    )
    return result
