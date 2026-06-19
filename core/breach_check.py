"""
core/breach_check.py — ReconNinja v7.0.0
HaveIBeenPwned (HIBP) domain breach check.

Checks all email addresses and the domain itself against HIBP's
breach database. No API key required for domain search endpoint.
For email-level search, a free HIBP API key is required.

Free tier: domain search (no key), email-level (key required).
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log

HIBP_DOMAIN_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
HIBP_EMAIL_URL  = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_BREACHES   = "https://haveibeenpwned.com/api/v3/breaches"


@dataclass
class BreachResult:
    domain:          str
    emails_breached: list[dict] = field(default_factory=list)  # {email, breaches}
    domain_breaches: list[str]  = field(default_factory=list)
    breach_count:    int        = 0
    critical:        bool       = False
    error:           str        = ""

    def to_dict(self) -> dict:
        return {
            "domain":          self.domain,
            "emails_breached": self.emails_breached,
            "domain_breaches": self.domain_breaches,
            "breach_count":    self.breach_count,
            "critical":        self.critical,
            "error":           self.error,
        }


def _hibp_get(url: str, api_key: Optional[str] = None, timeout: int = 15) -> Optional[dict | list]:
    headers = {
        "User-Agent": "ReconNinja/7.0.0 (Security Scanner)",
        "hibp-api-key": api_key or "",
    }
    if not api_key:
        headers.pop("hibp-api-key")
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # not found = not breached
        if e.code == 429:
            safe_print("[warning]  HIBP rate limit — waiting 2s[/]")
            time.sleep(2)
            return None
        log.debug(f"HIBP HTTP {e.code}: {url}")
        return None
    except Exception as e:
        log.debug(f"HIBP error: {e}")
        return None


def breach_check(
    domain: str,
    out_folder: Path,
    api_key: Optional[str] = None,
    emails: Optional[list[str]] = None,
) -> BreachResult:
    """
    Check domain and optional email list against HaveIBeenPwned.

    Args:
        domain:     target domain
        out_folder: output directory
        api_key:    HIBP API key (required for email-level lookup)
        emails:     list of email addresses to check (from WHOIS / SMTP enum)

    Returns:
        BreachResult
    """
    ensure_dir(out_folder)
    result = BreachResult(domain=domain)
    safe_print(f"[info]▶ Breach Check (HIBP) — {domain}[/]")

    # Domain-level search (free, no key)
    domain_url = HIBP_DOMAIN_URL.format(domain=domain)
    data = _hibp_get(domain_url)
    if isinstance(data, dict):
        # HIBP domain endpoint returns {email: [breach_names]}
        for email_addr, breach_list in data.items():
            result.emails_breached.append({
                "email":   email_addr,
                "breaches": breach_list,
            })
            result.breach_count += len(breach_list)
    elif isinstance(data, list) and data:
        result.domain_breaches = data

    # Email-level lookup (requires key)
    if api_key and emails:
        for email in emails[:20]:  # cap to avoid rate limits
            time.sleep(1.5)  # HIBP free: 1 req/1.5s
            email_url = HIBP_EMAIL_URL.format(account=urllib.request.quote(email))
            breaches = _hibp_get(email_url, api_key=api_key)
            if isinstance(breaches, list) and breaches:
                result.emails_breached.append({
                    "email":   email,
                    "breaches": [b.get("Name", "") for b in breaches],
                })
                result.breach_count += len(breaches)

    result.critical = result.breach_count > 0

    # Output
    if result.critical:
        safe_print(
            f"  [danger]⚠  HIBP: {len(result.emails_breached)} breached account(s), "
            f"{result.breach_count} total breach event(s)[/]"
        )
    else:
        safe_print(f"  [success]✔ HIBP: No breaches found for {domain}[/]")

    # Save
    out_file = out_folder / "breach_check.txt"
    lines = [f"# HIBP Breach Report — {domain}", ""]
    for entry in result.emails_breached:
        lines.append(f"  {entry['email']}: {', '.join(entry['breaches'])}")
    out_file.write_text("\n".join(lines))

    safe_print(f"[success]✔ Breach Check complete → {out_file}[/]")
    return result
