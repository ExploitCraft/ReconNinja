"""
ReconNinja v5.1.0 — Hunter.io Email Intelligence
Domain email enumeration via Hunter.io API v2.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import urllib.parse
from typing import Any

from utils.logger import log

_HUNTER_BASE = "https://api.hunter.io/v2"


# ─── Domain search ────────────────────────────────────────────────────────────

def hunter_domain_search(domain: str, api_key: str, limit: int = 100) -> dict[str, Any]:
    """
    Search for email addresses associated with *domain* via Hunter.io.

    Returns a normalised dict:
        domain, organization, total, emails[], pattern, sources[]

    Each email entry:
        value, type, confidence, first_name, last_name, position, sources[]
    """
    params = urllib.parse.urlencode({
        "domain":   domain,
        "api_key":  api_key,
        "limit":    limit,
    })
    url = f"{_HUNTER_BASE}/domain-search?{params}"

    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            raw = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        log.warning(f"Hunter.io HTTP {exc.code} for domain '{domain}'")
        return {"domain": domain, "error": f"HTTP {exc.code}"}
    except Exception as exc:
        log.warning(f"Hunter.io lookup failed for '{domain}': {exc}")
        return {"domain": domain, "error": str(exc)}

    data = raw.get("data", {})
    emails_raw = data.get("emails", [])

    emails = []
    for e in emails_raw:
        emails.append({
            "value":      e.get("value", ""),
            "type":       e.get("type", ""),
            "confidence": e.get("confidence", 0),
            "first_name": e.get("first_name", ""),
            "last_name":  e.get("last_name", ""),
            "position":   e.get("position", ""),
            "sources":    [s.get("uri", "") for s in e.get("sources", [])],
        })

    result: dict[str, Any] = {
        "domain":       domain,
        "organization": data.get("organization", ""),
        "total":        data.get("total", 0),
        "pattern":      data.get("pattern", ""),
        "emails":       emails,
    }

    log.info(
        f"Hunter.io: {domain} — {result['total']} total email(s), "
        f"{len(emails)} returned"
    )
    return result


# ─── Confidence filtering ─────────────────────────────────────────────────────

def filter_by_confidence(
    hunter_result: dict[str, Any],
    min_confidence: int = 50,
) -> dict[str, Any]:
    """
    Return a copy of *hunter_result* with emails below *min_confidence* removed.
    """
    filtered = [
        e for e in hunter_result.get("emails", [])
        if e.get("confidence", 0) >= min_confidence
    ]
    out = dict(hunter_result)
    out["emails"] = filtered
    out["filtered_count"] = len(hunter_result.get("emails", [])) - len(filtered)
    return out
