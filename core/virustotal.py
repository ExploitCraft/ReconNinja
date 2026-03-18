"""
core/virustotal.py — ReconNinja v5.0.0
VirusTotal domain/IP reputation lookup.
Free API: 4 requests/minute, 500/day.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from utils.logger import safe_print, log

VT_BASE     = "https://www.virustotal.com/api/v3"
VT_DOMAIN   = VT_BASE + "/domains/{domain}"
VT_IP       = VT_BASE + "/ip_addresses/{ip}"
VT_URL_ID   = VT_BASE + "/urls/{url_id}"


def _fetch_vt(url: str, api_key: str, timeout: int = 15) -> dict:
    try:
        req = urllib.request.Request(
            url,
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        if e.code == 429:
            safe_print("[warning]  VirusTotal rate limit hit — slow down or upgrade API key[/]")
            return {}
        log.warning(f"VT HTTP error {e.code}: {url}")
        return {}
    except Exception as e:
        log.warning(f"VT fetch error: {e}")
        return {}


def _parse_stats(stats: dict) -> dict:
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def vt_domain_lookup(domain: str, api_key: str) -> dict:
    """Check domain reputation on VirusTotal."""
    if not api_key:
        return {}
    try:
        data  = _fetch_vt(VT_DOMAIN.format(domain=domain), api_key)
        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            return {}

        stats  = _parse_stats(attrs.get("last_analysis_stats", {}))
        result = {
            "domain":       domain,
            "reputation":   attrs.get("reputation", 0),
            "categories":   attrs.get("categories", {}),
            "stats":        stats,
            "malicious":    stats["malicious"],
            "registrar":    attrs.get("registrar", ""),
            "creation_date":attrs.get("creation_date", 0),
            "tags":         attrs.get("tags", []),
            "whois":        attrs.get("whois", "")[:500],
        }

        sev = "danger" if stats["malicious"] > 0 else "success"
        safe_print(
            f"  [info]VirusTotal:[/] {domain} — "
            f"[{sev}]malicious={stats['malicious']}[/] "
            f"suspicious={stats['suspicious']} "
            f"reputation={result['reputation']}"
        )
        return result

    except Exception as e:
        log.warning(f"VT domain lookup failed for {domain}: {e}")
        return {}


def vt_ip_lookup(ip: str, api_key: str) -> dict:
    """Check IP reputation on VirusTotal."""
    if not api_key:
        return {}
    try:
        data  = _fetch_vt(VT_IP.format(ip=ip), api_key)
        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            return {}

        stats  = _parse_stats(attrs.get("last_analysis_stats", {}))
        result = {
            "ip":           ip,
            "asn":          attrs.get("asn", ""),
            "as_owner":     attrs.get("as_owner", ""),
            "country":      attrs.get("country", ""),
            "reputation":   attrs.get("reputation", 0),
            "stats":        stats,
            "malicious":    stats["malicious"],
            "tags":         attrs.get("tags", []),
            "network":      attrs.get("network", ""),
        }

        sev = "danger" if stats["malicious"] > 0 else "success"
        safe_print(
            f"  [info]VirusTotal:[/] {ip} — "
            f"[{sev}]malicious={stats['malicious']}[/] "
            f"ASN={result['asn']} ({result['as_owner']})"
        )
        return result

    except Exception as e:
        log.warning(f"VT IP lookup failed for {ip}: {e}")
        return {}


def vt_bulk_lookup(
    targets: list[str],
    api_key: str,
    is_domain: bool = True,
) -> list[dict]:
    """Bulk VT lookup with rate limiting (4 req/min free tier)."""
    import time
    if not api_key or not targets:
        return []

    safe_print(f"[info]  VirusTotal: checking {len(targets)} target(s) (rate limited)...[/]")
    results  = []
    fn       = vt_domain_lookup if is_domain else vt_ip_lookup

    for i, t in enumerate(targets):
        r = fn(t, api_key)
        if r:
            results.append(r)
        # Free tier: 4 requests/minute = 1 every 15s
        if i < len(targets) - 1:
            time.sleep(15)

    return results
