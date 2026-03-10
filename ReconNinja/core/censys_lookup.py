"""
ReconNinja v5.1.0 — Censys Host Intelligence
Censys Search v2 API — host lookup by IP with graceful fallback.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from unittest.mock import MagicMock

from utils.logger import log

# ── Censys availability check ─────────────────────────────────────────────────
try:
    from censys.search import CensysHosts          # type: ignore
    _CENSYS_AVAILABLE = True
except ImportError:
    _CENSYS_AVAILABLE = False


# ─── CDN / WAF detection heuristics (used by auto-scope) ──────────────────────

_CDN_WAF_ORGS: set[str] = {
    "cloudflare", "fastly", "akamai", "incapsula", "imperva",
    "sucuri", "cloudfront", "amazon", "stackpath", "limelight",
}

_CDN_WAF_LABELS: set[str] = {
    "cdn", "waf", "ddos-protection", "proxy", "load-balancer",
}


def _is_cdn_waf(result: dict) -> bool:
    """Return True if the Censys result looks like a CDN / WAF host."""
    org    = (result.get("autonomous_system", {}).get("description") or "").lower()
    labels = {lbl.lower() for lbl in result.get("labels", [])}
    if any(cdn in org for cdn in _CDN_WAF_ORGS):
        return True
    if labels & _CDN_WAF_LABELS:
        return True
    return False


# ─── Single-IP lookup ─────────────────────────────────────────────────────────

def censys_host_lookup(ip: str, api_id: str, api_secret: str) -> dict[str, Any]:
    """
    Look up a single IP via the Censys Hosts API.

    Returns a dict with normalised fields:
        ip, org, country, asn, labels, services, out_of_scope
    Falls back gracefully if the censys package is missing or the call fails.
    """
    if not _CENSYS_AVAILABLE:
        log.warning("censys package not installed — skipping Censys lookup (pip install censys)")
        return {"ip": ip, "error": "censys package not installed"}

    try:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        raw = h.view(ip)
    except Exception as exc:
        log.warning(f"Censys lookup failed for {ip}: {exc}")
        return {"ip": ip, "error": str(exc)}

    services = []
    for svc in raw.get("services", []):
        services.append({
            "port":        svc.get("port"),
            "transport":   svc.get("transport_protocol", ""),
            "service_name": svc.get("service_name", ""),
            "banner":      svc.get("banner", ""),
        })

    asn_info = raw.get("autonomous_system", {})
    result: dict[str, Any] = {
        "ip":           ip,
        "org":          asn_info.get("description", ""),
        "asn":          asn_info.get("asn", 0),
        "country":      raw.get("location", {}).get("country_code", ""),
        "labels":       raw.get("labels", []),
        "services":     services,
        "out_of_scope": _is_cdn_waf(raw),
        "raw":          raw,
    }

    scope_note = " [CDN/WAF — marked out-of-scope]" if result["out_of_scope"] else ""
    log.info(f"Censys: {ip} — {result['org']} (ASN{result['asn']}){scope_note}")
    return result


# ─── Bulk / CIDR lookup ───────────────────────────────────────────────────────

def censys_bulk_lookup(
    targets: list[str],
    api_id: str,
    api_secret: str,
    max_ips: int = 20,
) -> list[dict[str, Any]]:
    """
    Look up a list of IPs or CIDR ranges.

    CIDR notation is expanded (capped at max_ips addresses per range).
    Individual IPs are validated before querying.
    Returns a list of result dicts (one per reachable IP).
    """
    ips: list[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
            expanded = [str(a) for a in list(net.hosts())[:max_ips]]
            ips.extend(expanded)
        except ValueError:
            # Treat as bare IP
            try:
                ipaddress.ip_address(t)
                ips.append(t)
            except ValueError:
                log.warning(f"Censys: invalid IP/CIDR '{t}' — skipped")

    results: list[dict[str, Any]] = []
    for ip in ips[:max_ips]:
        r = censys_host_lookup(ip, api_id, api_secret)
        results.append(r)
    return results
