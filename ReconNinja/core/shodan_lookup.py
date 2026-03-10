"""
core/shodan_lookup.py — ReconNinja v5.0.0
Shodan host and search lookup.
Requires: pip install shodan  (optional)
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional

from utils.logger import safe_print, log

SHODAN_HOST_URL   = "https://api.shodan.io/shodan/host/{ip}?key={key}"
SHODAN_DNS_URL    = "https://api.shodan.io/dns/resolve?hostnames={host}&key={key}"


def _fetch(url: str, timeout: int = 10) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise
    except Exception as e:
        log.warning(f"Shodan fetch error: {e}")
        return {}


def shodan_host_lookup(ip: str, api_key: str) -> dict:
    """
    Query Shodan for a single IP.
    Returns parsed host data or empty dict.
    """
    if not api_key:
        return {}
    try:
        url  = SHODAN_HOST_URL.format(ip=ip, key=api_key)
        data = _fetch(url)
        if not data:
            return {}

        result = {
            "ip":           ip,
            "org":          data.get("org", ""),
            "isp":          data.get("isp", ""),
            "country":      data.get("country_name", ""),
            "city":         data.get("city", ""),
            "os":           data.get("os", ""),
            "hostnames":    data.get("hostnames", []),
            "domains":      data.get("domains", []),
            "tags":         data.get("tags", []),
            "vulns":        list(data.get("vulns", {}).keys()),
            "open_ports":   data.get("ports", []),
            "services":     [],
        }

        for banner in data.get("data", []):
            svc = {
                "port":      banner.get("port"),
                "transport": banner.get("transport", "tcp"),
                "product":   banner.get("product", ""),
                "version":   banner.get("version", ""),
                "cpe":       banner.get("cpe", []),
                "banner":    banner.get("data", "")[:200],
            }
            result["services"].append(svc)

        safe_print(
            f"  [info]Shodan:[/] {ip} — org=[cyan]{result['org']}[/] "
            f"ports={result['open_ports'][:10]} "
            f"vulns=[danger]{len(result['vulns'])}[/]"
        )
        return result

    except Exception as e:
        log.warning(f"Shodan lookup failed for {ip}: {e}")
        return {}


def shodan_resolve(hostname: str, api_key: str) -> Optional[str]:
    """Resolve hostname to IP via Shodan DNS API."""
    if not api_key:
        return None
    try:
        url  = SHODAN_DNS_URL.format(host=hostname, key=api_key)
        data = _fetch(url)
        return data.get(hostname)
    except Exception:
        return None


def shodan_bulk_lookup(ips: list[str], api_key: str) -> list[dict]:
    """Look up multiple IPs. Returns list of host results."""
    if not api_key or not ips:
        return []
    safe_print(f"[info]  Shodan: querying {len(ips)} host(s)...[/]")
    results = []
    for ip in ips:
        r = shodan_host_lookup(ip, api_key)
        if r:
            results.append(r)
    return results
