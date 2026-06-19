"""
core/censys_lookup.py — ReconNinja v7.0.0
Censys host and certificate intelligence.

Queries Censys.io for host information complementary to Shodan.
Requires free Censys API ID + secret (register at search.censys.io).

Also provides SecurityTrails-style DNS history via passive DNS
APIs (VirusTotal PDNS — extends existing VT integration).
"""

from __future__ import annotations

import base64
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print, log

CENSYS_HOST_URL   = "https://search.censys.io/api/v2/hosts/{ip}"
CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"


@dataclass
class CensysResult:
    ip:           str
    asn:          str         = ""
    org:          str         = ""
    country:      str         = ""
    city:         str         = ""
    services:     list[dict]  = field(default_factory=list)
    tags:         list[str]   = field(default_factory=list)
    labels:       list[str]   = field(default_factory=list)
    last_updated: str         = ""
    error:        str         = ""

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "asn":          self.asn,
            "org":          self.org,
            "country":      self.country,
            "services":     self.services[:10],
            "tags":         self.tags,
        }


def _censys_auth_header(api_id: str, api_secret: str) -> str:
    creds = f"{api_id}:{api_secret}"
    return "Basic " + base64.b64encode(creds.encode()).decode()


def censys_host_lookup(ip: str, api_id: str, api_secret: str) -> CensysResult:
    """Query Censys for a single IP host."""
    result = CensysResult(ip=ip)
    if not api_id or not api_secret:
        result.error = "No Censys API credentials"
        return result

    try:
        url = CENSYS_HOST_URL.format(ip=ip)
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": _censys_auth_header(api_id, api_secret),
                "User-Agent":    "ReconNinja/7.0.0",
                "Accept":        "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())

        result_data = data.get("result", {})
        asn_info    = result_data.get("autonomous_system", {})
        location    = result_data.get("location", {})

        result.asn          = str(asn_info.get("asn", ""))
        result.org          = asn_info.get("name", "")
        result.country      = location.get("country_code", "")
        result.city         = location.get("city", "")
        result.tags         = result_data.get("labels", [])
        result.last_updated = result_data.get("last_updated_at", "")

        for svc in result_data.get("services", []):
            result.services.append({
                "port":        svc.get("port"),
                "transport":   svc.get("transport_protocol", "tcp"),
                "service":     svc.get("service_name", ""),
                "product":     svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
            })

        safe_print(
            f"  [info]Censys:[/] {ip} — org=[cyan]{result.org}[/] "
            f"country={result.country} services={len(result.services)}"
        )

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result.error = "Not indexed by Censys"
        elif e.code == 401:
            result.error = "Invalid Censys API credentials"
        else:
            result.error = f"HTTP {e.code}"
    except Exception as e:
        result.error = str(e)
        log.debug(f"Censys error for {ip}: {e}")

    return result


def censys_bulk_lookup(
    ips: list[str],
    api_id: str,
    api_secret: str,
    out_folder: Path,
) -> list[CensysResult]:
    """Bulk lookup multiple IPs."""
    ensure_dir(out_folder)
    if not api_id or not api_secret:
        safe_print("[dim]Censys: no API credentials — skipping[/]")
        return []

    safe_print(f"[info]▶ Censys — querying {len(ips)} host(s)[/]")
    results = []
    for ip in ips[:20]:  # free tier cap
        r = censys_host_lookup(ip, api_id, api_secret)
        if not r.error:
            results.append(r)

    out_file = out_folder / "censys.txt"
    lines = ["# Censys Results\n"]
    for r in results:
        lines.append(f"{r.ip}: {r.org} ({r.country}) — {len(r.services)} service(s)")
    out_file.write_text("\n".join(lines))

    safe_print(f"[success]✔ Censys: {len(results)} host(s) enriched[/]")
    return results


# ── DNS history via VT PDNS ───────────────────────────────────────────────────

def dns_history_lookup(domain: str, vt_key: str, out_folder: Path) -> dict:
    """
    Fetch passive DNS history from VirusTotal PDNS API.
    Reveals historical IPs, A/MX/NS records, CDN bypass opportunities.
    """
    ensure_dir(out_folder)
    if not vt_key:
        safe_print("[dim]DNS History: requires VirusTotal API key (--vt-key)[/]")
        return {}

    safe_print(f"[info]▶ DNS History — {domain}[/]")

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
        req = urllib.request.Request(
            url,
            headers={"x-apikey": vt_key, "User-Agent": "ReconNinja/7.0.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())

        resolutions = data.get("data", [])
        history = {
            "domain":      domain,
            "total":       len(resolutions),
            "resolutions": [],
        }

        seen_ips: set[str] = set()
        for entry in resolutions[:50]:
            attrs = entry.get("attributes", {})
            ip    = attrs.get("ip_address", "")
            date  = attrs.get("date", 0)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                history["resolutions"].append({
                    "ip":   ip,
                    "date": date,
                })

        safe_print(
            f"  [info]DNS History:[/] {domain} — "
            f"[cyan]{len(seen_ips)}[/] unique historical IP(s)"
        )

        out_file = out_folder / "dns_history.txt"
        lines = [f"# DNS History — {domain}", ""]
        for r in history["resolutions"]:
            lines.append(f"  {r['ip']} (epoch {r['date']})")
        out_file.write_text("\n".join(lines))
        return history

    except Exception as e:
        log.debug(f"DNS history error: {e}")
        return {}
