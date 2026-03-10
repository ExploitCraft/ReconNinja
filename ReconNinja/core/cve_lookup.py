"""
core/cve_lookup.py
ReconNinja v3.3 — CVE Lookup via NVD API (free, no key required)

After nmap finds service versions like "Apache/2.4.52", this module
queries the NIST NVD API and returns known CVEs for that product/version.

NVD API: https://nvd.nist.gov/developers/vulnerabilities
  - Free, no API key required for basic use
  - Rate limit: 5 req/30s without key, 50 req/30s with free key
  - Optional: set NIST_API_KEY env var to get higher rate limits
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field

from utils.logger import safe_print
from utils.models import PortInfo, VulnFinding


# ── CVE result ────────────────────────────────────────────────────────────────

@dataclass
class CVEResult:
    cve_id:      str
    description: str
    severity:    str   # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_score:  float
    published:   str
    references:  list[str] = field(default_factory=list)

    def to_vuln_finding(self, target: str, tool: str = "nvd") -> VulnFinding:
        return VulnFinding(
            tool     = tool,
            severity = self.severity.lower(),
            title    = f"{self.cve_id} (CVSS {self.cvss_score})",
            target   = target,
            details  = self.description[:300],
            cve      = self.cve_id,
        )


# ── NVD API client ────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: dict[str, list[CVEResult]] = {}


def _nvd_search(keyword: str, api_key: str | None = None,
                max_results: int = 5) -> list[CVEResult]:
    """Query NVD for CVEs matching keyword (e.g. 'Apache 2.4.52')."""

    cache_key = f"{keyword}:{max_results}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    params: dict[str, str] = {
        "keywordSearch": keyword,
        "resultsPerPage": str(max_results),
    }
    api_key = api_key or os.environ.get("NIST_API_KEY")
    headers = {"User-Agent": "ReconNinja/3.2"}
    if api_key:
        headers["apiKey"] = api_key

    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"

    try:
        req  = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        safe_print(f"[dim]NVD lookup failed for '{keyword}': {e}[/]")
        return []

    results: list[CVEResult] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # CVSS score + severity
        score    = 0.0
        severity = "NONE"
        metrics  = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                score     = float(cvss_data.get("baseScore", 0))
                severity  = cvss_data.get("baseSeverity", "NONE")
                break

        published = cve.get("published", "")[:10]
        refs = [r["url"] for r in cve.get("references", [])[:3] if "url" in r]

        results.append(CVEResult(
            cve_id      = cve_id,
            description = desc,
            severity    = severity,
            cvss_score  = score,
            published   = published,
            references  = refs,
        ))

    # Sort by CVSS score descending
    results.sort(key=lambda x: x.cvss_score, reverse=True)
    _CACHE[cache_key] = results
    return results


# ── Port scanner integration ──────────────────────────────────────────────────

def _build_search_term(port: PortInfo) -> str | None:
    """
    Build a search keyword from port info.
    Returns None if there is not enough info to search.
    """
    parts: list[str] = []

    if port.product:
        parts.append(port.product)
    elif port.service:
        parts.append(port.service)

    if port.version:
        parts.append(port.version)

    if not parts:
        return None

    return " ".join(parts)


def lookup_cves_for_ports(
    ports:       list[PortInfo],
    target:      str,
    max_per_port: int = 3,
    delay:        float = 6.5,   # FIX v5.0.0: NVD rate limit is 5 req/30s = 6s/req minimum (was 0.7 — caused 403s)
    api_key:      str | None = None,
) -> list[VulnFinding]:
    """
    For each port with a known product/version, query NVD and return
    VulnFinding objects for any CVEs found.

    Args:
        ports:        list of PortInfo objects from nmap scan
        target:       scan target (used as VulnFinding.target)
        max_per_port: max CVEs to return per port (default 3)
        delay:        seconds between NVD requests (rate limit)
        api_key:      optional NIST NVD API key for higher rate limit

    Returns:
        list of VulnFinding, sorted critical → info
    """
    findings: list[VulnFinding] = []
    queried:  set[str] = set()   # avoid duplicate queries for same product

    for port in ports:
        term = _build_search_term(port)
        if not term or term in queried:
            continue
        queried.add(term)

        safe_print(f"[dim]CVE lookup: {term} (port {port.port})...[/]")
        cves = _nvd_search(term, api_key=api_key, max_results=max_per_port)

        for cve in cves:
            port_target = f"{target}:{port.port}"
            findings.append(cve.to_vuln_finding(port_target))
            safe_print(
                f"  [warning]{cve.cve_id}[/] CVSS {cve.cvss_score} "
                f"[{cve.severity}] — {cve.description[:80]}..."
            )

        if cves:
            time.sleep(delay)   # rate limit between searches

    # Sort: critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "": 5}
    findings.sort(key=lambda x: sev_order.get(x.severity.lower(), 5))
    return findings


def lookup_cves_for_host_result(host_result, target: str,
                                 max_per_port: int = 3,
                                 api_key: str | None = None) -> list[VulnFinding]:
    """Convenience wrapper — takes a HostResult directly."""
    return lookup_cves_for_ports(
        ports        = host_result.open_ports,
        target       = target,
        max_per_port = max_per_port,
        api_key      = api_key,
    )
