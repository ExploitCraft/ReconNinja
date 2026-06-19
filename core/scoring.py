"""
ReconNinja v9 — CVSSv4 + EPSS + ReconNinja Exploitability Index (REI)

EPSS (Exploit Prediction Scoring System) scores fetched from FIRST.org API.
CVSSv4 scores fetched from NVD 2.0 API alongside v3 fallback.
REI = composite: 0.4*EPSS + 0.3*normalized_cvss + 0.3*context_weight
Context weight raises score when: target is internet-facing, exploit exists in the wild,
vuln is in a critical service (AD, cloud, container), or chained in an attack path.
"""
from __future__ import annotations

import time
from functools import lru_cache
from typing import Optional

import requests

from utils.logger import log
from utils.models import VulnFinding


EPSS_API   = "https://api.first.org/data/v1/epss"
NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQ_DELAY = 0.6   # seconds between NVD calls (rate limit: 5 req/30s without key)


# ─── EPSS batch fetch ─────────────────────────────────────────────────────────

def fetch_epss_batch(cves: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores for up to 100 CVEs in one request.
    Returns dict: CVE-ID → EPSS probability (0.0–1.0).
    """
    if not cves:
        return {}
    try:
        resp = requests.get(
            EPSS_API,
            params={"cve": ",".join(cves[:100])},
            timeout=20,
        )
        data = resp.json()
        return {
            item["cve"]: float(item["epss"])
            for item in data.get("data", [])
        }
    except Exception as e:
        log.warning(f"[epss] Batch fetch error: {e}")
        return {}


# ─── CVSSv4 fetch ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=512)
def fetch_cvss_v4(cve_id: str, nvd_key: str = "") -> tuple[str, str]:
    """
    Returns (cvss_v4_score_str, vector_string).
    Falls back to CVSSv3 base score if v4 not available.
    """
    headers = {"apiKey": nvd_key} if nvd_key else {}
    try:
        time.sleep(_REQ_DELAY)
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            headers=headers,
            timeout=20,
        )
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return "", ""
        metrics = vulns[0]["cve"].get("metrics", {})
        # Prefer v4
        if "cvssMetricV40" in metrics:
            m = metrics["cvssMetricV40"][0]["cvssData"]
            return str(m.get("baseScore", "")), m.get("vectorString", "")
        # Fallback v3.1
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            return str(m.get("baseScore", "")), m.get("vectorString", "")
        # Fallback v2
        if "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            return str(m.get("baseScore", "")), m.get("vectorString", "")
    except Exception as e:
        log.warning(f"[cvss] Fetch error for {cve_id}: {e}")
    return "", ""


# ─── REI calculation ──────────────────────────────────────────────────────────

def calculate_rei(
    epss_score: float,
    cvss_score_str: str,
    context_flags: Optional[dict] = None,
) -> float:
    """
    ReconNinja Exploitability Index (0.0–10.0).

    Args:
        epss_score:     EPSS probability (0.0–1.0)
        cvss_score_str: CVSS base score as string (e.g. "7.5")
        context_flags:  dict with optional bool keys:
                          internet_facing, exploit_in_wild, in_attack_chain,
                          critical_service (AD/cloud/k8s), unauthenticated
    """
    flags = context_flags or {}

    # Normalise CVSS to 0.0–1.0
    try:
        cvss_norm = min(float(cvss_score_str), 10.0) / 10.0
    except (ValueError, TypeError):
        cvss_norm = 0.0

    # Context weight: accumulate up to 1.0
    ctx = 0.0
    if flags.get("internet_facing"):   ctx += 0.25
    if flags.get("exploit_in_wild"):   ctx += 0.30
    if flags.get("in_attack_chain"):   ctx += 0.25
    if flags.get("critical_service"):  ctx += 0.10
    if flags.get("unauthenticated"):   ctx += 0.10
    ctx = min(ctx, 1.0)

    # Weighted composite
    rei_norm = 0.4 * epss_score + 0.3 * cvss_norm + 0.3 * ctx
    return round(rei_norm * 10.0, 2)


def rei_severity(rei: float) -> str:
    """Map REI score to severity label."""
    if rei >= 8.0: return "critical"
    if rei >= 6.0: return "high"
    if rei >= 4.0: return "medium"
    if rei >= 2.0: return "low"
    return "info"


# ─── Enrich a list of VulnFindings in-place ───────────────────────────────────

def enrich_findings_with_scores(
    findings: list[VulnFinding],
    nvd_key: str = "",
    epss_threshold: float = 0.0,
    internet_facing: bool = True,
) -> list[VulnFinding]:
    """
    Batch-enrich VulnFindings with EPSS, CVSSv4, and REI.
    Findings below epss_threshold are demoted to 'info'.
    """
    # Collect all CVEs
    cve_ids = [f.cve for f in findings if f.cve and f.cve.startswith("CVE-")]
    epss_map = fetch_epss_batch(cve_ids)

    for vf in findings:
        if vf.cve and vf.cve.startswith("CVE-"):
            epss = epss_map.get(vf.cve, 0.0)
            vf.epss_score = epss

            cvss4, vector = fetch_cvss_v4(vf.cve, nvd_key)
            vf.cvss_v4 = cvss4
            vf.cvss_v4_vector = vector

            context = {
                "internet_facing":  internet_facing,
                "exploit_in_wild":  epss > 0.5,
                "critical_service": any(
                    kw in vf.title.lower()
                    for kw in ("active directory", "kerberos", "kubernetes", "aws", "azure")
                ),
                "unauthenticated": "unauthenticated" in vf.details.lower(),
            }
            vf.rei = calculate_rei(epss, cvss4, context)

            if epss_threshold > 0 and epss < epss_threshold and vf.severity != "critical":
                vf.severity = "info"

    return findings
