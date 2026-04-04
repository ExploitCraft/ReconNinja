"""
core/cors_scan.py — ReconNinja v7.0.0
CORS (Cross-Origin Resource Sharing) misconfiguration scanner.

Sends crafted Origin headers to each live endpoint and checks if the
server reflects arbitrary origins in Access-Control-Allow-Origin.
Also checks for dangerous combinations like ACAO: * with
Access-Control-Allow-Credentials: true.

No external tools required — pure Python stdlib.
"""

from __future__ import annotations

import concurrent.futures
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


# ── Test origins ──────────────────────────────────────────────────────────────

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://trusted.{target}",          # domain reflection bypass
    "https://{target}.evil.com",          # subdomain bypass
    "https://not{target}",               # prefix bypass
]

SEVERITY_MAP = {
    "wildcard_with_credentials": "critical",
    "arbitrary_origin_reflected": "high",
    "null_origin_allowed":        "high",
    "subdomain_takeover_vector":  "medium",
    "prefix_bypass":              "medium",
    "wildcard_no_credentials":    "info",
}


@dataclass
class CORSFinding:
    url:              str
    origin_sent:      str
    acao_header:      str    # Access-Control-Allow-Origin
    acac_header:      str    # Access-Control-Allow-Credentials
    issue_type:       str
    severity:         str
    detail:           str

    def to_dict(self) -> dict:
        return {
            "url":          self.url,
            "origin_sent":  self.origin_sent,
            "acao":         self.acao_header,
            "acac":         self.acac_header,
            "issue_type":   self.issue_type,
            "severity":     self.severity,
            "detail":       self.detail,
        }


# ── Single probe ──────────────────────────────────────────────────────────────

def _probe_cors(url: str, origin: str, timeout: int = 8) -> tuple[str, str, int]:
    """
    Send a request with Origin: <origin> and return
    (Access-Control-Allow-Origin, Access-Control-Allow-Credentials, status_code).
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Origin":     origin,
                "User-Agent": "Mozilla/5.0 (ReconNinja/7.0.0)",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            return acao, acac, r.status
    except urllib.error.HTTPError as e:
        acao = e.headers.get("Access-Control-Allow-Origin", "")
        acac = e.headers.get("Access-Control-Allow-Credentials", "")
        return acao, acac, e.code
    except Exception:
        return "", "", 0


def _analyse(url: str, origin: str, acao: str, acac: str, target_domain: str
             ) -> Optional[CORSFinding]:
    """Analyse CORS headers for misconfigurations."""
    acao_lower = acao.lower().strip()
    acac_lower = acac.lower().strip()

    if not acao:
        return None

    # Wildcard + credentials (most dangerous)
    if acao == "*" and acac_lower == "true":
        return CORSFinding(
            url=url, origin_sent=origin,
            acao_header=acao, acac_header=acac,
            issue_type="wildcard_with_credentials",
            severity="critical",
            detail="ACAO: * combined with ACAC: true — browsers ignore this but many HTTP clients don't",
        )

    # Arbitrary origin reflected
    if acao == origin and origin not in ("null", "*"):
        if acac_lower == "true":
            return CORSFinding(
                url=url, origin_sent=origin,
                acao_header=acao, acac_header=acac,
                issue_type="arbitrary_origin_reflected",
                severity="high",
                detail=f"Server reflects arbitrary origin '{origin}' with credentials=true — exploitable CORS",
            )
        # Without credentials it's still worth noting
        return CORSFinding(
            url=url, origin_sent=origin,
            acao_header=acao, acac_header=acac,
            issue_type="arbitrary_origin_reflected",
            severity="medium",
            detail=f"Server reflects arbitrary origin '{origin}' (no credentials — lower impact)",
        )

    # null origin allowed
    if origin == "null" and "null" in acao_lower:
        return CORSFinding(
            url=url, origin_sent=origin,
            acao_header=acao, acac_header=acac,
            issue_type="null_origin_allowed",
            severity="high",
            detail="Server allows null origin — exploitable via sandboxed iframes",
        )

    # Subdomain reflection (potential takeover vector)
    if target_domain in acao_lower and acao != f"https://{target_domain}":
        return CORSFinding(
            url=url, origin_sent=origin,
            acao_header=acao, acac_header=acac,
            issue_type="subdomain_takeover_vector",
            severity="medium",
            detail=f"Origin reflected with subdomain prefix — exploitable if any subdomain is takeable",
        )

    return None


# ── Public API ────────────────────────────────────────────────────────────────

def scan_cors(
    web_urls: list[str],
    target_domain: str,
    out_folder: Path,
    timeout: int = 8,
    concurrency: int = 10,
) -> list[CORSFinding]:
    """
    Scan live web services for CORS misconfigurations.

    Args:
        web_urls:      list of live URLs (from httpx)
        target_domain: base domain (used for bypass test generation)
        out_folder:    output directory
        timeout:       per-request timeout
        concurrency:   parallel probes

    Returns:
        list of CORSFinding
    """
    ensure_dir(out_folder)
    findings: list[CORSFinding] = []
    seen: set[str] = set()

    # Build test origins for this target
    test_origins = []
    for tpl in EVIL_ORIGINS:
        o = tpl.replace("{target}", target_domain)
        test_origins.append(o)

    urls_to_test = web_urls[:20]
    total_probes = len(urls_to_test) * len(test_origins)
    safe_print(
        f"[info]▶ CORS Scanner — {total_probes} probes across "
        f"{len(urls_to_test)} endpoint(s)[/]"
    )

    def probe(url: str, origin: str):
        acao, acac, _ = _probe_cors(url, origin, timeout)
        finding = _analyse(url, origin, acao, acac, target_domain)
        return finding

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {
            ex.submit(probe, url, origin): (url, origin)
            for url in urls_to_test
            for origin in test_origins
        }
        for fut in concurrent.futures.as_completed(futs):
            try:
                result = fut.result()
                if result:
                    key = f"{result.url}:{result.issue_type}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(result)
            except Exception as e:
                log.debug(f"CORS probe error: {e}")

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(key=lambda x: sev_order.get(x.severity, 9))

    critical = sum(1 for f in findings if f.severity == "critical")
    high     = sum(1 for f in findings if f.severity == "high")

    if critical:
        safe_print(f"  [danger]⚠  {critical} critical CORS misconfiguration(s) found![/]")
    if high:
        safe_print(f"  [warning]{high} high-severity CORS finding(s)[/]")

    # Save report
    out_file = out_folder / "cors_findings.txt"
    lines = [f"# CORS Scan Results — {target_domain}\n"]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.url}")
        lines.append(f"  Origin sent:  {f.origin_sent}")
        lines.append(f"  ACAO:         {f.acao_header}")
        lines.append(f"  ACAC:         {f.acac_header}")
        lines.append(f"  Issue:        {f.detail}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    safe_print(
        f"[success]✔ CORS Scanner: {len(findings)} finding(s) "
        f"(critical={critical}, high={high})[/]"
    )
    return findings
