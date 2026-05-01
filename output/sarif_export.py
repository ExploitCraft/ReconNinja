"""
output/sarif_export.py — ReconNinja v7.0.0
SARIF 2.1.0 (Static Analysis Results Interchange Format) export.

Exports all ReconNinja findings in SARIF format for integration with:
  - GitHub Code Scanning (upload to Security tab)
  - VS Code SARIF Viewer extension
  - Azure DevOps pipeline gates
  - Any SARIF-compatible SIEM/SOAR

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.models import ReconResult, VulnFinding
VF = VulnFinding
from utils.logger import safe_print

VERSION = "7.0.0"

SEVERITY_MAP = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}

LEVEL_MAP = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}


def _make_rule(finding: VulnFinding, rule_id: str) -> dict:
    """Convert a VulnFinding into a SARIF rule definition."""
    severity = finding.severity.lower()
    return {
        "id": rule_id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {
            "text": finding.title,
        },
        "fullDescription": {
            "text": finding.details or finding.title,
        },
        "defaultConfiguration": {
            "level": LEVEL_MAP.get(severity, "warning"),
        },
        "properties": {
            "tags":           ["security", "reconnaissance"],
            "severity":       severity,
            "tool":           finding.tool,
            "cve":            finding.cve or "",
            "precision":      "medium",
            "problem.severity": severity,
        },
        "helpUri": f"https://nvd.nist.gov/vuln/detail/{finding.cve}" if finding.cve else
                   "https://github.com/ExploitCraft/ReconNinja",
    }


def _make_result(finding: VulnFinding, rule_id: str) -> dict:
    """Convert a VulnFinding into a SARIF result."""
    severity = finding.severity.lower()
    return {
        "ruleId":   rule_id,
        "level":    LEVEL_MAP.get(severity, "warning"),
        "message":  {
            "text": (
                f"{finding.title} — {finding.details}"
                if finding.details else finding.title
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri":       finding.target,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                    },
                },
                "logicalLocations": [
                    {
                        "name":                finding.target,
                        "fullyQualifiedName":  finding.target,
                        "kind":                "url",
                    }
                ],
            }
        ],
        "properties": {
            "tool":     finding.tool,
            "cve":      finding.cve or "",
            "severity": severity,
        },
    }


def _port_to_finding(host_ip: str, port_info) -> VulnFinding:
    """Convert a PortInfo to a VulnFinding for SARIF export."""
    from utils.models import VulnFinding as VF
    severity = port_info.severity
    service  = port_info.service or "unknown"
    return VF(
        tool     = "port-scanner",
        severity = severity,
        title    = f"Open port {port_info.port}/{port_info.protocol} ({service})",
        target   = f"{host_ip}:{port_info.port}",
        details  = f"Service: {service} {port_info.product} {port_info.version}".strip(),
        cve      = "",
    )


def export_sarif(result: ReconResult, out_folder: Path) -> Path:
    """
    Export all ReconNinja findings as a SARIF 2.1.0 document.

    Args:
        result:     ReconResult from completed scan
        out_folder: output directory

    Returns:
        Path to generated .sarif file
    """
    out_folder.mkdir(parents=True, exist_ok=True)

    # Collect all findings
    all_findings: list[VulnFinding] = []

    # Nuclei / vuln findings
    all_findings.extend(result.nuclei_findings)

    # Port-level findings (critical/high severity ports)
    for host in result.hosts:
        for port in host.open_ports:
            if port.severity in ("critical", "high"):
                all_findings.append(_port_to_finding(host.ip, port))

    # CORS findings
    for cf in result.cors_findings:
        all_findings.append(VF(
            tool="cors-scanner",
            severity=cf.get("severity", "medium"),
            title=f"CORS Misconfiguration — {cf.get('issue_type', '')}",
            target=cf.get("url", result.target),
            details=cf.get("detail", ""),
        ))

    # GitHub findings
    for gf in result.github_findings:
        all_findings.append(VF(
            tool="github-osint",
            severity="high",
            title=f"GitHub exposure: {gf.get('label', '')}",
            target=gf.get("url", result.target),
            details=f"Repo: {gf.get('repo', '')} — File: {gf.get('file', '')}",
        ))

    # Build rules + results
    rules:   list[dict] = []
    results_sarif: list[dict] = []
    seen_rules: dict[str, bool] = {}

    for i, finding in enumerate(all_findings):
        rule_id = f"RN{str(i+1).zfill(4)}-{finding.tool}-{finding.severity.upper()}"
        if finding.cve:
            rule_id = finding.cve

        if rule_id not in seen_rules:
            rules.append(_make_rule(finding, rule_id))
            seen_rules[rule_id] = True

        results_sarif.append(_make_result(finding, rule_id))

    # Assemble SARIF document
    sarif_doc: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":           "ReconNinja",
                        "version":        VERSION,
                        "informationUri": "https://github.com/ExploitCraft/ReconNinja",
                        "organization":   "ExploitCraft",
                        "rules":          rules,
                        "properties": {
                            "target":     result.target,
                            "scan_start": result.start_time,
                            "scan_end":   result.end_time,
                        },
                    }
                },
                "results":   results_sarif,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "target":     result.target,
                    "subdomains": len(result.subdomains),
                    "hosts":      len(result.hosts),
                },
            }
        ],
    }

    sarif_path = out_folder / "report.sarif"
    sarif_path.write_text(json.dumps(sarif_doc, indent=2))

    safe_print(
        f"[success]✔ SARIF export: {len(results_sarif)} finding(s) → {sarif_path}[/]"
    )
    return sarif_path
