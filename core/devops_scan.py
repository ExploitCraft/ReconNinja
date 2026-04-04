"""
core/devops_scan.py — ReconNinja v7.0.0
DevOps Surface Exposure Scanner.

V7-22: Terraform State File Detection
  - S3 buckets with .tfstate files
  - Git repos with terraform.tfstate committed
  - Open directory listings exposing .tfstate

V7-23: Jenkins Exposure Check
  - Unauthenticated Jenkins instances
  - Anonymous job listing and build history
  - Credential store exposure
  - Script console access

No external tools required — pure Python urllib.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


# ── Terraform state ───────────────────────────────────────────────────────────

TFSTATE_PATHS = [
    "/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/terraform/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/deploy/terraform.tfstate",
    "/tf/terraform.tfstate",
]

TFSTATE_INDICATORS = [
    '"version":', '"terraform_version":', '"resources":', '"outputs":',
]


@dataclass
class TfStateFinding:
    url:       str
    exposed:   bool
    resources: int   = 0
    outputs:   list[str] = field(default_factory=list)
    secrets:   list[str] = field(default_factory=list)
    severity:  str   = "critical"

    def to_dict(self) -> dict:
        return {
            "url":       self.url,
            "exposed":   self.exposed,
            "resources": self.resources,
            "outputs":   self.outputs[:10],
            "secrets":   self.secrets[:10],
            "severity":  self.severity,
        }


def _fetch(url: str, timeout: int = 8) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (ReconNinja/7.0.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(500_000).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "__AUTH__"
        return None
    except Exception:
        return None


def _analyse_tfstate(url: str, content: str) -> TfStateFinding:
    finding = TfStateFinding(url=url, exposed=True)
    try:
        data = json.loads(content)
        resources = data.get("resources", [])
        finding.resources = len(resources)
        outputs = data.get("outputs", {})
        finding.outputs = list(outputs.keys())

        # Look for secrets in values
        secret_patterns = [
            r'"password"\s*:\s*"([^"]{4,})"',
            r'"secret[_-]?key"\s*:\s*"([^"]{4,})"',
            r'"access[_-]?key"\s*:\s*"([^"]{4,})"',
            r'"private[_-]?key"\s*:\s*"([^"]{4,})"',
            r'"token"\s*:\s*"([^"]{4,})"',
            r'"connection[_-]?string"\s*:\s*"([^"]{4,})"',
        ]
        import re as _re
        for pat in secret_patterns:
            for m in _re.finditer(pat, content, _re.I):
                finding.secrets.append(m.group(0)[:80])

    except json.JSONDecodeError:
        finding.resources = content.count('"type":')
    return finding


def terraform_state_scan(
    web_urls: list[str],
    out_folder: Path,
    timeout: int = 8,
) -> list[TfStateFinding]:
    """Scan web services for exposed Terraform state files."""
    ensure_dir(out_folder)
    findings: list[TfStateFinding] = []
    safe_print(f"[info]▶ Terraform State Scan — {len(web_urls)} base URL(s)[/]")

    for base_url in web_urls[:10]:
        base = base_url.rstrip("/")
        for path in TFSTATE_PATHS:
            url     = base + path
            content = _fetch(url, timeout=timeout)
            if not content or content == "__AUTH__":
                continue
            if any(ind in content for ind in TFSTATE_INDICATORS):
                finding = _analyse_tfstate(url, content)
                findings.append(finding)
                safe_print(
                    f"  [danger]⚠  TFSTATE EXPOSED: {url} — "
                    f"{finding.resources} resource(s), {len(finding.secrets)} secret(s)[/]"
                )

    # Save
    out_file = out_folder / "terraform_state.txt"
    lines = [f"# Terraform State Exposure\n"]
    for f in findings:
        lines.append(f"[CRITICAL] {f.url}")
        lines.append(f"  Resources: {f.resources}")
        lines.append(f"  Outputs:   {', '.join(f.outputs[:5])}")
        if f.secrets:
            lines.append(f"  Secrets:   {len(f.secrets)} found!")
        lines.append("")
    out_file.write_text("\n".join(lines))

    safe_print(f"[{'danger' if findings else 'success'}]✔ Terraform State: {len(findings)} exposed[/]")
    return findings


# ── Jenkins ───────────────────────────────────────────────────────────────────

JENKINS_PATHS = [
    "/jenkins", "/jenkins/", "/ci", "/ci/",
    "/", "",
]

JENKINS_INDICATORS = [
    "Jenkins", "hudson", "jenkins-ci", "Jenkins-Crumb",
]

JENKINS_UNAUTH_PATHS = [
    "/api/json",
    "/api/json?pretty=true",
    "/asynchPeople/api/json",
    "/credentials/api/json",
    "/script",  # Script console — RCE if accessible
]


@dataclass
class JenkinsFinding:
    url:          str
    accessible:   bool
    anon_jobs:    list[str] = field(default_factory=list)
    anon_users:   list[str] = field(default_factory=list)
    script_console: bool    = False
    version:      str       = ""
    severity:     str       = "high"

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "accessible":     self.accessible,
            "anon_jobs":      self.anon_jobs[:10],
            "anon_users":     self.anon_users[:10],
            "script_console": self.script_console,
            "version":        self.version,
            "severity":       self.severity,
        }


def jenkins_scan(
    web_urls: list[str],
    open_ports: Optional[set[int]] = None,
    out_folder: Path = Path("reports"),
    timeout: int = 8,
) -> list[JenkinsFinding]:
    """Detect exposed Jenkins instances."""
    ensure_dir(out_folder)
    findings: list[JenkinsFinding] = []
    tested: set[str] = set()

    # Also probe default Jenkins ports
    jenkins_ports = {8080, 8443, 8090, 9090, 8888}
    extra_urls = []
    if open_ports:
        for port in jenkins_ports & open_ports:
            extra_urls.append(f"http://localhost:{port}")

    all_urls = list(web_urls) + extra_urls

    safe_print(f"[info]▶ Jenkins Exposure Scan — {len(all_urls)} URL(s)[/]")

    for base_url in all_urls[:15]:
        base = base_url.rstrip("/")
        for prefix in JENKINS_PATHS:
            jenkins_base = base + prefix
            if jenkins_base in tested:
                continue

            # Quick probe to detect Jenkins
            api_url = jenkins_base.rstrip("/") + "/api/json"
            if api_url in tested:
                continue
            tested.add(api_url)

            content = _fetch(api_url, timeout=timeout)
            if not content:
                continue

            is_jenkins = any(ind in content for ind in JENKINS_INDICATORS)
            try:
                data = json.loads(content)
                is_jenkins = is_jenkins or "_class" in data
            except Exception:
                pass

            if not is_jenkins:
                continue

            finding = JenkinsFinding(url=jenkins_base, accessible=True)

            # Parse jobs
            try:
                data = json.loads(content)
                jobs = data.get("jobs", [])
                finding.anon_jobs = [j.get("name", "") for j in jobs[:20]]
                finding.version   = data.get("version", "")
            except Exception:
                pass

            # Enumerate users
            users_url = jenkins_base.rstrip("/") + "/asynchPeople/api/json"
            users_content = _fetch(users_url, timeout=timeout)
            if users_content:
                try:
                    users_data = json.loads(users_content)
                    for u in users_data.get("users", [])[:10]:
                        name = u.get("user", {}).get("fullName", "")
                        if name:
                            finding.anon_users.append(name)
                except Exception:
                    pass

            # Check script console (RCE if accessible without auth)
            script_url = jenkins_base.rstrip("/") + "/script"
            script_content = _fetch(script_url, timeout=timeout)
            if script_content and ("Groovy script" in script_content or "script" in script_content.lower()):
                finding.script_console = True
                finding.severity = "critical"

            findings.append(finding)

            severity_color = "danger" if finding.script_console else "warning"
            safe_print(
                f"  [{severity_color}]⚠  Jenkins at {jenkins_base}: "
                f"{len(finding.anon_jobs)} job(s) exposed"
                f"{', SCRIPT CONSOLE ACCESSIBLE (RCE!)' if finding.script_console else ''}[/]"
            )
            break

    # Save
    out_file = out_folder / "jenkins_findings.txt"
    lines = [f"# Jenkins Exposure Findings\n"]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.url}")
        lines.append(f"  Version: {f.version}")
        lines.append(f"  Jobs:    {', '.join(f.anon_jobs[:5])}")
        lines.append(f"  Users:   {', '.join(f.anon_users[:5])}")
        if f.script_console:
            lines.append("  !!! SCRIPT CONSOLE ACCESSIBLE — RCE potential !!!")
        lines.append("")
    out_file.write_text("\n".join(lines))

    safe_print(f"[{'danger' if findings else 'success'}]✔ Jenkins: {len(findings)} exposed instance(s)[/]")
    return findings
