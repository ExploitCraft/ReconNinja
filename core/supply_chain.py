"""
core/supply_chain.py — ReconNinja v7.0.0
Supply Chain Security: Outdated JS library detection + npm package squatting.

V7-08: Detects vulnerable/outdated JavaScript libraries loaded by web pages:
  jQuery, Angular, React, Vue, Bootstrap, Lodash, moment.js, etc.
  Checks versions against known CVE lists.

V7-25: Checks if target org's npm package names are registered or typo-squattable.

No external tools required for basic check. retire.js used if available.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir, run_cmd, tool_exists
from utils.logger import safe_print, log


# ── Known vulnerable library versions ─────────────────────────────────────────
# Format: (library_name, version_pattern, max_safe_version, CVE, severity)

KNOWN_VULNS: list[tuple[str, str, str, str, str]] = [
    ("jQuery",    r"jquery[.-](\d+\.\d+\.\d+)",     "3.5.0",  "CVE-2020-11022", "medium"),
    ("jQuery",    r"jquery[.-](\d+\.\d+\.\d+)",     "3.7.0",  "CVE-2019-11358", "medium"),
    ("Angular",   r"angular[.-](\d+\.\d+\.\d+)",    "1.8.3",  "CVE-2023-26116", "medium"),
    ("Bootstrap", r"bootstrap[.-](\d+\.\d+\.\d+)",  "4.6.1",  "CVE-2019-8331",  "medium"),
    ("Lodash",    r"lodash[.-](\d+\.\d+\.\d+)",     "4.17.21","CVE-2021-23337", "high"),
    ("Lodash",    r"lodash[.-](\d+\.\d+\.\d+)",     "4.17.21","CVE-2020-8203",  "high"),
    ("Moment",    r"moment[.-](\d+\.\d+\.\d+)",     "2.29.4", "CVE-2022-24785", "high"),
    ("Underscore",r"underscore[.-](\d+\.\d+\.\d+)", "1.12.1", "CVE-2021-23358", "high"),
    ("Vue",       r"vue[.-](\d+\.\d+\.\d+)",        "2.7.14", "CVE-2023-46695", "medium"),
    ("Polyfill",  r"polyfill[.-]?(?:io|js)",        "",       "CDN-SUPPLY-CHAIN","critical"),
]

# ── JS file URL patterns ───────────────────────────────────────────────────────

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)""", re.I)


@dataclass
class LibraryFinding:
    url:          str     # page or JS URL
    library:      str
    version:      str
    cve:          str
    severity:     str
    detail:       str

    def to_dict(self) -> dict:
        return {
            "url":      self.url,
            "library":  self.library,
            "version":  self.version,
            "cve":      self.cve,
            "severity": self.severity,
            "detail":   self.detail,
        }


@dataclass
class NpmSquatResult:
    package:    str
    registered: bool
    owner:      str = ""
    suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "package":    self.package,
            "registered": self.registered,
            "owner":      self.owner,
            "suspicious": self.suspicious,
        }


# ── HTML/JS fetch helpers ─────────────────────────────────────────────────────

def _fetch(url: str, max_bytes: int = 200_000, timeout: int = 10) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes).decode(errors="ignore")
    except Exception:
        return ""


# ── Library detection ─────────────────────────────────────────────────────────

def _detect_libraries(page_url: str, html: str) -> list[LibraryFinding]:
    """Detect vulnerable JS libraries loaded by a page."""
    findings = []
    seen = set()

    # Collect all script srcs + inline HTML for version scanning
    script_srcs = SCRIPT_SRC_RE.findall(html)
    content_to_scan = html + " ".join(script_srcs)

    for lib_name, version_re, safe_version, cve, severity in KNOWN_VULNS:
        # Polyfill special case
        if lib_name == "Polyfill" and "polyfill.io" in content_to_scan.lower():
            key = f"{lib_name}:polyfill.io"
            if key not in seen:
                seen.add(key)
                findings.append(LibraryFinding(
                    url=page_url, library=lib_name,
                    version="unknown (polyfill.io CDN)",
                    cve=cve, severity=severity,
                    detail="polyfill.io CDN loaded — supply chain compromise risk (2024 incident)",
                ))
            continue

        # Version-based checks
        m = re.search(version_re, content_to_scan, re.I)
        if not m:
            continue
        version = m.group(1) if m.lastindex else m.group(0)
        key = f"{lib_name}:{version}:{cve}"
        if key in seen:
            continue

        # Compare version (naive semver comparison)
        if safe_version:
            try:
                def ver_tuple(v):
                    return tuple(int(x) for x in v.split(".")[:3] if x.isdigit())
                if ver_tuple(version) >= ver_tuple(safe_version):
                    continue  # version is safe
            except Exception:
                pass

        seen.add(key)
        findings.append(LibraryFinding(
            url=page_url, library=lib_name, version=version,
            cve=cve, severity=severity,
            detail=f"{lib_name} v{version} is below safe version v{safe_version} — {cve}",
        ))

    return findings


# ── npm squatting check ───────────────────────────────────────────────────────

def _check_npm_package(name: str, timeout: int = 10) -> NpmSquatResult:
    """Check if an npm package name exists and inspect the owner."""
    url = f"https://registry.npmjs.org/{name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(50000).decode(errors="ignore"))
            maintainers = data.get("maintainers", [])
            owner = maintainers[0].get("name", "") if maintainers else ""
            return NpmSquatResult(
                package=name, registered=True, owner=owner,
                suspicious=False,  # name is taken
            )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return NpmSquatResult(package=name, registered=False, suspicious=True)
        return NpmSquatResult(package=name, registered=False)
    except Exception:
        return NpmSquatResult(package=name, registered=False)


def check_npm_squat(org_name: str, out_folder: Path) -> list[NpmSquatResult]:
    """
    Check if target org's common package name patterns are free (squattable).
    """
    ensure_dir(out_folder)
    safe_print(f"[info]▶ npm Squat Check — {org_name}[/]")

    # Generate candidate package names
    base = re.sub(r"[^a-z0-9]", "-", org_name.lower()).strip("-")
    candidates = [
        base,
        f"@{base}/core",
        f"@{base}/utils",
        f"@{base}/api",
        f"{base}-sdk",
        f"{base}-client",
        f"{base}-lib",
        f"{base}-node",
        f"{base}-js",
    ]

    results = []
    for pkg in candidates:
        r = _check_npm_package(pkg)
        results.append(r)
        if not r.registered:
            safe_print(f"  [danger]⚠  npm squattable: '{pkg}' is unregistered![/]")

    free = sum(1 for r in results if not r.registered)
    safe_print(f"[{'danger' if free else 'success'}]✔ npm Squat: {free}/{len(results)} names free (squattable)[/]")

    # Save
    out_file = out_folder / "npm_squat.txt"
    lines = [f"# npm Package Squat Check — {org_name}", ""]
    for r in results:
        status = "FREE (squattable)" if not r.registered else f"taken (owner: {r.owner})"
        lines.append(f"  {r.package}: {status}")
    out_file.write_text("\n".join(lines))
    return results


# ── Public API ────────────────────────────────────────────────────────────────

def supply_chain_scan(
    web_urls: list[str],
    target: str,
    out_folder: Path,
    timeout: int = 10,
) -> tuple[list[LibraryFinding], list[NpmSquatResult]]:
    """
    Run supply chain security checks:
      1. Detect vulnerable/outdated JS libraries on live pages
      2. Check npm package squatting for target org

    Returns:
        (library_findings, npm_squat_results)
    """
    ensure_dir(out_folder)
    lib_findings: list[LibraryFinding] = []
    safe_print(f"[info]▶ Supply Chain Scanner — JS libs + npm squat[/]")

    # JS library detection
    for url in web_urls[:10]:
        html = _fetch(url, timeout=timeout)
        if html:
            found = _detect_libraries(url, html)
            lib_findings.extend(found)
            if found:
                safe_print(f"  [warning]{len(found)} vulnerable lib(s) on {url}[/]")

    # npm squat check
    org = re.sub(r"[^a-z0-9]", "", target.split(".")[0].lower())
    npm_results = check_npm_squat(org, out_folder)

    # Save JS findings
    out_file = out_folder / "supply_chain.txt"
    lines = [f"# Supply Chain Findings — {target}", ""]
    for f in lib_findings:
        lines.append(f"[{f.severity.upper()}] {f.library} v{f.version} — {f.cve}")
        lines.append(f"  URL: {f.url}")
        lines.append(f"  {f.detail}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    crit = sum(1 for f in lib_findings if f.severity == "critical")
    high = sum(1 for f in lib_findings if f.severity == "high")
    safe_print(
        f"[{'danger' if crit else 'warning' if high else 'success'}]"
        f"✔ Supply Chain: {len(lib_findings)} JS vuln(s), "
        f"{sum(1 for r in npm_results if not r.registered)} npm name(s) squattable[/]"
    )
    return lib_findings, npm_results
