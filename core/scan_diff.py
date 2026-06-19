"""
core/scan_diff.py — ReconNinja v7.0.0
Scan diff — compare two JSON report files and highlight changes.

Usage:
  reconninja --diff reports/example.com/20260101/report.json \
                    reports/example.com/20260301/report.json

Outputs:
  - New open ports
  - Closed ports (previously open, now gone)
  - New subdomains
  - New vulnerabilities
  - New web services
  - Changed service versions
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import console
from rich.table import Table
from rich.panel import Panel


@dataclass
class ScanDiff:
    target:               str
    scan_a_time:          str
    scan_b_time:          str

    # Ports
    new_ports:            list[dict] = field(default_factory=list)   # opened
    closed_ports:         list[dict] = field(default_factory=list)   # closed
    changed_services:     list[dict] = field(default_factory=list)   # version changed

    # Subdomains
    new_subdomains:       list[str]  = field(default_factory=list)
    gone_subdomains:      list[str]  = field(default_factory=list)

    # Vulnerabilities
    new_vulns:            list[dict] = field(default_factory=list)
    fixed_vulns:          list[dict] = field(default_factory=list)

    # Web services
    new_web_services:     list[str]  = field(default_factory=list)
    gone_web_services:    list[str]  = field(default_factory=list)

    # New tech
    new_technologies:     list[str]  = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any([
            self.new_ports, self.closed_ports, self.changed_services,
            self.new_subdomains, self.new_vulns, self.new_web_services,
        ])

    @property
    def risk_delta(self) -> str:
        """Summarise risk change direction."""
        critical_new = sum(1 for p in self.new_ports if p.get("severity") == "critical")
        critical_new += sum(1 for v in self.new_vulns if v.get("severity") in ("critical", "high"))
        if critical_new > 3:
            return "INCREASED_CRITICAL"
        if critical_new > 0:
            return "INCREASED"
        if self.closed_ports or self.fixed_vulns:
            return "REDUCED"
        if self.has_changes:
            return "CHANGED"
        return "UNCHANGED"


# ── JSON helpers ──────────────────────────────────────────────────────────────

def _load_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"Cannot read report {path}: {e}") from e


def _port_key(port: dict) -> str:
    return f"{port.get('port')}/{port.get('protocol', 'tcp')}"


def _vuln_key(v: dict) -> str:
    return f"{v.get('tool')}:{v.get('title')}:{v.get('target')}"


# ── Diff engine ───────────────────────────────────────────────────────────────

def diff_reports(path_a: Path, path_b: Path) -> ScanDiff:
    """
    Compute diff between two ReconNinja JSON reports.

    path_a = older scan (baseline)
    path_b = newer scan (comparison)
    """
    rep_a = _load_report(path_a)
    rep_b = _load_report(path_b)

    target     = rep_b.get("meta", {}).get("target", "unknown")
    time_a     = rep_a.get("meta", {}).get("start", str(path_a))
    time_b     = rep_b.get("meta", {}).get("start", str(path_b))

    diff = ScanDiff(target=target, scan_a_time=time_a, scan_b_time=time_b)

    # ── Ports ─────────────────────────────────────────────────────────────────
    def _all_ports(report: dict) -> dict[str, dict]:
        ports: dict[str, dict] = {}
        for host in report.get("hosts", []):
            for p in host.get("ports", []):
                if p.get("state") == "open":
                    k = f"{host.get('ip', '')}:{_port_key(p)}"
                    ports[k] = {**p, "ip": host.get("ip", "")}
        return ports

    ports_a = _all_ports(rep_a)
    ports_b = _all_ports(rep_b)

    for key, port in ports_b.items():
        if key not in ports_a:
            diff.new_ports.append(port)
        else:
            old = ports_a[key]
            old_ver = f"{old.get('product','')} {old.get('version','')}".strip()
            new_ver = f"{port.get('product','')} {port.get('version','')}".strip()
            if old_ver and new_ver and old_ver != new_ver:
                diff.changed_services.append({
                    "ip": port.get("ip"), "port": port.get("port"),
                    "old_version": old_ver, "new_version": new_ver,
                })

    for key, port in ports_a.items():
        if key not in ports_b:
            diff.closed_ports.append(port)

    # ── Subdomains ────────────────────────────────────────────────────────────
    subs_a = set(rep_a.get("subdomains", []))
    subs_b = set(rep_b.get("subdomains", []))
    diff.new_subdomains  = sorted(subs_b - subs_a)
    diff.gone_subdomains = sorted(subs_a - subs_b)

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    vulns_a = {_vuln_key(v): v for v in rep_a.get("nuclei_findings", [])}
    vulns_b = {_vuln_key(v): v for v in rep_b.get("nuclei_findings", [])}
    diff.new_vulns   = [v for k, v in vulns_b.items() if k not in vulns_a]
    diff.fixed_vulns = [v for k, v in vulns_a.items() if k not in vulns_b]

    # ── Web services ──────────────────────────────────────────────────────────
    web_a = {w.get("url") for w in rep_a.get("web_findings", [])}
    web_b = {w.get("url") for w in rep_b.get("web_findings", [])}
    diff.new_web_services  = sorted(web_b - web_a)
    diff.gone_web_services = sorted(web_a - web_b)

    # ── Technologies ─────────────────────────────────────────────────────────
    tech_a: set[str] = set()
    tech_b: set[str] = set()
    for w in rep_a.get("web_findings", []):
        tech_a.update(w.get("technologies", []))
    for w in rep_b.get("web_findings", []):
        tech_b.update(w.get("technologies", []))
    diff.new_technologies = sorted(tech_b - tech_a)

    return diff


# ── Terminal renderer ─────────────────────────────────────────────────────────

def print_diff(diff: ScanDiff) -> None:
    """Render diff to the terminal using Rich tables."""
    sev_map = {"critical": "bold red", "high": "orange1", "medium": "yellow", "info": "dim"}

    console.print(Panel.fit(
        f"[header]Scan Diff — {diff.target}[/]\n"
        f"[dim]Baseline: {diff.scan_a_time}[/]\n"
        f"[dim]Current:  {diff.scan_b_time}[/]\n"
        f"Risk delta: [{('danger' if 'INCREASED' in diff.risk_delta else 'success' if diff.risk_delta == 'REDUCED' else 'warning')}]{diff.risk_delta}[/]",
        border_style="blue",
    ))

    if not diff.has_changes:
        console.print("[success]No changes detected between scans.[/]")
        return

    # New ports
    if diff.new_ports:
        t = Table(title=f"[danger]New Open Ports ({len(diff.new_ports)})[/]", show_lines=True)
        t.add_column("IP"); t.add_column("Port"); t.add_column("Service"); t.add_column("Version"); t.add_column("Severity")
        for p in diff.new_ports:
            ver = f"{p.get('product','')} {p.get('version','')}".strip()
            sev = p.get("severity", "info")
            t.add_row(p.get("ip",""), str(p.get("port","")),
                      p.get("service",""), ver or "–",
                      f"[{sev_map.get(sev,'white')}]{sev.upper()}[/]")
        console.print(t)

    # Closed ports
    if diff.closed_ports:
        t = Table(title=f"[success]Closed Ports ({len(diff.closed_ports)})[/]", show_lines=True)
        t.add_column("IP"); t.add_column("Port"); t.add_column("Service")
        for p in diff.closed_ports:
            t.add_row(p.get("ip",""), str(p.get("port","")), p.get("service",""))
        console.print(t)

    # New subdomains
    if diff.new_subdomains:
        console.print(f"\n[warning]New Subdomains ({len(diff.new_subdomains)}):[/]")
        for s in diff.new_subdomains[:20]:
            console.print(f"  [cyan]+[/] {s}")

    # New vulns
    if diff.new_vulns:
        t = Table(title=f"[danger]New Vulnerabilities ({len(diff.new_vulns)})[/]", show_lines=True)
        t.add_column("Severity"); t.add_column("Title"); t.add_column("Target"); t.add_column("CVE")
        for v in sorted(diff.new_vulns, key=lambda x: ("critical","high","medium","low","info").index(x.get("severity","info")) if x.get("severity","info") in ("critical","high","medium","low","info") else 9):
            sev = v.get("severity", "info")
            t.add_row(f"[{sev_map.get(sev,'white')}]{sev.upper()}[/]",
                      v.get("title",""), v.get("target",""), v.get("cve","–"))
        console.print(t)

    # Fixed vulns
    if diff.fixed_vulns:
        console.print(f"\n[success]Fixed/Gone Vulnerabilities ({len(diff.fixed_vulns)}):[/]")
        for v in diff.fixed_vulns[:10]:
            console.print(f"  [green]✓[/] [{v.get('severity','?').upper()}] {v.get('title','')}")

    # New web services
    if diff.new_web_services:
        console.print(f"\n[warning]New Web Services ({len(diff.new_web_services)}):[/]")
        for url in diff.new_web_services[:10]:
            console.print(f"  [cyan]+[/] {url}")

    # New technologies
    if diff.new_technologies:
        console.print(f"\n[info]New Technologies Detected:[/] {', '.join(diff.new_technologies[:15])}")


def diff_to_json(diff: ScanDiff) -> dict:
    """Serialise diff to a JSON-compatible dict."""
    return {
        "target":            diff.target,
        "baseline_time":     diff.scan_a_time,
        "current_time":      diff.scan_b_time,
        "risk_delta":        diff.risk_delta,
        "new_ports":         diff.new_ports,
        "closed_ports":      diff.closed_ports,
        "changed_services":  diff.changed_services,
        "new_subdomains":    diff.new_subdomains,
        "gone_subdomains":   diff.gone_subdomains,
        "new_vulns":         diff.new_vulns,
        "fixed_vulns":       diff.fixed_vulns,
        "new_web_services":  diff.new_web_services,
        "gone_web_services": diff.gone_web_services,
        "new_technologies":  diff.new_technologies,
    }
