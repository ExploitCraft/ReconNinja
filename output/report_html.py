"""
output/report_html.py — ReconNinja v3.2
Generates a professional self-contained HTML pentest report.
Single file — all CSS/JS embedded, no internet required to view.
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from utils.models import ReconResult


def generate_html_report(result: ReconResult, out_path: Path) -> Path:
    """Generate full HTML report and write to out_path. Returns the file path."""
    html = _build_html(result)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def _severity_color(sev: str) -> str:
    return {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#2ecc71",
        "info": "#95a5a6",
    }.get(sev.lower(), "#95a5a6")


def _badge(sev: str) -> str:
    c = _severity_color(sev)
    return f'<span class="badge" style="background:{c}">{sev.upper()}</span>'


def _build_html(r: ReconResult) -> str:
    total_ports = sum(len(h.open_ports) for h in r.hosts)
    total_vulns = len(r.nuclei_findings)
    total_hosts = len(r.hosts)
    total_subs = len(r.subdomains)
    crit_count = sum(1 for v in r.nuclei_findings if v.severity == "critical")
    high_count = sum(1 for v in r.nuclei_findings if v.severity == "high")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Port rows ─────────────────────────────────────────────
    port_rows = ""
    for host in r.hosts:
        for p in host.open_ports:
            svc = " ".join(filter(None, [p.service, p.product, p.version]))
            port_rows += f"""
            <tr>
              <td><code>{host.ip}</code></td>
              <td><strong>{p.port}</strong></td>
              <td>{p.protocol}</td>
              <td><span class="state-open">open</span></td>
              <td>{svc or "—"}</td>
              <td>{_badge(p.severity)}</td>
            </tr>"""

    # ── Vuln rows ─────────────────────────────────────────────
    sev_order = ["critical", "high", "medium", "low", "info"]
    sorted_vulns = sorted(
        r.nuclei_findings,
        key=lambda v: sev_order.index(v.severity)
        if v.severity in sev_order
        else 9,
    )

    vuln_rows = ""
    for v in sorted_vulns:
        cve_link = (
            f'<a href="https://nvd.nist.gov/vuln/detail/{v.cve}" target="_blank">{v.cve}</a>'
            if v.cve
            else "—"
        )
        vuln_rows += f"""
        <tr>
          <td>{_badge(v.severity)}</td>
          <td>{v.title}</td>
          <td><code>{v.target}</code></td>
          <td>{v.tool}</td>
          <td>{cve_link}</td>
          <td class="details-cell">{v.details or "—"}</td>
        </tr>"""

    # ── Web rows ─────────────────────────────────────────────
    web_rows = ""
    for wf in r.web_findings:
        tech = ", ".join(wf.technologies) if wf.technologies else "—"
        code_cls = "status-ok" if 200 <= wf.status_code < 300 else "status-err"
        web_rows += f"""
        <tr>
          <td><span class="{code_cls}">{wf.status_code}</span></td>
          <td><a href="{wf.url}" target="_blank">{wf.url}</a></td>
          <td>{wf.title or "—"}</td>
          <td>{tech}</td>
        </tr>"""

    # ── Sections precomputed (fix for 3.10/3.11) ─────────────
    ai_nav = "<a href='#ai'>AI Analysis</a>" if r.ai_analysis else ""
    error_nav = "<a href='#errors'>Errors</a>" if r.errors else ""

    if not port_rows:
        ports_section = "<p class='empty'>No ports discovered.</p>"
    else:
        ports_section = f"""
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Risk</th></tr>
            </thead>
            <tbody>{port_rows}</tbody>
          </table>
        </div>
        """

    if not vuln_rows:
        vulns_section = "<p class='empty'>No vulnerabilities found.</p>"
    else:
        vulns_section = f"""
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Severity</th><th>Title</th><th>Target</th><th>Tool</th><th>CVE</th><th>Details</th></tr>
            </thead>
            <tbody>{vuln_rows}</tbody>
          </table>
        </div>
        """

    if not web_rows:
        web_section = "<p class='empty'>No web services found.</p>"
    else:
        web_section = f"""
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Status</th><th>URL</th><th>Title</th><th>Technologies</th></tr>
            </thead>
            <tbody>{web_rows}</tbody>
          </table>
        </div>
        """

    if not r.subdomains:
        sub_section = "<p class='empty'>No subdomains discovered.</p>"
    else:
        sub_section = (
            '<div class="sub-grid">'
            + "".join(
                f'<div class="sub-item"><code>{s}</code></div>'
                for s in sorted(r.subdomains)
            )
            + "</div>"
        )

    ai_section = ""
    if r.ai_analysis:
        ai_section = f"""
        <section id="ai">
          <h2>🤖 AI Threat Analysis</h2>
          <div class="ai-box">
            <pre>{r.ai_analysis}</pre>
          </div>
        </section>
        """

    error_section = ""
    if r.errors:
        errs = "".join(f"<li>{e}</li>" for e in r.errors)
        error_section = f"""
        <section id="errors">
          <h2>⚠ Errors / Warnings</h2>
          <ul class="error-list">{errs}</ul>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconNinja Report — {r.target}</title>
</head>
<body>

<h1>ReconNinja Report</h1>
<p>Generated: {generated_at}</p>

<nav>
<a href="#summary">Summary</a>
<a href="#ports">Ports</a>
<a href="#vulns">Vulnerabilities</a>
<a href="#web">Web</a>
<a href="#subdomains">Subdomains</a>
{ai_nav}
{error_nav}
</nav>

<section id="summary">
<p>Target: {r.target}</p>
<p>Hosts: {total_hosts}</p>
<p>Ports: {total_ports}</p>
<p>Vulns: {total_vulns}</p>
</section>

<section id="ports">{ports_section}</section>
<section id="vulns">{vulns_section}</section>
<section id="web">{web_section}</section>
<section id="subdomains">{sub_section}</section>

{ai_section}
{error_section}

</body>
</html>
"""
