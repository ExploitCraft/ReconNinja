"""
output/integrations.py — ReconNinja v8.0.0
Output integrations:
  - PDF report export (weasyprint or fpdf2 fallback)
  - Jira issue creation per finding
  - GitHub Issues creation per finding
  - Splunk/Elastic SIEM HEC push
"""
from __future__ import annotations
import json, ssl, urllib.request, urllib.parse, urllib.error, base64
from datetime import datetime
from pathlib import Path
from typing import Any
from utils.logger import safe_print
from utils.models import ReconResult, VulnFinding

# ── PDF Export ────────────────────────────────────────────────────────────────

def export_pdf(result: ReconResult, out_folder: Path) -> Path | None:
    """
    Export a pentest-ready PDF report with exec summary, charts, finding tables.
    Uses weasyprint if available, falls back to fpdf2, then HTML-only if neither.
    """
    out_folder.mkdir(parents=True, exist_ok=True)
    out_path = out_folder / f"reconinja_report_{result.target.replace('/', '_')}.pdf"

    # Build HTML content first (always works)
    html = _build_report_html(result)

    # Try weasyprint
    try:
        from weasyprint import HTML as WP_HTML
        WP_HTML(string=html).write_pdf(str(out_path))
        safe_print(f"  [success]✓ PDF exported (weasyprint): {out_path.name}[/]")
        return out_path
    except ImportError:
        pass

    # Try fpdf2
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 12, "ReconNinja v8.0.0 — Security Report", ln=True, align="C")
        pdf.set_font("Helvetica", size=11)
        pdf.cell(0, 8, f"Target: {result.target}", ln=True)
        pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", ln=True)
        pdf.ln(5)

        # Stats bar
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 9, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", size=10)
        crit = sum(1 for v in result.vuln_findings if v.severity == "critical")
        high = sum(1 for v in result.vuln_findings if v.severity == "high")
        pdf.cell(0, 7, f"Subdomains: {len(result.subdomains)}  |  Open Ports: {len(result.open_ports)}  |  Vulnerabilities: {len(result.vuln_findings)}  (Critical: {crit}, High: {high})", ln=True)
        pdf.ln(4)

        # Findings table
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 9, "Vulnerability Findings", ln=True)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(25, 7, "Severity", border=1)
        pdf.cell(80, 7, "Title", border=1)
        pdf.cell(85, 7, "Detail", border=1, ln=True)
        pdf.set_font("Helvetica", size=8)
        for vf in result.vuln_findings[:50]:
            sev_colors = {"critical": (255, 0, 0), "high": (220, 80, 0),
                          "medium": (200, 160, 0), "low": (60, 120, 60)}
            r, g, b = sev_colors.get(vf.severity, (80, 80, 80))
            pdf.set_text_color(r, g, b)
            pdf.cell(25, 6, vf.severity.upper(), border=1)
            pdf.set_text_color(0, 0, 0)
            title = vf.title[:45] + "…" if len(vf.title) > 45 else vf.title
            detail = vf.details[:55] + "…" if len(vf.details) > 55 else vf.details
            pdf.cell(80, 6, title, border=1)
            pdf.cell(85, 6, detail, border=1, ln=True)

        pdf.output(str(out_path))
        safe_print(f"  [success]✓ PDF exported (fpdf2): {out_path.name}[/]")
        return out_path
    except ImportError:
        pass

    # Final fallback: save HTML (rename to .html)
    html_path = out_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    safe_print(f"  [dim]PDF libs not installed — saved HTML report: {html_path.name}[/]")
    safe_print("  [dim]Install: pip install weasyprint  OR  pip install fpdf2[/]")
    return html_path


def _build_report_html(result: ReconResult) -> str:
    rows = ""
    for vf in result.vuln_findings[:100]:
        color = {"critical": "#c0392b", "high": "#e67e22",
                 "medium": "#f39c12", "low": "#27ae60"}.get(vf.severity, "#666")
        rows += (f'<tr><td style="color:{color};font-weight:bold">{vf.severity.upper()}</td>'
                 f'<td>{vf.title}</td><td>{vf.tool}</td>'
                 f'<td>{vf.details[:120]}</td></tr>')

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
  h1 {{ color: #1a1a2e; }} h2 {{ color: #16213e; border-bottom: 2px solid #e74c3c; }}
  .stat {{ display: inline-block; background: #f4f4f4; border-radius: 8px;
           padding: 10px 20px; margin: 8px; text-align: center; }}
  .stat .n {{ font-size: 2em; font-weight: bold; }}
  .stat.crit .n {{ color: #c0392b; }} .stat.high .n {{ color: #e67e22; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th {{ background: #1a1a2e; color: white; padding: 8px; text-align: left; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
  tr:hover {{ background: #f9f9f9; }}
</style>
</head><body>
<h1>🥷 ReconNinja v8.0.0 — Security Report</h1>
<p><strong>Target:</strong> {result.target} &nbsp;|&nbsp;
   <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>

<h2>Executive Summary</h2>
<div class="stat crit"><div class="n">{sum(1 for v in result.vuln_findings if v.severity=="critical")}</div>Critical</div>
<div class="stat high"><div class="n">{sum(1 for v in result.vuln_findings if v.severity=="high")}</div>High</div>
<div class="stat"><div class="n">{sum(1 for v in result.vuln_findings if v.severity=="medium")}</div>Medium</div>
<div class="stat"><div class="n">{sum(1 for v in result.vuln_findings if v.severity=="low")}</div>Low</div>
<div class="stat"><div class="n">{len(result.subdomains)}</div>Subdomains</div>
<div class="stat"><div class="n">{len(result.open_ports)}</div>Open Ports</div>

<h2>Vulnerability Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Detail</th></tr>
{rows}
</table>

<h2>Open Ports</h2><p>{", ".join(f"{p.port}/{p.protocol}" for p in result.open_ports[:30]) or "None detected"}</p>
<h2>Subdomains ({len(result.subdomains)})</h2><p>{", ".join(list(result.subdomains)[:30]) or "None found"}</p>

<p style="color:#999;font-size:0.8em;margin-top:40px">
Generated by ReconNinja v8.0.0 — For authorized security testing only.</p>
</body></html>"""


# ── Jira Integration ─────────────────────────────────────────────────────────

def push_to_jira(findings: list[VulnFinding], jira_config: dict) -> int:
    """
    Create one Jira issue per finding (up to 25). Returns count created.
    jira_config: {url, email, api_token, project_key}
    """
    url = jira_config.get("url", "").rstrip("/")
    email = jira_config.get("email", "")
    token = jira_config.get("api_token", "")
    project = jira_config.get("project_key", "SEC")

    if not all([url, email, token]):
        safe_print("  [dim]Jira: missing url/email/api_token in config[/]")
        return 0

    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    priority_map = {"critical": "Highest", "high": "High",
                    "medium": "Medium", "low": "Low"}
    label_map = {"critical": "security-critical", "high": "security-high",
                 "medium": "security-medium", "low": "security-low"}

    created = 0
    for finding in findings[:25]:
        payload = json.dumps({
            "fields": {
                "project": {"key": project},
                "summary": f"[ReconNinja] {finding.severity.upper()}: {finding.title}",
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text":
                            f"Tool: {finding.tool}\n"
                            f"Target: {finding.target}\n"
                            f"Severity: {finding.severity.upper()}\n\n"
                            f"Details:\n{finding.details}\n\n"
                            f"Generated by ReconNinja v8.0.0"}]
                    }]
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(finding.severity, "Medium")},
                "labels": [label_map.get(finding.severity, "security"), "reconinja"],
            }
        }).encode()

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(f"{url}/rest/api/3/issue",
                                         data=payload, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status in (200, 201):
                    created += 1
        except Exception as e:
            safe_print(f"  [dim]Jira issue creation failed: {e}[/]")

    safe_print(f"  [success]✓ Jira: {created} issues created in project {project}[/]")
    return created


# ── GitHub Issues Integration ─────────────────────────────────────────────────

def push_to_github_issues(findings: list[VulnFinding], gh_config: dict) -> int:
    """
    Create one GitHub Issue per finding (up to 25).
    gh_config: {token, owner, repo}
    """
    token = gh_config.get("token", "")
    owner = gh_config.get("owner", "")
    repo = gh_config.get("repo", "")

    if not all([token, owner, repo]):
        safe_print("  [dim]GitHub Issues: missing token/owner/repo in config[/]")
        return 0

    label_map = {
        "critical": "severity: critical",
        "high": "severity: high",
        "medium": "severity: medium",
        "low": "severity: low",
    }

    created = 0
    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }

    for finding in findings[:25]:
        body = (f"**Tool:** {finding.tool}\n"
                f"**Target:** {finding.target}\n"
                f"**Severity:** {finding.severity.upper()}\n\n"
                f"### Details\n{finding.details}\n\n"
                "---\n*Generated by ReconNinja v8.0.0*")
        payload = json.dumps({
            "title": f"[{finding.severity.upper()}] {finding.title}",
            "body": body,
            "labels": [label_map.get(finding.severity, "security"), "reconinja"],
        }).encode()
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(api_url, data=payload, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status in (200, 201):
                    created += 1
        except Exception as e:
            safe_print(f"  [dim]GitHub issue failed: {e}[/]")

    safe_print(f"  [success]✓ GitHub Issues: {created} issues created in {owner}/{repo}[/]")
    return created


# ── SIEM (Splunk / Elastic) HEC Push ─────────────────────────────────────────

def push_to_siem(result: ReconResult, siem_config: dict) -> int:
    """
    Stream all findings as structured JSON events to a SIEM HEC endpoint.
    siem_config: {url, token, index (optional), type: "splunk"|"elastic"}
    """
    hec_url = siem_config.get("url", "")
    hec_token = siem_config.get("token", "")
    siem_type = siem_config.get("type", "splunk")

    if not all([hec_url, hec_token]):
        safe_print("  [dim]SIEM: missing url/token in config[/]")
        return 0

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    pushed = 0
    ts = datetime.utcnow().isoformat() + "Z"

    for finding in result.vuln_findings:
        event = {
            "reconinja_version": "8.0.0",
            "timestamp": ts,
            "target": result.target,
            "tool": finding.tool,
            "severity": finding.severity,
            "title": finding.title,
            "details": finding.details,
            "finding_target": finding.target,
        }

        if siem_type == "splunk":
            payload = json.dumps({
                "time": int(datetime.utcnow().timestamp()),
                "sourcetype": "reconinja:finding",
                "index": siem_config.get("index", "security"),
                "event": event,
            }).encode()
            headers = {"Authorization": f"Splunk {hec_token}",
                       "Content-Type": "application/json"}
        else:  # elastic
            payload = json.dumps(event).encode()
            headers = {"Authorization": f"ApiKey {hec_token}",
                       "Content-Type": "application/json"}

        try:
            req = urllib.request.Request(hec_url, data=payload, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=8, context=ctx):
                pushed += 1
        except Exception:
            pass

    safe_print(f"  [success]✓ SIEM ({siem_type}): {pushed} events pushed to {hec_url}[/]")
    return pushed
