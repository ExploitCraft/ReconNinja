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
    return {"critical":"#e74c3c","high":"#e67e22","medium":"#f1c40f",
            "low":"#2ecc71","info":"#95a5a6"}.get(sev.lower(), "#95a5a6")

def _badge(sev: str) -> str:
    c = _severity_color(sev)
    return f'<span class="badge" style="background:{c}">{sev.upper()}</span>'

def _build_html(r: ReconResult) -> str:
    # ── Stats ─────────────────────────────────────────────────────────────────
    total_ports  = sum(len(h.open_ports) for h in r.hosts)
    total_vulns  = len(r.nuclei_findings)
    total_hosts  = len(r.hosts)
    total_subs   = len(r.subdomains)
    crit_count   = sum(1 for v in r.nuclei_findings if v.severity == "critical")
    high_count   = sum(1 for v in r.nuclei_findings if v.severity == "high")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Port rows ─────────────────────────────────────────────────────────────
    port_rows = ""
    for host in r.hosts:
        for p in host.open_ports:
            svc = " ".join(filter(None,[p.service,p.product,p.version]))
            sev = p.severity
            port_rows += f"""
            <tr>
              <td><code>{host.ip}</code></td>
              <td><strong>{p.port}</strong></td>
              <td>{p.protocol}</td>
              <td><span class="state-open">open</span></td>
              <td>{svc or "—"}</td>
              <td>{_badge(sev)}</td>
            </tr>"""

    # ── Vuln rows ─────────────────────────────────────────────────────────────
    sev_order = ["critical","high","medium","low","info"]
    sorted_vulns = sorted(r.nuclei_findings,
        key=lambda v: sev_order.index(v.severity) if v.severity in sev_order else 9)
    vuln_rows = ""
    for v in sorted_vulns:
        cve_link = (f'<a href="https://nvd.nist.gov/vuln/detail/{v.cve}" '
                    f'target="_blank">{v.cve}</a>') if v.cve else "—"
        vuln_rows += f"""
        <tr>
          <td>{_badge(v.severity)}</td>
          <td>{v.title}</td>
          <td><code>{v.target}</code></td>
          <td>{v.tool}</td>
          <td>{cve_link}</td>
          <td class="details-cell">{v.details or "—"}</td>
        </tr>"""

    # ── Subdomain rows ────────────────────────────────────────────────────────
    sub_rows = "".join(
        f'<tr><td><code>{s}</code></td></tr>' for s in r.subdomains)

    # ── Web finding rows ──────────────────────────────────────────────────────
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

    # ── AI analysis section ───────────────────────────────────────────────────
    ai_section = ""
    if r.ai_analysis:
        ai_section = f"""
        <section id="ai">
          <h2>🤖 AI Threat Analysis</h2>
          <div class="ai-box">
            <pre>{r.ai_analysis}</pre>
          </div>
        </section>"""

    # ── Errors ────────────────────────────────────────────────────────────────
    error_section = ""
    if r.errors:
        errs = "".join(f"<li>{e}</li>" for e in r.errors)
        error_section = f"""
        <section id="errors">
          <h2>⚠ Errors / Warnings</h2>
          <ul class="error-list">{errs}</ul>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReconNinja Report — {r.target}</title>
  <style>
    :root {{
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #30363d;
      --text:     #e6edf3;
      --dim:      #8b949e;
      --green:    #2ecc71;
      --red:      #e74c3c;
      --orange:   #e67e22;
      --yellow:   #f1c40f;
      --cyan:     #58a6ff;
      --accent:   #1f6feb;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg); color: var(--text);
      line-height: 1.6; padding: 0 0 4rem 0;
    }}
    a {{ color: var(--cyan); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ font-family: 'JetBrains Mono','Fira Code',monospace;
            background: #21262d; padding: 2px 6px; border-radius: 4px;
            font-size: .85em; }}
    pre  {{ font-family: 'JetBrains Mono','Fira Code',monospace;
            background: #21262d; padding: 1rem; border-radius: 8px;
            overflow-x: auto; font-size: .85em; color: #c9d1d9; white-space: pre-wrap; }}

    /* ── Header ── */
    header {{
      background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
      border-bottom: 1px solid var(--border);
      padding: 2rem 3rem;
    }}
    header h1 {{ font-size: 2rem; color: var(--green); letter-spacing: 1px; }}
    header .meta {{ color: var(--dim); font-size: .9rem; margin-top: .5rem; }}
    header .target-badge {{
      display: inline-block; margin-top: .75rem;
      background: var(--accent); color: #fff;
      padding: .35rem 1rem; border-radius: 20px;
      font-size: .9rem; font-weight: 600;
    }}

    /* ── Navigation ── */
    nav {{
      background: var(--surface); border-bottom: 1px solid var(--border);
      padding: .75rem 3rem; position: sticky; top: 0; z-index: 100;
      display: flex; gap: 1.5rem; flex-wrap: wrap;
    }}
    nav a {{
      color: var(--dim); font-size: .85rem; font-weight: 500;
      padding: .25rem .5rem; border-radius: 4px; transition: .2s;
    }}
    nav a:hover {{ color: var(--text); background: var(--border); text-decoration: none; }}

    /* ── Stats row ── */
    .stats {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
      gap: 1rem; padding: 2rem 3rem 0;
    }}
    .stat-card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 1.25rem; text-align: center;
    }}
    .stat-card .num  {{ font-size: 2.25rem; font-weight: 700; color: var(--cyan); }}
    .stat-card .label{{ font-size: .8rem; color: var(--dim); margin-top: .25rem; }}
    .stat-card.danger .num {{ color: var(--red); }}
    .stat-card.warn   .num {{ color: var(--orange); }}
    .stat-card.ok     .num {{ color: var(--green); }}

    /* ── Section ── */
    section {{ padding: 2rem 3rem; border-top: 1px solid var(--border); }}
    section h2 {{ font-size: 1.2rem; margin-bottom: 1rem; color: var(--cyan); }}

    /* ── Tables ── */
    .table-wrap {{ overflow-x: auto; }}
    table {{
      width: 100%; border-collapse: collapse;
      background: var(--surface); border-radius: 8px;
      overflow: hidden; font-size: .875rem;
    }}
    th {{
      background: #21262d; padding: .75rem 1rem;
      text-align: left; color: var(--dim);
      border-bottom: 1px solid var(--border); font-weight: 600;
    }}
    td {{
      padding: .65rem 1rem; border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #1c2128; }}

    /* ── Badges ── */
    .badge {{
      display: inline-block; padding: .2rem .6rem; border-radius: 12px;
      font-size: .75rem; font-weight: 700; color: #000;
    }}
    .state-open  {{ color: var(--green); font-weight: 600; }}
    .status-ok   {{ color: var(--green); font-weight: 600; }}
    .status-err  {{ color: var(--red);   font-weight: 600; }}

    .details-cell {{ max-width: 300px; font-size: .8rem; color: var(--dim); }}

    /* ── AI box ── */
    .ai-box {{
      background: var(--surface); border: 1px solid var(--accent);
      border-radius: 8px; padding: 1.5rem;
    }}

    /* ── Empty state ── */
    .empty {{ color: var(--dim); font-style: italic; padding: 1rem 0; }}

    /* ── Error list ── */
    .error-list {{ padding-left: 1.5rem; color: var(--orange); font-size: .875rem; }}

    /* ── Footer ── */
    footer {{
      text-align: center; color: var(--dim); font-size: .8rem;
      padding: 2rem; border-top: 1px solid var(--border);
    }}

    /* ── Subdomains grid ── */
    .sub-grid {{
      display: grid; grid-template-columns: repeat(auto-fill, minmax(220px,1fr));
      gap: .5rem;
    }}
    .sub-item {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 6px; padding: .4rem .8rem; font-size: .85rem;
    }}
  </style>
</head>
<body>

<header>
  <h1>🥷 ReconNinja Report</h1>
  <div class="meta">Generated: {generated_at} &nbsp;|&nbsp; Duration: {r.start_time} → {r.end_time or "ongoing"}</div>
  <div class="target-badge">🎯 {r.target}</div>
</header>

<nav>
  <a href="#summary">Summary</a>
  <a href="#ports">Ports</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#web">Web</a>
  <a href="#subdomains">Subdomains</a>
  {"<a href='#ai'>AI Analysis</a>" if r.ai_analysis else ""}
  {"<a href='#errors'>Errors</a>" if r.errors else ""}
</nav>

<div class="stats">
  <div class="stat-card {'danger' if crit_count else 'ok'}">
    <div class="num">{crit_count}</div>
    <div class="label">Critical Vulns</div>
  </div>
  <div class="stat-card {'warn' if high_count else 'ok'}">
    <div class="num">{high_count}</div>
    <div class="label">High Vulns</div>
  </div>
  <div class="stat-card">
    <div class="num">{total_vulns}</div>
    <div class="label">Total Findings</div>
  </div>
  <div class="stat-card">
    <div class="num">{total_ports}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="num">{total_hosts}</div>
    <div class="label">Hosts</div>
  </div>
  <div class="stat-card">
    <div class="num">{total_subs}</div>
    <div class="label">Subdomains</div>
  </div>
</div>

<section id="summary">
  <h2>📋 Scan Summary</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Target</td><td><code>{r.target}</code></td></tr>
    <tr><td>Start Time</td><td>{r.start_time}</td></tr>
    <tr><td>End Time</td><td>{r.end_time or "—"}</td></tr>
    <tr><td>Phases Completed</td><td>{", ".join(r.phases_completed) or "—"}</td></tr>
    <tr><td>Hosts Discovered</td><td>{total_hosts}</td></tr>
    <tr><td>Open Ports</td><td>{total_ports}</td></tr>
    <tr><td>Vulnerabilities</td><td>{total_vulns} ({crit_count} critical, {high_count} high)</td></tr>
    <tr><td>Subdomains</td><td>{total_subs}</td></tr>
  </table>
</section>

<section id="ports">
  <h2>🔌 Open Ports & Services</h2>
  {"<p class='empty'>No ports discovered.</p>" if not port_rows else f"""
  <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Risk</th></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
  </div>"""}
</section>

<section id="vulns">
  <h2>🚨 Vulnerability Findings</h2>
  {"<p class='empty'>No vulnerabilities found.</p>" if not vuln_rows else f"""
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Tool</th><th>CVE</th><th>Details</th></tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>
  </div>"""}
</section>

<section id="web">
  <h2>🌐 Web Services</h2>
  {"<p class='empty'>No web services found.</p>" if not web_rows else f"""
  <div class="table-wrap">
    <table>
      <thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Technologies</th></tr></thead>
      <tbody>{web_rows}</tbody>
    </table>
  </div>"""}
</section>

<section id="subdomains">
  <h2>🔍 Subdomains ({total_subs})</h2>
  {"<p class='empty'>No subdomains discovered.</p>" if not r.subdomains else
   '<div class="sub-grid">' +
   "".join(f'<div class="sub-item"><code>{s}</code></div>' for s in sorted(r.subdomains)) +
   '</div>'}
</section>

{ai_section}
{error_section}

<footer>
  ReconNinja v3.2 &nbsp;·&nbsp; {generated_at} &nbsp;·&nbsp;
  <strong>⚠ Authorised use only</strong>
</footer>

</body>
</html>"""
