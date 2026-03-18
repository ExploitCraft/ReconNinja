"""
output/report_html.py — ReconNinja v3.3
Generates a professional self-contained HTML pentest report.
Single file — all CSS/JS embedded, no internet required to view.
Dark terminal aesthetic with full embedded styles.
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
        "critical": "#ff3b3b",
        "high":     "#ff8c00",
        "medium":   "#ffd700",
        "low":      "#00e676",
        "info":     "#607d8b",
    }.get(sev.lower(), "#607d8b")


def _badge(sev: str) -> str:
    c = _severity_color(sev)
    return (f'<span class="badge" style="background:{c};color:'
            f'{"#000" if sev.lower() in ("medium","low") else "#fff"}'
            f'">{sev.upper()}</span>')


def _build_html(r: ReconResult) -> str:
    total_ports = sum(len(h.open_ports) for h in r.hosts)
    total_vulns = len(r.nuclei_findings)
    total_hosts = len(r.hosts)
    total_subs  = len(r.subdomains)
    crit_count  = sum(1 for v in r.nuclei_findings if v.severity == "critical")
    high_count  = sum(1 for v in r.nuclei_findings if v.severity == "high")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk_color = "#ff3b3b" if crit_count else "#ff8c00" if high_count else "#ffd700" if total_vulns else "#00e676"
    risk_label = "CRITICAL" if crit_count else "HIGH" if high_count else "MEDIUM" if total_vulns else "LOW"

    # ── Port rows ────────────────────────────────────────────────
    port_rows = ""
    for host in r.hosts:
        for p in host.open_ports:
            svc = " ".join(filter(None, [p.service, p.product, p.version]))
            port_rows += f"""
            <tr>
              <td><code class="ip">{host.ip}</code></td>
              <td><strong class="port-num">{p.port}</strong></td>
              <td class="dim">{p.protocol}</td>
              <td><span class="state-open">● open</span></td>
              <td>{svc or "<span class='dim'>—</span>"}</td>
              <td>{_badge(p.severity)}</td>
            </tr>"""

    # ── Vuln rows ────────────────────────────────────────────────
    sev_order = ["critical","high","medium","low","info"]
    sorted_vulns = sorted(r.nuclei_findings,
        key=lambda v: sev_order.index(v.severity) if v.severity in sev_order else 9)

    vuln_rows = ""
    for v in sorted_vulns:
        cve_link = (f'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/{v.cve}" '
                    f'target="_blank">{v.cve}</a>' if v.cve else "<span class='dim'>—</span>")
        vuln_rows += f"""
        <tr>
          <td>{_badge(v.severity)}</td>
          <td class="vuln-title">{v.title}</td>
          <td><code class="ip">{v.target}</code></td>
          <td class="dim">{v.tool}</td>
          <td>{cve_link}</td>
          <td class="details-cell dim">{v.details[:120] + "…" if v.details and len(v.details) > 120 else v.details or "—"}</td>
        </tr>"""

    # ── Web rows ─────────────────────────────────────────────────
    web_rows = ""
    for wf in r.web_findings:
        tech = ", ".join(wf.technologies) if wf.technologies else "<span class='dim'>—</span>"
        code_cls = "status-ok" if 200 <= wf.status_code < 300 else \
                   "status-warn" if 300 <= wf.status_code < 400 else "status-err"
        web_rows += f"""
        <tr>
          <td><span class="{code_cls}">{wf.status_code}</span></td>
          <td><a class="url-link" href="{wf.url}" target="_blank">{wf.url}</a></td>
          <td>{wf.title or "<span class='dim'>—</span>"}</td>
          <td class="dim">{tech}</td>
        </tr>"""

    # ── Build section HTML ───────────────────────────────────────
    ports_html = f"""
      <div class="table-wrap">
        <table><thead><tr>
          <th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service / Version</th><th>Risk</th>
        </tr></thead><tbody>{port_rows}</tbody></table>
      </div>""" if port_rows else "<p class='empty'>No open ports discovered.</p>"

    vulns_html = f"""
      <div class="table-wrap">
        <table><thead><tr>
          <th>Severity</th><th>Title</th><th>Target</th><th>Tool</th><th>CVE</th><th>Details</th>
        </tr></thead><tbody>{vuln_rows}</tbody></table>
      </div>""" if vuln_rows else "<p class='empty'>No vulnerabilities found.</p>"

    web_html = f"""
      <div class="table-wrap">
        <table><thead><tr>
          <th>Status</th><th>URL</th><th>Title</th><th>Technologies</th>
        </tr></thead><tbody>{web_rows}</tbody></table>
      </div>""" if web_rows else "<p class='empty'>No web services found.</p>"

    sub_html = ('<div class="sub-grid">' +
                "".join(f'<div class="sub-item"><code>{s}</code></div>' for s in sorted(r.subdomains)) +
                "</div>") if r.subdomains else "<p class='empty'>No subdomains discovered.</p>"

    ai_section = f"""
    <section id="ai">
      <h2><span class="sec-icon">🤖</span> AI Threat Analysis</h2>
      <div class="ai-box"><pre>{r.ai_analysis}</pre></div>
    </section>""" if r.ai_analysis else ""

    ai_nav = "<a href='#ai'>AI Analysis</a>" if r.ai_analysis else ""

    error_section = f"""
    <section id="errors">
      <h2><span class="sec-icon">⚠</span> Errors / Warnings</h2>
      <ul class="error-list">{"".join(f"<li>{e}</li>" for e in r.errors)}</ul>
    </section>""" if r.errors else ""

    error_nav = "<a href='#errors'>Errors</a>" if r.errors else ""

    phases_html = " → ".join(f'<span class="phase">{p}</span>' for p in r.phases_completed) or "<span class='dim'>none</span>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconNinja Report — {r.target}</title>
<style>
  /* ── Reset & Base ─────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:       #0d1117;
    --bg2:      #161b22;
    --bg3:      #21262d;
    --border:   #30363d;
    --text:     #e6edf3;
    --dim:      #7d8590;
    --accent:   #00d4ff;
    --accent2:  #7c3aed;
    --green:    #00e676;
    --red:      #ff3b3b;
    --orange:   #ff8c00;
    --yellow:   #ffd700;
    --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    --font-ui:   'Segoe UI', system-ui, -apple-system, sans-serif;
  }}

  html {{ scroll-behavior: smooth; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Scrollbar ────────────────────────────────────── */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}

  /* ── Header ──────────────────────────────────────── */
  .site-header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1a0a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px 24px;
    position: relative;
    overflow: hidden;
  }}

  .site-header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,0.02) 2px,
      rgba(0,212,255,0.02) 4px
    );
    pointer-events: none;
  }}

  .header-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    flex-wrap: wrap;
  }}

  .brand {{
    display: flex;
    align-items: center;
    gap: 16px;
  }}

  .brand-logo {{
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 24px;
    flex-shrink: 0;
  }}

  .brand-text h1 {{
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: var(--text);
  }}

  .brand-text .subtitle {{
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 12px;
    opacity: 0.8;
  }}

  .risk-badge-large {{
    padding: 8px 20px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 1px;
    border: 1px solid currentColor;
    background: color-mix(in srgb, currentColor 15%, transparent);
  }}

  .target-info {{
    margin-top: 20px;
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
  }}

  .target-field label {{
    display: block;
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--dim);
    margin-bottom: 4px;
  }}

  .target-field .value {{
    font-family: var(--font-mono);
    font-size: 14px;
    color: var(--accent);
  }}

  /* ── Stat cards ───────────────────────────────────── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    padding: 24px 40px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
  }}

  .stat-card {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }}

  .stat-card:hover {{ border-color: var(--accent); }}

  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--card-accent, var(--accent));
  }}

  .stat-card .stat-num {{
    font-size: 32px;
    font-weight: 700;
    font-family: var(--font-mono);
    line-height: 1;
    color: var(--card-accent, var(--accent));
  }}

  .stat-card .stat-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--dim);
    margin-top: 4px;
  }}

  /* ── Nav ──────────────────────────────────────────── */
  nav {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(13,17,23,0.95);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border);
    padding: 0 40px;
    display: flex;
    gap: 0;
    overflow-x: auto;
  }}

  nav a {{
    display: inline-block;
    padding: 14px 18px;
    color: var(--dim);
    text-decoration: none;
    font-size: 13px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: color 0.2s, border-color 0.2s;
    white-space: nowrap;
  }}

  nav a:hover {{
    color: var(--text);
    border-bottom-color: var(--accent);
  }}

  /* ── Main layout ─────────────────────────────────── */
  main {{ padding: 32px 40px; max-width: 1400px; margin: 0 auto; }}

  section {{
    margin-bottom: 40px;
    animation: fadeIn 0.3s ease;
  }}

  @keyframes fadeIn {{ from {{ opacity:0; transform:translateY(8px); }} to {{ opacity:1; transform:none; }} }}

  section h2 {{
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .sec-icon {{ font-size: 18px; }}

  /* ── Tables ──────────────────────────────────────── */
  .table-wrap {{
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 10px;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}

  thead tr {{
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
  }}

  th {{
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--dim);
    font-weight: 600;
  }}

  td {{
    padding: 10px 14px;
    border-bottom: 1px solid rgba(48,54,61,0.5);
    vertical-align: middle;
  }}

  tr:last-child td {{ border-bottom: none; }}

  tbody tr {{ transition: background 0.15s; }}
  tbody tr:hover {{ background: rgba(255,255,255,0.03); }}

  /* ── Components ───────────────────────────────────── */
  code {{
    font-family: var(--font-mono);
    font-size: 12px;
    background: rgba(255,255,255,0.06);
    padding: 2px 6px;
    border-radius: 4px;
  }}

  code.ip {{ color: var(--accent); background: rgba(0,212,255,0.08); }}

  .port-num {{
    font-family: var(--font-mono);
    font-size: 14px;
    color: var(--accent2);
  }}

  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    font-family: var(--font-mono);
  }}

  .state-open {{
    color: var(--green);
    font-family: var(--font-mono);
    font-size: 12px;
  }}

  .status-ok   {{ color: var(--green);  font-family: var(--font-mono); font-weight: 700; }}
  .status-warn {{ color: var(--yellow); font-family: var(--font-mono); font-weight: 700; }}
  .status-err  {{ color: var(--red);    font-family: var(--font-mono); font-weight: 700; }}

  .dim {{ color: var(--dim); }}

  .cve-link {{
    color: var(--orange);
    text-decoration: none;
    font-family: var(--font-mono);
    font-size: 12px;
  }}
  .cve-link:hover {{ text-decoration: underline; }}

  .url-link {{ color: var(--accent); text-decoration: none; font-size: 12px; }}
  .url-link:hover {{ text-decoration: underline; }}

  .vuln-title {{ font-weight: 500; }}
  .details-cell {{ font-size: 12px; max-width: 300px; }}

  /* ── Subdomains grid ──────────────────────────────── */
  .sub-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 8px;
  }}

  .sub-item {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    transition: border-color 0.15s;
  }}
  .sub-item:hover {{ border-color: var(--accent); }}
  .sub-item code {{ background: none; padding: 0; color: var(--text); font-size: 13px; }}

  /* ── AI box ──────────────────────────────────────── */
  .ai-box {{
    background: linear-gradient(135deg, rgba(124,58,237,0.05), rgba(0,212,255,0.05));
    border: 1px solid rgba(124,58,237,0.3);
    border-radius: 10px;
    padding: 20px 24px;
  }}

  .ai-box pre {{
    font-family: var(--font-mono);
    font-size: 13px;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.7;
    color: var(--text);
  }}

  /* ── Error list ──────────────────────────────────── */
  .error-list {{
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}

  .error-list li {{
    background: rgba(255,59,59,0.06);
    border: 1px solid rgba(255,59,59,0.2);
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 10px 14px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: #ffaaaa;
  }}

  /* ── Phases ──────────────────────────────────────── */
  .phases-wrap {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 12px;
  }}

  .phase {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 3px 10px;
    font-family: var(--font-mono);
    color: var(--accent);
    font-size: 11px;
  }}

  .phases-wrap span.arrow {{ color: var(--dim); }}

  /* ── Empty state ─────────────────────────────────── */
  .empty {{
    color: var(--dim);
    font-style: italic;
    padding: 20px;
    text-align: center;
    background: var(--bg2);
    border: 1px dashed var(--border);
    border-radius: 8px;
  }}

  /* ── Footer ──────────────────────────────────────── */
  footer {{
    text-align: center;
    padding: 24px 40px;
    color: var(--dim);
    font-size: 12px;
    border-top: 1px solid var(--border);
    font-family: var(--font-mono);
  }}

  footer a {{ color: var(--accent); text-decoration: none; }}

  /* ── Responsive ──────────────────────────────────── */
  @media (max-width: 768px) {{
    .site-header, .stats-grid, main, nav {{ padding-left: 16px; padding-right: 16px; }}
    .header-top {{ flex-direction: column; }}
  }}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────── -->
<header class="site-header">
  <div class="header-top">
    <div class="brand">
      <div class="brand-logo">🥷</div>
      <div class="brand-text">
        <h1>ReconNinja</h1>
        <div class="subtitle">v5.2.2 // Automated Recon Framework</div>
      </div>
    </div>
    <div class="risk-badge-large" style="color:{risk_color}">{risk_label} RISK</div>
  </div>
  <div class="target-info">
    <div class="target-field">
      <label>Target</label>
      <div class="value">{r.target}</div>
    </div>
    <div class="target-field">
      <label>Scan Start</label>
      <div class="value">{r.start_time}</div>
    </div>
    <div class="target-field">
      <label>Scan End</label>
      <div class="value">{r.end_time or "—"}</div>
    </div>
    <div class="target-field">
      <label>Generated</label>
      <div class="value">{generated_at}</div>
    </div>
    <div class="target-field">
      <label>Phases</label>
      <div class="phases-wrap">{phases_html}</div>
    </div>
  </div>
</header>

<!-- ── Stats ──────────────────────────────────────────── -->
<div class="stats-grid">
  <div class="stat-card" style="--card-accent: var(--accent)">
    <div class="stat-num">{total_hosts}</div>
    <div class="stat-label">Hosts</div>
  </div>
  <div class="stat-card" style="--card-accent: var(--accent2)">
    <div class="stat-num">{total_ports}</div>
    <div class="stat-label">Open Ports</div>
  </div>
  <div class="stat-card" style="--card-accent: var(--red)">
    <div class="stat-num">{crit_count}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card" style="--card-accent: var(--orange)">
    <div class="stat-num">{high_count}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card" style="--card-accent: var(--yellow)">
    <div class="stat-num">{total_vulns}</div>
    <div class="stat-label">Total Vulns</div>
  </div>
  <div class="stat-card" style="--card-accent: var(--green)">
    <div class="stat-num">{total_subs}</div>
    <div class="stat-label">Subdomains</div>
  </div>
</div>

<!-- ── Nav ────────────────────────────────────────────── -->
<nav>
  <a href="#ports">Ports</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#web">Web Services</a>
  <a href="#subdomains">Subdomains</a>
  {ai_nav}
  {error_nav}
</nav>

<!-- ── Content ────────────────────────────────────────── -->
<main>

  <section id="ports">
    <h2><span class="sec-icon">🔌</span> Open Ports &amp; Services
      <span class="dim" style="font-size:12px;font-weight:400;margin-left:8px">{total_ports} found</span>
    </h2>
    {ports_html}
  </section>

  <section id="vulns">
    <h2><span class="sec-icon">🚨</span> Vulnerability Findings
      <span class="dim" style="font-size:12px;font-weight:400;margin-left:8px">{total_vulns} found</span>
    </h2>
    {vulns_html}
  </section>

  <section id="web">
    <h2><span class="sec-icon">🌐</span> Web Services
      <span class="dim" style="font-size:12px;font-weight:400;margin-left:8px">{len(r.web_findings)} found</span>
    </h2>
    {web_html}
  </section>

  <section id="subdomains">
    <h2><span class="sec-icon">🔍</span> Subdomains
      <span class="dim" style="font-size:12px;font-weight:400;margin-left:8px">{total_subs} found</span>
    </h2>
    {sub_html}
  </section>

  {ai_section}
  {error_section}

</main>

<footer>
  <p>Generated by <a href="https://github.com/ExploitCraft/ReconNinja" target="_blank">ReconNinja v5.2.2</a>
  · {generated_at}
  · For authorized use only</p>
</footer>

</body>
</html>
"""
