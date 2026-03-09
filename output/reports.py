"""
ReconNinja v5.0.0 — Report Generation
Produces JSON, HTML (dark UI dashboard), and Markdown reports.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from utils.models import ReconResult, VulnFinding, HostResult

APP_NAME = "ReconNinja"
VERSION  = "5.0.0"


# ─── JSON ─────────────────────────────────────────────────────────────────────

def generate_json_report(result: ReconResult, path: Path) -> None:
    def _vuln(v: VulnFinding) -> dict:
        return {
            "tool": v.tool, "severity": v.severity, "title": v.title,
            "target": v.target, "details": v.details, "cve": v.cve,
        }

    def _host(h: HostResult) -> dict:
        return {
            "ip": h.ip, "mac": h.mac, "hostnames": h.hostnames,
            "os": h.os_guess, "os_accuracy": h.os_accuracy,
            "source_subdomain": h.source_subdomain,
            "web_urls": h.web_urls,
            "ports": [
                {
                    "port": p.port, "protocol": p.protocol, "state": p.state,
                    "service": p.service, "product": p.product, "version": p.version,
                    "severity": p.severity, "scripts": p.scripts,
                }
                for p in h.ports
            ],
        }

    payload = {
        "meta": {
            "tool": APP_NAME, "version": VERSION,
            "target": result.target,
            "start": result.start_time, "end": result.end_time,
            "phases_completed": result.phases_completed,
        },
        "summary": {
            "subdomains":    len(result.subdomains),
            "hosts":         len(result.hosts),
            "open_ports":    sum(len(h.open_ports) for h in result.hosts),
            "web_services":  len(result.web_findings),
            "vuln_findings": len(result.nuclei_findings),
            "dir_findings":  len(result.dir_findings),
        },
        "subdomains":       result.subdomains,
        "hosts":            [_host(h) for h in result.hosts],
        "web_findings":     [
            {
                "url": w.url, "status": w.status_code, "title": w.title,
                "technologies": w.technologies, "server": w.server,
            }
            for w in result.web_findings
        ],
        "dir_findings":     result.dir_findings[:500],
        "nikto_findings":   result.nikto_findings,
        "whatweb_findings": result.whatweb_findings,
        "nuclei_findings":  [_vuln(v) for v in result.nuclei_findings],
        "ai_analysis":      result.ai_analysis,
        "errors":           result.errors,
        # v5.0.0 intelligence data
        "shodan_results":   result.shodan_results,
        "vt_results":       result.vt_results,
        "whois_results":    result.whois_results,
        "wayback_results":  result.wayback_results,
        "ssl_results":      result.ssl_results,
    }

    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


# ─── HTML ─────────────────────────────────────────────────────────────────────

def generate_html_report(result: ReconResult, path: Path) -> None:
    def esc(s) -> str:
        s = str(s)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Port table rows
    port_rows = ""
    for host in result.hosts:
        label = esc(", ".join(host.hostnames) if host.hostnames else host.ip)
        for p in host.open_ports:
            sev_colors = {
                "critical": "#ff4444", "high": "#ff8c00",
                "medium": "#ffd700",   "info": "#888",
            }
            ver        = esc(" ".join(filter(None, [p.product, p.version, p.extra_info])))
            script_out = esc("; ".join(f"{k}: {v[:80]}" for k, v in p.scripts.items()))
            port_rows += f"""
            <tr>
              <td>{label}</td>
              <td><strong>{p.port}</strong></td>
              <td>{esc(p.protocol)}</td>
              <td style="color:#2ecc71">{esc(p.state)}</td>
              <td>{esc(p.service)}</td>
              <td>{ver}</td>
              <td><span class="badge" style="background:{sev_colors.get(p.severity,'#555')}">{p.severity.upper()}</span></td>
              <td class="small">{script_out}</td>
            </tr>"""

    # Web findings rows
    web_rows = ""
    for wf in result.web_findings:
        sc_color = "#2ecc71" if 200 <= wf.status_code < 300 else \
                   "#f39c12" if 300 <= wf.status_code < 400 else "#e74c3c"
        tech = esc(", ".join(wf.technologies[:5]))
        web_rows += f"""
        <tr>
          <td><a href="{esc(wf.url)}" target="_blank" style="color:#00d4ff">{esc(wf.url)}</a></td>
          <td style="color:{sc_color}">{wf.status_code}</td>
          <td>{esc(wf.title)}</td>
          <td>{esc(wf.server)}</td>
          <td>{tech}</td>
        </tr>"""

    # Vuln rows
    vuln_rows = ""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(result.nuclei_findings, key=lambda v: sev_order.get(v.severity, 5))
    for vf in sorted_vulns:
        sev_colors = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#ffd700"}
        vuln_rows += f"""
        <tr>
          <td><span class="badge" style="background:{sev_colors.get(vf.severity,'#555')}">{vf.severity.upper()}</span></td>
          <td>{esc(vf.title)}</td>
          <td>{esc(vf.target)}</td>
          <td>{esc(vf.cve)}</td>
          <td class="small">{esc(vf.details)}</td>
        </tr>"""

    sub_items   = "".join(f"<li><code>{esc(s)}</code></li>" for s in result.subdomains)
    dir_items   = "".join(f"<li>{esc(f)}</li>"              for f in result.dir_findings[:200])
    nikto_items = "".join(f"<li>{esc(f)}</li>"              for f in result.nikto_findings)

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit_ports = sum(1 for h in result.hosts for p in h.open_ports if p.severity == "critical")
    crit_vulns = sum(1 for v in result.nuclei_findings if v.severity in ("critical", "high"))

    # v5 — WHOIS section
    whois_section = ""
    if result.whois_results:
        w = result.whois_results[0]
        whois_section = f"""
        <section>
          <h2>🌐 WHOIS — {esc(w.get('target', ''))}</h2>
          <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Registrar</td><td>{esc(w.get('registrar','—'))}</td></tr>
            <tr><td>Registered</td><td>{esc(w.get('registered','—'))}</td></tr>
            <tr><td>Expires</td><td>{esc(w.get('expires','—'))}</td></tr>
            <tr><td>Updated</td><td>{esc(w.get('updated','—'))}</td></tr>
            <tr><td>Registrant</td><td>{esc(w.get('registrant','—'))}</td></tr>
            <tr><td>Country</td><td>{esc(w.get('country','—'))}</td></tr>
            <tr><td>Name Servers</td><td>{esc(', '.join(w.get('name_servers',[])))}</td></tr>
            <tr><td>Emails</td><td>{esc(', '.join(w.get('emails',[])))}</td></tr>
          </table>
        </section>"""

    # v5 — Wayback section
    wayback_section = ""
    if result.wayback_results:
        wb = result.wayback_results[0]
        interesting = wb.get("interesting", [])[:20]
        wb_rows = "".join(
            f"<tr><td><a href='{esc(i['url'])}' target='_blank' style='color:#00d4ff'>{esc(i['url'])}</a></td>"
            f"<td>{esc(i['reason'])}</td><td>{esc(i['timestamp'])}</td></tr>"
            for i in interesting
        )
        wayback_section = f"""
        <section>
          <h2>📜 Wayback Machine — {esc(wb.get('domain', ''))} ({wb.get('total', 0)} URLs found)</h2>
          {"<table><thead><tr><th>URL</th><th>Reason</th><th>Timestamp</th></tr></thead><tbody>" + wb_rows + "</tbody></table>" if wb_rows else "<p style='color:var(--dim)'>No interesting URLs found.</p>"}
        </section>"""

    # v5 — SSL section
    ssl_section = ""
    if result.ssl_results:
        ssl_r = result.ssl_results[0]
        ssl_rows = ""
        for cert in ssl_r.get("certs", []):
            exp_color = "#ff4444" if cert.get("expired") else "#ffd700" if cert.get("days_left", 999) < 30 else "#2ecc71"
            ssl_rows += f"""
            <tr>
              <td>{cert.get('port','—')}</td>
              <td>{esc(cert.get('version','—'))}</td>
              <td>{esc(cert.get('cipher','—'))}</td>
              <td>{esc(cert.get('subject',{}).get('commonName','—'))}</td>
              <td style="color:{exp_color}">{cert.get('not_after','—')} ({cert.get('days_left','?')}d)</td>
              <td>{"⚠ SELF-SIGNED" if cert.get("self_signed") else "✔"}</td>
              <td class="small">{esc(', '.join(cert.get('issues',[])))}</td>
            </tr>"""
        _sev_colours = {'critical': '#ff4444', 'high': '#ff8c00', 'medium': '#ffd700'}
        issue_rows = "".join(
            f"<tr><td><span class='badge' style='background:{_sev_colours.get(i.get('severity','info'),'#555')}'>{esc(i.get('severity','').upper())}</span></td><td>{esc(i.get('detail',''))}</td></tr>"
            for i in ssl_r.get("issues", [])
        )
        ssl_section = f"""
        <section>
          <h2>🔒 SSL/TLS Analysis — {esc(ssl_r.get('host', ''))}</h2>
          {"<table><thead><tr><th>Port</th><th>Protocol</th><th>Cipher</th><th>CN</th><th>Expiry</th><th>Self-Signed</th><th>Issues</th></tr></thead><tbody>" + ssl_rows + "</tbody></table>" if ssl_rows else "<p style='color:var(--dim)'>No SSL data.</p>"}
          {"<h3 style='margin-top:1rem;color:var(--warn)'>Issues</h3><table><thead><tr><th>Severity</th><th>Detail</th></tr></thead><tbody>" + issue_rows + "</tbody></table>" if issue_rows else ""}
        </section>"""

    # v5 — VirusTotal section
    vt_section = ""
    if result.vt_results:
        vt_r = result.vt_results[0]
        mal  = vt_r.get("malicious", 0)
        vt_color = "#ff4444" if mal > 0 else "#2ecc71"
        vt_section = f"""
        <section>
          <h2>🦠 VirusTotal — {esc(vt_r.get('domain', vt_r.get('ip', '')))}</h2>
          <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Malicious</td><td style="color:{vt_color}"><strong>{mal}</strong></td></tr>
            <tr><td>Suspicious</td><td>{vt_r.get('suspicious',0)}</td></tr>
            <tr><td>Reputation</td><td>{vt_r.get('reputation','—')}</td></tr>
            <tr><td>Registrar</td><td>{esc(vt_r.get('registrar','—'))}</td></tr>
            <tr><td>Tags</td><td>{esc(', '.join(vt_r.get('tags',[])))}</td></tr>
          </table>
        </section>"""

    # v5 — Shodan section
    shodan_section = ""
    if result.shodan_results:
        sh_rows = ""
        for sh in result.shodan_results[:10]:
            sh_rows += f"""
            <tr>
              <td><code>{esc(sh.get('ip',''))}</code></td>
              <td>{esc(sh.get('org','—'))}</td>
              <td>{esc(sh.get('country','—'))}</td>
              <td>{esc(', '.join(str(p) for p in sh.get('open_ports',[])[:10]))}</td>
              <td style="color:#ff4444">{esc(', '.join(sh.get('vulns',[])[:5]))}</td>
              <td>{esc(', '.join(sh.get('tags',[])))}</td>
            </tr>"""
        shodan_section = f"""
        <section>
          <h2>🔭 Shodan Intelligence ({len(result.shodan_results)} host(s))</h2>
          <table>
            <thead><tr><th>IP</th><th>Org</th><th>Country</th><th>Open Ports</th><th>CVEs</th><th>Tags</th></tr></thead>
            <tbody>{sh_rows}</tbody>
          </table>
        </section>"""

    ai_section = ""
    if result.ai_analysis:
        ai_section = f"""
        <section>
          <h2>🤖 AI Analysis</h2>
          <div class="ai-box">{esc(result.ai_analysis)}</div>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconNinja v5 — {esc(result.target)}</title>
<style>
:root {{
  --bg:#0a0a0f;--surface:#13131f;--surface2:#1a1a2e;
  --accent:#00d4ff;--accent2:#7c3aed;
  --text:#e2e8f0;--dim:#64748b;--border:#1e293b;
  --success:#22c55e;--danger:#ef4444;--warn:#f59e0b;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;line-height:1.6}}
a{{color:var(--accent)}}
header{{
  background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
  padding:2.5rem 2rem;text-align:center;
  border-bottom:1px solid var(--accent);
  position:relative;overflow:hidden;
}}
header h1{{font-size:3rem;color:var(--accent);letter-spacing:6px;text-shadow:0 0 30px rgba(0,212,255,.4)}}
header .ninja{{font-size:1.2rem;color:var(--accent2);letter-spacing:2px;margin-top:.3rem}}
header .meta{{color:var(--dim);margin-top:.8rem;font-size:.9rem}}
.stats{{display:flex;gap:1rem;padding:1.5rem 2rem;background:var(--surface);flex-wrap:wrap;border-bottom:1px solid var(--border)}}
.stat{{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:1rem 1.5rem;flex:1;min-width:130px;text-align:center;transition:border-color .2s}}
.stat:hover{{border-color:var(--accent)}}
.stat .val{{font-size:2.2rem;font-weight:bold;color:var(--accent)}}
.stat .val.danger{{color:var(--danger)}}
.stat .val.warn{{color:var(--warn)}}
.stat .lbl{{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:.2rem}}
main{{padding:2rem;max-width:1600px;margin:auto}}
section{{margin-bottom:2.5rem;background:var(--surface);border-radius:12px;padding:1.5rem;border:1px solid var(--border)}}
h2{{color:var(--accent);font-size:1.1rem;margin-bottom:1rem;letter-spacing:1px;text-transform:uppercase}}
h3{{color:var(--accent2);font-size:.95rem;margin-bottom:.7rem;letter-spacing:.5px}}
table{{width:100%;border-collapse:collapse;font-size:.88rem}}
th{{background:var(--surface2);color:var(--accent);padding:.6rem .8rem;text-align:left;font-size:.78rem;letter-spacing:.5px;text-transform:uppercase}}
td{{padding:.5rem .8rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:var(--surface2)}}
.small{{font-size:.78rem;color:var(--dim)}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.72rem;font-weight:bold;color:#fff}}
.sub-grid{{display:flex;flex-wrap:wrap;gap:.5rem}}
.sub-chip{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:.3rem .7rem;font-size:.82rem;font-family:monospace;color:var(--accent)}}
.ai-box{{background:var(--surface2);border-left:3px solid var(--accent2);padding:1rem 1.5rem;border-radius:0 8px 8px 0;white-space:pre-wrap;font-size:.9rem;line-height:1.7}}
.err-list{{color:var(--dim);font-size:.85rem}} .err-list li{{margin:.3rem 0}}
code{{background:var(--surface2);padding:.1rem .4rem;border-radius:4px;color:#7dd3fc}}
footer{{text-align:center;padding:2rem;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>

<header>
  <div class="ninja">⚡ RECON NINJA v5.0.0</div>
  <h1>{esc(result.target)}</h1>
  <div class="meta">
    Started: {esc(result.start_time)} &nbsp;→&nbsp; Finished: {esc(result.end_time)}<br>
    Phases: {esc(", ".join(result.phases_completed))}
  </div>
</header>

<div class="stats">
  <div class="stat"><div class="val">{len(result.subdomains)}</div><div class="lbl">Subdomains</div></div>
  <div class="stat"><div class="val">{len(result.hosts)}</div><div class="lbl">Hosts</div></div>
  <div class="stat"><div class="val">{total_open}</div><div class="lbl">Open Ports</div></div>
  <div class="stat"><div class="val {'danger' if crit_ports else ''}">{crit_ports}</div><div class="lbl">High-Risk Ports</div></div>
  <div class="stat"><div class="val">{len(result.web_findings)}</div><div class="lbl">Web Services</div></div>
  <div class="stat"><div class="val">{len(result.dir_findings)}</div><div class="lbl">Dir Findings</div></div>
  <div class="stat"><div class="val {'danger' if crit_vulns else 'warn' if result.nuclei_findings else ''}">{len(result.nuclei_findings)}</div><div class="lbl">Vulns Found</div></div>
  <div class="stat"><div class="val">{len(result.errors)}</div><div class="lbl">Errors</div></div>
</div>

<main>

{"<section><h2>🌐 Subdomains (" + str(len(result.subdomains)) + ")</h2><div class='sub-grid'>" + sub_items.replace('<li>','<div class="sub-chip">').replace('</li>','</div>').replace('<code>','').replace('</code>','') + "</div></section>" if result.subdomains else ""}

{"<section><h2>🌍 Live Web Services</h2><table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th></tr></thead><tbody>" + web_rows + "</tbody></table></section>" if web_rows else ""}

{"<section><h2>🔍 Open Ports</h2><table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Risk</th><th>Scripts</th></tr></thead><tbody>" + port_rows + "</tbody></table></section>" if port_rows else "<section><h2>🔍 Open Ports</h2><p style='color:var(--dim)'>No open ports found.</p></section>"}

{"<section><h2>🚨 Vulnerability Findings (" + str(len(result.nuclei_findings)) + ")</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>CVE</th><th>Details</th></tr></thead><tbody>" + vuln_rows + "</tbody></table></section>" if vuln_rows else ""}

{"<section><h2>📁 Directory Findings</h2><ul class='err-list'>" + dir_items + "</ul></section>" if result.dir_findings else ""}

{"<section><h2>🧪 Nikto Findings</h2><ul class='err-list'>" + nikto_items + "</ul></section>" if result.nikto_findings else ""}

{whois_section}
{wayback_section}
{ssl_section}
{vt_section}
{shodan_section}
{ai_section}

{"<section><h2>⚠ Errors</h2><ul class='err-list'>" + "".join(f'<li>{esc(e)}</li>' for e in result.errors) + "</ul></section>" if result.errors else ""}

</main>
<footer>
  {APP_NAME} v{VERSION} &nbsp;•&nbsp; Report generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
  <em style="color:#ff4444">⚠ For authorized penetration testing only. Unauthorized use is illegal.</em>
</footer>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")


# ─── Markdown ─────────────────────────────────────────────────────────────────

def generate_markdown_report(result: ReconResult, path: Path) -> None:
    total_open = sum(len(h.open_ports) for h in result.hosts)
    lines = [
        f"# ReconNinja v5.0.0 Report — `{result.target}`", "",
        "## Summary", "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Target | `{result.target}` |",
        f"| Start | {result.start_time} |",
        f"| End | {result.end_time} |",
        f"| Subdomains | {len(result.subdomains)} |",
        f"| Hosts | {len(result.hosts)} |",
        f"| Open Ports | {total_open} |",
        f"| Web Services | {len(result.web_findings)} |",
        f"| Vulnerabilities | {len(result.nuclei_findings)} |",
        "",
    ]

    if result.subdomains:
        lines += ["## Subdomains", ""]
        lines += [f"- `{s}`" for s in result.subdomains]
        lines += [""]

    if result.web_findings:
        lines += ["## Live Web Services", "",
                  "| URL | Status | Title | Server | Tech |",
                  "|---|---|---|---|---|"]
        for wf in result.web_findings:
            tech = ", ".join(wf.technologies[:3])
            lines.append(f"| {wf.url} | {wf.status_code} | {wf.title} | {wf.server} | {tech} |")
        lines += [""]

    lines += ["## Open Ports", "",
              "| Host | Port | Proto | State | Service | Version | Risk |",
              "|---|---|---|---|---|---|---|"]
    for host in result.hosts:
        label = ", ".join(host.hostnames) if host.hostnames else host.ip
        for p in host.open_ports:
            ver = " ".join(filter(None, [p.product, p.version]))
            lines.append(
                f"| {label} | {p.port} | {p.protocol} | {p.state} "
                f"| {p.service} | {ver} | **{p.severity.upper()}** |"
            )
    lines += [""]

    if result.nuclei_findings:
        lines += ["## Vulnerability Findings", "",
                  "| Severity | Title | Target | CVE |",
                  "|---|---|---|---|"]
        for vf in result.nuclei_findings:
            lines.append(f"| **{vf.severity.upper()}** | {vf.title} | {vf.target} | {vf.cve} |")
        lines += [""]

    # v5 — WHOIS
    if result.whois_results:
        w = result.whois_results[0]
        lines += ["## WHOIS", "",
                  f"| Field | Value |", "|---|---|",
                  f"| Registrar | {w.get('registrar','—')} |",
                  f"| Registered | {w.get('registered','—')} |",
                  f"| Expires | {w.get('expires','—')} |",
                  f"| Updated | {w.get('updated','—')} |",
                  f"| Registrant | {w.get('registrant','—')} |",
                  f"| Country | {w.get('country','—')} |",
                  f"| Name Servers | {', '.join(w.get('name_servers',[]))} |",
                  f"| Emails | {', '.join(w.get('emails',[]))} |",
                  ""]

    # v5 — Wayback
    if result.wayback_results:
        wb = result.wayback_results[0]
        interesting = wb.get("interesting", [])[:30]
        lines += [f"## Wayback Machine ({wb.get('total', 0)} URLs found)", "",
                  "| URL | Reason | Timestamp |",
                  "|---|---|---|"]
        for i in interesting:
            lines.append(f"| {i['url']} | {i['reason']} | {i['timestamp']} |")
        lines += [""]

    # v5 — SSL
    if result.ssl_results:
        ssl_r = result.ssl_results[0]
        lines += ["## SSL/TLS Analysis", "",
                  "| Port | Protocol | Cipher | CN | Expiry | Self-Signed |",
                  "|---|---|---|---|---|---|"]
        for cert in ssl_r.get("certs", []):
            cn = cert.get("subject", {}).get("commonName", "—")
            lines.append(
                f"| {cert.get('port','—')} | {cert.get('version','—')} | "
                f"{cert.get('cipher','—')} | {cn} | "
                f"{cert.get('not_after','—')} ({cert.get('days_left','?')}d) | "
                f"{'YES ⚠' if cert.get('self_signed') else 'No'} |"
            )
        if ssl_r.get("issues"):
            lines += ["", "### SSL Issues", "",
                      "| Severity | Detail |", "|---|---|"]
            for issue in ssl_r["issues"]:
                lines.append(f"| **{issue.get('severity','').upper()}** | {issue.get('detail','')} |")
        lines += [""]

    # v5 — VirusTotal
    if result.vt_results:
        vt_r = result.vt_results[0]
        lines += ["## VirusTotal", "",
                  f"| Field | Value |", "|---|---|",
                  f"| Target | {vt_r.get('domain', vt_r.get('ip', '—'))} |",
                  f"| Malicious | {vt_r.get('malicious', 0)} |",
                  f"| Suspicious | {vt_r.get('suspicious', 0)} |",
                  f"| Reputation | {vt_r.get('reputation', '—')} |",
                  f"| Registrar | {vt_r.get('registrar', '—')} |",
                  ""]

    # v5 — Shodan
    if result.shodan_results:
        lines += ["## Shodan Intelligence", "",
                  "| IP | Org | Country | Ports | CVEs |",
                  "|---|---|---|---|---|"]
        for sh in result.shodan_results[:10]:
            ports = ", ".join(str(p) for p in sh.get("open_ports", [])[:10])
            cves  = ", ".join(sh.get("vulns", [])[:5])
            lines.append(
                f"| {sh.get('ip','—')} | {sh.get('org','—')} | "
                f"{sh.get('country','—')} | {ports} | {cves} |"
            )
        lines += [""]

    if result.ai_analysis:
        lines += ["## AI Analysis", "", result.ai_analysis, ""]

    if result.errors:
        lines += ["## Errors", ""] + [f"- {e}" for e in result.errors]

    path.write_text("\n".join(lines), encoding="utf-8")
