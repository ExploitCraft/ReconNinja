"""
ReconNinja v9 — Interactive HTML Report v2
Generates a self-contained single-file HTML report with:
  - D3.js force-directed attack surface graph
  - MITRE ATT&CK heatmap (techniques heatmap by count)
  - Filterable findings table (by severity, module, CVE)
  - Attack chain cards with probability meters
  - REI gauge charts
  - Executive summary section
  - Dark/light mode toggle
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from utils.logger import safe_print
from utils.models import ReconResult, ScanConfig


def generate_interactive_report(
    result: ReconResult,
    cfg: ScanConfig,
    out_folder: Path,
) -> Path:
    safe_print("[module]📊  Generating interactive HTML report v2...[/]")

    # Serialise data for embedding
    findings_json = json.dumps([
        {
            "severity": vf.severity,
            "title":    vf.title,
            "target":   vf.target,
            "cve":      vf.cve,
            "tool":     vf.tool,
            "epss":     vf.epss_score,
            "rei":      vf.rei,
            "details":  (vf.details or "")[:300],
        }
        for vf in result.nuclei_findings
    ], indent=2)

    chains_json = json.dumps([
        {
            "id":          c.chain_id,
            "title":       c.title,
            "probability": c.probability,
            "severity":    c.severity,
            "steps":       c.steps,
            "mitre_ttps":  c.mitre_ttps,
            "remediation": c.remediation,
        }
        for c in result.attack_chains
    ], indent=2)

    graph_json = json.dumps({"nodes": result.graph_nodes, "edges": result.graph_edges}, indent=2)

    all_ttps = [ttp for c in result.attack_chains for ttp in c.mitre_ttps]
    ttp_counts = {}
    for t in all_ttps:
        ttp_counts[t] = ttp_counts.get(t, 0) + 1
    ttp_json = json.dumps(ttp_counts)

    stats = {
        "target":         result.target,
        "start_time":     result.start_time,
        "end_time":       result.end_time,
        "subdomains":     len(result.subdomains),
        "hosts":          len(result.hosts),
        "open_ports":     sum(len(h.open_ports) for h in result.hosts),
        "critical":       sum(1 for f in result.nuclei_findings if f.severity == "critical"),
        "high":           sum(1 for f in result.nuclei_findings if f.severity == "high"),
        "medium":         sum(1 for f in result.nuclei_findings if f.severity == "medium"),
        "low":            sum(1 for f in result.nuclei_findings if f.severity == "low"),
        "attack_chains":  len(result.attack_chains),
        "ad_findings":    len(result.ad_findings),
        "cloud_findings": len(result.cloud_deep_findings),
        "ai_analysis":    result.ai_analysis or "",
    }
    stats_json = json.dumps(stats)

    html = _build_html(stats_json, findings_json, chains_json, graph_json, ttp_json)

    out_path = out_folder / f"report_interactive_{result.target.replace('/', '_')}.html"
    out_path.write_text(html, encoding="utf-8")
    safe_print(f"[success]  ✔ Interactive report: {out_path}[/]")
    return out_path


def _build_html(stats_json, findings_json, chains_json, graph_json, ttp_json) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconNinja v9 — Interactive Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
:root {{
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --border: #30363d; --text: #e6edf3; --text2: #8b949e;
  --accent: #58a6ff; --green: #3fb950; --yellow: #d29922;
  --orange: #db6d28; --red: #f85149; --purple: #bc8cff;
}}
body.light {{
  --bg: #ffffff; --bg2: #f6f8fa; --bg3: #eaeef2;
  --border: #d0d7de; --text: #1f2328; --text2: #636c76;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5; }}
.header {{ background: var(--bg2); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; }}
.header h1 {{ font-size: 1.25rem; display: flex; align-items: center; gap: .5rem; }}
.logo {{ color: var(--accent); font-weight: 700; }}
.btn {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: .35rem .75rem; border-radius: 6px; cursor: pointer; font-size: .85rem; }}
.btn:hover {{ border-color: var(--accent); }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
.stat-card .num {{ font-size: 2rem; font-weight: 700; }}
.stat-card .label {{ font-size: .75rem; color: var(--text2); margin-top: .25rem; }}
.c-critical {{ color: var(--red); }} .c-high {{ color: var(--orange); }}
.c-medium {{ color: var(--yellow); }} .c-low {{ color: var(--accent); }}
.c-ok {{ color: var(--green); }}
.tabs {{ display: flex; gap: .5rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); }}
.tab {{ padding: .6rem 1rem; cursor: pointer; border-bottom: 2px solid transparent; font-size: .9rem; color: var(--text2); transition: color .2s; }}
.tab.active {{ border-bottom-color: var(--accent); color: var(--text); }}
.panel {{ display: none; }} .panel.active {{ display: block; }}
.filter-bar {{ display: flex; gap: .75rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center; }}
.filter-bar input {{ background: var(--bg2); border: 1px solid var(--border); color: var(--text); padding: .4rem .75rem; border-radius: 6px; font-size: .85rem; min-width: 240px; }}
.filter-bar select {{ background: var(--bg2); border: 1px solid var(--border); color: var(--text); padding: .4rem .75rem; border-radius: 6px; font-size: .85rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
th {{ text-align: left; padding: .6rem .75rem; background: var(--bg3); border-bottom: 1px solid var(--border); color: var(--text2); font-weight: 600; }}
td {{ padding: .6rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:hover td {{ background: var(--bg3); }}
.badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
.badge-critical {{ background: rgba(248,81,73,.15); color: var(--red); }}
.badge-high {{ background: rgba(219,109,40,.15); color: var(--orange); }}
.badge-medium {{ background: rgba(210,153,34,.15); color: var(--yellow); }}
.badge-low {{ background: rgba(88,166,255,.15); color: var(--accent); }}
.badge-info {{ background: rgba(139,148,158,.15); color: var(--text2); }}
.chain-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
.chain-card h3 {{ font-size: 1rem; margin-bottom: .5rem; }}
.chain-meta {{ display: flex; gap: 1rem; font-size: .8rem; color: var(--text2); margin-bottom: .75rem; flex-wrap: wrap; }}
.chain-steps {{ list-style: none; border-left: 2px solid var(--border); padding-left: 1rem; font-size: .85rem; }}
.chain-steps li {{ padding: .2rem 0; color: var(--text2); }}
.prob-bar {{ height: 6px; background: var(--bg3); border-radius: 3px; margin-top: .5rem; }}
.prob-fill {{ height: 100%; border-radius: 3px; background: var(--accent); }}
.ttp-badge {{ display: inline-block; background: rgba(188,140,255,.15); color: var(--purple); padding: .1rem .4rem; border-radius: 3px; font-size: .75rem; margin: .1rem; }}
#graph-container {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; height: 520px; position: relative; overflow: hidden; }}
#graph-svg {{ width: 100%; height: 100%; }}
.node circle {{ cursor: pointer; stroke-width: 2; }}
.node text {{ font-size: 10px; fill: var(--text2); pointer-events: none; }}
.link {{ stroke: var(--border); stroke-opacity: .6; }}
.heatmap-cell {{ cursor: pointer; rx: 3; }}
.section-title {{ font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: var(--text2); text-transform: uppercase; letter-spacing: .05em; font-size: .8rem; }}
.ai-box {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; white-space: pre-wrap; font-size: .85rem; line-height: 1.7; }}
.remediation-item {{ background: var(--bg2); border: 1px solid var(--border); border-left: 3px solid var(--red); border-radius: 8px; padding: 1rem; margin-bottom: .75rem; }}
.remediation-item .pri {{ font-size: .75rem; color: var(--red); font-weight: 600; }}
.remediation-item h4 {{ font-size: .9rem; margin: .25rem 0; }}
.remediation-item p {{ font-size: .85rem; color: var(--text2); }}
</style>
</head>
<body>
<div class="header">
  <h1><span class="logo">⚔ ReconNinja</span> v9.0.0 — Interactive Security Report</h1>
  <button class="btn" onclick="toggleTheme()">🌓 Theme</button>
</div>
<div class="container">
  <div id="stats-grid" class="stat-grid"></div>
  <div class="tabs">
    <div class="tab active" onclick="showTab('findings')">Findings</div>
    <div class="tab" onclick="showTab('chains')">Attack Chains</div>
    <div class="tab" onclick="showTab('graph')">Attack Graph</div>
    <div class="tab" onclick="showTab('mitre')">MITRE Heatmap</div>
    <div class="tab" onclick="showTab('ai')">AI Analysis</div>
    <div class="tab" onclick="showTab('remediation')">Remediation</div>
  </div>

  <!-- Findings panel -->
  <div id="panel-findings" class="panel active">
    <div class="filter-bar">
      <input id="search-input" placeholder="Search findings…" oninput="filterFindings()">
      <select id="sev-filter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option>critical</option><option>high</option>
        <option>medium</option><option>low</option><option>info</option>
      </select>
      <select id="tool-filter" onchange="filterFindings()">
        <option value="">All Tools</option>
      </select>
      <span id="finding-count" style="color:var(--text2);font-size:.85rem;"></span>
    </div>
    <table>
      <thead><tr>
        <th>Severity</th><th>Title</th><th>Target</th>
        <th>CVE</th><th>EPSS</th><th>REI</th>
      </tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>

  <!-- Chains panel -->
  <div id="panel-chains" class="panel">
    <div id="chains-container"></div>
  </div>

  <!-- Graph panel -->
  <div id="panel-graph" class="panel">
    <div id="graph-container">
      <svg id="graph-svg"></svg>
    </div>
  </div>

  <!-- MITRE panel -->
  <div id="panel-mitre" class="panel">
    <p class="section-title">MITRE ATT&amp;CK Technique Coverage</p>
    <svg id="mitre-svg" width="100%" height="420"></svg>
  </div>

  <!-- AI Analysis panel -->
  <div id="panel-ai" class="panel">
    <p class="section-title">AI Analysis &amp; Executive Summary</p>
    <div id="ai-content" class="ai-box"></div>
  </div>

  <!-- Remediation panel -->
  <div id="panel-remediation" class="panel">
    <p class="section-title">Remediation Plan</p>
    <div id="remediation-container"></div>
  </div>
</div>

<script>
const STATS    = {stats_json};
const FINDINGS = {findings_json};
const CHAINS   = {chains_json};
const GRAPH    = {graph_json};
const TTP_COUNTS = {ttp_json};

// ── Stats ──────────────────────────────────────────────────────────────────
function renderStats() {{
  const sev = (s, cls) => `<div class="stat-card"><div class="num ${{cls}}">${{s}}</div></div>`;
  const grid = document.getElementById('stats-grid');
  const cards = [
    {{num: STATS.critical, label: 'Critical', cls: 'c-critical'}},
    {{num: STATS.high,     label: 'High',     cls: 'c-high'}},
    {{num: STATS.medium,   label: 'Medium',   cls: 'c-medium'}},
    {{num: STATS.low,      label: 'Low',      cls: 'c-low'}},
    {{num: STATS.hosts,         label: 'Hosts',         cls: ''}},
    {{num: STATS.open_ports,    label: 'Open Ports',    cls: ''}},
    {{num: STATS.subdomains,    label: 'Subdomains',    cls: ''}},
    {{num: STATS.attack_chains, label: 'Attack Chains', cls: 'c-critical'}},
    {{num: STATS.ad_findings,   label: 'AD Findings',   cls: 'c-high'}},
    {{num: STATS.cloud_findings,label: 'Cloud Findings',cls: 'c-high'}},
  ];
  grid.innerHTML = cards.map(c =>
    `<div class="stat-card"><div class="num ${{c.cls}}">${{c.num}}</div><div class="label">${{c.label}}</div></div>`
  ).join('');
}}

// ── Findings table ─────────────────────────────────────────────────────────
let currentFindings = [...FINDINGS];
function renderFindings(data) {{
  const body = document.getElementById('findings-body');
  body.innerHTML = data.map(f => `
    <tr>
      <td><span class="badge badge-${{f.severity}}">${{f.severity.toUpperCase()}}</span></td>
      <td title="${{f.details}}">${{f.title}}</td>
      <td style="color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${{f.target}}</td>
      <td>${{f.cve ? `<span style="color:var(--accent)">${{f.cve}}</span>` : ''}}</td>
      <td>${{f.epss ? (f.epss * 100).toFixed(1) + '%' : ''}}</td>
      <td><span style="color:${{f.rei >= 8 ? 'var(--red)' : f.rei >= 6 ? 'var(--orange)' : 'var(--text2)'}}">${{f.rei || ''}}</span></td>
    </tr>`).join('');
  document.getElementById('finding-count').textContent = `${{data.length}} findings`;
}}
function filterFindings() {{
  const q    = document.getElementById('search-input').value.toLowerCase();
  const sev  = document.getElementById('sev-filter').value;
  const tool = document.getElementById('tool-filter').value;
  const filtered = FINDINGS.filter(f =>
    (!q || f.title.toLowerCase().includes(q) || (f.cve||'').toLowerCase().includes(q) || f.target.toLowerCase().includes(q)) &&
    (!sev  || f.severity === sev) &&
    (!tool || f.tool === tool)
  );
  renderFindings(filtered);
}}
function populateToolFilter() {{
  const tools = [...new Set(FINDINGS.map(f => f.tool))].sort();
  const sel = document.getElementById('tool-filter');
  tools.forEach(t => {{ const o = document.createElement('option'); o.value = o.textContent = t; sel.appendChild(o); }});
}}

// ── Attack chains ──────────────────────────────────────────────────────────
function renderChains() {{
  const container = document.getElementById('chains-container');
  if (!CHAINS.length) {{ container.innerHTML = '<p style="color:var(--text2)">No attack chains generated.</p>'; return; }}
  container.innerHTML = CHAINS.map(c => `
    <div class="chain-card">
      <h3>${{c.title}}</h3>
      <div class="chain-meta">
        <span><span class="badge badge-${{c.severity}}">${{c.severity}}</span></span>
        <span>Confidence: ${{Math.round(c.probability*100)}}%</span>
        <span>${{c.mitre_ttps.map(t => `<span class="ttp-badge">${{t}}</span>`).join('')}}</span>
      </div>
      <div class="prob-bar"><div class="prob-fill" style="width:${{c.probability*100}}%"></div></div>
      <ul class="chain-steps" style="margin-top:.75rem">${{c.steps.map(s => `<li>${{s}}</li>`).join('')}}</ul>
      ${{c.remediation ? `<p style="margin-top:.75rem;font-size:.82rem;color:var(--green)">✓ ${{c.remediation}}</p>` : ''}}
    </div>`).join('');
}}

// ── Attack graph (D3 force) ────────────────────────────────────────────────
function renderGraph() {{
  const nodes = GRAPH.nodes || [];
  const edges = GRAPH.edges || [];
  if (!nodes.length) return;
  const svg = d3.select('#graph-svg');
  const w = document.getElementById('graph-container').clientWidth;
  const h = 520;
  svg.attr('viewBox', `0 0 ${{w}} ${{h}}`);
  const typeColor = {{ host:'var(--accent)', port:'var(--green)', service:'var(--yellow)',
                       subdomain:'var(--purple)', vuln:'var(--red)', url:'var(--orange)',
                       ad_object:'var(--red)', cloud_resource:'var(--orange)' }};
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d => d.node_id).distance(80))
    .force('charge', d3.forceManyBody().strength(-120))
    .force('center', d3.forceCenter(w/2, h/2));
  const link = svg.append('g').selectAll('line').data(edges).enter().append('line')
    .attr('class','link').attr('stroke-width', 1);
  const node = svg.append('g').selectAll('g').data(nodes).enter().append('g').attr('class','node')
    .call(d3.drag()
      .on('start', (e,d) => {{ if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; }})
      .on('drag',  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
      .on('end',   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));
  node.append('circle').attr('r', d => d.node_type==='vuln'?7:5)
    .style('fill', d => typeColor[d.node_type]||'var(--text2)')
    .style('stroke', 'var(--bg)');
  node.append('text').attr('dx',8).attr('dy',4).text(d => (d.label||'').substring(0,20));
  sim.on('tick', () => {{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform', d=>`translate(${{d.x}},${{d.y}})`);
  }});
}}

// ── MITRE heatmap ──────────────────────────────────────────────────────────
function renderMitre() {{
  const entries = Object.entries(TTP_COUNTS).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) return;
  const svg = document.getElementById('mitre-svg');
  const W = svg.clientWidth || 900;
  const cellW = 110, cellH = 50, cols = Math.floor(W / cellW);
  const rows = Math.ceil(entries.length / cols);
  svg.setAttribute('height', rows * cellH + 40);
  let html = '';
  const max = Math.max(...entries.map(e=>e[1]));
  entries.forEach(([ttp, count], i) => {{
    const x = (i % cols) * cellW + 5;
    const y = Math.floor(i / cols) * cellH + 5;
    const intensity = count / max;
    const r = Math.round(248 * intensity);
    html += `<rect class="heatmap-cell" x="${{x}}" y="${{y}}" width="${{cellW-8}}" height="${{cellH-8}}" fill="rgba(${{r}},81,73,0.7)" rx="4"/>
    <text x="${{x+6}}" y="${{y+18}}" fill="white" font-size="11" font-weight="bold">${{ttp}}</text>
    <text x="${{x+6}}" y="${{y+34}}" fill="rgba(255,255,255,.7)" font-size="10">count: ${{count}}</text>`;
  }});
  svg.innerHTML = html;
}}

// ── AI analysis ────────────────────────────────────────────────────────────
function renderAI() {{
  document.getElementById('ai-content').textContent = STATS.ai_analysis || 'AI analysis was not run for this scan.';
}}

// ── Remediation ────────────────────────────────────────────────────────────
function renderRemediation() {{
  const c = document.getElementById('remediation-container');
  const crits = CHAINS.filter(ch => ch.severity === 'critical');
  const items = [
    ...crits.map(ch => ({{pri:'P0 — Immediate', title: ch.title, action: ch.remediation}})),
    ...FINDINGS.filter(f=>f.severity==='critical').slice(0,10)
      .map(f=>( {{pri:'P1 — Within 7 Days', title: `Patch ${{f.cve||f.title}}`, action:`REI: ${{f.rei}} | EPSS: ${{(f.epss*100).toFixed(1)}}%`}})),
  ];
  c.innerHTML = items.length
    ? items.map(i=>`<div class="remediation-item"><div class="pri">${{i.pri}}</div><h4>${{i.title}}</h4><p>${{i.action}}</p></div>`).join('')
    : '<p style="color:var(--text2)">No critical findings.</p>';
}}

// ── Tabs ───────────────────────────────────────────────────────────────────
function showTab(name) {{
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  event.target.classList.add('active');
  if (name==='graph') renderGraph();
  if (name==='mitre') renderMitre();
}}

function toggleTheme() {{
  document.body.classList.toggle('light');
}}

// ── Init ───────────────────────────────────────────────────────────────────
renderStats();
populateToolFilter();
renderFindings(FINDINGS);
renderChains();
renderAI();
renderRemediation();
</script>
</body>
</html>"""
