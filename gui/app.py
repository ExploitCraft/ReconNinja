"""
gui/app.py — ReconNinja  (version → see info/version)
Local desktop GUI — Flask web app launched by `reconninja --gui`.

Start with:  python -m gui.app   OR   reconninja --gui
Opens a browser on http://127.0.0.1:7117

Features:
  - Point-and-click scan configuration
  - Real-time live progress via SSE (Server-Sent Events)
  - In-app report viewer (findings table, severity chart)
  - Scan history with re-open
  - Single-file, no JavaScript framework (vanilla JS + CSS)
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from info import __version__

# ── Flask optional import ─────────────────────────────────────────────────────
try:
    from flask import Flask, Response, jsonify, render_template_string, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Use the same default output dir as reconninja.py ("reports/"), resolved
# relative to the project root so it's always absolute regardless of cwd.
_PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = _PROJECT_ROOT / "reports"

# ── SSE progress queue (thread-safe) ─────────────────────────────────────────
_scan_queues: dict[str, queue.Queue] = {}
_scan_results: dict[str, dict] = {}

# ── HTML template ─────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ReconNinja v__RN_VERSION__</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#e74c3c;
      --green:#238636;--yellow:#d29922;--text:#c9d1d9;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;display:flex;flex-direction:column}
header{background:var(--surface);border-bottom:1px solid var(--border);
       padding:14px 28px;display:flex;align-items:center;gap:12px}
header h1{font-size:1.25rem;font-weight:600;color:#fff}
header .badge{background:var(--accent);color:#fff;border-radius:4px;
              padding:2px 8px;font-size:.75rem;font-weight:600}
.layout{display:grid;grid-template-columns:340px 1fr;flex:1;gap:0}
.sidebar{background:var(--surface);border-right:1px solid var(--border);
         padding:24px 20px;display:flex;flex-direction:column;gap:16px}
.main{padding:24px;overflow-y:auto}
label{font-size:.8rem;color:var(--dim);margin-bottom:4px;display:block}
input,select,textarea{width:100%;background:#0d1117;border:1px solid var(--border);
  border-radius:6px;color:var(--text);padding:8px 10px;font-size:.875rem;outline:none}
input:focus,select:focus{border-color:var(--accent)}
.section-title{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;
               color:var(--dim);margin-bottom:8px}
.checkbox-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.cb-item{display:flex;align-items:center;gap:6px;font-size:.8rem;cursor:pointer}
.cb-item input[type=checkbox]{width:14px;height:14px;accent-color:var(--accent)}
.btn{width:100%;padding:10px;border:none;border-radius:6px;font-size:.875rem;
     font-weight:600;cursor:pointer;transition:.15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{filter:brightness(1.1)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-secondary{background:var(--border);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
      padding:18px;margin-bottom:16px}
.card h2{font-size:.95rem;font-weight:600;margin-bottom:12px}
#progress-log{font-family:'Courier New',monospace;font-size:.78rem;height:260px;
              overflow-y:auto;background:#0d1117;padding:12px;border-radius:6px;
              border:1px solid var(--border);white-space:pre-wrap;color:var(--dim)}
.log-info{color:#58a6ff}.log-warn{color:var(--yellow)}.log-danger{color:var(--accent)}
.log-success{color:var(--green)}
#findings-table{width:100%;border-collapse:collapse;font-size:.8rem}
#findings-table th{background:var(--border);padding:8px 10px;text-align:left;
                   font-weight:600;position:sticky;top:0}
#findings-table td{padding:7px 10px;border-bottom:1px solid #1c2128}
#findings-table tr:hover td{background:#1c2128}
.sev{border-radius:3px;padding:1px 6px;font-size:.72rem;font-weight:700}
.sev-critical{background:#4a0f0f;color:#f85149}
.sev-high{background:#3d1f00;color:#f0883e}
.sev-medium{background:#3d2c00;color:#e3b341}
.sev-low{background:#0d2311;color:#56d364}
.sev-info{background:#1c2432;color:#79c0ff}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:8px;
      padding:12px 18px;text-align:center;flex:1;min-width:80px}
.stat .n{font-size:1.6rem;font-weight:700}
.stat .l{font-size:.72rem;color:var(--dim);margin-top:2px}
.n-crit{color:#f85149}.n-high{color:#f0883e}.n-med{color:#e3b341}
.n-low{color:#56d364}.n-info{color:#79c0ff}
#status-bar{font-size:.78rem;color:var(--dim);margin-bottom:8px}
.tab-bar{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:8px 16px;cursor:pointer;border-radius:6px 6px 0 0;font-size:.85rem;
     color:var(--dim);border:1px solid transparent;border-bottom:none;margin-bottom:-1px}
.tab.active{background:var(--surface);border-color:var(--border);color:var(--text)}
.tab-panel{display:none}.tab-panel.active{display:block}
</style>
</head>
<body>
<header>
  <span style="font-size:1.5rem">🥷</span>
  <h1>ReconNinja</h1>
  <span class="badge">v__RN_VERSION__</span>
  <span style="margin-left:auto;font-size:.78rem;color:var(--dim)" id="clock"></span>
</header>
<div class="layout">
  <!-- SIDEBAR -->
  <div class="sidebar">
    <div>
      <div class="section-title">Target</div>
      <input id="target" placeholder="example.com or 10.0.0.1" autocomplete="off">
    </div>
    <div>
      <div class="section-title">Scan profile</div>
      <select id="profile">
        <option value="quick">Quick recon (fast)</option>
        <option value="standard" selected>Standard (recommended)</option>
        <option value="full">Full scan (all modules)</option>
        <option value="custom">Custom (choose below)</option>
      </select>
    </div>
    <div id="module-chooser" style="display:none">
      <div class="section-title">Modules</div>
      <div class="checkbox-grid" id="module-list"></div>
    </div>
    <div>
      <div class="section-title">Output format</div>
      <div class="checkbox-grid">
        <label class="cb-item"><input type="checkbox" name="fmt" value="html" checked> HTML</label>
        <label class="cb-item"><input type="checkbox" name="fmt" value="json"> JSON</label>
        <label class="cb-item"><input type="checkbox" name="fmt" value="md"> Markdown</label>
        <label class="cb-item"><input type="checkbox" name="fmt" value="pdf"> PDF</label>
        <label class="cb-item"><input type="checkbox" name="fmt" value="sarif"> SARIF</label>
      </div>
    </div>
    <div>
      <label>Timeout per module (sec)</label>
      <input id="timeout" type="number" value="30" min="5" max="300">
    </div>
    <button class="btn btn-primary" id="run-btn" onclick="startScan()">▶ Start Scan</button>
    <button class="btn btn-secondary" id="stop-btn" onclick="stopScan()" style="display:none">■ Stop Scan</button>
  </div>

  <!-- MAIN -->
  <div class="main">
    <div class="tab-bar">
      <div class="tab active" onclick="switchTab('progress')">Progress</div>
      <div class="tab" onclick="switchTab('findings')">Findings</div>
      <div class="tab" onclick="switchTab('history')">History</div>
    </div>

    <!-- PROGRESS TAB -->
    <div class="tab-panel active" id="tab-progress">
      <div class="stats">
        <div class="stat"><div class="n n-crit" id="s-crit">0</div><div class="l">Critical</div></div>
        <div class="stat"><div class="n n-high" id="s-high">0</div><div class="l">High</div></div>
        <div class="stat"><div class="n n-med"  id="s-med">0</div><div class="l">Medium</div></div>
        <div class="stat"><div class="n n-low"  id="s-low">0</div><div class="l">Low</div></div>
        <div class="stat"><div class="n n-info" id="s-subs">0</div><div class="l">Subdomains</div></div>
        <div class="stat"><div class="n n-info" id="s-ports">0</div><div class="l">Open Ports</div></div>
      </div>
      <div id="status-bar">Ready — enter a target and press Start Scan.</div>
      <div id="progress-log">ReconNinja v__RN_VERSION__ ready.\n</div>
    </div>

    <!-- FINDINGS TAB -->
    <div class="tab-panel" id="tab-findings">
      <div class="card">
        <h2>Vulnerability Findings</h2>
        <table id="findings-table">
          <thead><tr>
            <th>Severity</th><th>Title</th><th>Tool</th><th>Target</th><th>Detail</th>
          </tr></thead>
          <tbody id="findings-body">
            <tr><td colspan="5" style="color:var(--dim);padding:20px;text-align:center">
              No scan results yet — run a scan first.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- HISTORY TAB -->
    <div class="tab-panel" id="tab-history">
      <div class="card">
        <h2>Recent Scans</h2>
        <div id="history-list" style="color:var(--dim);font-size:.85rem">Loading…</div>
      </div>
    </div>
  </div>
</div>

<script>
const MODULES = [
  "subdomains","httpx","ssl","waf","cors","js-extract","graphql",
  "nuclei","cve","jwt-scan","db-exposure","github-osint","wayback","breach-check",
  "cloud-buckets","cloud-meta","asn-map","censys","greynoise","vt","shodan",
  "k8s-probe","smtp-enum","ldap-enum","snmp-scan","devops-scan","typosquat","supply-chain",
  "api-fuzz","oauth-scan","web-vulns","open-redirect","linkedin","paste-monitor",
  "se-osint","app-store","anon-detect","dns-leak","web3-scan","ens-lookup",
  "ai","ai-consensus","attack-paths","ai-remediate","pdf-report","sarif"
];

const PROFILES = {
  quick:    ["subdomains","httpx","ssl","waf"],
  standard: ["subdomains","httpx","ssl","waf","cors","nuclei","cve",
             "github-osint","wayback","cloud-buckets","typosquat"],
  full:     MODULES,
  custom:   []
};

let scanId = null;
let evtSource = null;

// Build module checkboxes
const ml = document.getElementById("module-list");
MODULES.forEach(m => {
  const label = document.createElement("label");
  label.className = "cb-item";
  label.innerHTML = `<input type="checkbox" class="mod-cb" value="${m}"> ${m}`;
  ml.appendChild(label);
});

document.getElementById("profile").addEventListener("change", e => {
  document.getElementById("module-chooser").style.display =
    e.target.value === "custom" ? "block" : "none";
});

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t,i) =>
    t.classList.toggle("active", t.textContent.toLowerCase().startsWith(name)));
  document.querySelectorAll(".tab-panel").forEach(p =>
    p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "history") loadHistory();
}

function log(msg, cls="") {
  const el = document.getElementById("progress-log");
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = msg + "\n";
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

async function startScan() {
  const target = document.getElementById("target").value.trim();
  if (!target) { alert("Please enter a target."); return; }

  const profile = document.getElementById("profile").value;
  let modules = PROFILES[profile];
  if (profile === "custom") {
    modules = [...document.querySelectorAll(".mod-cb:checked")].map(c => c.value);
    if (!modules.length) { alert("Select at least one module."); return; }
  }

  const fmts = [...document.querySelectorAll("input[name=fmt]:checked")].map(c=>c.value);
  const timeout = parseInt(document.getElementById("timeout").value) || 30;

  document.getElementById("run-btn").disabled = true;
  document.getElementById("stop-btn").style.display = "";
  document.getElementById("progress-log").textContent = "";
  log(`[${new Date().toLocaleTimeString()}] Starting scan: ${target}`, "log-info");

  const resp = await fetch("/api/scan/start", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({target, modules, formats: fmts, timeout})
  });
  const data = await resp.json();
  if (!data.scan_id) { log("Failed to start scan: " + JSON.stringify(data), "log-danger"); return; }

  scanId = data.scan_id;
  subscribeProgress(scanId);
}

function subscribeProgress(id) {
  if (evtSource) evtSource.close();
  evtSource = new EventSource(`/api/scan/progress/${id}`);
  evtSource.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === "log") {
      const cls = msg.level === "warning" ? "log-warn" :
                  msg.level === "danger" ? "log-danger" :
                  msg.level === "success" ? "log-success" : "log-info";
      log(msg.text, cls);
    } else if (msg.type === "stats") {
      document.getElementById("s-crit").textContent = msg.critical || 0;
      document.getElementById("s-high").textContent = msg.high || 0;
      document.getElementById("s-med").textContent  = msg.medium || 0;
      document.getElementById("s-low").textContent  = msg.low || 0;
      document.getElementById("s-subs").textContent = msg.subdomains || 0;
      document.getElementById("s-ports").textContent= msg.ports || 0;
      document.getElementById("status-bar").textContent = msg.phase || "";
    } else if (msg.type === "findings") {
      updateFindingsTable(msg.findings);
    } else if (msg.type === "done") {
      log("✓ Scan complete. Report saved to: " + msg.output_dir, "log-success");
      evtSource.close();
      document.getElementById("run-btn").disabled = false;
      document.getElementById("stop-btn").style.display = "none";
      if (msg.findings) updateFindingsTable(msg.findings);
    } else if (msg.type === "error") {
      log("Error: " + msg.text, "log-danger");
    }
  };
  evtSource.onerror = () => { evtSource.close(); };
}

function updateFindingsTable(findings) {
  const tbody = document.getElementById("findings-body");
  tbody.innerHTML = "";
  if (!findings || !findings.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--dim);text-align:center;padding:20px">No vulnerability findings.</td></tr>';
    return;
  }
  findings.forEach(f => {
    const tr = document.createElement("tr");
    const sevClass = "sev sev-" + (f.severity||"info");
    tr.innerHTML = `<td><span class="${sevClass}">${(f.severity||"").toUpperCase()}</span></td>
      <td>${f.title||""}</td><td>${f.tool||""}</td>
      <td style="font-size:.75rem">${(f.target||"").slice(0,40)}</td>
      <td style="font-size:.75rem">${(f.details||"").slice(0,100)}</td>`;
    tbody.appendChild(tr);
  });
}

async function stopScan() {
  if (!scanId) return;
  await fetch(`/api/scan/stop/${scanId}`, {method:"POST"});
  if (evtSource) evtSource.close();
  log("Scan stopped by user.", "log-warn");
  document.getElementById("run-btn").disabled = false;
  document.getElementById("stop-btn").style.display = "none";
}

async function loadHistory() {
  const resp = await fetch("/api/history");
  const data = await resp.json();
  const el = document.getElementById("history-list");
  if (!data.scans || !data.scans.length) {
    el.textContent = "No previous scans found."; return;
  }
  el.innerHTML = data.scans.map(s =>
    `<div style="padding:8px 0;border-bottom:1px solid var(--border)">
      <strong>${s.target}</strong> — ${s.date}
      <span style="float:right;font-size:.75rem;color:var(--dim)">${s.output_dir}</span>
    </div>`
  ).join("");
}

// Clock
setInterval(() => {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}, 1000);
loadHistory();
</script>
</body></html>"""


# ── Flask App ─────────────────────────────────────────────────────────────────

def create_app() -> "Flask":
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(HTML.replace("__RN_VERSION__", __version__))

    @app.route("/api/scan/start", methods=["POST"])
    def start_scan():
        data = request.get_json(force=True)
        target = data.get("target", "").strip()
        modules = data.get("modules", [])
        formats = data.get("formats", ["html"])
        timeout = data.get("timeout", 30)

        if not target:
            return jsonify({"error": "target required"}), 400

        scan_id = f"{int(time.time())}"
        q: queue.Queue = queue.Queue(maxsize=500)
        _scan_queues[scan_id] = q

        # Build reconninja command
        # BUG FIX 1: use --target flag, not positional arg (argparse rejects positional)
        # BUG FIX 2: add --yes so subprocess isn't stuck on permission prompt
        # BUG FIX 3: --output-format only accepts a single choice; collapse to "all"
        #            when multiple formats are selected
        # BUG FIX 6: pass --output with absolute path so GUI and tool agree on dir
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(_PROJECT_ROOT / "reconninja.py"),
               "--target", target, "--yes",
               "--output", str(OUTPUT_DIR)]
        for mod in modules:
            cmd.append(f"--{mod}")
        fmt = formats[0] if len(formats) == 1 else "all"
        cmd += ["--output-format", fmt]
        cmd += ["--timeout", str(timeout)]

        def run_scan():
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, cwd=Path(__file__).parent.parent,
                )
                _scan_results[scan_id] = {"proc": proc, "target": target}
                for line in proc.stdout:
                    line = line.rstrip()
                    level = ("success" if "✓" in line or "[success]" in line else
                             "warning" if "⚠" in line or "[warning]" in line else
                             "danger" if "[danger]" in line or "error" in line.lower() else "info")
                    q.put(json.dumps({"type": "log", "text": line, "level": level}))

                proc.wait()
                # Scan done — try to load findings from output JSON
                findings = []
                out_dirs = sorted(OUTPUT_DIR.glob(f"{target.replace('/','_')}*"),
                                  key=lambda p: p.stat().st_mtime, reverse=True)
                output_dir = str(out_dirs[0]) if out_dirs else ""
                if out_dirs:
                    for jf in out_dirs[0].glob("*.json"):
                        try:
                            content = json.loads(jf.read_text())
                            if isinstance(content, list):
                                findings.extend(content)
                        except Exception:
                            pass
                q.put(json.dumps({"type": "done",
                                  "output_dir": output_dir,
                                  "findings": findings[:200]}))
            except Exception as e:
                q.put(json.dumps({"type": "error", "text": str(e)}))
            finally:
                q.put(None)  # sentinel
                # Prune dicts to prevent unbounded memory growth
                _scan_queues.pop(scan_id, None)
                _scan_results.pop(scan_id, None)

        threading.Thread(target=run_scan, daemon=True).start()
        return jsonify({"scan_id": scan_id})

    @app.route("/api/scan/progress/<scan_id>")
    def scan_progress(scan_id):
        q = _scan_queues.get(scan_id)
        if not q:
            return Response("data: " + json.dumps({"type":"error","text":"unknown scan"}) + "\n\n",
                            content_type="text/event-stream")

        def generate():
            while True:
                try:
                    item = q.get(timeout=30)
                    if item is None:
                        break
                    yield f"data: {item}\n\n"
                except queue.Empty:
                    yield "data: " + json.dumps({"type": "keepalive"}) + "\n\n"
        return Response(generate(), content_type="text/event-stream")

    @app.route("/api/scan/stop/<scan_id>", methods=["POST"])
    def stop_scan(scan_id):
        info = _scan_results.get(scan_id, {})
        proc = info.get("proc")
        if proc:
            proc.terminate()
        return jsonify({"stopped": True})

    @app.route("/api/history")
    def history():
        scans = []
        if OUTPUT_DIR.exists():
            for d in sorted(OUTPUT_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
                if d.is_dir():
                    scans.append({
                        "target": d.name.split("_")[0],
                        "date": datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "output_dir": str(d),
                    })
        return jsonify({"scans": scans})

    return app


def launch_gui(host: str = "127.0.0.1", port: int = 7117, open_browser: bool = True):
    """Entry point called by reconninja.py --gui."""
    if not FLASK_AVAILABLE:
        print("Flask is required for the GUI. Install it with:")
        print("  pip install flask")
        sys.exit(1)

    print(f"\n🥷 ReconNinja v{__version__} GUI")
    print(f"   http://{host}:{port}\n")
    print("   Press Ctrl+C to stop\n")

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    app = create_app()
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    launch_gui()
