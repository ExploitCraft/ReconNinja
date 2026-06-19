"""
ReconNinja v9 — MCP Server Mode  (--mcp-server)
Exposes ReconNinja as an MCP (Model Context Protocol) server.
Claude Code, Cursor, and other MCP clients can drive scans natively.

Tools exposed:
  - reconninja_scan       Start a scan, returns job_id
  - reconninja_status     Get scan status + summary
  - reconninja_findings   Get structured findings (filterable by severity)
  - reconninja_graph      Get attack graph as JSON
  - reconninja_chains     Get attack chains
  - reconninja_report     Get report text (executive | technical)

Run with: reconninja --mcp-server --mcp-server-port 8765
"""
from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any

from utils.logger import log, safe_print


# ─── Job store (in-memory) ────────────────────────────────────────────────────

_JOBS: dict[str, dict] = {}
_JOB_LOCK = threading.Lock()


def _new_job(target: str, flags: dict) -> str:
    job_id = str(uuid.uuid4())[:8]
    with _JOB_LOCK:
        _JOBS[job_id] = {
            "id":      job_id,
            "target":  target,
            "flags":   flags,
            "status":  "queued",
            "result":  None,
            "error":   None,
        }
    return job_id


# ─── MCP tool definitions ─────────────────────────────────────────────────────

MCP_TOOLS = [
    {
        "name": "reconninja_scan",
        "description": "Start a ReconNinja scan against a target. Returns a job_id to track progress.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or IP"},
                "profile": {"type": "string", "enum": ["fast", "standard", "thorough", "stealth"],
                            "default": "standard"},
                "modules": {"type": "array", "items": {"type": "string"},
                            "description": "Specific modules: subdomains, nuclei, cloud_deep, ad_recon, etc."},
            },
            "required": ["target"],
        },
    },
    {
        "name": "reconninja_status",
        "description": "Get the status and a brief summary of a running or completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "reconninja_findings",
        "description": "Get structured vulnerability findings from a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id":   {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "all"],
                             "default": "all"},
                "limit":    {"type": "integer", "default": 50},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "reconninja_graph",
        "description": "Get the ReconGraph (attack surface graph) as JSON from a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "reconninja_chains",
        "description": "Get the AI-generated attack chains from a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "reconninja_report",
        "description": "Get the executive or technical report text from a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "format": {"type": "string", "enum": ["executive", "technical"], "default": "technical"},
            },
            "required": ["job_id"],
        },
    },
]


# ─── Tool dispatch ────────────────────────────────────────────────────────────

def _dispatch_tool(name: str, params: dict, cfg_base) -> dict:
    from dataclasses import replace

    if name == "reconninja_scan":
        target  = params["target"]
        profile = params.get("profile", "standard")
        modules = params.get("modules", [])

        # Build flags from modules list
        flags = {"profile": profile}
        module_map = {
            "subdomains":    "run_subdomains",
            "nuclei":        "run_nuclei",
            "cloud_deep":    "run_cloud_deep",
            "ad_recon":      "run_ad_recon",
            "container_deep":"run_container_deep",
            "llm_recon":     "run_llm_recon",
            "iot_scan":      "run_iot_scan",
            "httpx":         "run_httpx",
            "whatweb":       "run_whatweb",
            "shodan":        "run_shodan",
        }
        for mod in modules:
            if mod in module_map:
                flags[module_map[mod]] = True

        job_id = _new_job(target, flags)
        _start_job_async(job_id, target, flags, cfg_base)
        return {"job_id": job_id, "status": "queued", "message": f"Scan started for {target}"}

    if name == "reconninja_status":
        job_id = params["job_id"]
        job = _JOBS.get(job_id)
        if not job:
            return {"error": f"No job with id {job_id}"}
        out: dict = {"job_id": job_id, "status": job["status"], "target": job["target"]}
        if job["result"]:
            r = job["result"]
            out["summary"] = {
                "subdomains":       len(r.subdomains),
                "hosts":            len(r.hosts),
                "open_ports":       sum(len(h.open_ports) for h in r.hosts),
                "nuclei_findings":  len(r.nuclei_findings),
                "attack_chains":    len(r.attack_chains),
                "ad_findings":      len(r.ad_findings),
                "cloud_findings":   len(r.cloud_deep_findings),
            }
        if job["error"]:
            out["error"] = job["error"]
        return out

    if name == "reconninja_findings":
        job_id   = params["job_id"]
        severity = params.get("severity", "all")
        limit    = int(params.get("limit", 50))
        job = _JOBS.get(job_id)
        if not job or not job["result"]:
            return {"error": "Job not found or not complete"}
        r = job["result"]
        from dataclasses import asdict
        findings = [asdict(f) for f in r.nuclei_findings]
        if severity != "all":
            findings = [f for f in findings if f["severity"] == severity]
        return {"findings": findings[:limit], "total": len(findings)}

    if name == "reconninja_graph":
        job = _JOBS.get(params["job_id"])
        if not job or not job["result"]:
            return {"error": "Job not found or not complete"}
        r = job["result"]
        return {"nodes": r.graph_nodes, "edges": r.graph_edges}

    if name == "reconninja_chains":
        job = _JOBS.get(params["job_id"])
        if not job or not job["result"]:
            return {"error": "Job not found or not complete"}
        from dataclasses import asdict
        return {"chains": [asdict(c) for c in job["result"].attack_chains]}

    if name == "reconninja_report":
        job = _JOBS.get(params["job_id"])
        if not job or not job["result"]:
            return {"error": "Job not found or not complete"}
        fmt = params.get("format", "technical")
        r = job["result"]
        if fmt == "executive":
            from core.correlation import ReportAgent
            agent = ReportAgent(cfg_base)
            return {"report": agent.executive_summary(r)}
        # Technical = full AI analysis
        return {"report": r.ai_analysis or "Analysis not available"}

    return {"error": f"Unknown tool: {name}"}


def _start_job_async(job_id: str, target: str, flags: dict, cfg_base) -> None:
    """Run the scan in a background thread."""
    def _run():
        from utils.models import ScanConfig
        from dataclasses import replace
        import copy
        try:
            cfg = copy.copy(cfg_base)
            cfg.target = target
            for k, v in flags.items():
                if hasattr(cfg, k):
                    object.__setattr__(cfg, k, v)
            with _JOB_LOCK:
                _JOBS[job_id]["status"] = "running"
            from core.orchestrator_v9 import run_scan
            result = run_scan(cfg)
            with _JOB_LOCK:
                _JOBS[job_id]["status"]  = "complete"
                _JOBS[job_id]["result"]  = result
        except Exception as e:
            with _JOB_LOCK:
                _JOBS[job_id]["status"] = "failed"
                _JOBS[job_id]["error"]  = str(e)
            log.error(f"[mcp] Job {job_id} failed: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ─── HTTP server (SSE transport) ──────────────────────────────────────────────

def start_mcp_server(port: int, cfg_base, bind: str = "127.0.0.1",
                     token: str = "") -> None:
    """
    Start a minimal MCP-over-HTTP server.
    Implements the MCP 1.0 SSE transport:
      GET  /sse         → event stream (connection)
      POST /message     → tool call handler

    v10 hardening:
      • Binds to 127.0.0.1 by default (was 0.0.0.0 — open to LAN).
      • Optional Bearer-token auth (recommended if --bind 0.0.0.0).
      • Server version pulled from info.__version__ (was hardcoded 9.0.0).
    """
    from flask import Flask, request, Response, jsonify, stream_with_context
    from info import __version__
    import functools
    import time

    app = Flask("reconninja-mcp")

    def _require_auth(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if token:
                auth = request.headers.get("Authorization", "")
                if auth != f"Bearer {token}":
                    return jsonify({"error": "unauthorized"}), 401
            return fn(*args, **kwargs)
        return wrapper

    @app.get("/")
    def health():
        return jsonify({
            "server": "ReconNinja MCP",
            "version": __version__,
            "tools": len(MCP_TOOLS),
            "bind": bind,
            "auth": "bearer" if token else "none",
        })

    @app.get("/sse")
    @_require_auth
    def sse():
        def stream():
            # Send server capabilities
            caps = json.dumps({
                "jsonrpc": "2.0",
                "method":  "initialize",
                "params":  {
                    "serverInfo":   {"name": "ReconNinja", "version": __version__},
                    "capabilities": {"tools": {}},
                },
            })
            yield f"data: {caps}\n\n"
            # Keep alive
            while True:
                time.sleep(15)
                yield ": keepalive\n\n"
        return Response(stream_with_context(stream()), mimetype="text/event-stream")

    @app.post("/message")
    @_require_auth
    def message():
        body = request.get_json(force=True, silent=True) or {}
        method = body.get("method", "")
        msg_id = body.get("id")

        if method == "tools/list":
            return jsonify({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"tools": MCP_TOOLS},
            })

        if method == "tools/call":
            tool_name = body.get("params", {}).get("name", "")
            tool_args  = body.get("params", {}).get("arguments", {})
            result = _dispatch_tool(tool_name, tool_args, cfg_base)
            return jsonify({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": "error" in result,
                },
            })

        return jsonify({
            "jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        })

    safe_print(f"[module]🔌  MCP Server v{__version__} on http://{bind}:{port}[/]")
    if bind == "0.0.0.0" and not token:
        safe_print("[danger]  ⚠ WARNING: --bind 0.0.0.0 without --token exposes the server to the network![/]")
    safe_print(f"[info]  Add to Claude Code: reconninja mcp at http://{bind}:{port}[/]")
    app.run(host=bind, port=port, threaded=True, debug=False)
