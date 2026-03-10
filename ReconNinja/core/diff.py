"""
ReconNinja v5.1.0 — Scan Diff Engine
Compare two state.json snapshots and produce a structured delta report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from utils.logger import log


# ─── State loader ─────────────────────────────────────────────────────────────

def load_state(path: Path) -> dict[str, Any]:
    """Load a state.json file and return its parsed content."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning(f"diff: failed to load state file '{path}': {exc}")
        return {}


# ─── Port set helpers ─────────────────────────────────────────────────────────

def _extract_open_ports(state: dict) -> set[str]:
    """Return a set of 'ip:port' strings for all open ports in a state."""
    ports: set[str] = set()
    for host in state.get("hosts", []):
        ip = host.get("ip", "")
        for p in host.get("ports", []):
            if p.get("state", "") == "open":
                ports.add(f"{ip}:{p.get('port', '')}")
    return ports


def _extract_subdomains(state: dict) -> set[str]:
    return set(state.get("subdomains", []))


def _extract_vuln_keys(state: dict) -> set[str]:
    """Return a set of 'severity|title|target' strings for all vuln findings."""
    keys: set[str] = set()
    for v in state.get("nuclei_findings", []):
        keys.add(f"{v.get('severity', '')}|{v.get('title', '')}|{v.get('target', '')}")
    return keys


# ─── Core diff logic ──────────────────────────────────────────────────────────

def diff_states(
    old_state: dict[str, Any],
    new_state: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare two parsed state dicts and return a structured diff summary.

    Returns:
        {
            "old_target":    str,
            "new_target":    str,
            "old_scan_time": str,
            "new_scan_time": str,
            "ports": {
                "new_open":   list[str],   # "ip:port" strings
                "closed":     list[str],
                "unchanged":  int,
            },
            "subdomains": {
                "added":   list[str],
                "removed": list[str],
            },
            "vulns": {
                "new":      list[str],   # "sev|title|target"
                "resolved": list[str],
            },
            "summary": str,
        }
    """
    old_ports = _extract_open_ports(old_state)
    new_ports = _extract_open_ports(new_state)

    old_subs = _extract_subdomains(old_state)
    new_subs = _extract_subdomains(new_state)

    old_vulns = _extract_vuln_keys(old_state)
    new_vulns = _extract_vuln_keys(new_state)

    new_open    = sorted(new_ports - old_ports)
    closed      = sorted(old_ports - new_ports)
    unchanged   = len(old_ports & new_ports)
    added_subs  = sorted(new_subs - old_subs)
    removed_subs = sorted(old_subs - new_subs)
    new_vuln_list  = sorted(new_vulns - old_vulns)
    resolved_vulns = sorted(old_vulns - new_vulns)

    # Build human-readable summary
    parts: list[str] = []
    if new_open:
        parts.append(f"{len(new_open)} new open port(s)")
    if closed:
        parts.append(f"{len(closed)} closed port(s)")
    if added_subs:
        parts.append(f"{len(added_subs)} new subdomain(s)")
    if removed_subs:
        parts.append(f"{len(removed_subs)} removed subdomain(s)")
    if new_vuln_list:
        parts.append(f"{len(new_vuln_list)} new vuln(s)")
    if resolved_vulns:
        parts.append(f"{len(resolved_vulns)} resolved vuln(s)")
    summary = "; ".join(parts) if parts else "No changes detected"

    diff: dict[str, Any] = {
        "old_target":    old_state.get("target", ""),
        "new_target":    new_state.get("target", ""),
        "old_scan_time": old_state.get("start_time", ""),
        "new_scan_time": new_state.get("start_time", ""),
        "ports": {
            "new_open":  new_open,
            "closed":    closed,
            "unchanged": unchanged,
        },
        "subdomains": {
            "added":   added_subs,
            "removed": removed_subs,
        },
        "vulns": {
            "new":      new_vuln_list,
            "resolved": resolved_vulns,
        },
        "summary": summary,
    }

    log.info(f"Diff complete: {summary}")
    return diff


# ─── High-level entry point ───────────────────────────────────────────────────

def run_diff(old_path: Path, new_state_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Load *old_path* (a previous state.json) and diff against *new_state_dict*.
    Returns the diff summary dict, or an error dict on failure.
    """
    if not old_path.exists():
        log.warning(f"diff: file not found: {old_path}")
        return {"error": f"File not found: {old_path}"}
    old = load_state(old_path)
    if not old:
        return {"error": f"Could not parse state file: {old_path}"}
    return diff_states(old, new_state_dict)


# ─── Markdown renderer ────────────────────────────────────────────────────────

def render_diff_markdown(diff: dict[str, Any]) -> str:
    """Render a diff summary dict as a Markdown string."""
    if "error" in diff:
        return f"## Scan Diff\n\n**Error:** {diff['error']}\n"

    lines = [
        "## Scan Diff",
        "",
        f"| | Old | New |",
        f"|---|---|---|",
        f"| Target | {diff.get('old_target','-')} | {diff.get('new_target','-')} |",
        f"| Scan time | {diff.get('old_scan_time','-')} | {diff.get('new_scan_time','-')} |",
        "",
        f"**Summary:** {diff.get('summary', 'N/A')}",
        "",
    ]

    ports = diff.get("ports", {})
    if ports.get("new_open"):
        lines += ["### New Open Ports", ""]
        for p in ports["new_open"]:
            lines.append(f"- `{p}` ⚠ NEW")
        lines.append("")

    if ports.get("closed"):
        lines += ["### Closed Ports", ""]
        for p in ports["closed"]:
            lines.append(f"- `{p}` ✔ closed")
        lines.append("")

    subs = diff.get("subdomains", {})
    if subs.get("added") or subs.get("removed"):
        lines += ["### Subdomain Changes", ""]
        for s in subs.get("added", []):
            lines.append(f"- `{s}` ⚠ NEW")
        for s in subs.get("removed", []):
            lines.append(f"- ~~`{s}`~~ removed")
        lines.append("")

    vulns = diff.get("vulns", {})
    if vulns.get("new") or vulns.get("resolved"):
        lines += ["### Vulnerability Changes", ""]
        for v in vulns.get("new", []):
            sev, title, tgt = v.split("|", 2) if "|" in v else (v, v, "")
            lines.append(f"- **[{sev.upper()}]** {title} @ `{tgt}` ⚠ NEW")
        for v in vulns.get("resolved", []):
            sev, title, tgt = v.split("|", 2) if "|" in v else (v, v, "")
            lines.append(f"- ~~[{sev.upper()}] {title} @ {tgt}~~ resolved")
        lines.append("")

    return "\n".join(lines)
