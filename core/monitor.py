"""
ReconNinja v9 — Continuous Monitoring Mode  (--monitor)
Re-runs configured scan phases on a defined interval.
On each run, diffs findings against the previous run and alerts on new critical/high issues.
Passive-only mode skips active scanning to stay low-noise in prod environments.
"""
from __future__ import annotations

import copy
import json
import time
from dataclasses import asdict
from pathlib import Path

from utils.logger import log, safe_print
from utils.models import ReconResult, ScanConfig
from utils.notify import notify_finding


def _parse_interval(interval_str: str) -> int:
    """Parse interval string like '24h', '6h', '30m', '1h' into seconds."""
    s = interval_str.strip().lower()
    try:
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        elif s.endswith("m"):
            return int(s[:-1]) * 60
        elif s.endswith("s"):
            return int(s[:-1])
        else:
            return int(s) * 3600  # default unit: hours
    except ValueError:
        log.warning(f"[monitor] Invalid interval '{interval_str}' — defaulting to 24h")
        return 86400


def _passive_only_cfg(cfg: ScanConfig) -> ScanConfig:
    """Return a copy of cfg with only passive phases enabled."""
    c = copy.copy(cfg)
    # Disable all active scanning
    active_flags = [
        "run_rustscan", "run_masscan", "run_feroxbuster", "run_nikto",
        "run_nuclei", "run_api_fuzz", "run_oauth_scan", "run_web_vulns",
        "run_open_redirect", "run_graphql", "run_jwt_scan", "run_container_deep",
        "run_ad_recon", "run_iot_scan", "run_aquatone",
    ]
    for flag in active_flags:
        if hasattr(c, flag):
            object.__setattr__(c, flag, False)
    return c


def _load_previous_result(target: str, output_dir: str) -> ReconResult | None:
    """Load most recent scan result for target from output_dir."""
    base = Path(output_dir) / target.replace("/", "_")
    if not base.exists():
        return None
    # Find newest reconninja_state.json
    states = sorted(base.rglob("reconninja_state.json"), key=lambda p: p.stat().st_mtime)
    if not states:
        return None
    try:
        data = json.loads(states[-1].read_text())
        # Minimal reconstruction — just nuclei findings for diff
        r = ReconResult(
            target=data.get("target", target),
            start_time=data.get("start_time", ""),
        )
        r.nuclei_findings = []
        for f in data.get("nuclei_findings", []):
            from utils.models import VulnFinding
            r.nuclei_findings.append(VulnFinding(**{
                k: v for k, v in f.items()
                if k in ("tool", "severity", "title", "target", "details", "cve",
                         "cvss_v4", "cvss_v4_vector", "epss_score", "rei")
            }))
        r.subdomains = data.get("subdomains", [])
        return r
    except Exception as e:
        log.warning(f"[monitor] Could not load previous result: {e}")
        return None


def _diff_results(prev: ReconResult | None, curr: ReconResult) -> dict:
    """Compare two results and return a diff summary."""
    if prev is None:
        return {
            "new_findings": curr.nuclei_findings,
            "resolved_findings": [],
            "new_subdomains": curr.subdomains,
            "lost_subdomains": [],
        }

    prev_titles = {f.title for f in prev.nuclei_findings}
    curr_titles = {f.title for f in curr.nuclei_findings}

    new_findings = [f for f in curr.nuclei_findings if f.title not in prev_titles]
    resolved = [f for f in prev.nuclei_findings if f.title not in curr_titles]
    new_subs = [s for s in curr.subdomains if s not in prev.subdomains]
    lost_subs = [s for s in prev.subdomains if s not in curr.subdomains]

    return {
        "new_findings":    new_findings,
        "resolved_findings": resolved,
        "new_subdomains":  new_subs,
        "lost_subdomains": lost_subs,
    }


def _alert_on_diff(diff: dict, cfg: ScanConfig) -> None:
    """Print and optionally notify on new critical/high findings."""
    new_findings = diff["new_findings"]
    new_crits = [f for f in new_findings if f.severity in ("critical", "high")]
    new_subs = diff["new_subdomains"]

    if new_crits:
        safe_print(f"\n[danger]🚨  MONITOR ALERT: {len(new_crits)} new critical/high findings[/]")
        for f in new_crits[:10]:
            safe_print(f"  [{f.severity.upper()}] {f.title} @ {f.target}")
            if cfg.notify_url:
                notify_finding(cfg.notify_url, f.severity, f.title, f.target, f.details)

    if new_subs:
        safe_print(f"[warning]  🌐 {len(new_subs)} new subdomains discovered: {new_subs[:5]}")

    if diff["resolved_findings"]:
        safe_print(f"[success]  ✔ {len(diff['resolved_findings'])} findings resolved since last run[/]")

    if not new_crits and not new_subs and not diff["resolved_findings"]:
        safe_print("[success]  ✔ No changes detected[/]")


def _write_diff_report(diff: dict, target: str, output_dir: str) -> None:
    """Write a JSON diff report to the output directory."""
    from utils.helpers import timestamp, ensure_dir, sanitize_dirname
    out = ensure_dir(Path(output_dir) / sanitize_dirname(target) / "monitor_diffs")
    ts = timestamp()
    report = {
        "timestamp": ts,
        "target": target,
        "new_findings_count":      len(diff["new_findings"]),
        "resolved_findings_count": len(diff["resolved_findings"]),
        "new_subdomains":          diff["new_subdomains"],
        "lost_subdomains":         diff["lost_subdomains"],
        "new_findings": [
            {"severity": f.severity, "title": f.title, "target": f.target, "cve": f.cve}
            for f in diff["new_findings"]
        ],
        "resolved_findings": [
            {"severity": f.severity, "title": f.title}
            for f in diff["resolved_findings"]
        ],
    }
    path = out / f"diff_{ts.replace(':', '-')}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    safe_print(f"[info]  → Monitor diff report: {path}[/]")


def run_monitor_loop(cfg: ScanConfig) -> None:
    """
    Main monitoring loop. Runs indefinitely until interrupted (Ctrl+C).
    On each tick:
      1. Load previous result
      2. Run scan (passive-only if --monitor-passive-only)
      3. Diff against previous
      4. Alert on new critical/high findings
      5. Sleep until next interval
    """
    from core.orchestrator_v9 import run_scan

    interval_secs = _parse_interval(cfg.monitor_interval)
    run_cfg = _passive_only_cfg(cfg) if cfg.monitor_passive_only else cfg
    mode = "passive-only" if cfg.monitor_passive_only else "full"

    safe_print(f"\n[module]🔁  Continuous Monitoring Mode[/]")
    safe_print(f"[info]  Target:   {cfg.target}[/]")
    safe_print(f"[info]  Interval: {cfg.monitor_interval} ({interval_secs}s)[/]")
    safe_print(f"[info]  Mode:     {mode}[/]")
    safe_print("[dim]  Press Ctrl+C to stop[/]\n")

    run_num = 0
    while True:
        run_num += 1
        safe_print(f"[module]▶  Monitor run #{run_num} — {cfg.target}[/]")

        prev = _load_previous_result(cfg.target, cfg.output_dir)
        try:
            curr = run_scan(run_cfg)
        except Exception as e:
            log.error(f"[monitor] Scan failed on run #{run_num}: {e}")
            safe_print(f"[danger]Scan error: {e} — retrying at next interval[/]")
            time.sleep(interval_secs)
            continue

        diff = _diff_results(prev, curr)
        _alert_on_diff(diff, cfg)
        _write_diff_report(diff, cfg.target, cfg.output_dir)

        safe_print(f"[info]  ⏳ Next run in {cfg.monitor_interval}. Sleeping...[/]\n")
        try:
            time.sleep(interval_secs)
        except KeyboardInterrupt:
            safe_print("\n[warning]Monitor stopped by user.[/]")
            break
