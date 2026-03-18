"""
core/resume.py
ReconNinja v5.0.0 — Scan State / Resume System

Saves scan state to a JSON file after each phase completes.
If a scan crashes, use --resume <state_file> to continue from last checkpoint.

Usage:
  python3 reconninja.py -t target.com --profile full_suite
  # ... crashes at phase 7 ...
  python3 reconninja.py --resume reports/target.com/20240101_120000/state.json
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from utils.logger import safe_print, console
from utils.models import (
    ReconResult, ScanConfig, ScanProfile, NmapOptions,
    HostResult, PortInfo, WebFinding, VulnFinding,
)


# ── State file helpers ────────────────────────────────────────────────────────

STATE_FILE = "state.json"


def save_state(result: ReconResult, cfg: ScanConfig, out_folder: Path) -> None:
    """
    Persist current scan state to disk after each phase.
    Called by orchestrator after every completed phase.
    """
    state = {
        "version":    "5.2.2",
        "config":     cfg.to_dict(),
        "result":     _result_to_dict(result),
        "out_folder": str(out_folder),
    }
    path = out_folder / STATE_FILE
    try:
        path.write_text(json.dumps(state, indent=2, default=str))
    except Exception as e:
        safe_print(f"[dim]State save failed: {e}[/]")


def load_state(state_path: Path) -> tuple[ReconResult, ScanConfig, Path] | None:
    """
    Load saved state from a state.json file.
    Returns (result, config, out_folder) or None on failure.
    """
    try:
        raw    = json.loads(state_path.read_text())
        cfg    = _dict_to_config(raw["config"])
        result = _dict_to_result(raw["result"])
        out_folder = Path(raw["out_folder"])
        safe_print(f"[success]✔ Resumed scan for [bold]{cfg.target}[/][/]")
        safe_print(f"  Completed phases: {', '.join(result.phases_completed) or 'none'}")
        return result, cfg, out_folder
    except Exception as e:
        console.print(f"[danger]Failed to load state: {e}[/]")
        return None


def find_latest_state(target: str, reports_dir: Path = Path("reports")) -> Path | None:
    """
    Find the most recent state.json for a given target.
    Useful for: reconninja --resume target.com  (without specifying exact path)
    """
    target_dir = reports_dir / _sanitize(target)
    if not target_dir.exists():
        return None

    states = sorted(target_dir.glob("*/state.json"), reverse=True)
    return states[0] if states else None


def _sanitize(name: str) -> str:
    for ch in r'<>:"/\|?* ':
        name = name.replace(ch, "_")
    return name


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _result_to_dict(result: ReconResult) -> dict:
    return asdict(result)


def _dict_to_result(d: dict) -> ReconResult:
    hosts = []
    for h in d.get("hosts", []):
        ports = [PortInfo(**p) for p in h.get("ports", [])]
        h["ports"] = ports
        host = HostResult(**h)
        hosts.append(host)

    web_findings    = [WebFinding(**wf) for wf in d.get("web_findings", [])]
    nuclei_findings = [VulnFinding(**vf) for vf in d.get("nuclei_findings", [])]

    return ReconResult(
        target           = d["target"],
        start_time       = d["start_time"],
        end_time         = d.get("end_time", ""),
        subdomains       = d.get("subdomains", []),
        hosts            = hosts,
        web_findings     = web_findings,
        dir_findings     = d.get("dir_findings", []),
        nikto_findings   = d.get("nikto_findings", []),
        whatweb_findings = d.get("whatweb_findings", []),
        nuclei_findings  = nuclei_findings,
        masscan_ports    = d.get("masscan_ports", []),
        ai_analysis      = d.get("ai_analysis", ""),
        errors           = d.get("errors", []),
        phases_completed = d.get("phases_completed", []),
        # v5.0.0 — new intelligence fields
        shodan_results   = d.get("shodan_results", []),
        vt_results       = d.get("vt_results", []),
        whois_results    = d.get("whois_results", []),
        wayback_results  = d.get("wayback_results", []),
        ssl_results      = d.get("ssl_results", []),
    )


def _dict_to_config(d: dict) -> ScanConfig:
    nmap_raw  = d.get("nmap_opts", {})
    nmap_opts = NmapOptions(
        all_ports         = nmap_raw.get("all_ports", False),
        top_ports         = nmap_raw.get("top_ports", 1000),
        scripts           = nmap_raw.get("scripts", True),
        version_detection = nmap_raw.get("version_detection", True),
        os_detection      = nmap_raw.get("os_detection", False),
        aggressive        = nmap_raw.get("aggressive", False),
        stealth           = nmap_raw.get("stealth", False),
        timing            = nmap_raw.get("timing", "T4"),
        extra_flags       = nmap_raw.get("extra_flags", []),
        script_args       = nmap_raw.get("script_args", None),
    )
    profile_str = d.get("profile", "standard")
    return ScanConfig(
        target            = d["target"],
        profile           = ScanProfile(profile_str),
        nmap_opts         = nmap_opts,
        run_subdomains    = d.get("run_subdomains", False),
        run_rustscan      = d.get("run_rustscan", False),
        run_feroxbuster   = d.get("run_feroxbuster", False),
        run_masscan       = d.get("run_masscan", False),
        run_aquatone      = d.get("run_aquatone", False),
        run_whatweb       = d.get("run_whatweb", False),
        run_nikto         = d.get("run_nikto", False),
        run_nuclei        = d.get("run_nuclei", False),
        run_httpx         = d.get("run_httpx", False),
        run_ai_analysis   = d.get("run_ai_analysis", False),
        run_cve_lookup    = d.get("run_cve_lookup", False),
        ai_provider       = d.get("ai_provider", "groq"),
        ai_key            = d.get("ai_key", ""),
        ai_model          = d.get("ai_model", ""),
        nvd_key           = d.get("nvd_key", ""),
        # v5.0.0 fields
        run_shodan        = d.get("run_shodan", False),
        run_virustotal    = d.get("run_virustotal", False),
        run_whois         = d.get("run_whois", False),
        run_wayback       = d.get("run_wayback", False),
        run_ssl           = d.get("run_ssl", False),
        shodan_key        = d.get("shodan_key", ""),
        vt_key            = d.get("vt_key", ""),
        output_format     = d.get("output_format", "all"),
        exclude_phases    = d.get("exclude_phases", []),
        global_timeout    = d.get("global_timeout", 30),
        rate_limit        = d.get("rate_limit", 0.0),
        masscan_rate      = d.get("masscan_rate", 5000),
        threads           = d.get("threads", 20),
        wordlist_size     = d.get("wordlist_size", "medium"),
        output_dir        = d.get("output_dir", "reports"),
        async_concurrency = d.get("async_concurrency", 1000),
        async_timeout     = d.get("async_timeout", 1.5),
    )
