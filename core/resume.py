"""
core/resume.py
ReconNinja v10 — Scan State / Resume System

V10 fixes:
  • save_state() now accepts BOTH the legacy (result, out_folder) call site
    (used by orchestrator_v9 throughout the scan) AND the explicit
    (result, cfg, out_folder) form (used at top-level checkpoints). It
    auto-detects which form was used.
  • load_state() returns (result, cfg, out_folder) — the v10 caller in
    reconninja.py:main() now correctly unpacks 3 values.
  • _dict_to_result() / _dict_to_config() now round-trip EVERY v9/v10
    field — no more silent data loss when resuming a scan.
  • A schema_version field is written so future V11+ can migrate old
    state files without guessing.
"""
from __future__ import annotations

import json
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path

from utils.logger import safe_print, console
from utils.models import (
    ReconResult, ScanConfig, ScanProfile, NmapOptions,
    HostResult, PortInfo, WebFinding, VulnFinding,
    ADFinding, CloudFinding, LLMSurface, IoTFinding,
    ContainerFinding, WirelessFinding, DarkWebFinding,
    AttackChain, EvidenceItem,
)
from info import __version__


SCHEMA_VERSION = 3
STATE_FILE = "state.json"


# ── State file helpers ────────────────────────────────────────────────────────

def save_state(result: ReconResult, cfg_or_out=None, out_folder: Path | None = None) -> None:
    """
    Persist current scan state to disk after each phase.

    Supports two call forms (auto-detected):
        save_state(result, cfg, out_folder)   # explicit — preferred
        save_state(result, out_folder)        # legacy short-form used
                                              # inside orchestrator loops
    """
    if out_folder is None:
        # Legacy short-form — cfg_or_out is actually the out_folder Path.
        out_folder = Path(cfg_or_out) if cfg_or_out is not None else Path(".")
        cfg: ScanConfig | None = _last_cfg
    else:
        cfg = cfg_or_out  # type: ignore[assignment]

    if cfg is None:
        cfg = ScanConfig(target=result.target)

    state = {
        "schema_version": SCHEMA_VERSION,
        "version":        __version__,
        "config":         cfg.to_dict(),
        "result":         _result_to_dict(result),
        "out_folder":     str(out_folder),
    }
    path = Path(out_folder) / STATE_FILE
    try:
        path.write_text(json.dumps(state, indent=2, default=str))
    except Exception as e:
        safe_print(f"[dim]State save failed: {e}[/]")


# Process-local cache so the legacy 2-arg form can persist cfg between calls.
_last_cfg: ScanConfig | None = None


def set_active_config(cfg: ScanConfig) -> None:
    """Stash the active ScanConfig so subsequent save_state(result, out_folder)
    calls have access to it for serialisation."""
    global _last_cfg
    _last_cfg = cfg


def load_state(state_path) -> tuple[ReconResult, ScanConfig, Path] | None:
    """
    Load saved state from a state.json file.
    Returns (result, config, out_folder) or None on failure.
    """
    try:
        raw = json.loads(Path(state_path).read_text())
        cfg = _dict_to_config(raw.get("config", {}))
        result = _dict_to_result(raw.get("result", {}))
        out_folder = Path(raw.get("out_folder", Path(state_path).parent))
        set_active_config(cfg)
        safe_print(f"[success]✔ Resumed scan for [bold]{cfg.target}[/][/]")
        safe_print(f"  Completed phases: {', '.join(result.phases_completed) or 'none'}")
        return result, cfg, out_folder
    except Exception as e:
        console.print(f"[danger]Failed to load state: {e}[/]")
        return None


def find_latest_state(target: str, reports_dir: Path = Path("reports")) -> Path | None:
    """Find the most recent state.json for a given target."""
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


# Reconstruct dataclass lists from raw dicts.
_V9_LIST_FIELDS = {
    "ad_findings":         ADFinding,
    "cloud_deep_findings": CloudFinding,
    "llm_surfaces":        LLMSurface,
    "iot_findings":        IoTFinding,
    "container_findings":  ContainerFinding,
    "wireless_findings":   WirelessFinding,
    "darkweb_findings":    DarkWebFinding,
    "attack_chains":       AttackChain,
    "evidence_items":      EvidenceItem,
}


def _dict_to_result(d: dict) -> ReconResult:
    """Reconstruct ReconResult from a dict, restoring ALL v8/v9/v10 fields."""
    # Hosts need nested PortInfo reconstruction
    hosts = []
    for h in d.get("hosts", []):
        ports = [PortInfo(**p) for p in h.get("ports", [])]
        h = {**h, "ports": ports}
        hosts.append(HostResult(**h))

    web_findings    = [WebFinding(**wf) for wf in d.get("web_findings", [])]
    nuclei_findings = [VulnFinding(**vf) for vf in d.get("nuclei_findings", [])]

    kwargs: dict = {
        "target":           d.get("target", ""),
        "start_time":       d.get("start_time", ""),
        "end_time":         d.get("end_time", ""),
        "subdomains":       d.get("subdomains", []),
        "hosts":            hosts,
        "web_findings":     web_findings,
        "dir_findings":     d.get("dir_findings", []),
        "nikto_findings":   d.get("nikto_findings", []),
        "whatweb_findings": d.get("whatweb_findings", []),
        "nuclei_findings":  nuclei_findings,
        "masscan_ports":    d.get("masscan_ports", []),
        "rustscan_ports":   d.get("rustscan_ports", []),
        "ai_analysis":      d.get("ai_analysis", ""),
        "errors":           d.get("errors", []),
        "phases_completed": d.get("phases_completed", []),
        "shodan_results":   d.get("shodan_results", []),
        "vt_results":       d.get("vt_results", []),
        "whois_results":    d.get("whois_results", []),
        "wayback_results":  d.get("wayback_results", []),
        "ssl_results":      d.get("ssl_results", []),
        "github_findings":  d.get("github_findings", []),
        "js_findings":      d.get("js_findings", []),
        "bucket_findings":  d.get("bucket_findings", []),
        "dns_zone_results": d.get("dns_zone_results", []),
        "waf_results":      d.get("waf_results", []),
        "cors_findings":    d.get("cors_findings", []),
        "email_security":   d.get("email_security", []),
        "breach_results":   d.get("breach_results", []),
        "cloud_meta":       d.get("cloud_meta", []),
        "graphql_findings": d.get("graphql_findings", []),
        "jwt_findings":     d.get("jwt_findings", []),
        "asn_results":      d.get("asn_results", []),
        "supply_chain":     d.get("supply_chain", []),
        "k8s_findings":     d.get("k8s_findings", []),
        "db_findings":      d.get("db_findings", []),
        "smtp_findings":    d.get("smtp_findings", []),
        "snmp_findings":    d.get("snmp_findings", []),
        "ldap_findings":    d.get("ldap_findings", []),
        "devops_findings":  d.get("devops_findings", []),
        "greynoise_data":   d.get("greynoise_data", []),
        "typosquat_data":   d.get("typosquat_data", []),
        "censys_results":   d.get("censys_results", []),
        "dns_history":      d.get("dns_history", []),
        "api_fuzz":         d.get("api_fuzz", []),
        "oauth_scan":       d.get("oauth_scan", []),
        "web_vulns":        d.get("web_vulns", []),
        "open_redirect":    d.get("open_redirect", []),
        "linkedin":         d.get("linkedin", []),
        "paste_monitor":    d.get("paste_monitor", []),
        "se_osint":         d.get("se_osint", []),
        "apk_scan":         d.get("apk_scan", []),
        "app_store":        d.get("app_store", []),
        "anon_detect":      d.get("anon_detect", []),
        "dns_leak":         d.get("dns_leak", []),
        "web3_scan":        d.get("web3_scan", []),
        "ens_lookup":       d.get("ens_lookup", []),
        "attack_paths":     d.get("attack_paths", []),
        "remediations":     d.get("remediations", []),
        # v9
        "ad_findings":           [_coerce_dataclass(ADFinding, x) for x in d.get("ad_findings", [])],
        "cloud_deep_findings":   [_coerce_dataclass(CloudFinding, x) for x in d.get("cloud_deep_findings", [])],
        "llm_surfaces":          [_coerce_dataclass(LLMSurface, x) for x in d.get("llm_surfaces", [])],
        "iot_findings":          [_coerce_dataclass(IoTFinding, x) for x in d.get("iot_findings", [])],
        "container_findings":    [_coerce_dataclass(ContainerFinding, x) for x in d.get("container_findings", [])],
        "wireless_findings":     [_coerce_dataclass(WirelessFinding, x) for x in d.get("wireless_findings", [])],
        "darkweb_findings":      [_coerce_dataclass(DarkWebFinding, x) for x in d.get("darkweb_findings", [])],
        "attack_chains":         [_coerce_dataclass(AttackChain, x) for x in d.get("attack_chains", [])],
        "evidence_items":        [_coerce_dataclass(EvidenceItem, x) for x in d.get("evidence_items", [])],
        "graph_nodes":           d.get("graph_nodes", []),
        "graph_edges":           d.get("graph_edges", []),
        # v10
        "ai_consensus":          d.get("ai_consensus", {}),
        "aquatone_results":      d.get("aquatone_results", []),
    }
    return ReconResult(**kwargs)


def _coerce_dataclass(cls, value):
    """Rebuild a dataclass instance from a dict, ignoring unknown keys."""
    if isinstance(value, cls):
        return value
    if not isinstance(value, dict):
        return value
    valid = {f.name for f in fields(cls)}
    filtered = {k: v for k, v in value.items() if k in valid}
    try:
        return cls(**filtered)
    except Exception:
        return value


def _dict_to_config(d: dict) -> ScanConfig:
    """Reconstruct ScanConfig — restores ALL v8/v9/v10 fields via dataclass
    introspection so we never silently lose a setting."""
    nmap_raw = d.get("nmap_opts", {})
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
    try:
        profile = ScanProfile(profile_str)
    except Exception:
        profile = ScanProfile.STANDARD

    # Build kwargs by introspecting ScanConfig fields — this is forward-
    # compatible: any field added in v11+ will round-trip automatically.
    valid = {f.name for f in fields(ScanConfig)}
    kwargs: dict = {}
    for k, v in d.items():
        if k in ("nmap_opts", "profile"):
            continue
        if k in valid:
            kwargs[k] = v
    kwargs["profile"] = profile
    kwargs["nmap_opts"] = nmap_opts
    if "target" not in kwargs:
        kwargs["target"] = ""

    try:
        return ScanConfig(**kwargs)
    except Exception as e:
        # If a field has an unexpected type, fall back to defaults for it
        # by retrying with only the keys we know are safe.
        safe_print(f"[dim]Config rebuild fallback: {e}[/]")
        return ScanConfig(target=kwargs.get("target", ""), profile=profile, nmap_opts=nmap_opts)
