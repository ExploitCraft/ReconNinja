"""
ReconNinja v9 — Orchestration Engine
Replaces the v8 monolithic orchestrator.py with:
  - PhaseScheduler (parallel DAG execution)
  - SupervisorAgent (adaptive LLM-driven routing)
  - Scope enforcement pre-flight
  - All new v9 modules integrated
  - Evidence collection hooks
  - Graph building post-scan
  - Correlation pipeline
  - classic_mode=True → identical to v8 sequential behaviour

All v8 flags are preserved. State files from v8.x resume correctly.
"""
from __future__ import annotations

import copy
import ipaddress as _ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table

from utils.helpers import ensure_dir, timestamp, sanitize_dirname
from utils.logger import safe_print, console, _RESULT_LOCK, log
from utils.models import (
    ReconResult, ScanConfig, HostResult, ScopePolicy
)
from utils.notify import notify_finding

# v8 modules (all retained for backwards compat)
from core.subdomains import subdomain_enum
from core.ports import async_port_scan, run_rustscan, run_masscan, nmap_worker
from core.web import run_httpx, run_whatweb, run_nikto, run_dir_scan, enrich_hosts_with_web
from core.vuln import run_nuclei, run_aquatone, run_gowitness
from core.cve_lookup import lookup_cves_for_host_result
from core.ai_analysis import run_ai_analysis
from core.resume import save_state
from core.shodan_lookup import shodan_bulk_lookup
from core.virustotal import vt_domain_lookup, vt_ip_lookup
from core.whois_lookup import whois_lookup
from core.wayback import wayback_lookup
from core.ssl_scan import ssl_scan
from core.github_osint import github_osint
from core.js_extractor import extract_js_findings
from core.cloud_buckets import enumerate_buckets
from core.dns_zone_transfer import dns_zone_transfer_scan
from core.waf_detect import detect_waf
from core.cors_scan import scan_cors
from output.reports import generate_json_report, generate_html_report, generate_markdown_report
from core.email_security import email_security_scan
from core.breach_check import breach_check
from core.cloud_meta import cloud_meta_scan
from core.graphql_scan import graphql_scan
from core.jwt_scan import jwt_scan
from core.asn_map import asn_map
from core.supply_chain import supply_chain_scan
from core.k8s_probe import k8s_probe
from core.db_exposure import db_exposure_scan
from core.smtp_enum import smtp_user_enum as smtp_enum
from core.snmp_scan import snmp_scan
from core.ldap_enum import ldap_enum
from core.devops_scan import terraform_state_scan, jenkins_scan
from core.greynoise import greynoise_lookup
from core.typosquat import typosquat_scan
from core.censys_lookup import censys_bulk_lookup, dns_history_lookup
from output.sarif_export import export_sarif
from core.api_fuzz import api_fuzz_scan
from core.oauth_scan import oauth_scan
from core.web_vulns import web_vuln_scan
from core.open_redirect import open_redirect_scan
from core.linkedin_osint import linkedin_osint
from core.paste_monitor import paste_monitor
from core.se_osint import se_osint
from core.apk_scan import apk_scan
from core.app_store import app_store_scan
from core.anon_detect import anon_detect
from core.dns_leak import dns_leak_check
from core.web3_scan import web3_scan
from core.ens_lookup import ens_lookup
from core.ai_enhanced import run_consensus, generate_attack_paths, generate_remediations
from output.integrations import export_pdf, push_to_jira, push_to_github_issues, push_to_siem

# v9 modules
from core.ad_recon import ad_recon_scan
from core.cloud_deep import cloud_deep_scan
from core.llm_recon import llm_recon_scan
from core.iot_scan import iot_scan
from core.container_deep import container_deep_scan
from core.wireless_darkweb import wireless_osint_scan, darkweb_osint_scan
from core.scoring import enrich_findings_with_scores
from core.correlation import run_correlation_pipeline
from core.graph import ReconGraph, build_graph_from_result
from core.phase_scheduler import PhaseScheduler, PhaseTask
from core.supervisor import SupervisorAgent
from core.scope_evidence import (
    load_scope_policy, validate_preflight, filter_in_scope,
    collect_http_evidence, write_evidence_manifest,
)
from output.interactive_report import generate_interactive_report
from output.integrations_v9 import push_to_defectdojo, export_to_notion, export_to_obsidian
from plugins import discover_plugins, run_plugins
from info import __version__

REPORTS_DIR = Path("reports")
VERSION = __version__


# ─── Display helpers ──────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    colors = {"critical": "bold red", "high": "orange1", "medium": "yellow", "info": "dim"}
    return f"[{colors.get(sev, 'white')}]{sev.upper()}[/]"


def _phase_banner(phase: str) -> None:
    safe_print(Rule(f"[phase] {phase.upper()} [/phase]", style="bold blue"))


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_scan(cfg: ScanConfig) -> ReconResult:
    """
    v9 scan entry point.
    In classic_mode, falls through to sequential v8 execution.
    In agent_mode, uses PhaseScheduler + SupervisorAgent.
    """
    from utils.logger import setup_file_logger

    target = cfg.target
    out_folder = ensure_dir(
        Path(cfg.output_dir) / sanitize_dirname(target) / timestamp()
    )
    log_path = out_folder / "scan.log"
    global log
    log = setup_file_logger(log_path)

    safe_print(Panel(
        f"[bold cyan]ReconNinja v{VERSION}[/bold cyan]  |  Target: [bold]{target}[/bold]  "
        f"| Mode: [bold]{'CLASSIC' if cfg.classic_mode else 'AGENT' if cfg.agent_mode else 'STANDARD'}[/bold]",
        border_style="blue",
    ))

    # ── Scope enforcement ────────────────────────────────────────────────────
    scope = load_scope_policy(cfg)
    if not validate_preflight(target, scope, cfg):
        result = ReconResult(target=target, start_time=timestamp())
        result.errors.append(f"Target {target} is out of scope — scan aborted")
        return result

    result = ReconResult(target=target, start_time=timestamp())
    save_state(result, out_folder)

    plugins = discover_plugins()

    if cfg.classic_mode:
        _run_classic(cfg, result, out_folder, scope, plugins)
    elif cfg.agent_mode:
        _run_agent(cfg, result, out_folder, scope, plugins)
    else:
        _run_standard(cfg, result, out_folder, scope, plugins)

    result.end_time = timestamp()
    _finalise(cfg, result, out_folder)
    return result


# ─── Standard mode (parallel phases, no LLM routing) ─────────────────────────

def _run_standard(
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
    plugins: list,
) -> None:
    scheduler = PhaseScheduler(max_workers=cfg.parallel_phases)
    _register_all_phases(scheduler, cfg, result, out_folder, scope)

    completed_count = [0]
    total = len(scheduler._tasks)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=total)

        def on_start(phase_id: str):
            progress.update(task_id, description=f"[cyan]{phase_id}[/]")

        def on_done(phase_id: str, success: bool):
            completed_count[0] += 1
            progress.update(task_id, advance=1)
            result.phases_completed.append(phase_id)
            if not success:
                result.errors.append(f"Phase '{phase_id}' failed")
            save_state(result, out_folder)

        scheduler.run(on_start=on_start, on_done=on_done)

    run_plugins(plugins, cfg.target, out_folder, result, cfg)


# ─── Agent mode (PhaseScheduler + SupervisorAgent) ───────────────────────────

def _run_agent(
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
    plugins: list,
) -> None:
    supervisor = SupervisorAgent(cfg)
    scheduler = PhaseScheduler(max_workers=cfg.parallel_phases)
    queued: set[str] = set()

    _register_all_phases(scheduler, cfg, result, out_folder, scope)
    queued.update(scheduler._tasks.keys())

    def on_done(phase_id: str, success: bool):
        result.phases_completed.append(phase_id)
        if not success:
            result.errors.append(f"Phase '{phase_id}' failed")
        save_state(result, out_folder)
        # Ask supervisor for follow-up phases
        new_phases = supervisor.decide_next_phases(phase_id, result, queued)
        for p in new_phases:
            task = _build_phase_task(p, cfg, result, out_folder, scope)
            if task:
                scheduler.add(task)
                queued.add(p)
                safe_print(f"[info]  → Supervisor queued: {p}[/]")

    safe_print(f"[module]🧠  Agent mode: budget={cfg.agent_budget} LLM calls[/]")
    scheduler.run(on_done=on_done)
    safe_print(f"[info]Supervisor used {supervisor.calls_made}/{cfg.agent_budget} LLM calls[/]")
    run_plugins(plugins, cfg.target, out_folder, result, cfg)


# ─── Classic mode (v8 sequential, no scheduler) ───────────────────────────────

def _run_classic(
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
    plugins: list,
) -> None:
    safe_print("[dim]  Classic mode: sequential v8 execution[/]")
    _phase_banner("passive")
    _passive_phases(cfg, result, out_folder)
    _phase_banner("discovery")
    _discovery_phases(cfg, result, out_folder, scope)
    _phase_banner("web")
    _web_phases(cfg, result, out_folder)
    _phase_banner("vuln")
    _vuln_phases(cfg, result, out_folder)
    _phase_banner("v9 modules")
    _v9_modules(cfg, result, out_folder, scope)
    run_plugins(plugins, cfg.target, out_folder, result, cfg)


# ─── Phase registration ───────────────────────────────────────────────────────

def _register_all_phases(
    scheduler: PhaseScheduler,
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
) -> None:
    """Register all enabled phases with the scheduler."""
    t = cfg.target

    def add(phase_id: str, fn, *args, **kwargs):
        scheduler.add(PhaseTask(phase_id, fn, *args, **kwargs))

    # Passive
    if cfg.run_subdomains:     add("subdomains",    _run_subdomains,   cfg, result, out_folder)
    if cfg.run_whois:          add("whois",         whois_lookup,      t, result)
    if cfg.run_wayback:        add("wayback",       wayback_lookup,    t, result)
    if cfg.run_github_osint:   add("github_osint",  github_osint,      t, result, cfg)
    if cfg.run_asn_map:        add("asn_map",       asn_map,           t, result)
    if cfg.run_breach_check:   add("breach_check",  breach_check,      t, result, cfg)
    if cfg.run_email_security: add("email_security",email_security_scan,t,result)
    if cfg.run_supply_chain:   add("supply_chain",  supply_chain_scan, t, result)
    if cfg.run_typosquat:      add("typosquat",     typosquat_scan,    t, result)
    if cfg.run_virustotal:     add("virustotal",    _run_vt,           cfg, result)
    if cfg.run_censys:         add("censys",        censys_bulk_lookup,result.hosts, cfg.censys_api_id, cfg.censys_api_secret, result)
    if cfg.run_dns_history:    add("dns_history",   dns_history_lookup,t, cfg.censys_api_id, cfg.censys_api_secret, result)
    if cfg.run_shodan:         add("shodan",        shodan_bulk_lookup,result.hosts, cfg.shodan_key, result)
    if cfg.run_linkedin:       add("linkedin",      linkedin_osint,    t, result)
    if cfg.run_paste_monitor:  add("paste_monitor", paste_monitor,     t, result)
    if cfg.run_se_osint:       add("se_osint",      se_osint,          t, result)
    if cfg.run_app_store:      add("app_store",     app_store_scan,    t, result)
    if cfg.run_wireless_osint: add("wireless_osint",wireless_osint_scan,t, result, cfg, out_folder)
    if cfg.run_darkweb_osint:  add("darkweb_osint", darkweb_osint_scan,t, result, cfg, out_folder)
    if cfg.run_ad_recon:       add("ad_recon",      ad_recon_scan,     t, result, cfg, out_folder)

    # Port discovery
    add("async_tcp", _run_async_tcp, cfg, result)
    if cfg.run_rustscan: add("rustscan", _run_rustscan, cfg, result)
    if cfg.run_masscan:  add("masscan",  _run_masscan,  cfg, result, out_folder)

    # Nmap
    add("nmap", _run_nmap, cfg, result, out_folder)

    # Web
    if cfg.run_httpx:         add("httpx",    run_httpx,    cfg.target, result, cfg)
    if cfg.run_whatweb:       add("whatweb",  run_whatweb,  cfg.target, result, cfg)
    if cfg.run_ssl:            add("ssl",      ssl_scan,     cfg.target, result)
    if cfg.run_waf:            add("waf",      detect_waf,   cfg.target, result, cfg)
    if cfg.run_feroxbuster:    add("feroxbuster",run_dir_scan,cfg.target, result, cfg, out_folder)
    if cfg.run_cors:           add("cors",     scan_cors,    cfg.target, result, cfg)
    if cfg.run_js_extract:     add("js_extract",extract_js_findings,cfg.target, result, cfg)
    if cfg.run_api_fuzz:       add("api_fuzz", api_fuzz_scan,cfg.target, result, cfg)
    if cfg.run_oauth_scan:     add("oauth_scan",oauth_scan,  cfg.target, result, cfg)
    if cfg.run_web_vulns:      add("web_vulns",web_vuln_scan,cfg.target, result, cfg)
    if cfg.run_open_redirect:  add("open_redirect",open_redirect_scan,cfg.target, result, cfg)
    if cfg.run_graphql:        add("graphql",  graphql_scan, cfg.target, result, cfg)
    if cfg.run_jwt_scan:       add("jwt_scan", jwt_scan,     cfg.target, result, cfg)
    if cfg.run_nikto:          add("nikto",    run_nikto,    cfg.target, result, cfg, out_folder)
    if cfg.run_cloud_buckets:  add("cloud_buckets",enumerate_buckets,cfg.target, result, cfg)
    if cfg.run_anon_detect:    add("anon_detect",anon_detect,cfg.target, result, cfg)
    if cfg.run_web3_scan:      add("web3_scan",web3_scan,    cfg.target, result, cfg)
    if cfg.run_dns_zone:       add("dns_zone", dns_zone_transfer_scan,cfg.target, result)
    if cfg.run_dns_leak:       add("dns_leak", dns_leak_check,cfg.target, result)
    if cfg.run_ens_lookup:     add("ens_lookup",ens_lookup,  cfg.target, result, cfg)

    # Service-specific
    if cfg.run_cloud_meta:     add("cloud_meta",  cloud_meta_scan,    cfg.target, result, cfg)
    if cfg.run_cloud_deep:     add("cloud_deep",  cloud_deep_scan,    cfg.target, result, cfg, out_folder)
    if cfg.run_db_exposure:    add("db_exposure", db_exposure_scan,   cfg.target, result, cfg)
    if cfg.run_devops_scan:    add("devops_scan", _run_devops,        cfg, result)
    if cfg.run_k8s_probe:      add("k8s_probe",   k8s_probe,          cfg.target, result, cfg)
    if cfg.run_container_deep: add("container_deep",container_deep_scan,cfg.target, result, cfg, out_folder)
    if cfg.run_smtp_enum:      add("smtp_enum",   smtp_enum,           cfg.target, result, cfg)
    if cfg.run_snmp_scan:      add("snmp_scan",   snmp_scan,           cfg.target, result, cfg)
    if cfg.run_ldap_enum:      add("ldap_enum",   ldap_enum,           cfg.target, result, cfg)
    if cfg.run_greynoise:      add("greynoise",   greynoise_lookup,    result.hosts, cfg.greynoise_key, result)
    if cfg.run_llm_recon:      add("llm_recon",   llm_recon_scan,      cfg.target, result, cfg, out_folder)
    if cfg.run_iot_scan:       add("iot_scan",    iot_scan,            cfg.target, result, cfg, out_folder)

    # Vuln
    if cfg.run_nuclei:         add("nuclei",    run_nuclei,       cfg.target, result, cfg, out_folder)
    if cfg.run_cve_lookup:     add("cve_lookup",_run_cve_lookup,  cfg, result)
    if cfg.run_aquatone:       add("aquatone",  run_aquatone,     cfg.target, result, cfg, out_folder)
    if cfg.apk_path:           add("apk_scan",  apk_scan,         cfg.apk_path, result, cfg)

    # AI & correlation
    if cfg.run_ai_consensus:   add("ai_consensus",run_consensus,  cfg.target, result, cfg)
    if cfg.run_attack_paths:   add("attack_paths",generate_attack_paths,cfg.target, result, cfg)
    if cfg.run_ai_remediate:   add("ai_remediate",generate_remediations,cfg.target, result, cfg)
    if cfg.run_correlation:    add("correlation", run_correlation_pipeline, result, cfg)

    # Reports
    if cfg.run_sarif_export:   add("sarif_export",export_sarif,   result, out_folder)


# ─── Finalisation ─────────────────────────────────────────────────────────────

def _finalise(cfg: ScanConfig, result: ReconResult, out_folder: Path) -> None:
    """EPSS enrichment → graph build → reports → integrations → summary."""

    # EPSS / CVSSv4 enrichment
    if result.nuclei_findings:
        safe_print("[module]📊  Enriching with EPSS + CVSSv4...[/]")
        result.nuclei_findings = enrich_findings_with_scores(
            result.nuclei_findings,
            nvd_key=cfg.nvd_key,
            epss_threshold=cfg.epss_threshold,
        )

    # Build ReconGraph
    safe_print("[module]🕸  Building ReconGraph...[/]")
    graph = build_graph_from_result(result)
    data = graph.to_dict()
    result.graph_nodes = data["nodes"]
    result.graph_edges = data["edges"]

    # Graph export
    if cfg.graph_export == "graphml":
        gml = out_folder / "recon_graph.graphml"
        gml.write_text(graph.to_graphml(), encoding="utf-8")
        safe_print(f"[success]  ✔ GraphML: {gml}[/]")
    elif cfg.graph_export == "json-ld":
        jld = out_folder / "recon_graph.jsonld"
        jld.write_text(graph.to_json_ld(), encoding="utf-8")
        safe_print(f"[success]  ✔ JSON-LD: {jld}[/]")
    elif cfg.graph_export == "neo4j":
        try:
            graph.push_to_neo4j(cfg.neo4j_url)
            safe_print("[success]  ✔ Neo4j push complete[/]")
        except Exception as e:
            log.warning(f"Neo4j push failed: {e}")

    # AI analysis (fallback if not already done)
    if cfg.run_ai_analysis and not result.ai_analysis:
        result.ai_analysis = run_ai_analysis(result, cfg)

    # Standard reports
    _generate_reports(cfg, result, out_folder)

    # Interactive report
    if cfg.run_interactive_report:
        generate_interactive_report(result, cfg, out_folder)

    # Evidence manifest
    if cfg.run_evidence and result.evidence_items:
        write_evidence_manifest(result.evidence_items, out_folder)

    # Integrations
    if cfg.jira_config:          push_to_jira(result, cfg)
    if cfg.github_issues_config: push_to_github_issues(result, cfg)
    if cfg.siem_config:          push_to_siem(result, cfg)
    if cfg.defectdojo_url:       push_to_defectdojo(result, cfg)
    if cfg.run_notion_export:    export_to_notion(result, cfg)
    if cfg.run_obsidian_export:  export_to_obsidian(result, cfg, out_folder)

    # Summary table
    _print_summary(result, out_folder)
    save_state(result, out_folder)


# ─── Phase wrappers (thin functions for scheduler) ────────────────────────────

def _run_subdomains(cfg, result, out_folder):
    subs = subdomain_enum(cfg.target, out_folder, cfg)
    with _RESULT_LOCK:
        result.subdomains = list(set(result.subdomains + subs))
    result.phases_completed.append("subdomains")

def _run_async_tcp(cfg, result):
    import asyncio
    ports = asyncio.run(async_port_scan(cfg.target, cfg))
    with _RESULT_LOCK:
        result.rustscan_ports = list(set(result.rustscan_ports + ports))

def _run_rustscan(cfg, result):
    ports = run_rustscan(cfg.target, cfg)
    with _RESULT_LOCK:
        result.rustscan_ports = list(set(result.rustscan_ports + ports))

def _run_masscan(cfg, result, out_folder):
    ports = run_masscan(cfg.target, out_folder, cfg)
    with _RESULT_LOCK:
        result.masscan_ports = list(set(result.masscan_ports + ports))

def _run_nmap(cfg, result, out_folder):
    all_ports = list(set(result.rustscan_ports + result.masscan_ports))
    hosts = nmap_worker(cfg.target, all_ports, out_folder, cfg)
    with _RESULT_LOCK:
        result.hosts.extend(hosts)

def _run_vt(cfg, result):
    if result.subdomains:
        for sub in result.subdomains[:20]:
            data = vt_domain_lookup(sub, cfg.vt_key)
            if data:
                result.vt_results.append(data)
    for host in result.hosts[:10]:
        data = vt_ip_lookup(host.ip, cfg.vt_key)
        if data:
            result.vt_results.append(data)

def _run_cve_lookup(cfg, result):
    for host in result.hosts:
        lookup_cves_for_host_result(host, cfg.nvd_key, result)

def _run_devops(cfg, result):
    terraform_state_scan(cfg.target, result, cfg)
    jenkins_scan(cfg.target, result, cfg)

def _passive_phases(cfg, result, out_folder):
    if cfg.run_subdomains: _run_subdomains(cfg, result, out_folder)
    if cfg.run_whois:      whois_lookup(cfg.target, result)
    if cfg.run_wayback:    wayback_lookup(cfg.target, result)

def _discovery_phases(cfg, result, out_folder, scope):
    _run_async_tcp(cfg, result)
    if cfg.run_rustscan: _run_rustscan(cfg, result)
    if cfg.run_masscan:  _run_masscan(cfg, result, out_folder)
    _run_nmap(cfg, result, out_folder)

def _web_phases(cfg, result, out_folder):
    if cfg.run_httpx:       run_httpx(cfg.target, result, cfg)
    if cfg.run_whatweb:     run_whatweb(cfg.target, result, cfg)
    if cfg.run_ssl:          ssl_scan(cfg.target, result)
    if cfg.run_feroxbuster:  run_dir_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_nikto:        run_nikto(cfg.target, result, cfg, out_folder)

def _vuln_phases(cfg, result, out_folder):
    if cfg.run_nuclei:    run_nuclei(cfg.target, result, cfg, out_folder)
    if cfg.run_cve_lookup: _run_cve_lookup(cfg, result)

def _v9_modules(cfg, result, out_folder, scope):
    if cfg.run_ad_recon:       ad_recon_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_cloud_deep:     cloud_deep_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_llm_recon:      llm_recon_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_iot_scan:       iot_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_container_deep: container_deep_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_wireless_osint: wireless_osint_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_darkweb_osint:  darkweb_osint_scan(cfg.target, result, cfg, out_folder)
    if cfg.run_correlation:    run_correlation_pipeline(result, cfg)


def _generate_reports(cfg, result, out_folder):
    if cfg.output_format in ("all", "json"):
        generate_json_report(result, out_folder)
    if cfg.output_format in ("all", "html"):
        generate_html_report(result, out_folder, cfg)
    if cfg.output_format in ("all", "md"):
        generate_markdown_report(result, out_folder)
    if cfg.run_pdf_report:
        export_pdf(result, out_folder, cfg)


def _print_summary(result: ReconResult, out_folder: Path) -> None:
    table = Table(title=f"[bold]ReconNinja v{VERSION} — Scan Complete[/bold]", border_style="blue")
    table.add_column("Category", style="bold cyan")
    table.add_column("Count", justify="right")
    rows = [
        ("Subdomains",       len(result.subdomains)),
        ("Hosts",            len(result.hosts)),
        ("Open Ports",       sum(len(h.open_ports) for h in result.hosts)),
        ("Nuclei Findings",  len(result.nuclei_findings)),
        ("Critical",         sum(1 for f in result.nuclei_findings if f.severity == "critical")),
        ("Attack Chains",    len(result.attack_chains)),
        ("AD Findings",      len(result.ad_findings)),
        ("Cloud Findings",   len(result.cloud_deep_findings)),
        ("IoT Findings",     len(result.iot_findings)),
        ("Container Findings",len(result.container_findings)),
        ("LLM Surfaces",     len(result.llm_surfaces)),
        ("Errors",           len(result.errors)),
        ("Graph Nodes",      len(result.graph_nodes)),
        ("Report Dir",       str(out_folder)),
    ]
    for label, val in rows:
        style = "bold red" if label == "Critical" and val > 0 else ""
        table.add_row(label, f"[{style}]{val}[/]" if style else str(val))
    safe_print(table)


def _build_phase_task(
    phase_id: str,
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
) -> PhaseTask | None:
    """Build a PhaseTask for a supervisor-requested phase."""
    dispatch = {
        "ad_recon":       lambda: PhaseTask(phase_id, ad_recon_scan, cfg.target, result, cfg, out_folder),
        "cloud_deep":     lambda: PhaseTask(phase_id, cloud_deep_scan, cfg.target, result, cfg, out_folder),
        "llm_recon":      lambda: PhaseTask(phase_id, llm_recon_scan, cfg.target, result, cfg, out_folder),
        "iot_scan":       lambda: PhaseTask(phase_id, iot_scan, cfg.target, result, cfg, out_folder),
        "container_deep": lambda: PhaseTask(phase_id, container_deep_scan, cfg.target, result, cfg, out_folder),
        "ldap_enum":      lambda: PhaseTask(phase_id, ldap_enum, cfg.target, result, cfg),
        "db_exposure":    lambda: PhaseTask(phase_id, db_exposure_scan, cfg.target, result, cfg),
        "jwt_scan":       lambda: PhaseTask(phase_id, jwt_scan, cfg.target, result, cfg),
        "graphql":        lambda: PhaseTask(phase_id, graphql_scan, cfg.target, result, cfg),
        "api_fuzz":       lambda: PhaseTask(phase_id, api_fuzz_scan, cfg.target, result, cfg),
        "cors":           lambda: PhaseTask(phase_id, scan_cors, cfg.target, result, cfg),
        "oauth_scan":     lambda: PhaseTask(phase_id, oauth_scan, cfg.target, result, cfg),
    }
    factory = dispatch.get(phase_id)
    return factory() if factory else None
