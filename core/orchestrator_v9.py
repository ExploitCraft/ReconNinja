"""
ReconNinja v10 — Orchestration Engine
=====================================

V10 replaces the broken v9 call-site spaghetti with a uniform PhaseContext
adapter pattern. Every v8 module is invoked through a thin wrapper that:

  1. Calls the underlying function with its ORIGINAL signature (no more
     TypeError because we passed (cfg, result, out_folder) to a function
     that expects (target, out_folder)).
  2. Catches all exceptions per-phase so one failing module never aborts
     the whole scan.
  3. Routes the return value into the correct ReconResult field under
     _RESULT_LOCK so concurrent PhaseScheduler workers stay safe.
  4. Logs the elapsed time + exception (if any) to the scan log file.

All v8 / v9 modules, AI wrappers, reports and integrations are retained.
classic_mode=True is still a faithful v8-sequential fallback.

Resume round-trip (save_state/load_state) is fixed and forward-compatible
via a `schema_version` field — see core/resume.py.
"""
from __future__ import annotations

import functools
import time
import traceback
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
from utils.models import ReconResult, ScanConfig, HostResult, ScopePolicy
from utils.notify import notify_finding

# v8 modules — all retained
from core.subdomains import subdomain_enum
from core.ports import async_port_scan, run_rustscan, run_masscan, nmap_worker
from core.web import run_httpx, run_whatweb, run_nikto, run_dir_scan, enrich_hosts_with_web
from core.vuln import run_nuclei, run_aquatone, run_gowitness
from core.cve_lookup import lookup_cves_for_host_result
from core.ai_analysis import run_ai_analysis
from core.resume import save_state
from core.shodan_lookup import shodan_bulk_lookup, shodan_host_lookup
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

VERSION = __version__


# ─── Display helpers ──────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    colors = {"critical": "bold red", "high": "orange1", "medium": "yellow", "info": "dim"}
    return f"[{colors.get(sev, 'white')}]{sev.upper()}[/]"


def _phase_banner(phase: str) -> None:
    safe_print(Rule(f"[phase] {phase.upper()} [/phase]", style="bold blue"))


# ─── Phase wrapper decorator ──────────────────────────────────────────────────
#
# Every wrapper below is wrapped with @phase_wrap("name").  The decorator:
#   • Acquires _RESULT_LOCK around the body (so result mutation is thread-safe)
#   • Catches Exception, logs traceback to file, appends a friendly error to
#     result.errors
#   • Prints a one-line status banner with elapsed time
# The wrapped function still receives (cfg, result, out_folder) so the
# PhaseScheduler passes a uniform PhaseContext.

def phase_wrap(phase_id: str):
    def deco(fn):
        @functools.wraps(fn)
        def inner(cfg: ScanConfig, result: ReconResult, out_folder: Path):
            t0 = time.monotonic()
            safe_print(f"[cyan]▸ {phase_id}[/cyan]")
            try:
                fn(cfg, result, out_folder)
                elapsed = time.monotonic() - t0
                safe_print(f"[green]  ✔ {phase_id} ({elapsed:.1f}s)[/green]")
                if phase_id not in result.phases_completed:
                    result.phases_completed.append(phase_id)
            except Exception as e:
                tb = traceback.format_exc()
                try:
                    log.error(f"Phase '{phase_id}' failed: {e}\n{tb}")
                except Exception:
                    pass
                msg = f"Phase '{phase_id}' failed: {type(e).__name__}: {e}"
                result.errors.append(msg)
                safe_print(f"[red]  ✗ {phase_id}: {type(e).__name__}: {e}[/red]")
            finally:
                try:
                    save_state(result, cfg, out_folder)
                except Exception:
                    pass
        return inner
    return deco


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_scan(cfg: ScanConfig) -> ReconResult:
    """v10 scan entry point."""
    from utils.logger import setup_file_logger
    from core.resume import set_active_config
    set_active_config(cfg)

    target = cfg.target
    out_folder = ensure_dir(
        Path(cfg.output_dir) / sanitize_dirname(target) / timestamp()
    )
    log_path = out_folder / "scan.log"
    setup_file_logger(log_path)

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
    save_state(result, cfg, out_folder)

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

    total = len(scheduler.task_ids())

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=total)

        def on_start(phase_id: str):
            progress.update(task_id, description=f"[cyan]{phase_id}[/]")

        def on_done(phase_id: str, success: bool):
            progress.update(task_id, advance=1)
            if not success:
                result.errors.append(f"Phase '{phase_id}' failed")

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
    _register_all_phases(scheduler, cfg, result, out_folder, scope)
    queued: set[str] = set(scheduler.task_ids())

    def on_done(phase_id: str, success: bool):
        if not success:
            result.errors.append(f"Phase '{phase_id}' failed")
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
#
# Each `add(phase_id, fn, cfg, result, out_folder)` schedules a wrapper that
# matches the v8 module's REAL signature.  No more TypeErrors.

def _register_all_phases(
    scheduler: PhaseScheduler,
    cfg: ScanConfig,
    result: ReconResult,
    out_folder: Path,
    scope: ScopePolicy,
) -> None:
    """Register all enabled phases with the scheduler."""

    def add(phase_id: str, fn, *args, **kwargs):
        scheduler.add(PhaseTask(phase_id, fn, *args, **kwargs))

    # ── Passive ──────────────────────────────────────────────────────────────
    if cfg.run_subdomains:        add("subdomains",      _w_subdomains,        cfg, result, out_folder)
    if cfg.run_whois:             add("whois",           _w_whois,             cfg, result, out_folder)
    if cfg.run_wayback:           add("wayback",         _w_wayback,           cfg, result, out_folder)
    if cfg.run_github_osint:      add("github_osint",    _w_github_osint,      cfg, result, out_folder)
    if cfg.run_asn_map:           add("asn_map",         _w_asn_map,           cfg, result, out_folder)
    if cfg.run_breach_check:      add("breach_check",    _w_breach_check,      cfg, result, out_folder)
    if cfg.run_email_security:    add("email_security",  _w_email_security,    cfg, result, out_folder)
    if cfg.run_supply_chain:      add("supply_chain",    _w_supply_chain,      cfg, result, out_folder)
    if cfg.run_typosquat:         add("typosquat",       _w_typosquat,         cfg, result, out_folder)
    if cfg.run_virustotal:        add("virustotal",      _w_virustotal,        cfg, result, out_folder)
    if cfg.run_censys:            add("censys",          _w_censys,            cfg, result, out_folder)
    if cfg.run_dns_history:       add("dns_history",     _w_dns_history,       cfg, result, out_folder)
    if cfg.run_shodan:            add("shodan",          _w_shodan,            cfg, result, out_folder)
    if cfg.run_linkedin:          add("linkedin",        _w_linkedin,          cfg, result, out_folder)
    if cfg.run_paste_monitor:     add("paste_monitor",   _w_paste_monitor,     cfg, result, out_folder)
    if cfg.run_se_osint:          add("se_osint",        _w_se_osint,          cfg, result, out_folder)
    if cfg.run_app_store:         add("app_store",       _w_app_store,         cfg, result, out_folder)
    if cfg.run_wireless_osint:    add("wireless_osint",  _w_wireless_osint,    cfg, result, out_folder)
    if cfg.run_darkweb_osint:     add("darkweb_osint",   _w_darkweb_osint,     cfg, result, out_folder)
    if cfg.run_ad_recon:          add("ad_recon",        _w_ad_recon,          cfg, result, out_folder)

    # ── Port discovery ──────────────────────────────────────────────────────
    add("async_tcp", _w_async_tcp, cfg, result, out_folder)
    if cfg.run_rustscan: add("rustscan", _w_rustscan, cfg, result, out_folder)
    if cfg.run_masscan:  add("masscan",  _w_masscan,  cfg, result, out_folder)
    add("nmap", _w_nmap, cfg, result, out_folder)

    # ── Web ─────────────────────────────────────────────────────────────────
    if cfg.run_httpx:           add("httpx",         _w_httpx,         cfg, result, out_folder)
    if cfg.run_whatweb:         add("whatweb",       _w_whatweb,       cfg, result, out_folder)
    if cfg.run_ssl:             add("ssl",           _w_ssl,           cfg, result, out_folder)
    if cfg.run_waf:             add("waf",           _w_waf,           cfg, result, out_folder)
    if cfg.run_feroxbuster:     add("feroxbuster",   _w_dir_scan,      cfg, result, out_folder)
    if cfg.run_cors:            add("cors",          _w_cors,          cfg, result, out_folder)
    if cfg.run_js_extract:      add("js_extract",    _w_js_extract,    cfg, result, out_folder)
    if cfg.run_api_fuzz:        add("api_fuzz",      _w_api_fuzz,      cfg, result, out_folder)
    if cfg.run_oauth_scan:      add("oauth_scan",    _w_oauth_scan,    cfg, result, out_folder)
    if cfg.run_web_vulns:       add("web_vulns",     _w_web_vulns,     cfg, result, out_folder)
    if cfg.run_open_redirect:   add("open_redirect", _w_open_redirect, cfg, result, out_folder)
    if cfg.run_graphql:         add("graphql",       _w_graphql,       cfg, result, out_folder)
    if cfg.run_jwt_scan:        add("jwt_scan",      _w_jwt_scan,      cfg, result, out_folder)
    if cfg.run_nikto:           add("nikto",         _w_nikto,         cfg, result, out_folder)
    if cfg.run_cloud_buckets:   add("cloud_buckets", _w_cloud_buckets, cfg, result, out_folder)
    if cfg.run_anon_detect:     add("anon_detect",   _w_anon_detect,   cfg, result, out_folder)
    if cfg.run_web3_scan:       add("web3_scan",     _w_web3_scan,     cfg, result, out_folder)
    if cfg.run_dns_zone:        add("dns_zone",      _w_dns_zone,      cfg, result, out_folder)
    if cfg.run_dns_leak:        add("dns_leak",      _w_dns_leak,      cfg, result, out_folder)
    if cfg.run_ens_lookup:      add("ens_lookup",    _w_ens_lookup,    cfg, result, out_folder)

    # ── Service-specific ────────────────────────────────────────────────────
    if cfg.run_cloud_meta:      add("cloud_meta",     _w_cloud_meta,     cfg, result, out_folder)
    if cfg.run_cloud_deep:      add("cloud_deep",     _w_cloud_deep,     cfg, result, out_folder)
    if cfg.run_db_exposure:     add("db_exposure",    _w_db_exposure,    cfg, result, out_folder)
    if cfg.run_devops_scan:     add("devops_scan",    _w_devops,    cfg, result, out_folder)
    if cfg.run_k8s_probe:       add("k8s_probe",      _w_k8s_probe,      cfg, result, out_folder)
    if cfg.run_container_deep:  add("container_deep", _w_container_deep, cfg, result, out_folder)
    if cfg.run_smtp_enum:       add("smtp_enum",      _w_smtp_enum,      cfg, result, out_folder)
    if cfg.run_snmp_scan:       add("snmp_scan",      _w_snmp_scan,      cfg, result, out_folder)
    if cfg.run_ldap_enum:       add("ldap_enum",      _w_ldap_enum,      cfg, result, out_folder)
    if cfg.run_greynoise:       add("greynoise",      _w_greynoise,      cfg, result, out_folder)
    if cfg.run_llm_recon:       add("llm_recon",      _w_llm_recon,      cfg, result, out_folder)
    if cfg.run_iot_scan:        add("iot_scan",       _w_iot_scan,       cfg, result, out_folder)

    # ── Vuln ────────────────────────────────────────────────────────────────
    if cfg.run_nuclei:          add("nuclei",         _w_nuclei,         cfg, result, out_folder)
    if cfg.run_cve_lookup:      add("cve_lookup",     _w_cve_lookup,     cfg, result, out_folder)
    if cfg.run_aquatone:        add("aquatone",       _w_aquatone,       cfg, result, out_folder)
    if cfg.apk_path:            add("apk_scan",       _w_apk_scan,       cfg, result, out_folder)

    # ── AI & correlation ─────────────────────────────────────────────────────
    if cfg.run_ai_consensus:    add("ai_consensus",   _w_ai_consensus,   cfg, result, out_folder)
    if cfg.run_attack_paths:    add("attack_paths",   _w_attack_paths,   cfg, result, out_folder)
    if cfg.run_ai_remediate:    add("ai_remediate",   _w_ai_remediate,   cfg, result, out_folder)
    if cfg.run_correlation:     add("correlation",    _w_correlation,    cfg, result, out_folder)

    # ── Reports ──────────────────────────────────────────────────────────────
    if cfg.run_sarif_export:    add("sarif_export",   _w_sarif_export,   cfg, result, out_folder)


# ─── Finalisation ─────────────────────────────────────────────────────────────

def _finalise(cfg: ScanConfig, result: ReconResult, out_folder: Path) -> None:
    """EPSS enrichment → graph build → reports → integrations → summary."""

    # EPSS / CVSSv4 enrichment
    if result.nuclei_findings:
        safe_print("[module]📊  Enriching with EPSS + CVSSv4...[/]")
        try:
            result.nuclei_findings = enrich_findings_with_scores(
                result.nuclei_findings,
                nvd_key=cfg.nvd_key,
                epss_threshold=cfg.epss_threshold,
            )
        except Exception as e:
            log.warning(f"EPSS enrichment failed: {e}")

    # Build ReconGraph
    safe_print("[module]🕸  Building ReconGraph...[/]")
    try:
        graph = build_graph_from_result(result)
        data = graph.to_dict()
        result.graph_nodes = data["nodes"]
        result.graph_edges = data["edges"]
    except Exception as e:
        log.warning(f"Graph build failed: {e}")
        graph = None

    # Graph export
    if graph and cfg.graph_export == "graphml":
        gml = out_folder / "recon_graph.graphml"
        gml.write_text(graph.to_graphml(), encoding="utf-8")
        safe_print(f"[success]  ✔ GraphML: {gml}[/]")
    elif graph and cfg.graph_export == "json-ld":
        jld = out_folder / "recon_graph.jsonld"
        jld.write_text(graph.to_json_ld(), encoding="utf-8")
        safe_print(f"[success]  ✔ JSON-LD: {jld}[/]")
    elif graph and cfg.graph_export == "neo4j":
        try:
            graph.push_to_neo4j(cfg.neo4j_url)
            safe_print("[success]  ✔ Neo4j push complete[/]")
        except Exception as e:
            log.warning(f"Neo4j push failed: {e}")

    # AI analysis (fallback if not already done)
    if cfg.run_ai_analysis and not result.ai_analysis:
        try:
            result.ai_analysis = run_ai_analysis(result, cfg)
        except Exception as e:
            log.warning(f"AI analysis failed: {e}")

    # Standard reports
    _generate_reports(cfg, result, out_folder)

    # Interactive report
    if cfg.run_interactive_report:
        try:
            generate_interactive_report(result, cfg, out_folder)
        except Exception as e:
            log.warning(f"Interactive report failed: {e}")

    # Evidence manifest
    if cfg.run_evidence and result.evidence_items:
        try:
            write_evidence_manifest(result.evidence_items, out_folder)
        except Exception as e:
            log.warning(f"Evidence manifest failed: {e}")

    # Integrations
    if cfg.jira_config:          _safe_call(push_to_jira, result, cfg)
    if cfg.github_issues_config: _safe_call(push_to_github_issues, result, cfg)
    if cfg.siem_config:          _safe_call(push_to_siem, result, cfg)
    if cfg.defectdojo_url:       _safe_call(push_to_defectdojo, result, cfg)
    if cfg.run_notion_export:    _safe_call(export_to_notion, result, cfg)
    if cfg.run_obsidian_export:  _safe_call(export_to_obsidian, result, cfg, out_folder)

    # Summary table
    _print_summary(result, out_folder)
    save_state(result, cfg, out_folder)


def _safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        try:
            log.warning(f"Integration {fn.__name__} failed: {e}")
        except Exception:
            pass


# ─── Classic-mode phase groups (sequential v8 fallback) ───────────────────────

def _passive_phases(cfg, result, out_folder):
    if cfg.run_subdomains: _w_subdomains(cfg, result, out_folder)
    if cfg.run_whois:      _w_whois(cfg, result, out_folder)
    if cfg.run_wayback:    _w_wayback(cfg, result, out_folder)

def _discovery_phases(cfg, result, out_folder, scope):
    _w_async_tcp(cfg, result, out_folder)
    if cfg.run_rustscan: _w_rustscan(cfg, result, out_folder)
    if cfg.run_masscan:  _w_masscan(cfg, result, out_folder)
    _w_nmap(cfg, result, out_folder)

def _web_phases(cfg, result, out_folder):
    if cfg.run_httpx:       _w_httpx(cfg, result, out_folder)
    if cfg.run_whatweb:     _w_whatweb(cfg, result, out_folder)
    if cfg.run_ssl:         _w_ssl(cfg, result, out_folder)
    if cfg.run_feroxbuster: _w_dir_scan(cfg, result, out_folder)
    if cfg.run_nikto:       _w_nikto(cfg, result, out_folder)

def _vuln_phases(cfg, result, out_folder):
    if cfg.run_nuclei:     _w_nuclei(cfg, result, out_folder)
    if cfg.run_cve_lookup: _w_cve_lookup(cfg, result, out_folder)

def _v9_modules(cfg, result, out_folder, scope):
    if cfg.run_ad_recon:       _w_ad_recon(cfg, result, out_folder)
    if cfg.run_cloud_deep:     _w_cloud_deep(cfg, result, out_folder)
    if cfg.run_llm_recon:      _w_llm_recon(cfg, result, out_folder)
    if cfg.run_iot_scan:       _w_iot_scan(cfg, result, out_folder)
    if cfg.run_container_deep: _w_container_deep(cfg, result, out_folder)
    if cfg.run_wireless_osint: _w_wireless_osint(cfg, result, out_folder)
    if cfg.run_darkweb_osint:  _w_darkweb_osint(cfg, result, out_folder)
    if cfg.run_correlation:    _w_correlation(cfg, result, out_folder)


def _generate_reports(cfg, result, out_folder):
    """v10 fix: report generators take a FILE path, not a directory.
    The v9 orchestrator passed `out_folder` (a Path to a directory) and
    every report call raised IsADirectoryError."""
    if cfg.output_format in ("all", "json"):
        _safe_call(generate_json_report, result, out_folder / "report.json")
    if cfg.output_format in ("all", "html"):
        _safe_call(generate_html_report, result, out_folder / "report.html")
    if cfg.output_format in ("all", "md"):
        _safe_call(generate_markdown_report, result, out_folder / "report.md")
    if cfg.run_pdf_report:
        _safe_call(export_pdf, result, out_folder)


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
        "ad_recon":       lambda: PhaseTask(phase_id, _w_ad_recon,       cfg, result, out_folder),
        "cloud_deep":     lambda: PhaseTask(phase_id, _w_cloud_deep,     cfg, result, out_folder),
        "llm_recon":      lambda: PhaseTask(phase_id, _w_llm_recon,      cfg, result, out_folder),
        "iot_scan":       lambda: PhaseTask(phase_id, _w_iot_scan,       cfg, result, out_folder),
        "container_deep": lambda: PhaseTask(phase_id, _w_container_deep, cfg, result, out_folder),
        "ldap_enum":      lambda: PhaseTask(phase_id, _w_ldap_enum,      cfg, result, out_folder),
        "db_exposure":    lambda: PhaseTask(phase_id, _w_db_exposure,    cfg, result, out_folder),
        "jwt_scan":       lambda: PhaseTask(phase_id, _w_jwt_scan,       cfg, result, out_folder),
        "graphql":        lambda: PhaseTask(phase_id, _w_graphql,        cfg, result, out_folder),
        "api_fuzz":       lambda: PhaseTask(phase_id, _w_api_fuzz,       cfg, result, out_folder),
        "cors":           lambda: PhaseTask(phase_id, _w_cors,           cfg, result, out_folder),
        "oauth_scan":     lambda: PhaseTask(phase_id, _w_oauth_scan,     cfg, result, out_folder),
    }
    factory = dispatch.get(phase_id)
    return factory() if factory else None


# ═══════════════════════════════════════════════════════════════════════════════
#   PHASE WRAPPERS  (each calls its v8 module with the REAL signature)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Conventions:
#   • Each wrapper takes (cfg, result, out_folder) — the uniform PhaseContext.
#   • Each wrapper acquires _RESULT_LOCK around result mutation.
#   • Each wrapper swallows module-specific exceptions and routes them to
#     result.errors so one bad module never aborts the whole scan.
#   • The @phase_wrap decorator handles timing, logging and save_state().

@phase_wrap("subdomains")
def _w_subdomains(cfg, result, out_folder):
    subs = subdomain_enum(cfg.target, out_folder, cfg.wordlist_size)
    with _RESULT_LOCK:
        result.subdomains = sorted(set(result.subdomains + (subs or [])))


@phase_wrap("whois")
def _w_whois(cfg, result, out_folder):
    data = whois_lookup(cfg.target)
    with _RESULT_LOCK:
        result.whois_results.append(data or {})


@phase_wrap("wayback")
def _w_wayback(cfg, result, out_folder):
    data = wayback_lookup(cfg.target, limit=500)
    with _RESULT_LOCK:
        result.wayback_results.append(data or {})


@phase_wrap("github_osint")
def _w_github_osint(cfg, result, out_folder):
    data = github_osint(cfg.target, cfg.github_token)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.github_findings.extend(data)
        elif data:
            result.github_findings.append(data)


@phase_wrap("asn_map")
def _w_asn_map(cfg, result, out_folder):
    data = asn_map(cfg.target, out_folder)
    with _RESULT_LOCK:
        result.asn_results.append(data or {})


@phase_wrap("breach_check")
def _w_breach_check(cfg, result, out_folder):
    data = breach_check(cfg.target, out_folder, cfg.hibp_key)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.breach_results.extend(data)
        elif data:
            result.breach_results.append(data)


@phase_wrap("email_security")
def _w_email_security(cfg, result, out_folder):
    data = email_security_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.email_security.extend(data)
        elif data:
            result.email_security.append(data)


@phase_wrap("supply_chain")
def _w_supply_chain(cfg, result, out_folder):
    web_urls = _web_urls(result)
    data = supply_chain_scan(web_urls, cfg.target)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.supply_chain.extend(data)
        elif data:
            result.supply_chain.append(data)


@phase_wrap("typosquat")
def _w_typosquat(cfg, result, out_folder):
    data = typosquat_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.typosquat_data.extend(data)
        elif data:
            result.typosquat_data.append(data)


@phase_wrap("virustotal")
def _w_virustotal(cfg, result, out_folder):
    if not cfg.vt_key:
        raise RuntimeError("VirusTotal API key not set (--vt-key or VT_KEY env var)")
    findings = []
    for sub in (result.subdomains or [])[:20]:
        d = vt_domain_lookup(sub, cfg.vt_key)
        if d:
            findings.append(d)
    for host in (result.hosts or [])[:10]:
        d = vt_ip_lookup(host.ip, cfg.vt_key)
        if d:
            findings.append(d)
    with _RESULT_LOCK:
        result.vt_results.extend(findings)


@phase_wrap("censys")
def _w_censys(cfg, result, out_folder):
    if not cfg.censys_api_id or not cfg.censys_api_secret:
        raise RuntimeError("Censys API id/secret not set")
    ips = [h.ip for h in result.hosts if h.ip]
    data = censys_bulk_lookup(ips, cfg.censys_api_id, cfg.censys_api_secret)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.censys_results.extend(data)
        elif data:
            result.censys_results.append(data)


@phase_wrap("dns_history")
def _w_dns_history(cfg, result, out_folder):
    if not cfg.vt_key:
        raise RuntimeError("DNS history uses VirusTotal --vt-key (not set)")
    data = dns_history_lookup(cfg.target, cfg.vt_key, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.dns_history.extend(data)
        elif data:
            result.dns_history.append(data)


@phase_wrap("shodan")
def _w_shodan(cfg, result, out_folder):
    if not cfg.shodan_key:
        raise RuntimeError("Shodan API key not set (--shodan-key or SHODAN_KEY env var)")
    ips = [h.ip for h in result.hosts if h.ip]
    if not ips:
        # Fall back to single host lookup against the target itself
        data = shodan_host_lookup(cfg.target, cfg.shodan_key)
        with _RESULT_LOCK:
            result.shodan_results.append(data or {})
        return
    data = shodan_bulk_lookup(ips, cfg.shodan_key)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.shodan_results.extend(data)
        elif data:
            result.shodan_results.append(data)


@phase_wrap("linkedin")
def _w_linkedin(cfg, result, out_folder):
    data = linkedin_osint(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.linkedin.extend(data)
        elif data:
            result.linkedin.append(data)


@phase_wrap("paste_monitor")
def _w_paste_monitor(cfg, result, out_folder):
    data = paste_monitor(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.paste_monitor.extend(data)
        elif data:
            result.paste_monitor.append(data)


@phase_wrap("se_osint")
def _w_se_osint(cfg, result, out_folder):
    data = se_osint(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.se_osint.extend(data)
        elif data:
            result.se_osint.append(data)


@phase_wrap("app_store")
def _w_app_store(cfg, result, out_folder):
    data = app_store_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.app_store.extend(data)
        elif data:
            result.app_store.append(data)


@phase_wrap("wireless_osint")
def _w_wireless_osint(cfg, result, out_folder):
    data = wireless_osint_scan(cfg.target, out_folder, cfg.wigle_api_token)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.wireless_findings.extend(data)
        elif data:
            result.wireless_findings.append(data)


@phase_wrap("darkweb_osint")
def _w_darkweb_osint(cfg, result, out_folder):
    data = darkweb_osint_scan(cfg.target, out_folder, cfg.telegram_token)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.darkweb_findings.extend(data)
        elif data:
            result.darkweb_findings.append(data)


@phase_wrap("ad_recon")
def _w_ad_recon(cfg, result, out_folder):
    data = ad_recon_scan(cfg.target, out_folder, cfg)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.ad_findings.extend(data)
        elif data:
            result.ad_findings.append(data)


@phase_wrap("async_tcp")
def _w_async_tcp(cfg, result, out_folder):
    # async_port_scan signature:
    #   (target, ports=None, top_n=None, concurrency, connect_timeout, out_folder)
    #   → (list[PortInfo] for OPEN ports, list[int] for FILTERED ports)
    # v10.5.1 FIX: the second return value is FILTERED ports, NOT open ports!
    # We were storing filtered ports as rustscan_ports — which polluted the
    # port list with 1000 closed ports and made nmap scan everything.
    # Now we extract open port numbers from port_infos (the first return value).
    port_infos, _filtered = async_port_scan(
        cfg.target, top_n=cfg.nmap_opts.top_ports, out_folder=out_folder,
    )
    open_port_nums = [p.port for p in (port_infos or [])]
    with _RESULT_LOCK:
        result.rustscan_ports = sorted(set(result.rustscan_ports + open_port_nums))
        # v10.5.1 FIX: create a HostResult from the async scan results so that
        # even when nmap isn't installed, the open ports show up in the report.
        # Without this, result.hosts stays empty and the report shows
        # "Open Ports: 0" even though async_tcp found open ports.
        if port_infos and not any(h.ip == cfg.target or cfg.target in h.hostnames
                                   for h in result.hosts):
            # Resolve the target to an IP for the HostResult
            import socket
            try:
                ip = socket.gethostbyname(cfg.target)
            except Exception:
                ip = cfg.target
            host = HostResult(
                ip=ip,
                hostnames=[cfg.target],
                ports=list(port_infos),
            )
            result.hosts.append(host)


@phase_wrap("rustscan")
def _w_rustscan(cfg, result, out_folder):
    # run_rustscan signature: (target, out_folder, all_ports=True) → set[int]
    ports = run_rustscan(cfg.target, out_folder, all_ports=cfg.nmap_opts.all_ports)
    with _RESULT_LOCK:
        result.rustscan_ports = sorted(set(result.rustscan_ports + (ports or set())))


@phase_wrap("masscan")
def _w_masscan(cfg, result, out_folder):
    # run_masscan signature: (target, out_folder, rate=5000) → (Path|None, set[int])
    _, ports = run_masscan(cfg.target, out_folder, rate=cfg.masscan_rate)
    with _RESULT_LOCK:
        result.masscan_ports = sorted(set(result.masscan_ports + (ports or set())))


@phase_wrap("nmap")
def _w_nmap(cfg, result, out_folder):
    all_ports = list(set(result.rustscan_ports + result.masscan_ports))
    if not all_ports:
        # v10.5.1: no open ports discovered by async_tcp/rustscan/masscan —
        # nothing for nmap to deep-scan. Don't call nmap_worker with an empty
        # port list (it would error out or scan all 65535 ports).
        return
    # nmap_worker signature is (subdomain, open_ports, out_folder, scripts,
    # version_detection, timing) and returns (subdomain, hosts, errors).
    ret = nmap_worker(
        cfg.target,
        set(all_ports),
        out_folder,
        scripts=cfg.nmap_opts.scripts,
        version_detection=cfg.nmap_opts.version_detection,
        timing=cfg.nmap_opts.timing,
    )
    # Unpack — ret is (subdomain_str, hosts_list, errors_list)
    if isinstance(ret, tuple) and len(ret) == 3:
        _, hosts, errors = ret
        if errors:
            result.errors.extend([f"nmap: {e}" for e in errors])
    else:
        hosts = ret if isinstance(ret, list) else []
    with _RESULT_LOCK:
        if hosts:
            # v10.5.1: merge nmap results into existing HostResult (if async_tcp
            # already created one) instead of appending a duplicate. If nmap
            # found richer data (service versions, scripts), replace the
            # async_tcp HostResult's ports with nmap's more detailed ports.
            existing = next((h for h in result.hosts
                             if h.ip == cfg.target or cfg.target in h.hostnames), None)
            if existing:
                # Merge: keep the richer port info from nmap
                existing.ports = hosts[0].ports if hosts else existing.ports
            else:
                result.hosts.extend(hosts)


@phase_wrap("httpx")
def _w_httpx(cfg, result, out_folder):
    targets = [cfg.target] + (result.subdomains or [])
    data = run_httpx(targets, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.web_findings.extend(data)
        elif data:
            result.web_findings.append(data)


@phase_wrap("whatweb")
def _w_whatweb(cfg, result, out_folder):
    data = run_whatweb(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.whatweb_findings.extend(data)
        elif data:
            result.whatweb_findings.append(data)


@phase_wrap("ssl")
def _w_ssl(cfg, result, out_folder):
    data = ssl_scan(cfg.target)
    with _RESULT_LOCK:
        result.ssl_results.append(data or {})


@phase_wrap("waf")
def _w_waf(cfg, result, out_folder):
    data = detect_waf([cfg.target])
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.waf_results.extend(data)
        elif data:
            result.waf_results.append(data)


@phase_wrap("feroxbuster")
def _w_dir_scan(cfg, result, out_folder):
    data = run_dir_scan(cfg.target, out_folder, cfg.wordlist_size)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.dir_findings.extend(data)
        elif data:
            result.dir_findings.append(data)


@phase_wrap("cors")
def _w_cors(cfg, result, out_folder):
    data = scan_cors(_web_urls(result))
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.cors_findings.extend(data)
        elif data:
            result.cors_findings.append(data)


@phase_wrap("js_extract")
def _w_js_extract(cfg, result, out_folder):
    data = extract_js_findings(_web_urls(result))
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.js_findings.extend(data)
        elif data:
            result.js_findings.append(data)


@phase_wrap("api_fuzz")
def _w_api_fuzz(cfg, result, out_folder):
    data = api_fuzz_scan(cfg.target, out_folder, timeout=cfg.global_timeout)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.api_fuzz.extend(data)
        elif data:
            result.api_fuzz.append(data)


@phase_wrap("oauth_scan")
def _w_oauth_scan(cfg, result, out_folder):
    data = oauth_scan(cfg.target, out_folder, timeout=cfg.global_timeout)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.oauth_scan.extend(data)
        elif data:
            result.oauth_scan.append(data)


@phase_wrap("web_vulns")
def _w_web_vulns(cfg, result, out_folder):
    data = web_vuln_scan(cfg.target, _web_urls(result), out_folder, timeout=cfg.global_timeout)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.web_vulns.extend(data)
        elif data:
            result.web_vulns.append(data)


@phase_wrap("open_redirect")
def _w_open_redirect(cfg, result, out_folder):
    data = open_redirect_scan(cfg.target, _web_urls(result), out_folder, timeout=cfg.global_timeout)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.open_redirect.extend(data)
        elif data:
            result.open_redirect.append(data)


@phase_wrap("graphql")
def _w_graphql(cfg, result, out_folder):
    data = graphql_scan(_web_urls(result), out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.graphql_findings.extend(data)
        elif data:
            result.graphql_findings.append(data)


@phase_wrap("jwt_scan")
def _w_jwt_scan(cfg, result, out_folder):
    data = jwt_scan(_web_urls(result), out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.jwt_findings.extend(data)
        elif data:
            result.jwt_findings.append(data)


@phase_wrap("nikto")
def _w_nikto(cfg, result, out_folder):
    data = run_nikto(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.nikto_findings.extend(data)
        elif data:
            result.nikto_findings.append(data)


@phase_wrap("cloud_buckets")
def _w_cloud_buckets(cfg, result, out_folder):
    data = enumerate_buckets(cfg.target)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.bucket_findings.extend(data)
        elif data:
            result.bucket_findings.append(data)


@phase_wrap("anon_detect")
def _w_anon_detect(cfg, result, out_folder):
    extra_ips = [h.ip for h in result.hosts if h.ip]
    data = anon_detect(cfg.target, extra_ips, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.anon_detect.extend(data)
        elif data:
            result.anon_detect.append(data)


@phase_wrap("web3_scan")
def _w_web3_scan(cfg, result, out_folder):
    data = web3_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.web3_scan.extend(data)
        elif data:
            result.web3_scan.append(data)


@phase_wrap("dns_zone")
def _w_dns_zone(cfg, result, out_folder):
    data = dns_zone_transfer_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.dns_zone_results.extend(data)
        elif data:
            result.dns_zone_results.append(data)


@phase_wrap("dns_leak")
def _w_dns_leak(cfg, result, out_folder):
    data = dns_leak_check(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.dns_leak.extend(data)
        elif data:
            result.dns_leak.append(data)


@phase_wrap("ens_lookup")
def _w_ens_lookup(cfg, result, out_folder):
    data = ens_lookup(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.ens_lookup.extend(data)
        elif data:
            result.ens_lookup.append(data)


@phase_wrap("cloud_meta")
def _w_cloud_meta(cfg, result, out_folder):
    data = cloud_meta_scan(cfg.target, _web_urls(result))
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.cloud_meta.extend(data)
        elif data:
            result.cloud_meta.append(data)


@phase_wrap("cloud_deep")
def _w_cloud_deep(cfg, result, out_folder):
    data = cloud_deep_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.cloud_deep_findings.extend(data)
        elif data:
            result.cloud_deep_findings.append(data)


@phase_wrap("db_exposure")
def _w_db_exposure(cfg, result, out_folder):
    open_ports = {p.port for host in result.hosts for p in host.ports}
    data = db_exposure_scan(cfg.target, open_ports, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.db_findings.extend(data)
        elif data:
            result.db_findings.append(data)


@phase_wrap("devops_scan")
def _w_devops(cfg, result, out_folder):
    web_urls = _web_urls(result)
    open_ports = {p.port for host in result.hosts for p in host.ports}
    findings = []
    try:
        d = terraform_state_scan(web_urls, out_folder, timeout=cfg.global_timeout)
        if isinstance(d, list):
            findings.extend(d)
        elif d:
            findings.append(d)
    except Exception as e:
        result.errors.append(f"terraform_state_scan: {e}")
    try:
        d = jenkins_scan(web_urls, open_ports, timeout=cfg.global_timeout)
        if isinstance(d, list):
            findings.extend(d)
        elif d:
            findings.append(d)
    except Exception as e:
        result.errors.append(f"jenkins_scan: {e}")
    with _RESULT_LOCK:
        result.devops_findings.extend(findings)


@phase_wrap("k8s_probe")
def _w_k8s_probe(cfg, result, out_folder):
    open_ports = {p.port for host in result.hosts for p in host.ports}
    data = k8s_probe(cfg.target, open_ports, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.k8s_findings.extend(data)
        elif data:
            result.k8s_findings.append(data)


@phase_wrap("container_deep")
def _w_container_deep(cfg, result, out_folder):
    data = container_deep_scan(cfg.target, result, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.container_findings.extend(data)
        elif data:
            result.container_findings.append(data)


@phase_wrap("smtp_enum")
def _w_smtp_enum(cfg, result, out_folder):
    data = smtp_enum(cfg.target, cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.smtp_findings.extend(data)
        elif data:
            result.smtp_findings.append(data)


@phase_wrap("snmp_scan")
def _w_snmp_scan(cfg, result, out_folder):
    data = snmp_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.snmp_findings.extend(data)
        elif data:
            result.snmp_findings.append(data)


@phase_wrap("ldap_enum")
def _w_ldap_enum(cfg, result, out_folder):
    data = ldap_enum(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.ldap_findings.extend(data)
        elif data:
            result.ldap_findings.append(data)


@phase_wrap("greynoise")
def _w_greynoise(cfg, result, out_folder):
    ips = [h.ip for h in result.hosts if h.ip]
    data = greynoise_lookup(ips, out_folder, cfg.greynoise_key)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.greynoise_data.extend(data)
        elif data:
            result.greynoise_data.append(data)


@phase_wrap("llm_recon")
def _w_llm_recon(cfg, result, out_folder):
    data = llm_recon_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.llm_surfaces.extend(data)
        elif data:
            result.llm_surfaces.append(data)


@phase_wrap("iot_scan")
def _w_iot_scan(cfg, result, out_folder):
    data = iot_scan(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.iot_findings.extend(data)
        elif data:
            result.iot_findings.append(data)


@phase_wrap("nuclei")
def _w_nuclei(cfg, result, out_folder):
    data = run_nuclei(cfg.target, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.nuclei_findings.extend(data)
        elif data:
            result.nuclei_findings.append(data)


@phase_wrap("cve_lookup")
def _w_cve_lookup(cfg, result, out_folder):
    for host in result.hosts:
        try:
            lookup_cves_for_host_result(host, cfg.target, max_per_port=3, api_key=cfg.nvd_key)
        except Exception as e:
            result.errors.append(f"cve_lookup({host.ip}): {e}")


@phase_wrap("aquatone")
def _w_aquatone(cfg, result, out_folder):
    # aquatone takes a file of URLs, not a string
    urls_file = out_folder / "aquatone_urls.txt"
    urls = _web_urls(result) or [f"http://{cfg.target}", f"https://{cfg.target}"]
    urls_file.write_text("\n".join(urls), encoding="utf-8")
    data = run_aquatone(urls_file, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.aquatone_results.extend(data)
        elif data:
            result.aquatone_results.append(data)


@phase_wrap("apk_scan")
def _w_apk_scan(cfg, result, out_folder):
    data = apk_scan(cfg.apk_path, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.apk_scan.extend(data)
        elif data:
            result.apk_scan.append(data)


@phase_wrap("ai_consensus")
def _w_ai_consensus(cfg, result, out_folder):
    ai_config = {
        "provider": cfg.ai_provider,
        "key": cfg.ai_key,
        "model": cfg.ai_model or None,
        "ollama_url": cfg.local_llm_url,
    }
    data = run_consensus(result, ai_config, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, dict):
            result.ai_consensus = data
        elif isinstance(data, list):
            result.remediations.extend(data)


@phase_wrap("attack_paths")
def _w_attack_paths(cfg, result, out_folder):
    ai_config = {
        "provider": cfg.ai_provider,
        "key": cfg.ai_key,
        "model": cfg.ai_model or None,
        "ollama_url": cfg.local_llm_url,
    }
    chains = generate_attack_paths(result, ai_config, out_folder)
    with _RESULT_LOCK:
        if isinstance(chains, list):
            result.attack_chains.extend(chains)


@phase_wrap("ai_remediate")
def _w_ai_remediate(cfg, result, out_folder):
    ai_config = {
        "provider": cfg.ai_provider,
        "key": cfg.ai_key,
        "model": cfg.ai_model or None,
        "ollama_url": cfg.local_llm_url,
    }
    data = generate_remediations(result, ai_config, out_folder)
    with _RESULT_LOCK:
        if isinstance(data, list):
            result.remediations.extend(data)


@phase_wrap("correlation")
def _w_correlation(cfg, result, out_folder):
    run_correlation_pipeline(result, cfg)


@phase_wrap("sarif_export")
def _w_sarif_export(cfg, result, out_folder):
    export_sarif(result, out_folder)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _web_urls(result: ReconResult) -> list[str]:
    """All discovered web URLs — primary input for many web-phase modules."""
    urls: list[str] = []
    for wf in result.web_findings or []:
        if getattr(wf, "url", None):
            urls.append(wf.url)
    if not urls:
        urls = [f"http://{result.target}", f"https://{result.target}"]
    return urls
