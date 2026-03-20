"""
ReconNinja v6.0.0 — Core Orchestration Engine
Drives the full recon pipeline: passive → async TCP → nmap → web → vuln → AI → report.

Bug fixes applied in v6.0.0:
  BUG-FIX #2: rustscan_ports restored from result on resume (no more empty port set)
  BUG-FIX #4: AI fallback (_generate_ai_analysis) now reachable when no key / API error
  BUG-FIX #6: Aquatone receives url_file (http:// URLs), not sub_file (bare hostnames)
"""

from __future__ import annotations

import copy
import ipaddress as _ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from pathlib import Path

from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table

from utils.helpers import ensure_dir, timestamp, sanitize_dirname
from utils.logger import safe_print, console, _RESULT_LOCK
from utils.models import ReconResult, ScanConfig, HostResult
from utils.notify import notify_finding

from core.subdomains import subdomain_enum
from core.ports import async_port_scan, run_rustscan, run_masscan, nmap_worker
from core.web import run_httpx, run_whatweb, run_nikto, run_dir_scan, enrich_hosts_with_web
from core.vuln import run_nuclei, run_aquatone, run_gowitness
from core.cve_lookup import lookup_cves_for_host_result
from core.ai_analysis import run_ai_analysis
from core.resume import save_state
from utils.logger import setup_file_logger
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
from plugins import discover_plugins, run_plugins

REPORTS_DIR = Path("reports")
VERSION = "6.0.0"


# ─── Terminal display helpers ─────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    colors = {
        "critical": "bold red", "high": "orange1",
        "medium": "yellow",     "info": "dim",
    }
    return f"[{colors.get(sev, 'white')}]{sev.upper()}[/]"


def render_open_ports_table(hosts: list[HostResult]) -> Table:
    table = Table(
        title="[bold]Open Ports Summary[/]",
        show_lines=True, highlight=True, border_style="blue",
    )
    table.add_column("Host / IP",     style="cyan",  no_wrap=True)
    table.add_column("Port",          justify="right")
    table.add_column("Proto",         justify="center")
    table.add_column("State",         justify="center")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Risk",          justify="center")
    table.add_column("Script Output", max_width=40, overflow="fold")
    for host in hosts:
        label = ", ".join(host.hostnames) if host.hostnames else host.ip
        for p in host.open_ports:
            ver        = " ".join(filter(None, [p.product, p.version, p.extra_info]))
            script_out = "; ".join(f"{k}: {v[:60]}" for k, v in p.scripts.items())
            table.add_row(
                label, str(p.port), p.protocol, p.display_state,
                p.service or "-", ver or "-",
                _severity_badge(p.severity), script_out or "-",
            )
    return table


def print_tool_status() -> None:
    from utils.helpers import tool_exists, detect_seclists
    tools = [
        ("nmap",         True),
        ("rustscan",     False),
        ("subfinder",    False),
        ("amass",        False),
        ("assetfinder",  False),
        ("ffuf",         False),
        ("httpx",        False),
        ("feroxbuster",  False),
        ("dirsearch",    False),
        ("masscan",      False),
        ("whatweb",      False),
        ("nikto",        False),
        ("nuclei",       False),
        ("aquatone",     False),
        ("gowitness",    False),
        ("wafw00f",      False),
        ("dig",          False),
    ]
    table = Table(title="Tool Availability", border_style="blue", show_lines=False)
    table.add_column("Tool",     style="cyan")
    table.add_column("Required", justify="center")
    table.add_column("Status",   justify="center")
    for name, required in tools:
        found = tool_exists(name)
        status = (
            "[success]✔ FOUND[/]" if found
            else ("[danger]✘ MISSING[/]" if required else "[dim]– optional[/]")
        )
        table.add_row(name, "[danger]yes[/]" if required else "no", status)
    console.print(table)
    seclists = detect_seclists()
    console.print(f"[info]SecLists:[/] {seclists or '[warning]NOT FOUND[/]'}")
    console.print()


# ─── Main orchestrator ────────────────────────────────────────────────────────

def orchestrate(
    cfg: ScanConfig,
    resume_result: ReconResult | None = None,
    resume_folder: Path | None = None,
) -> ReconResult:

    stamp      = timestamp() if not resume_folder else resume_folder.name
    out_folder = resume_folder if resume_folder else ensure_dir(
        REPORTS_DIR / sanitize_dirname(cfg.target) / stamp
    )
    setup_file_logger(out_folder / "scan.log")
    (out_folder / "scan_config.json").write_text(
        json.dumps(cfg.to_dict(), indent=2, default=str)
    )

    result = resume_result if resume_result else ReconResult(target=cfg.target, start_time=stamp)
    console.print(f"\n[success]📁 Output folder: {out_folder}[/]\n")

    # ── Phase 1: Passive Recon ────────────────────────────────────────────
    if cfg.run_subdomains and "passive_recon" not in result.phases_completed \
            and "passive" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 1 — Passive Recon [/]"))
        result.subdomains = subdomain_enum(cfg.target, out_folder / "subdomains", cfg.wordlist_size)
        result.phases_completed.append("passive_recon")
        save_state(result, cfg, out_folder)
    elif "passive_recon" in result.phases_completed:
        safe_print("[dim]Phase 1 — Passive Recon: already completed, skipping[/]")
    elif "passive" in cfg.exclude_phases:
        safe_print("[dim]Phase 1 — Passive Recon: excluded[/]")

    # ─── Port discovery pipeline ──────────────────────────────────────────
    nmap_opts = copy.deepcopy(cfg.nmap_opts)
    all_open_ports: set[int] = set()

    # Phase 2: RustScan
    if cfg.run_rustscan and "rustscan" not in result.phases_completed \
            and "port" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 2 — RustScan Port Discovery [/]"))
        rustscan_ports = run_rustscan(cfg.target, out_folder / "rustscan")
        all_open_ports |= rustscan_ports
        result.rustscan_ports = sorted(rustscan_ports)   # BUG-FIX v6 #2: persist
        result.phases_completed.append("rustscan")
        save_state(result, cfg, out_folder)
    elif "rustscan" in result.phases_completed:
        safe_print("[dim]Phase 2 — RustScan: already completed, skipping[/]")
        rustscan_ports = set(result.rustscan_ports)       # BUG-FIX v6 #2: restore
        all_open_ports |= rustscan_ports
    else:
        rustscan_ports: set[int] = set()

    # Phase 2b: Async TCP
    if "port" not in cfg.exclude_phases:
        label = "RustScan fallback" if not rustscan_ports else "gap-fill"
        console.print(Panel.fit(f"[phase] PHASE 2b — Async TCP Scan ({label}) [/]"))
        async_top_n = None if nmap_opts.all_ports else (nmap_opts.top_ports or 1000)
        async_port_infos, _ = async_port_scan(
            target=cfg.target, top_n=async_top_n,
            concurrency=cfg.async_concurrency, connect_timeout=cfg.async_timeout,
            out_folder=ensure_dir(out_folder / "async_scan"),
        )
        if "async_tcp_scan" not in result.phases_completed:
            async_ports = {p.port for p in async_port_infos}
            new_async   = async_ports - all_open_ports
            if new_async:
                safe_print(f"[info]Async scan found {len(new_async)} extra port(s)[/]")
            all_open_ports |= async_ports
            result.phases_completed.append("async_tcp_scan")
            save_state(result, cfg, out_folder)
        else:
            safe_print("[dim]Phase 2b — Async TCP: already completed, skipping[/]")
    else:
        safe_print("[dim]Phase 2b — Async TCP: excluded[/]")

    # Phase 3: Masscan
    if cfg.run_masscan and "masscan" not in result.phases_completed \
            and "port" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 3 — Masscan Sweep [/]"))
        _, masscan_ports = run_masscan(cfg.target, out_folder / "masscan", cfg.masscan_rate)
        if masscan_ports:
            result.masscan_ports = sorted(masscan_ports)
            all_open_ports |= masscan_ports
        result.phases_completed.append("masscan")
        save_state(result, cfg, out_folder)
    elif "masscan" in result.phases_completed:
        safe_print("[dim]Phase 3 — Masscan: already completed, skipping[/]")
        all_open_ports |= set(result.masscan_ports)

    if all_open_ports:
        safe_print(
            f"[success]✔ Confirmed {len(all_open_ports)} open port(s): "
            f"{', '.join(str(p) for p in sorted(all_open_ports))}[/]"
        )
        crit_open = [p for p in all_open_ports if p in {21, 22, 23, 445, 3389}]
        if crit_open and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "Port Scan", "high",
                           f"{len(crit_open)} high-risk port(s) open",
                           f"Ports: {', '.join(str(p) for p in sorted(crit_open))}")
    else:
        safe_print("[warning]No open ports found — skipping Nmap[/]")

    # Phase 4: Nmap service analysis
    targets_to_scan = result.subdomains if result.subdomains else [cfg.target]
    all_hosts: list[HostResult] = []
    if "nmap" in result.phases_completed:
        safe_print("[dim]Phase 4 — Nmap: already completed, skipping[/]")
        all_hosts = result.hosts
    elif "port" in cfg.exclude_phases:
        safe_print("[dim]Phase 4 — Nmap: excluded[/]")
    else:
        console.print(Panel.fit("[phase] PHASE 4 — Nmap Service Analysis [/]"))
        if not all_open_ports:
            safe_print("[dim]No ports to analyse — skipping[/]")
        else:
            workers = min(cfg.threads, len(targets_to_scan))
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                          console=console) as progress:
                task = progress.add_task("Nmap service scans...", total=len(targets_to_scan))
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    nmap_out = ensure_dir(out_folder / "nmap")
                    futures: dict[Future, str] = {
                        ex.submit(nmap_worker, t, all_open_ports, nmap_out,
                                  nmap_opts.scripts, nmap_opts.version_detection,
                                  nmap_opts.timing): t
                        for t in targets_to_scan
                    }
                    for fut in as_completed(futures):
                        sd = futures[fut]
                        try:
                            _, hosts, errs = fut.result()
                            with _RESULT_LOCK:
                                all_hosts.extend(hosts)
                                result.errors.extend(errs)
                            safe_print(f"[success]  ✔ {sd} — {sum(len(h.ports) for h in hosts)} service(s)[/]")
                        except Exception as e:
                            with _RESULT_LOCK:
                                result.errors.append(f"{sd}: {e}")
                            safe_print(f"[warning]  ✘ {sd}: {e}[/]")
                        progress.advance(task)
        result.hosts = all_hosts
        result.phases_completed.append("nmap")
        save_state(result, cfg, out_folder)

    # Phase 4b: CVE Lookup
    if cfg.run_cve_lookup and result.hosts \
            and "cve_lookup" not in result.phases_completed \
            and "vuln" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 4b — CVE Lookup (NVD) [/]"))
        cve_findings = []
        for host in result.hosts:
            cve_findings += lookup_cves_for_host_result(
                host, target=host.ip, api_key=cfg.nvd_key or None,
            )
        result.nuclei_findings += cve_findings
        safe_print(f"[success]✔ CVE lookup: {len(cve_findings)} finding(s)[/]")
        result.phases_completed.append("cve_lookup")
        save_state(result, cfg, out_folder)

    # Phase 5: Web Service Detection
    if cfg.run_httpx and "httpx" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 5 — Web Service Detection [/]"))
        web_targets = list(result.subdomains) if result.subdomains else [cfg.target]
        for host in result.hosts:
            for p in host.web_ports:
                scheme = "https" if p.port in {443, 8443} else "http"
                url    = f"{scheme}://{host.ip}:{p.port}"
                if url not in web_targets:
                    web_targets.append(url)
        result.web_findings = run_httpx(web_targets, out_folder / "httpx")
        enrich_hosts_with_web(result.hosts, result.web_findings)
        result.phases_completed.append("httpx")
        save_state(result, cfg, out_folder)

    live_urls = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]

    # Phase 5b: WAF Detection
    if cfg.run_waf and "waf_detect" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 5b — WAF Detection [/]"))
        waf_results = detect_waf(live_urls, out_folder / "waf")
        result.waf_results = [r.to_dict() for r in waf_results]
        result.phases_completed.append("waf_detect")
        save_state(result, cfg, out_folder)

    # Phase 5c: CORS Scanner
    if cfg.run_cors and "cors_scan" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 5c — CORS Misconfiguration Scan [/]"))
        cors_findings = scan_cors(live_urls, cfg.target, out_folder / "cors")
        result.cors_findings = [f.to_dict() for f in cors_findings]
        crit_cors = [f for f in cors_findings if f.severity == "critical"]
        if crit_cors and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "CORS", "critical",
                           f"{len(crit_cors)} critical CORS misconfiguration(s)",
                           crit_cors[0].detail)
        result.phases_completed.append("cors_scan")
        save_state(result, cfg, out_folder)

    # Phase 6: Directory Brute Force
    if cfg.run_feroxbuster and "directory_scan" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 6 — Directory Discovery [/]"))
        for url in live_urls[:10]:
            dir_file = run_dir_scan(url, out_folder / "dirscan" / sanitize_dirname(url), cfg.wordlist_size)
            if dir_file and dir_file.exists():
                result.dir_findings += [ln for ln in dir_file.read_text().splitlines() if ln.strip()]
        result.dir_findings = result.dir_findings[:1000]
        result.phases_completed.append("directory_scan")
        save_state(result, cfg, out_folder)

    # Phase 6b: JS Endpoint & Secret Extraction
    if cfg.run_js_extract and "js_extract" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 6b — JS Endpoint & Secret Extraction [/]"))
        js_findings = extract_js_findings(live_urls, out_folder / "js_extract")
        result.js_findings = [
            {"url": f.url, "endpoints": f.endpoints[:50], "secrets": f.secrets}
            for f in js_findings
        ]
        exposed = sum(len(f.secrets) for f in js_findings)
        if exposed and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "JS Extraction", "high",
                           f"{exposed} potential secret(s) in JS files")
        result.phases_completed.append("js_extract")
        save_state(result, cfg, out_folder)

    # Phase 7: Tech Fingerprinting
    if cfg.run_whatweb and "whatweb" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 7 — Tech Fingerprinting [/]"))
        ww_file = run_whatweb(f"https://{cfg.target}", out_folder / "whatweb")
        if ww_file and ww_file.exists():
            result.whatweb_findings = ww_file.read_text().splitlines()
        result.phases_completed.append("whatweb")
        save_state(result, cfg, out_folder)

    # Phase 8: Nikto
    if cfg.run_nikto and "nikto" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 8 — Nikto Web Scan [/]"))
        nk_file = run_nikto(f"https://{cfg.target}", out_folder / "nikto")
        if nk_file and nk_file.exists():
            result.nikto_findings = [ln for ln in nk_file.read_text().splitlines() if ln.strip()]
        result.phases_completed.append("nikto")
        save_state(result, cfg, out_folder)

    # Phase 9: Nuclei
    if cfg.run_nuclei and "nuclei" not in result.phases_completed \
            and "vuln" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 9 — Nuclei Vulnerability Scan [/]"))
        for t in live_urls[:20]:
            result.nuclei_findings += run_nuclei(t, out_folder / "nuclei" / sanitize_dirname(t))
        result.phases_completed.append("nuclei")
        save_state(result, cfg, out_folder)
        crit_vulns = [v for v in result.nuclei_findings if v.severity == "critical"]
        if crit_vulns and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "Nuclei", "critical",
                           f"{len(crit_vulns)} critical vulnerability/ies", crit_vulns[0].title)

    # Phase 10: Screenshots
    if cfg.run_aquatone and "screenshots" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 10 — Screenshots [/]"))
        screenshot_urls = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]
        url_file = out_folder / "_screenshot_urls.txt"
        url_file.write_text("\n".join(screenshot_urls))
        # BUG-FIX v6 #6: pass url_file (full URLs) to aquatone, not sub_file (bare hostnames)
        if not run_aquatone(url_file, out_folder):
            run_gowitness(url_file, out_folder)
        result.phases_completed.append("screenshots")
        save_state(result, cfg, out_folder)

    # Phase 11: AI Analysis
    if cfg.run_ai_analysis and "ai_analysis" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 11 — AI Analysis [/]"))
        # BUG-FIX v6 #4: old branch was always True; fallback was dead code.
        # Now: attempt LLM only when key is present (or ollama needs no key).
        has_key = bool(cfg.ai_key) or cfg.ai_provider == "ollama"
        if has_key:
            analysis = run_ai_analysis(
                result, provider=cfg.ai_provider,
                api_key=cfg.ai_key or None, model=cfg.ai_model or None,
            )
            if not analysis.error:
                result.ai_analysis = analysis.to_text()
        if not result.ai_analysis:
            result.ai_analysis = _generate_ai_analysis(result)
        result.phases_completed.append("ai_analysis")
        save_state(result, cfg, out_folder)

    # Phase 12: Intelligence integrations
    if cfg.run_whois and "whois" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12a — WHOIS Lookup [/]"))
        w = whois_lookup(cfg.target)
        if w:
            result.whois_results.append(w)
        result.phases_completed.append("whois")
        save_state(result, cfg, out_folder)

    if cfg.run_wayback and "wayback" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12b — Wayback URL Discovery [/]"))
        wb = wayback_lookup(cfg.target)
        if wb:
            result.wayback_results.append(wb)
        result.phases_completed.append("wayback")
        save_state(result, cfg, out_folder)

    if cfg.run_ssl and "ssl" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12c — SSL/TLS Analysis [/]"))
        ssl_r = ssl_scan(cfg.target)
        if ssl_r and ssl_r.get("certs"):
            result.ssl_results.append(ssl_r)
        result.phases_completed.append("ssl")
        save_state(result, cfg, out_folder)

    if cfg.run_virustotal and cfg.vt_key and "virustotal" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12d — VirusTotal Reputation [/]"))
        try:
            _ipaddress.ip_address(cfg.target)
            vt_r = vt_ip_lookup(cfg.target, cfg.vt_key)
        except ValueError:
            vt_r = vt_domain_lookup(cfg.target, cfg.vt_key)
        if vt_r:
            result.vt_results.append(vt_r)
        result.phases_completed.append("virustotal")
        save_state(result, cfg, out_folder)

    if cfg.run_shodan and cfg.shodan_key and result.hosts \
            and "shodan" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12e — Shodan Intelligence [/]"))
        ips = [h.ip for h in result.hosts if h.ip][:10]
        result.shodan_results.extend(shodan_bulk_lookup(ips, cfg.shodan_key))
        result.phases_completed.append("shodan")
        save_state(result, cfg, out_folder)

    # Phase 13: v6 new modules
    if cfg.run_github_osint and "github_osint" not in result.phases_completed \
            and "passive" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 13a — GitHub OSINT [/]"))
        gh = github_osint(cfg.target, token=cfg.github_token or None)
        result.github_findings = [gh.to_dict()]
        if gh.total_findings and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "GitHub OSINT", "high",
                           f"{gh.total_findings} secret/file exposure(s) on GitHub")
        result.phases_completed.append("github_osint")
        save_state(result, cfg, out_folder)

    if cfg.run_cloud_buckets and "cloud_buckets" not in result.phases_completed \
            and "passive" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 13b — Cloud Bucket Enumeration [/]"))
        buckets = enumerate_buckets(cfg.target, out_folder / "cloud_buckets")
        result.bucket_findings = [
            {"provider": b.provider, "url": b.url, "name": b.name, "status": b.status}
            for b in buckets
        ]
        public_b = [b for b in buckets if b.status == "public"]
        if public_b and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "Cloud Buckets", "critical",
                           f"{len(public_b)} PUBLIC bucket(s) found!", public_b[0].url)
        result.phases_completed.append("cloud_buckets")
        save_state(result, cfg, out_folder)

    if cfg.run_dns_zone and "dns_zone_transfer" not in result.phases_completed \
            and "passive" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 13c — DNS Zone Transfer [/]"))
        zone_result = dns_zone_transfer_scan(cfg.target, out_folder / "dns_zone")
        result.dns_zone_results = [zone_result.to_dict()]
        if zone_result.vulnerable_ns and cfg.notify_url:
            notify_finding(cfg.notify_url, cfg.target, "DNS Zone Transfer", "critical",
                           "AXFR vulnerable! Full DNS zone leaked",
                           ", ".join(zone_result.vulnerable_ns))
        result.phases_completed.append("dns_zone_transfer")
        save_state(result, cfg, out_folder)

    # Phase 14: Plugins
    plugins = discover_plugins()
    if plugins:
        run_plugins(plugins, cfg.target, out_folder, result, cfg)
        result.phases_completed.append("plugins")
        save_state(result, cfg, out_folder)

    # Phase 15: Reports
    result.end_time = timestamp()
    console.print(Rule("[header]Generating Reports[/]"))

    fmt = getattr(cfg, "output_format", "all")
    json_path = out_folder / "report.json"
    html_path = out_folder / "report.html"
    md_path   = out_folder / "report.md"
    if fmt in ("all", "json"):
        generate_json_report(result, json_path)
        console.print(f"[info]  JSON: {json_path}[/]")
    if fmt in ("all", "html"):
        generate_html_report(result, html_path)
        console.print(f"[info]  HTML: {html_path}[/]")
    if fmt in ("all", "md"):
        generate_markdown_report(result, md_path)
        console.print(f"[info]  MD:   {md_path}[/]")

    if result.hosts:
        console.print(render_open_ports_table(result.hosts))

    total_open  = sum(len(h.open_ports) for h in result.hosts)
    crit_count  = sum(1 for h in result.hosts for p in h.open_ports if p.severity == "critical")
    vuln_count  = sum(1 for v in result.nuclei_findings if v.severity in ("critical", "high"))
    gh_hits     = sum(r.get("total_findings", 0) for r in result.github_findings)
    pub_buckets = sum(1 for b in result.bucket_findings if b.get("status") == "public")

    console.print(Panel.fit(
        f"[success]✔ ReconNinja v{VERSION} Complete[/]\n"
        f"Subdomains [cyan]{len(result.subdomains)}[/]  |  "
        f"Hosts [cyan]{len(result.hosts)}[/]  |  "
        f"Open Ports [cyan]{total_open}[/]  |  "
        f"Web [cyan]{len(result.web_findings)}[/]\n"
        f"High-Risk Ports [danger]{crit_count}[/]  |  "
        f"Vulns [danger]{vuln_count}[/]  |  "
        f"GitHub Hits [warning]{gh_hits}[/]  |  "
        f"Public Buckets [danger]{pub_buckets}[/]\n"
        f"Reports → [dim]{out_folder}[/]",
        border_style="green",
    ))

    if result.errors:
        console.print(f"[warning]{len(result.errors)} error(s) — see report.json[/]")

    if cfg.notify_url:
        notify_finding(cfg.notify_url, cfg.target, "Scan Complete", "info",
                       f"ReconNinja v{VERSION} scan complete",
                       f"Ports={total_open} Vulns={vuln_count} GitHub={gh_hits} Buckets={pub_buckets}")
    return result


# ─── Rule-based AI analysis fallback ─────────────────────────────────────────

def _generate_ai_analysis(result: ReconResult) -> str:
    """Rule-based fallback — no external API required. Reachable since BUG-FIX v6 #4."""
    lines = ["=== ReconNinja v6 AI Analysis (Rule-Based) ===", ""]
    total_open  = sum(len(h.open_ports) for h in result.hosts)
    crit_ports  = [(h, p) for h in result.hosts for p in h.open_ports if p.severity == "critical"]
    high_vulns  = [v for v in result.nuclei_findings if v.severity in ("critical", "high")]
    gh_hits     = sum(r.get("total_findings", 0) for r in result.github_findings)
    pub_buckets = [b for b in result.bucket_findings if b.get("status") == "public"]

    risk = "LOW"
    if crit_ports or high_vulns or pub_buckets:
        risk = "CRITICAL" if (len(crit_ports) > 3 or len(high_vulns) > 2 or pub_buckets) else "HIGH"
    elif total_open > 20 or result.nuclei_findings or gh_hits:
        risk = "MEDIUM"

    lines += [f"Overall Risk Level: {risk}", "",
              "Attack Surface Summary:",
              f"  • {len(result.subdomains)} subdomains",
              f"  • {total_open} open ports across {len(result.hosts)} hosts",
              f"  • {len(result.web_findings)} live web services",
              f"  • {len(result.nuclei_findings)} vuln findings"]
    if gh_hits:       lines.append(f"  • {gh_hits} GitHub secret/file exposure(s)")
    if pub_buckets:   lines.append(f"  • {len(pub_buckets)} PUBLIC cloud bucket(s)!")
    if result.cors_findings:
        lines.append(f"  • {len(result.cors_findings)} CORS misconfiguration(s)")
    if result.dns_zone_results:
        vuln_ns = result.dns_zone_results[0].get("vulnerable_ns", [])
        if vuln_ns:
            lines.append(f"  • DNS zone transfer: VULNERABLE ({', '.join(vuln_ns)})")
    lines.append("")

    if crit_ports:
        lines.append("High-Risk Ports:")
        for host, port in crit_ports[:10]:
            label = host.hostnames[0] if host.hostnames else host.ip
            lines.append(f"  ⚠ {label}:{port.port} ({port.service})")
        lines.append("")

    if high_vulns:
        lines.append("Critical/High Vulnerabilities:")
        for v in high_vulns[:10]:
            cve = f" [{v.cve}]" if v.cve else ""
            lines.append(f"  ✗ [{v.severity.upper()}] {v.title}{cve} @ {v.target}")
        lines.append("")

    lines.append("Recommendations:")
    port_set = {p.port for h in result.hosts for p in h.open_ports}
    if port_set & {21, 23}:    lines.append("  • Disable FTP/Telnet — use SFTP/SSH")
    if 22 in port_set:         lines.append("  • Harden SSH: disable root login, enforce key auth")
    if port_set & {3306,5432,27017}: lines.append("  • Database ports exposed — restrict to internal")
    if port_set & {445, 139}:  lines.append("  • SMB exposed — verify MS17-010 patching")
    if len(result.subdomains) > 20: lines.append("  • Large subdomain footprint — audit for shadow IT")
    if result.dir_findings:    lines.append(f"  • {len(result.dir_findings)} dir findings — review for sensitive paths")
    if gh_hits:                lines.append("  • Rotate all credentials exposed on GitHub immediately")
    if pub_buckets:            lines.append("  • Public cloud buckets — restrict ACLs immediately")
    if result.cors_findings:   lines.append("  • Harden CORS: never reflect arbitrary origins")
    if not any(ln.startswith("  •") for ln in lines[-6:]):
        lines.append("  • No critical issues detected — continue with manual testing")

    lines += ["", "This analysis is automated. Manual review recommended before reporting."]
    return "\n".join(lines)
