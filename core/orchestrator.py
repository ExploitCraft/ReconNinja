"""
ReconNinja v5.2.2 — Core Orchestration Engine
Drives the full recon pipeline: passive → async TCP scan → nmap → web → vuln → report.
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
from utils.models import (
    ReconResult, ScanConfig, HostResult,
)
from core.subdomains import subdomain_enum
from core.ports import (
    async_port_scan, run_rustscan, run_masscan,
    nmap_worker,
)
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
from output.reports import generate_json_report, generate_html_report, generate_markdown_report
from plugins import discover_plugins, run_plugins

REPORTS_DIR = Path("reports")


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

def orchestrate(cfg: ScanConfig,
                resume_result: ReconResult | None = None,
                resume_folder: Path | None = None) -> ReconResult:
    stamp      = timestamp() if not resume_folder else resume_folder.name
    out_folder = resume_folder if resume_folder else ensure_dir(REPORTS_DIR / sanitize_dirname(cfg.target) / stamp)
    log_path   = out_folder / "scan.log"

    setup_file_logger(log_path)

    (out_folder / "scan_config.json").write_text(
        json.dumps(cfg.to_dict(), indent=2, default=str)
    )

    result = resume_result if resume_result else ReconResult(target=cfg.target, start_time=stamp)
    console.print(f"\n[success]📁 Output folder: {out_folder}[/]\n")

    # ── Phase 1: Passive Recon ─────────────────────────────────────────────
    # BUG #1 FIX: exclude_phases check added to all phases
    if cfg.run_subdomains and "passive_recon" not in result.phases_completed \
            and "passive" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase]P1[/]"))
        sub_dir = out_folder / "subdomains"
        result.subdomains = subdomain_enum(cfg.target, sub_dir, cfg.wordlist_size)
        result.phases_completed.append("passive_recon")
        save_state(result, cfg, out_folder)
    elif "passive_recon" in result.phases_completed:
        safe_print("[dim]Phase 1 — Passive Recon: already completed, skipping[/]")
    elif "passive" in cfg.exclude_phases:
        safe_print("[dim]Phase 1 — Passive Recon: excluded[/]")

    # ─────────────────────────────────────────────────────────────────────
    # PORT DISCOVERY & SERVICE ANALYSIS (v3.3):
    #
    #   Phase 2  : RustScan  — PRIMARY port scanner, all 65535 ports
    #   Phase 2b : Async TCP — fallback/gap-filler (pure Python, no root)
    #   Phase 3  : Masscan   — optional extra sweep, merged into port set
    #   Phase 4  : Nmap      — SERVICE ANALYSIS ONLY on confirmed-open ports
    #                          nmap -sT -Pn -sV -sC -p<port_list>
    #                          NEVER sweeps — only fingerprints known-open ports
    # ─────────────────────────────────────────────────────────────────────
    nmap_opts      = copy.deepcopy(cfg.nmap_opts)
    all_open_ports: set[int] = set()

    # ── Phase 2: RustScan — primary port discovery ─────────────────────
    if cfg.run_rustscan and "rustscan" not in result.phases_completed \
            and "port" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 2 — RustScan Port Discovery [/]"))
        rustscan_ports = run_rustscan(cfg.target, out_folder / "rustscan")
        all_open_ports |= rustscan_ports
        result.phases_completed.append("rustscan")
        save_state(result, cfg, out_folder)
    elif "rustscan" in result.phases_completed:
        safe_print("[dim]Phase 2 — RustScan: already completed, skipping[/]")
        rustscan_ports: set[int] = set()
    else:
        rustscan_ports: set[int] = set()

    # ── Phase 2b: Async TCP — fallback / gap-filler ────────────────────
    if "port" not in cfg.exclude_phases:
        if not rustscan_ports:
            console.print(Panel.fit("[phase] PHASE 2b — Async TCP Scan (RustScan fallback) [/]"))
        else:
            console.print(Panel.fit("[phase] PHASE 2b — Async TCP Scan (gap-fill) [/]"))

        async_out = ensure_dir(out_folder / "async_scan")
        async_top_n = None if nmap_opts.all_ports else (nmap_opts.top_ports or 1000)
        async_port_infos, _ = async_port_scan(
            target          = cfg.target,
            top_n           = async_top_n,
            concurrency     = cfg.async_concurrency,
            connect_timeout = cfg.async_timeout,
            out_folder      = async_out,
        )
        if "async_tcp_scan" not in result.phases_completed:
            async_ports = {p.port for p in async_port_infos}
            new_from_async = async_ports - all_open_ports
            if new_from_async:
                safe_print(f"[info]Async scan found {len(new_from_async)} extra port(s): "
                           f"{', '.join(str(p) for p in sorted(new_from_async))}[/]")
            all_open_ports |= async_ports
            result.phases_completed.append("async_tcp_scan")
            save_state(result, cfg, out_folder)
        else:
            safe_print("[dim]Phase 2b — Async TCP: already completed, skipping[/]")
    elif "port" in cfg.exclude_phases:
        safe_print("[dim]Phase 2b — Async TCP: excluded[/]")

    # ── Phase 3: Masscan — optional extra sweep ────────────────────────
    if cfg.run_masscan and "masscan" not in result.phases_completed \
            and "port" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 3 — Masscan Sweep [/]"))
        _, masscan_ports = run_masscan(cfg.target, out_folder / "masscan", cfg.masscan_rate)
        if masscan_ports:
            result.masscan_ports = sorted(masscan_ports)
            new_from_masscan = masscan_ports - all_open_ports
            if new_from_masscan:
                safe_print(f"[info]Masscan added {len(new_from_masscan)} extra port(s)[/]")
            all_open_ports |= masscan_ports
        result.phases_completed.append("masscan")
        save_state(result, cfg, out_folder)
    elif "masscan" in result.phases_completed:
        safe_print("[dim]Phase 3 — Masscan: already completed, skipping[/]")
        if result.masscan_ports:
            all_open_ports |= set(result.masscan_ports)

    if all_open_ports:
        safe_print(
            f"[success]✔ Confirmed open ports ({len(all_open_ports)}): "
            f"{', '.join(str(p) for p in sorted(all_open_ports))}[/]"
        )
    else:
        safe_print("[warning]No open ports found — skipping Nmap service analysis[/]")

    # ── Phase 4: Nmap service analysis — confirmed ports only ──────────
    targets_to_scan = result.subdomains if result.subdomains else [cfg.target]
    all_hosts: list[HostResult] = []
    if "nmap" in result.phases_completed:
        safe_print("[dim]Phase 4 — Nmap: already completed, skipping[/]")
        all_hosts = result.hosts
    elif "port" in cfg.exclude_phases:
        safe_print("[dim]Phase 4 — Nmap: skipped (excluded)[/]")
    else:
        console.print(Panel.fit("[phase] PHASE 4 — Nmap Service Analysis [/]"))
        if not all_open_ports:
            safe_print("[dim]No ports to analyse — skipping[/]")
        else:
            console.print(
                f"[dim]{len(targets_to_scan)} target(s) | "
                f"ports: {','.join(str(p) for p in sorted(all_open_ports))} | "
                f"{min(cfg.threads, len(targets_to_scan))} workers[/]"
            )
            workers = min(cfg.threads, len(targets_to_scan))
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Nmap service scans...", total=len(targets_to_scan))
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    nmap_out = ensure_dir(out_folder / "nmap")
                    futures: dict[Future, str] = {
                        ex.submit(
                            nmap_worker, t, all_open_ports, nmap_out,
                            nmap_opts.scripts, nmap_opts.version_detection, nmap_opts.timing,
                        ): t
                        for t in targets_to_scan
                    }
                    for fut in as_completed(futures):
                        sd = futures[fut]
                        try:
                            _, hosts, errs = fut.result()
                            with _RESULT_LOCK:
                                all_hosts.extend(hosts)
                                result.errors.extend(errs)
                            svc_c = sum(len(h.ports) for h in hosts)
                            safe_print(f"[success]  ✔ {sd} — {svc_c} service(s) identified[/]")
                        except Exception as e:
                            with _RESULT_LOCK:
                                result.errors.append(f"{sd}: {e}")
                            safe_print(f"[warning]  ✘ {sd}: {e}[/]")
                        progress.advance(task)
        result.hosts = all_hosts
        result.phases_completed.append("nmap")
        save_state(result, cfg, out_folder)

    # ── Phase 4b: CVE Lookup ──────────────────────────────────────────────────
    if cfg.run_cve_lookup and result.hosts and "cve_lookup" not in result.phases_completed \
            and "vuln" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 4b — CVE Lookup (NVD) [/]"))
        cve_findings = []
        for host in result.hosts:
            cve_findings += lookup_cves_for_host_result(
                host,
                target   = host.ip,
                api_key  = cfg.nvd_key or None,
            )
        result.nuclei_findings += cve_findings
        safe_print(f"[success]✔ CVE lookup: {len(cve_findings)} finding(s)[/]")
        result.phases_completed.append("cve_lookup")
        save_state(result, cfg, out_folder)

    # ── Phase 5: Web Service Detection (httpx) ────────────────────────────
    web_targets: list[str] = []
    if cfg.run_httpx and "httpx" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 5 — Web Service Detection [/]"))
        web_targets = list(result.subdomains) if result.subdomains else [cfg.target]
        for host in result.hosts:
            for p in host.web_ports:
                scheme = "https" if p.port in {443, 8443} else "http"
                url = f"{scheme}://{host.ip}:{p.port}"
                if url not in web_targets:
                    web_targets.append(url)

        result.web_findings = run_httpx(web_targets, out_folder / "httpx")
        enrich_hosts_with_web(result.hosts, result.web_findings)
        result.phases_completed.append("httpx")
        save_state(result, cfg, out_folder)

    # ── Phase 6: Directory Brute Force ────────────────────────────────────
    if cfg.run_feroxbuster and "directory_scan" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 6 — Directory Discovery [/]"))
        dir_targets = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]
        for url in dir_targets[:10]:
            dir_file = run_dir_scan(url, out_folder / "dirscan" / sanitize_dirname(url), cfg.wordlist_size)
            if dir_file and dir_file.exists():
                result.dir_findings += [
                    l for l in dir_file.read_text().splitlines() if l.strip()
                ]
        result.dir_findings = result.dir_findings[:1000]
        result.phases_completed.append("directory_scan")
        save_state(result, cfg, out_folder)

    # ── Phase 7: Tech Fingerprinting ──────────────────────────────────────
    if cfg.run_whatweb and "whatweb" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 7 — Tech Fingerprinting [/]"))
        ww_file = run_whatweb(f"https://{cfg.target}", out_folder / "whatweb")
        if ww_file and ww_file.exists():
            result.whatweb_findings = ww_file.read_text().splitlines()
        result.phases_completed.append("whatweb")
        save_state(result, cfg, out_folder)

    # ── Phase 8: Web Vulnerability Scan (Nikto) ───────────────────────────
    if cfg.run_nikto and "nikto" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 8 — Nikto Web Scan [/]"))
        nk_file = run_nikto(f"https://{cfg.target}", out_folder / "nikto")
        if nk_file and nk_file.exists():
            result.nikto_findings = [l for l in nk_file.read_text().splitlines() if l.strip()]
        result.phases_completed.append("nikto")
        save_state(result, cfg, out_folder)

    # ── Phase 9: Nuclei Vulnerability Templates ───────────────────────────
    if cfg.run_nuclei and "nuclei" not in result.phases_completed \
            and "vuln" not in cfg.exclude_phases:
        console.print(Panel.fit("[phase] PHASE 9 — Nuclei Vulnerability Scan [/]"))
        nuclei_targets = [wf.url for wf in result.web_findings] or [f"https://{cfg.target}"]
        for t in nuclei_targets[:20]:
            result.nuclei_findings += run_nuclei(t, out_folder / "nuclei" / sanitize_dirname(t))
        result.phases_completed.append("nuclei")
        save_state(result, cfg, out_folder)

    # ── Phase 10: Screenshots ─────────────────────────────────────────────
    # BUG #3 FIX: screenshot all live web targets, not just subdomain file
    if cfg.run_aquatone and "screenshots" not in result.phases_completed \
            and "web" not in cfg.exclude_phases:
        # Collect all screenshot targets: web_findings first, fallback to main domain
        screenshot_urls = [wf.url for wf in result.web_findings]
        if not screenshot_urls:
            screenshot_urls = [f"https://{cfg.target}"]

        if screenshot_urls:
            console.print(Panel.fit("[phase] PHASE 10 — Screenshots [/]"))
            url_file = out_folder / "_screenshot_urls.txt"
            url_file.write_text("\n".join(screenshot_urls))

            # Try aquatone with subdomain file if available, else gowitness
            sub_file = out_folder / "subdomains" / "subdomains_merged.txt"
            screenshotted = False
            if sub_file.exists():
                screenshotted = run_aquatone(sub_file, out_folder)
            if not screenshotted:
                run_gowitness(url_file, out_folder)

        result.phases_completed.append("screenshots")
        save_state(result, cfg, out_folder)

    # ── Phase 11: AI Analysis ─────────────────────────────────────────────
    if cfg.run_ai_analysis and "ai_analysis" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 11 — AI Analysis [/]"))
        if cfg.ai_provider and cfg.ai_provider != "":
            analysis = run_ai_analysis(
                result,
                provider = cfg.ai_provider,
                api_key  = cfg.ai_key or None,
                model    = cfg.ai_model or None,
            )
            result.ai_analysis = analysis.to_text()
        else:
            result.ai_analysis = _generate_ai_analysis(result)
        result.phases_completed.append("ai_analysis")
        save_state(result, cfg, out_folder)

    # ── Phase 12: v5 Integrations ────────────────────────────────────────

    # WHOIS
    if cfg.run_whois and "whois" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12a — WHOIS Lookup [/]"))
        w = whois_lookup(cfg.target)
        if w:
            result.whois_results.append(w)
        result.phases_completed.append("whois")
        save_state(result, cfg, out_folder)

    # Wayback Machine
    if cfg.run_wayback and "wayback" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12b — Wayback URL Discovery [/]"))
        wb = wayback_lookup(cfg.target)
        if wb:
            result.wayback_results.append(wb)
        result.phases_completed.append("wayback")
        save_state(result, cfg, out_folder)

    # SSL Scan
    if cfg.run_ssl and "ssl" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12c — SSL/TLS Analysis [/]"))
        ssl_r = ssl_scan(cfg.target)
        if ssl_r and ssl_r.get("certs"):
            result.ssl_results.append(ssl_r)
        result.phases_completed.append("ssl")
        save_state(result, cfg, out_folder)

    # VirusTotal — BUG #2 FIX: route IP targets to vt_ip_lookup
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

    # Shodan
    if cfg.run_shodan and cfg.shodan_key and result.hosts and "shodan" not in result.phases_completed:
        console.print(Panel.fit("[phase] PHASE 12e — Shodan Intelligence [/]"))
        ips = [h.ip for h in result.hosts if h.ip][:10]
        sh_results = shodan_bulk_lookup(ips, cfg.shodan_key)
        result.shodan_results.extend(sh_results)
        result.phases_completed.append("shodan")
        save_state(result, cfg, out_folder)

    # ── Phase 13: Plugins ─────────────────────────────────────────────────
    plugins = discover_plugins()
    if plugins:
        run_plugins(plugins, cfg.target, out_folder, result, cfg)
        result.phases_completed.append("plugins")
        save_state(result, cfg, out_folder)

    # ── Phase 14: Reports ─────────────────────────────────────────────────
    result.end_time = timestamp()
    console.print(Rule("[header]Generating Reports[/]"))

    json_path = out_folder / "report.json"
    html_path = out_folder / "report.html"
    md_path   = out_folder / "report.md"

    fmt = cfg.output_format if hasattr(cfg, "output_format") else "all"
    if fmt in ("all", "json"):
        generate_json_report(result, json_path)
        console.print(f"[info]  JSON: {json_path}[/]")
    if fmt in ("all", "html"):
        generate_html_report(result, html_path)
        console.print(f"[info]  HTML: {html_path}[/]")
    if fmt in ("all", "md"):
        generate_markdown_report(result, md_path)
        console.print(f"[info]  MD:   {md_path}[/]")

    # ── Terminal summary ──────────────────────────────────────────────────
    if result.hosts:
        console.print(render_open_ports_table(result.hosts))

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit       = sum(1 for h in result.hosts for p in h.open_ports if p.severity == "critical")
    vuln_c     = sum(1 for v in result.nuclei_findings if v.severity in ("critical", "high"))

    console.print(Panel.fit(
        f"[success]✔ ReconNinja v5.2.2 Complete[/]\n"
        f"Subdomains [cyan]{len(result.subdomains)}[/]  |  "
        f"Hosts [cyan]{len(result.hosts)}[/]  |  "
        f"Open Ports [cyan]{total_open}[/]  |  "
        f"Web Services [cyan]{len(result.web_findings)}[/]  |  "
        f"High-Risk Ports [danger]{crit}[/]  |  "
        f"Vulns [danger]{vuln_c}[/]\n"
        f"Reports → [dim]{out_folder}[/]",
        border_style="green",
    ))

    if result.errors:
        console.print(f"[warning]{len(result.errors)} error(s) — see report.json[/]")

    return result


# ─── AI Analysis ─────────────────────────────────────────────────────────────

def _generate_ai_analysis(result: ReconResult) -> str:
    """
    Rule-based AI analysis (no external API required).
    Examines findings and produces a plain-English threat summary.
    """
    lines: list[str] = ["=== ReconNinja AI Analysis ===", ""]

    total_open = sum(len(h.open_ports) for h in result.hosts)
    crit_ports = [
        (h, p) for h in result.hosts
        for p in h.open_ports if p.severity == "critical"
    ]
    high_vulns = [v for v in result.nuclei_findings if v.severity in ("critical", "high")]

    risk = "LOW"
    if crit_ports or high_vulns:
        risk = "CRITICAL" if (len(crit_ports) > 3 or len(high_vulns) > 2) else "HIGH"
    elif total_open > 20 or result.nuclei_findings:
        risk = "MEDIUM"

    lines.append(f"Overall Risk Level: {risk}")
    lines.append("")

    lines.append("Attack Surface Summary:")
    lines.append(f"  • {len(result.subdomains)} subdomains discovered")
    lines.append(f"  • {total_open} open ports across {len(result.hosts)} hosts")
    lines.append(f"  • {len(result.web_findings)} live web services")
    lines.append(f"  • {len(result.nuclei_findings)} vulnerability findings")
    lines.append("")

    if crit_ports:
        lines.append("High-Risk Ports (immediate attention):")
        for host, port in crit_ports[:10]:
            label = host.hostnames[0] if host.hostnames else host.ip
            lines.append(f"  ⚠ {label}:{port.port} ({port.service}) — {port.severity.upper()}")
        lines.append("")

    if high_vulns:
        lines.append("Critical/High Vulnerabilities:")
        for v in high_vulns[:10]:
            cve = f" [{v.cve}]" if v.cve else ""
            lines.append(f"  ✗ [{v.severity.upper()}] {v.title}{cve} @ {v.target}")
        lines.append("")

    lines.append("Recommendations:")
    if any(p.port in {21, 23} for h in result.hosts for p in h.open_ports):
        lines.append("  • Disable plaintext protocols (FTP/Telnet) — use SFTP/SSH")
    if any(p.port == 22 for h in result.hosts for p in h.open_ports):
        lines.append("  • Review SSH configuration: disable root login, use key auth only")
    if any(p.port in {3306, 5432, 27017} for h in result.hosts for p in h.open_ports):
        lines.append("  • Database ports exposed — restrict to internal network only")
    if any(p.port in {445, 139} for h in result.hosts for p in h.open_ports):
        lines.append("  • SMB exposed — patch EternalBlue/MS17-010 if unpatched")
    if len(result.subdomains) > 20:
        lines.append("  • Large subdomain footprint — review for forgotten/shadow IT assets")
    if result.dir_findings:
        lines.append(f"  • {len(result.dir_findings)} directory findings — review for sensitive paths")
    if not lines[-1].startswith("  •"):
        lines.append("  • No critical issues detected — continue with manual testing")

    lines.append("")
    lines.append("This analysis is automated. Manual review recommended before reporting.")

    return "\n".join(lines)
