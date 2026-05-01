#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝

ReconNinja v7.0.0 — Elite All-in-One Recon Framework
  ⚠  Use ONLY against targets you own or have explicit written permission to test.

Changelog v3.0 (from v2.1):
  + NEW: RustScan integration for ultra-fast port pre-discovery
  + NEW: httpx for live web service detection & tech fingerprinting
  + NEW: gowitness as aquatone fallback for screenshots
  + NEW: dirsearch as third fallback dir scanner
  + NEW: crt.sh Certificate Transparency passive subdomain source
  + NEW: Plugin system (drop .py into plugins/ to extend)
  + NEW: AI analysis engine (rule-based, no API required)
  + NEW: Structured VulnFinding dataclass (severity, CVE, target)
  + NEW: Web findings now linked back to HostResult.web_urls
  + NEW: Per-scan file logger (scan.log in output dir)
  + NEW: CIDR and list-file target input support
  + NEW: Phase-based orchestration with named progress display
  + NEW: gowitness fallback when aquatone unavailable
  + OPT: Nuclei now exports JSON for structured parsing
  + OPT: Dir scan now tries feroxbuster → ffuf → dirsearch
  + OPT: Subdomain DNS brute uses 100 concurrent threads
  + OPT: crt.sh fetched in Python (no external dep required)
  + FIX: All v2.1 fixes retained

Changelog v3.3 (from v3.1):
  + NEW: --ai flag with Groq/Ollama/Gemini/OpenAI support (--ai-provider, --ai-key)
  + NEW: --cve-lookup auto-queries NVD for open port services (free, no key needed)
  + NEW: --resume <state.json> resumes interrupted scans from last checkpoint
  + NEW: --update checks GitHub and self-installs latest version

Changelog v3.1 (from v3.0):
  + NEW: Built-in AsyncTCPScanner — asyncio TCP connect scan, no root required
  + NEW: async scan runs BEFORE nmap, feeds confirmed open ports to nmap (-p<ports>)
  + NEW: Banner grabbing on open ports for instant service hints
  + NEW: --async-concurrency and --async-timeout CLI flags
  + OPT: RustScan now merges with async results (union) for maximum coverage
  + OPT: Nmap only scans confirmed-open ports — dramatically faster deep analysis
  + FIX: masscan_rate crash on non-integer input (v6.0.0)
  + FIX: FULL_SUITE no longer triggers custom nmap builder (v6.0.0)
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
except ImportError:
    print("ERROR: 'rich' library required.  pip install rich", file=sys.stderr)
    sys.exit(1)

from utils.helpers import is_valid_target
from utils.logger import console
from utils.models import ScanConfig, ScanProfile, NmapOptions
from core.orchestrator import orchestrate, print_tool_status
from core.updater import run_update
from core.scan_diff import diff_reports, print_diff

APP_NAME = "ReconNinja"
VERSION  = "7.0.0"



# ─── Safe input helpers ───────────────────────────────────────────────────────

def _prompt_int(label: str, default: int, min_val: int = 1, max_val: int = 65535) -> int:
    """Keep asking until the user enters a valid integer in range."""
    while True:
        raw = Prompt.ask(label, default=str(default))
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            console.print(f"[danger]Enter a number between {min_val} and {max_val}[/]")
        except ValueError:
            console.print(f"[danger]'{raw}' is not a number — please enter digits only[/]")


# ─── Interactive config builder ───────────────────────────────────────────────

def prompt_nmap_opts(profile: ScanProfile) -> NmapOptions:
    if profile == ScanProfile.FAST:
        return NmapOptions(top_ports=100, scripts=False, version_detection=False, timing="T4")
    if profile in (ScanProfile.STANDARD, ScanProfile.WEB_ONLY):
        return NmapOptions(top_ports=1000, scripts=True, version_detection=True, timing="T4")
    if profile == ScanProfile.THOROUGH:
        return NmapOptions(
            all_ports=True, scripts=True, version_detection=True, os_detection=True, timing="T3"
        )
    if profile == ScanProfile.STEALTH:
        return NmapOptions(
            top_ports=1000, stealth=True, scripts=False, version_detection=False, timing="T2"
        )
    if profile in (ScanProfile.PORT_ONLY, ScanProfile.FULL_SUITE):
        return NmapOptions(top_ports=1000, scripts=True, version_detection=True, timing="T4")

    # CUSTOM — only reached when profile == ScanProfile.CUSTOM
    console.print(Panel.fit("[header]Custom Scan Builder[/]"))
    all_ports = Confirm.ask("Scan ALL ports (-p-)?", default=False)
    top_ports = 0
    if not all_ports:
        top_ports = _prompt_int("Top ports to scan", default=1000, min_val=1, max_val=65535)
    return NmapOptions(
        all_ports        = all_ports,
        top_ports        = top_ports,
        scripts          = Confirm.ask("Use default scripts (-sC)?", default=True),
        version_detection= Confirm.ask("Version detection (-sV)?", default=True),
        os_detection     = Confirm.ask("OS detection (-O)?", default=False),
        aggressive       = Confirm.ask("Aggressive mode (-A)?", default=False),
        stealth          = Confirm.ask("Stealth SYN scan (-sS, needs root)?", default=False),
        timing           = Prompt.ask(
            "Timing template", choices=["T1","T2","T3","T4","T5"], default="T4"
        ),
        extra_flags=[
            f for f in
            Prompt.ask("Extra nmap flags (space-separated, or blank)", default="").split()
            if f
        ],
    )


def build_config_interactive() -> ScanConfig | None:
    console.print(Panel.fit(
        f"[bold green]{APP_NAME} v{VERSION}[/]\n"
        "[dim]Elite recon framework — authorized use only[/]",
        border_style="green",
    ))
    console.print(Rule("[dim]Select Scan Profile[/]"))
    console.print("""
  [1] Fast          — top 100 ports, no scripts
  [2] Standard      — top 1000 ports, scripts + versions  [default]
  [3] Thorough      — all ports, OS/version/scripts
  [4] Stealth       — SYN scan, low timing, no scripts
  [5] Custom        — build your own
  [6] Full Suite    — complete pipeline: passive → port → web → vuln → AI
  [7] Web Only      — httpx + dir scan + nuclei (skip port scan)
  [8] Port Only     — masscan + nmap only
  [0] Exit
""")
    choice = Prompt.ask("Choice", choices=["0","1","2","3","4","5","6","7","8"], default="2")
    if choice == "0":
        return None

    profile_map = {
        "1": ScanProfile.FAST,      "2": ScanProfile.STANDARD,
        "3": ScanProfile.THOROUGH,  "4": ScanProfile.STEALTH,
        "5": ScanProfile.CUSTOM,    "6": ScanProfile.FULL_SUITE,
        "7": ScanProfile.WEB_ONLY,  "8": ScanProfile.PORT_ONLY,
    }
    profile = profile_map[choice]

    target = Prompt.ask("\n[bold]Target[/] (domain, IP, CIDR, or path/to/list.txt)").strip()
    if not target:
        console.print("[danger]No target provided.[/]")
        return None

    if not is_valid_target(target) and not Path(target).exists():
        console.print(f"[warning]'{target}' may not be a valid target.[/]")
        if not Confirm.ask("Continue anyway?", default=False):
            return None

    if not Confirm.ask(
        f"\n[danger bold]⚠  You confirm written permission to scan {target}?[/]",
        default=False,
    ):
        console.print("[danger]Aborted — permission not confirmed.[/]")
        return None

    nmap_opts = prompt_nmap_opts(profile)
    cfg = ScanConfig(target=target, profile=profile, nmap_opts=nmap_opts)

    # Profile-specific defaults
    if profile == ScanProfile.FULL_SUITE:
        console.print(Rule("[dim]Full Suite Options[/]"))
        cfg.run_subdomains  = Confirm.ask("Subdomain enumeration?",              default=True)
        cfg.run_rustscan    = Confirm.ask("RustScan fast port sweep?",            default=True)
        cfg.run_feroxbuster = Confirm.ask("Directory scan?",                      default=True)
        cfg.run_masscan     = Confirm.ask("Masscan sweep (root required)?",       default=False)
        cfg.run_httpx       = Confirm.ask("httpx live web detection?",            default=True)
        cfg.run_whatweb     = Confirm.ask("WhatWeb fingerprinting?",              default=True)
        cfg.run_nikto       = Confirm.ask("Nikto web scanner?",                   default=False)
        cfg.run_nuclei      = Confirm.ask("Nuclei vulnerability templates?",      default=True)
        cfg.run_aquatone    = Confirm.ask("Screenshots (aquatone/gowitness)?",    default=False)
        cfg.run_ai_analysis = Confirm.ask("AI threat analysis?",                  default=True)
        if cfg.run_masscan:
            cfg.masscan_rate = _prompt_int("Masscan rate (pps)", default=5000, min_val=100, max_val=1000000)
        cfg.wordlist_size = Prompt.ask(
            "Wordlist size", choices=["small","medium","large"], default="medium"
        )

    elif profile == ScanProfile.WEB_ONLY:
        cfg.run_httpx       = True
        cfg.run_feroxbuster = True
        cfg.run_nuclei      = True
        cfg.run_whatweb     = True
        cfg.run_ai_analysis = Confirm.ask("AI analysis?", default=True)

    elif profile == ScanProfile.PORT_ONLY:
        cfg.run_rustscan = Confirm.ask("RustScan pre-scan?", default=True)
        cfg.run_masscan  = Confirm.ask("Masscan sweep (root)?", default=False)

    else:
        # Ask about optional extras for other profiles
        console.print(Rule("[dim]Optional Modules[/]"))
        cfg.run_subdomains  = Confirm.ask("Subdomain enumeration?", default=False)
        cfg.run_rustscan    = Confirm.ask("RustScan fast port sweep?", default=False)
        cfg.run_httpx       = Confirm.ask("httpx web detection?", default=False)
        cfg.run_nuclei      = Confirm.ask("Nuclei vuln scan?", default=False)
        cfg.run_ai_analysis = Confirm.ask("AI analysis?", default=False)

    return cfg


# ─── CLI arg builder ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace | None:
    parser = argparse.ArgumentParser(
        prog="reconninja",
        description=f"{APP_NAME} v{VERSION} — Elite all-in-one recon framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  reconninja -t example.com --profile full_suite -y\n"
            "  reconninja -t 10.0.0.1 --profile thorough --all-ports\n"
            "  reconninja -t targets.txt --profile standard --threads 10\n"
            "  reconninja --check-tools"
        ),
    )
    parser.add_argument("--target", "-t",  help="Target: domain, IP, CIDR, or path to list")
    parser.add_argument("--profile", "-p",
        choices=["fast","standard","thorough","stealth","custom","full_suite","web_only","port_only"],
        default=None,
    )
    # Nmap tuning
    parser.add_argument("--all-ports",    action="store_true")
    parser.add_argument("--top-ports",    type=int, default=1000)
    parser.add_argument("--timing",       default="T4", choices=["T1","T2","T3","T4","T5"])
    parser.add_argument("--threads",      type=int, default=20)

    # Feature flags
    parser.add_argument("--subdomains",   action="store_true")
    parser.add_argument("--rustscan",     action="store_true")
    parser.add_argument("--ferox",        action="store_true")
    parser.add_argument("--masscan",      action="store_true")
    parser.add_argument("--httpx",        action="store_true")
    parser.add_argument("--nuclei",       action="store_true")
    parser.add_argument("--nikto",        action="store_true")
    parser.add_argument("--whatweb",      action="store_true")
    parser.add_argument("--aquatone",     action="store_true")
    parser.add_argument("--ai",           action="store_true", help="Enable AI analysis (Groq/Ollama/Gemini/OpenAI)")
    parser.add_argument("--ai-key",       default=None,        help="API key for AI provider")
    parser.add_argument("--ai-provider",  default="groq",      choices=["groq","ollama","gemini","openai"], help="AI provider (default: groq)")
    parser.add_argument("--ai-model",     default=None,        help="Override default model for provider")

    # Other
    parser.add_argument("--wordlist-size", choices=["small","medium","large"], default="medium")
    parser.add_argument("--masscan-rate",  type=int, default=5000)
    parser.add_argument("--async-concurrency", type=int, default=1000,
                        help="Async TCP scanner concurrency (default: 1000)")
    parser.add_argument("--async-timeout",    type=float, default=1.5,
                        help="Async TCP connect timeout in seconds (default: 1.5)")
    parser.add_argument("--output",       default="reports", help="Output directory")
    parser.add_argument("--check-tools",  action="store_true")
    parser.add_argument("--update",       action="store_true", help="Check for updates and install latest version")
    parser.add_argument("--resume",       default=None,        metavar="STATE_FILE", help="Resume interrupted scan from state.json")
    parser.add_argument("--cve",          action="store_true", help="Enable NVD CVE lookup for detected services (free)")
    parser.add_argument("--cve-lookup",   action="store_true", help="Alias for --cve (backwards compat)")
    parser.add_argument("--nvd-key",      default=None,        help="Optional NVD API key (raises rate limit 5→50 req/30s)")
    parser.add_argument("--update-branch", default="main",     help="Branch to pull from on --update (default: main)")
    parser.add_argument("--force-update",  action="store_true", help="Update even if already on latest version")
    parser.add_argument("--yes", "-y",    action="store_true",
                        help="Skip permission confirmation (automation)")

    # v5.0.0 — intelligence integrations
    parser.add_argument("--shodan",       action="store_true", help="Shodan host lookup for discovered IPs")
    parser.add_argument("--shodan-key",   default=None,        help="Shodan API key")
    parser.add_argument("--vt",           action="store_true", help="VirusTotal reputation check")
    parser.add_argument("--vt-key",       default=None,        help="VirusTotal API key")
    parser.add_argument("--whois",        action="store_true", help="WHOIS lookup on target domain")
    parser.add_argument("--wayback",      action="store_true", help="Wayback Machine URL discovery")
    parser.add_argument("--ssl",          action="store_true", help="SSL/TLS certificate analysis")

    # v6.0.0 — new recon modules
    parser.add_argument("--github-osint",  action="store_true", help="GitHub OSINT: search for secrets/config files")
    parser.add_argument("--github-token",  default=None,        help="GitHub personal access token (raises API rate limit)")
    parser.add_argument("--js-extract",    action="store_true", help="Extract endpoints and secrets from JS files")
    parser.add_argument("--cloud-buckets", action="store_true", help="Cloud bucket enumeration (AWS S3/Azure/GCS)")
    parser.add_argument("--dns-zone",      action="store_true", help="DNS zone transfer (AXFR) check")
    parser.add_argument("--waf",           action="store_true", help="WAF detection (passive + wafw00f)")
    parser.add_argument("--cors",          action="store_true", help="CORS misconfiguration scanner")

    # v7.0.0 — new modules
    parser.add_argument("--email-security", action="store_true", help="SPF/DKIM/DMARC email security scan")
    parser.add_argument("--breach-check",   action="store_true", help="HaveIBeenPwned domain breach check")
    parser.add_argument("--hibp-key",       default="",          metavar="KEY",    help="HIBP API key for email-level lookup")
    parser.add_argument("--cloud-meta",     action="store_true", help="AWS/Azure/GCP metadata SSRF probe")
    parser.add_argument("--graphql",        action="store_true", help="GraphQL endpoint discovery and introspection")
    parser.add_argument("--jwt-scan",       action="store_true", help="JWT vulnerability scanner (none-alg, weak secrets)")
    parser.add_argument("--asn-map",        action="store_true", help="BGP/ASN IP range mapping")
    parser.add_argument("--supply-chain",   action="store_true", help="Outdated JS libraries + npm squatting")
    parser.add_argument("--k8s-probe",      action="store_true", help="Kubernetes/Docker API exposure check")
    parser.add_argument("--db-exposure",    action="store_true", help="Unauthenticated Redis/ES/MongoDB/Memcached")
    parser.add_argument("--smtp-enum",      action="store_true", help="SMTP user enumeration via VRFY/RCPT TO")
    parser.add_argument("--snmp-scan",      action="store_true", help="SNMP community string brute-force")
    parser.add_argument("--ldap-enum",      action="store_true", help="LDAP anonymous bind and attribute dump")
    parser.add_argument("--devops-scan",    action="store_true", help="Terraform state + Jenkins exposure")
    parser.add_argument("--greynoise",      action="store_true", help="GreyNoise IP context (noise vs targeted)")
    parser.add_argument("--greynoise-key",  default="",          metavar="KEY",    help="GreyNoise API key (optional)")
    parser.add_argument("--typosquat",      action="store_true", help="Typosquatting domain variant detection")
    parser.add_argument("--censys",         action="store_true", help="Censys host intelligence")
    parser.add_argument("--censys-id",      default="",          metavar="ID",     help="Censys API ID")
    parser.add_argument("--censys-secret",  default="",          metavar="SECRET", help="Censys API secret")
    parser.add_argument("--dns-history",    action="store_true", help="DNS history via VirusTotal PDNS (requires --vt-key)")
    parser.add_argument("--sarif",          action="store_true", help="Export findings as SARIF 2.1.0 report")

    # ── v8.0.0 — New modules ──────────────────────────────────────────────────
    parser.add_argument("--api-fuzz",       action="store_true", help="REST API fuzzer: endpoint discovery, IDOR, auth bypass, mass assignment")
    parser.add_argument("--oauth-scan",     action="store_true", help="OAuth 2.0/OIDC misconfiguration scanner")
    parser.add_argument("--web-vulns",      action="store_true", help="Web vuln probes: XSS, SQLi, LFI, SSRF")
    parser.add_argument("--open-redirect",  action="store_true", help="Open redirect vulnerability scanner")
    parser.add_argument("--linkedin",       action="store_true", help="LinkedIn employee OSINT + tech stack inference")
    parser.add_argument("--paste-monitor",  action="store_true", help="Scan paste sites for credential/secret leaks")
    parser.add_argument("--se-osint",       action="store_true", help="Social engineering OSINT: emails, phones, contacts")
    parser.add_argument("--apk-scan",       default=None,        metavar="APK_PATH", help="APK static analysis (provide path to .apk)")
    parser.add_argument("--app-store",      action="store_true", help="Google Play + Apple App Store metadata scraper")
    parser.add_argument("--anon-detect",    action="store_true", help="Tor/VPN/proxy/hosting IP detection")
    parser.add_argument("--dns-leak",       action="store_true", help="DNS leak check: rebinding, open resolver, internal exposure")
    parser.add_argument("--web3-scan",      action="store_true", help="Blockchain/Web3 recon: smart contracts, ABI, on-chain data")
    parser.add_argument("--ens-lookup",     action="store_true", help="ENS domain lookup + on-chain social profile resolution")

    # ── v8.0.0 — AI upgrades ───────────────────────────────────────────────────
    parser.add_argument("--ai-consensus",   action="store_true", help="Run AI analysis across multiple providers and synthesize consensus")
    parser.add_argument("--attack-paths",   action="store_true", help="AI-generated MITRE ATT&CK kill-chain attack paths")
    parser.add_argument("--ai-remediate",   action="store_true", help="AI per-finding remediation + CVSSv3 scoring")

    # ── v8.0.0 — Output & integrations ────────────────────────────────────────
    parser.add_argument("--pdf-report",     action="store_true", help="Export pentest-ready PDF report (requires weasyprint or fpdf2)")
    parser.add_argument("--jira",           default=None,        metavar="URL:EMAIL:TOKEN:PROJECT", help="Push findings to Jira as issues")
    parser.add_argument("--gh-issues",      default=None,        metavar="TOKEN:OWNER/REPO",        help="Push findings to GitHub Issues")
    parser.add_argument("--siem",           default=None,        metavar="URL:TOKEN[:TYPE]",        help="Push findings to Splunk/Elastic HEC endpoint")

    # ── v8.0.0 — GUI ──────────────────────────────────────────────────────────
    parser.add_argument("--gui",            action="store_true", help="Launch local desktop GUI (opens browser on http://127.0.0.1:7117)")
    parser.add_argument("--gui-port",       type=int, default=7117, help="GUI port (default: 7117)")

    parser.add_argument("--notify",        default=None,        metavar="URL",
                        help="Webhook for mid-scan alerts: slack://... discord://... or https://...")
    parser.add_argument("--diff",          nargs=2,             metavar=("REPORT_A", "REPORT_B"),
                        help="Compare two scan JSON reports: --diff old.json new.json")

    # v5.0.0 — output control
    parser.add_argument("--output-format", default="all",
        choices=["all","html","json","md","txt","pdf","sarif"],
        help="Report format (default: all)")
    parser.add_argument("--exclude",      default="",
        help="Comma-separated phases to skip: passive,port,web,vuln,report")

    # v5.0.0 — performance
    parser.add_argument("--timeout",      type=int,   default=30,
        help="Global per-operation timeout in seconds (default: 30)")
    parser.add_argument("--rate-limit",   type=float, default=0.0,
        help="Seconds between requests (default: 0 = no limit)")

    if len(sys.argv) == 1:
        return None
    return parser.parse_args()


def _parse_jira(val: str | None) -> dict | None:
    """Parse jira arg: URL:EMAIL:TOKEN:PROJECT"""
    if not val:
        return None
    parts = val.split(":", 3)
    if len(parts) < 3:
        return None
    return {"url": parts[0], "email": parts[1],
            "api_token": parts[2], "project_key": parts[3] if len(parts) > 3 else "SEC"}


def _parse_gh_issues(val: str | None) -> dict | None:
    """Parse gh-issues arg: TOKEN:OWNER/REPO"""
    if not val:
        return None
    parts = val.split(":", 1)
    if len(parts) < 2 or "/" not in parts[1]:
        return None
    owner, repo = parts[1].split("/", 1)
    return {"token": parts[0], "owner": owner, "repo": repo}


def _parse_siem(val: str | None) -> dict | None:
    """Parse siem arg: URL:TOKEN[:type]"""
    if not val:
        return None
    parts = val.split(":", 2)
    if len(parts) < 2:
        return None
    return {"url": parts[0], "token": parts[1],
            "type": parts[2] if len(parts) > 2 else "splunk"}



def build_config_from_args(args: argparse.Namespace) -> ScanConfig | None:
    if getattr(args, "update", False):
        run_update(force=getattr(args, "force_update", False))
        return None

    # v6.0.0 — scan diff mode
    if getattr(args, "diff", None):
        from pathlib import Path as _Path
        path_a, path_b = _Path(args.diff[0]), _Path(args.diff[1])
        for p in (path_a, path_b):
            if not p.exists():
                console.print(f"[danger]Diff: file not found: {p}[/]")
                return None
        diff = diff_reports(path_a, path_b)
        print_diff(diff)
        return None

    if getattr(args, "resume", None):
        from pathlib import Path as _Path
        from core.resume import load_state
        state = load_state(_Path(args.resume))
        if state:
            result, cfg, out_folder = state
            orchestrate(cfg, resume_result=result, resume_folder=out_folder)
        else:
            console.print("[danger]Failed to load resume state — check the file path.[/]")
        return None

    if args.check_tools:
        print_tool_status()
        return None

    if not args.target:
        console.print("[danger]--target/-t is required[/]")
        return None

    if not args.yes:
        if not Confirm.ask(
            f"[danger]⚠  Confirm written permission to scan {args.target}?[/]",
            default=False,
        ):
            console.print("[danger]Aborted.[/]")
            return None

    profile   = ScanProfile(args.profile) if args.profile else ScanProfile.STANDARD
    nmap_opts = NmapOptions(
        all_ports        = args.all_ports,
        top_ports        = args.top_ports,
        timing           = args.timing,
        scripts          = True,
        version_detection= True,
    )

    # Full suite shorthand
    is_full = (profile == ScanProfile.FULL_SUITE)

    exclude = [p.strip() for p in getattr(args, "exclude", "").split(",") if p.strip()]

    return ScanConfig(
        target          = args.target,
        profile         = profile,
        nmap_opts       = nmap_opts,
        run_subdomains  = args.subdomains or is_full,
        run_rustscan    = args.rustscan   or is_full,
        run_feroxbuster = args.ferox      or is_full,
        run_masscan     = args.masscan,
        run_httpx       = args.httpx      or is_full,
        run_whatweb     = args.whatweb    or is_full,
        run_nikto       = args.nikto,
        run_nuclei      = args.nuclei     or is_full,
        run_aquatone    = args.aquatone,
        run_ai_analysis = args.ai         or is_full,
        run_cve_lookup  = getattr(args, "cve", False) or getattr(args, "cve_lookup", False),
        ai_provider     = getattr(args, "ai_provider", "groq"),
        ai_key          = getattr(args, "ai_key", None) or "",
        ai_model        = getattr(args, "ai_model", None) or "",
        nvd_key         = getattr(args, "nvd_key", None) or "",
        # v5.0.0
        run_shodan      = getattr(args, "shodan", False) or is_full,
        run_virustotal  = getattr(args, "vt", False),
        run_whois       = getattr(args, "whois", False) or is_full,
        run_wayback     = getattr(args, "wayback", False) or is_full,
        run_ssl         = getattr(args, "ssl", False) or is_full,
        shodan_key      = getattr(args, "shodan_key", None) or "",
        vt_key          = getattr(args, "vt_key", None) or "",
        # v6.0.0 — new modules
        run_github_osint  = getattr(args, "github_osint", False) or is_full,
        github_token      = getattr(args, "github_token", None) or "",
        run_js_extract    = getattr(args, "js_extract", False) or is_full,
        run_cloud_buckets = getattr(args, "cloud_buckets", False) or is_full,
        run_dns_zone      = getattr(args, "dns_zone", False) or is_full,
        run_waf           = getattr(args, "waf", False) or is_full,
        run_cors          = getattr(args, "cors", False) or is_full,
        notify_url        = getattr(args, "notify", None) or "",
        # v7.0.0 — new modules
        run_email_security = getattr(args, "email_security", False) or is_full,
        run_breach_check   = getattr(args, "breach_check", False) or is_full,
        hibp_key           = getattr(args, "hibp_key", "") or "",
        run_cloud_meta     = getattr(args, "cloud_meta", False) or is_full,
        run_graphql        = getattr(args, "graphql", False) or is_full,
        run_jwt_scan       = getattr(args, "jwt_scan", False) or is_full,
        run_asn_map        = getattr(args, "asn_map", False) or is_full,
        run_supply_chain   = getattr(args, "supply_chain", False) or is_full,
        run_k8s_probe      = getattr(args, "k8s_probe", False) or is_full,
        run_db_exposure    = getattr(args, "db_exposure", False) or is_full,
        run_smtp_enum      = getattr(args, "smtp_enum", False) or is_full,
        run_snmp_scan      = getattr(args, "snmp_scan", False) or is_full,
        run_ldap_enum      = getattr(args, "ldap_enum", False) or is_full,
        run_devops_scan    = getattr(args, "devops_scan", False) or is_full,
        run_greynoise      = getattr(args, "greynoise", False) or is_full,
        greynoise_key      = getattr(args, "greynoise_key", "") or "",
        run_typosquat      = getattr(args, "typosquat", False) or is_full,
        run_censys         = getattr(args, "censys", False),
        censys_api_id      = getattr(args, "censys_id", "") or "",
        censys_api_secret  = getattr(args, "censys_secret", "") or "",
        run_dns_history    = getattr(args, "dns_history", False) or is_full,
        run_sarif_export   = getattr(args, "sarif", False),
        # v8.0.0 — new modules
        run_api_fuzz        = getattr(args, "api_fuzz", False),
        run_oauth_scan      = getattr(args, "oauth_scan", False),
        run_web_vulns       = getattr(args, "web_vulns", False),
        run_open_redirect   = getattr(args, "open_redirect", False),
        run_linkedin        = getattr(args, "linkedin", False),
        run_paste_monitor   = getattr(args, "paste_monitor", False),
        run_se_osint        = getattr(args, "se_osint", False),
        apk_path            = getattr(args, "apk_scan", None),
        run_app_store       = getattr(args, "app_store", False),
        run_anon_detect     = getattr(args, "anon_detect", False),
        run_dns_leak        = getattr(args, "dns_leak", False),
        run_web3_scan       = getattr(args, "web3_scan", False),
        run_ens_lookup      = getattr(args, "ens_lookup", False),
        # v8.0.0 — AI upgrades
        run_ai_consensus    = getattr(args, "ai_consensus", False),
        run_attack_paths    = getattr(args, "attack_paths", False),
        run_ai_remediate    = getattr(args, "ai_remediate", False),
        # v8.0.0 — output integrations
        run_pdf_report      = getattr(args, "pdf_report", False),
        jira_config         = _parse_jira(getattr(args, "jira", None)),
        github_issues_config= _parse_gh_issues(getattr(args, "gh_issues", None)),
        siem_config         = _parse_siem(getattr(args, "siem", None)),
        output_format   = getattr(args, "output_format", "all"),
        exclude_phases  = exclude,
        global_timeout  = getattr(args, "timeout", 30),
        rate_limit      = getattr(args, "rate_limit", 0.0),
        threads         = args.threads,
        wordlist_size      = args.wordlist_size,
        masscan_rate       = args.masscan_rate,
        output_dir         = args.output,
        async_concurrency  = args.async_concurrency,
        async_timeout      = args.async_timeout,
    )


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    def _sigint(sig, frame):
        console.print("\n[danger]Interrupted — partial results may exist in reports/[/]")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    args = parse_args()
    if args is None:
        # Interactive mode
        print_tool_status()
        cfg = build_config_interactive()
    else:
        # v8.0.0 — GUI mode
        if getattr(args, "gui", False):
            from gui.app import launch_gui
            launch_gui(port=getattr(args, "gui_port", 7117))
            return
        cfg = build_config_from_args(args)

    if cfg is None:
        return

    orchestrate(cfg)


if __name__ == "__main__":
    main()
