#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝

ReconNinja v5.0.0 — Elite All-in-One Recon Framework
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
  + FIX: masscan_rate crash on non-integer input (v5.0.0)
  + FIX: FULL_SUITE no longer triggers custom nmap builder (v5.0.0)
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
from utils.logger import console, log
from utils.models import ScanConfig, ScanProfile, NmapOptions
from core.orchestrator import orchestrate, print_tool_status
from core.updater import run_update, print_update_status

APP_NAME = "ReconNinja"
VERSION  = "5.0.0"



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

    # v5.0.0 — new integrations
    parser.add_argument("--shodan",       action="store_true", help="Shodan host lookup for discovered IPs")
    parser.add_argument("--shodan-key",   default=None,        help="Shodan API key")
    parser.add_argument("--vt",           action="store_true", help="VirusTotal reputation check")
    parser.add_argument("--vt-key",       default=None,        help="VirusTotal API key")
    parser.add_argument("--whois",        action="store_true", help="WHOIS lookup on target domain")
    parser.add_argument("--wayback",      action="store_true", help="Wayback Machine URL discovery")
    parser.add_argument("--ssl",          action="store_true", help="SSL/TLS certificate analysis")

    # v5.0.0 — output control
    parser.add_argument("--output-format", default="all",
        choices=["all","html","json","md","txt"],
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


def build_config_from_args(args: argparse.Namespace) -> ScanConfig | None:
    if getattr(args, "update", False):
        run_update(force=getattr(args, "force_update", False))
        return None

    if getattr(args, "resume", None):
        from pathlib import Path as _Path
        from core.resume import load_state
        state = load_state(_Path(args.resume))
        if state:
            result, cfg, out_folder = state
            orchestrate(cfg, resume_result=result, resume_folder=out_folder)
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
        cfg = build_config_from_args(args)

    if cfg is None:
        return

    orchestrate(cfg)


if __name__ == "__main__":
    main()
