"""
ReconNinja v10.5 — Interactive CLI Menu (fsociety-style)
========================================================

When the user runs `reconninja` with no arguments, they get this numbered
menu instead of a 200-line argparse wall or a heavy TUI. Inspired by the
fsociety framework's iconic interactive launcher.

Layout
──────

  ╔════════════════════════════════════════════════════════════════════╗
  ║                      [ ASCII BANNER ]                              ║
  ║              v10.5.0  ·  ExploitCraft                             ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║  SELECT AN OPERATION                                              ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║   [01] ⚡  Full Scan              (all phases)                    ║
  ║   [02] 🚀  Quick Recon           (passive OSINT, ~2 min)         ║
  ║   [03] 🌐  Web Application Scan  (httpx + nuclei + feroxbuster)  ║
  ║   ...                                                              ║
  ║   [99] 🚪  Exit                                                    ║
  ╚════════════════════════════════════════════════════════════════════╝

    ► Select option [1-18, 99]:

Each option prompts for any required inputs (target, API keys, etc.),
builds a ScanConfig with the right phase flags preset, and runs the scan.
After completion, control returns to the menu so the user can run another
operation without re-launching.

Ctrl+C at any prompt returns to the menu. Ctrl+C at the menu exits.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from info import __version__
from utils.logger import console as _shared_console

console = _shared_console

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
   ____  _____ ____ ___  _   _  _   _ ___ _   _     _
  |  _ \| ____/ ___/ _ \| \ | || \ | |_ _| \ | |   / \
  | |_) |  _|| |  | | | |  \| ||  \| || ||  \| |  / _ \
  |  _ <| |__| |__| |_| | |\  || |\  || || |\  | / ___ \
  |_| \_\_____\____\___/|_| \_||_| \_|___|_| \_|/_/   \_\
"""


# ─── Menu options ────────────────────────────────────────────────────────────
# Each entry: (id, emoji, title, description, handler_name)
# handler_name refers to a method on the InteractiveMenu class.

MENU_OPTIONS = [
    ("01", "⚡",  "Full Scan",              "All phases enabled — the kitchen sink",
     "full_scan"),
    ("02", "🚀", "Quick Recon",            "Passive OSINT only (whois + wayback + ssl), ~2 min",
     "quick_recon"),
    ("03", "🌐", "Web Application Scan",   "httpx + whatweb + nuclei + feroxbuster + cors + jwt",
     "web_app_scan"),
    ("04", "🔌", "Port Scan Only",         "Async TCP + optional rustscan/masscan + nmap",
     "port_scan"),
    ("05", "🔍", "Subdomain Enumeration",  "subfinder + amass + assetfinder + crt.sh + DNS brute",
     "subdomain_enum"),
    ("06", "💥", "Vulnerability Scan",     "nuclei templates + CVE lookup via NVD",
     "vuln_scan"),
    ("07", "☁️",  "Cloud Recon",            "S3 / Azure Blob / GCS bucket enumeration",
     "cloud_recon"),
    ("08", "🏢", "Active Directory Recon", "Kerberoasting + AS-REP + ACL + BloodHound",
     "ad_recon"),
    ("09", "🤖", "AI/LLM Endpoint Scan",   "Discover exposed Ollama / Qdrant / MCP / LiteLLM",
     "llm_recon"),
    ("10", "🔁", "Continuous Monitoring",  "Re-scan on interval, diff findings, alert on new crits",
     "monitor"),
    ("11", "🎯", "Custom Scan",            "Pick phases interactively — choose your own adventure",
     "custom_scan"),
    ("12", "⏯",  "Resume Previous Scan",   "Continue from a saved state.json",
     "resume"),
    ("13", "📊", "Diff Two Scans",         "Compare two state.json files for new/resolved findings",
     "diff_scans"),
    ("14", "🛠",  "Check Tools",            "Show which external tools (nmap, nuclei, …) are installed",
     "check_tools"),
    ("15", "⬆️",  "Self-Update",            "Pull latest from GitHub via git or release zip",
     "self_update"),
    ("16", "🖥️", "Launch GUI",             "Flask web interface on http://localhost:7117",
     "launch_gui"),
    ("17", "🎛️", "Launch TUI",             "Textual terminal UI (the v10.1 interactive interface)",
     "launch_tui"),
    ("18", "🔌", "MCP Server",             "JSON-RPC over SSE for Claude Code / Cursor",
     "mcp_server"),
    ("99", "🚪", "Exit",                   "Quit ReconNinja",
     "exit"),
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _print_banner() -> None:
    """Render the colored ASCII banner + version line."""
    banner_text = Text(BANNER, style="bold red")
    version_line = Text(f"  v{__version__}  ·  Autonomous Security Recon Agent  ·  ExploitCraft",
                        style="bold cyan")
    console.print(banner_text)
    console.print(version_line)
    console.print()


def _print_menu() -> None:
    """Render the numbered options table."""
    table = Table(
        title="[bold blue]SELECT AN OPERATION[/]",
        title_style="bold blue",
        border_style="blue",
        show_header=False,
        expand=True,
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("num", style="bold yellow", width=5, justify="right")
    table.add_column("icon", width=4, justify="center")
    table.add_column("title", style="bold white", min_width=26)
    table.add_column("desc", style="dim")

    for num, emoji, title, desc, _ in MENU_OPTIONS:
        if num == "99":
            # Spacer row before Exit
            table.add_row("", "", "", "")
        table.add_row(f"[{num}]", emoji, title, desc)

    console.print(table)


# ─── Prompt helpers ──────────────────────────────────────────────────────────

def _prompt_target() -> str:
    """Ask the user for a target. Returns empty string on Ctrl+C."""
    try:
        return Prompt.ask(
            "[bold cyan]► Target[/]  [dim](domain or IP, e.g. example.com)[/]",
            console=console,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Cancelled.[/]")
        return ""


def _prompt_optional(label: str, hint: str = "", default: str = "") -> str:
    try:
        return Prompt.ask(
            f"[bold cyan]► {label}[/]  [dim]({hint})[/]" if hint else f"[bold cyan]► {label}[/]",
            console=console,
            default=default,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return default


def _confirm(label: str, default: bool = True) -> bool:
    try:
        from rich.prompt import Confirm
        return Confirm.ask(f"[bold cyan]► {label}[/]", console=console, default=default)
    except (KeyboardInterrupt, EOFError):
        return default


# ─── Interactive Menu ────────────────────────────────────────────────────────

class InteractiveMenu:
    """The fsociety-style interactive launcher. Run via .run()."""

    def __init__(self) -> None:
        self._running = True

    def run(self) -> int:
        """Main loop. Returns process exit code (0 = clean exit)."""
        while self._running:
            try:
                _clear_screen()
                _print_banner()
                _print_menu()
                console.print()
                choice = Prompt.ask(
                    "[bold green]► Select option[/]",
                    console=console,
                    default="99",
                ).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold red]Goodbye.[/]")
                return 0

            # _dispatch normalises both bare ("1") and zero-padded ("01")
            # forms, so we pass the raw choice straight through.
            handler = self._dispatch(choice)
            if handler is None:
                console.print(f"\n[bold red]✗ Invalid option '{choice}'. "
                              f"Enter a number between 1 and 18, or 99 to exit.[/]")
                self._pause()
                continue

            exit_code = handler()
            if exit_code is not None:
                return exit_code
            # Most handlers return None to mean "loop back to menu"
        return 0

    # ─── Dispatch ────────────────────────────────────────────────────────────

    def _dispatch(self, choice: str):
        """Map a number string to a handler method.

        Accepts both bare ('1') and zero-padded ('01') forms — both are
        normalised by stripping leading zeros before comparison.
        """
        choice_norm = (choice or "").lstrip("0") or "0"
        for num, _, _, _, handler_name in MENU_OPTIONS:
            num_norm = num.lstrip("0") or "0"
            if choice_norm == num_norm:
                return getattr(self, f"_op_{handler_name}", None)
        return None

    # ─── Pause helper ────────────────────────────────────────────────────────

    @staticmethod
    def _pause() -> None:
        try:
            Prompt.ask("\n[dim]Press Enter to return to the menu…[/]",
                       console=console, default="")
        except (KeyboardInterrupt, EOFError):
            pass

    # ─── Scan runner ─────────────────────────────────────────────────────────

    def _run_scan_with_cfg(self, cfg) -> None:
        """Run a scan with the given config, handling errors gracefully."""
        try:
            from core.orchestrator_v9 import run_scan
            from core.resume import set_active_config
            set_active_config(cfg)
            run_scan(cfg)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠ Scan interrupted by user.[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ Scan failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _build_cfg(self, target: str, **overrides):
        """Build a ScanConfig with sensible defaults + overrides."""
        from utils.models import ScanConfig, NmapOptions, ScanProfile
        cfg = ScanConfig(
            target=target,
            profile=ScanProfile.STANDARD,
            nmap_opts=NmapOptions(),
            output_format="all",
            no_tui=True,
        )
        for k, v in overrides.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    # ═════════════════════════════════════════════════════════════════════════
    #   OPERATION HANDLERS
    # ═════════════════════════════════════════════════════════════════════════

    def _op_full_scan(self):
        """[01] Full Scan — every phase enabled."""
        console.print(Panel("[bold cyan]⚡  FULL SCAN[/] — every phase enabled. "
                            "This will take a while.", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(target)
        # Enable every phase
        for attr in dir(cfg):
            if attr.startswith("run_") and not attr.startswith("run_ai_"):
                try:
                    setattr(cfg, attr, True)
                except Exception:
                    pass
        cfg.run_correlation = True
        cfg.run_interactive_report = True
        cfg.nmap_opts.all_ports = True
        self._run_scan_with_cfg(cfg)

    def _op_quick_recon(self):
        """[02] Quick Recon — passive only."""
        console.print(Panel("[bold cyan]🚀  QUICK RECON[/] — passive OSINT, ~2 min.",
                            border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(
            target,
            run_whois=True,
            run_wayback=True,
            run_ssl=True,
            run_asn_map=True,
            run_email_security=True,
            run_typosquat=True,
            run_dns_zone=True,
        )
        self._run_scan_with_cfg(cfg)

    def _op_web_app_scan(self):
        """[03] Web Application Scan."""
        console.print(Panel("[bold cyan]🌐  WEB APPLICATION SCAN[/]", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(
            target,
            run_subdomains=True,
            run_httpx=True,
            run_whatweb=True,
            run_waf=True,
            run_cors=True,
            run_js_extract=True,
            run_graphql=True,
            run_jwt_scan=True,
            run_feroxbuster=True,
            run_nikto=True,
            run_nuclei=True,
            run_cve_lookup=True,
            run_api_fuzz=True,
            run_oauth_scan=True,
            run_web_vulns=True,
            run_open_redirect=True,
        )
        self._run_scan_with_cfg(cfg)

    def _op_port_scan(self):
        """[04] Port Scan Only."""
        console.print(Panel("[bold cyan]🔌  PORT SCAN ONLY[/]", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        all_ports = _confirm("Scan all 65535 ports?", default=False)
        cfg = self._build_cfg(target, run_rustscan=True)
        cfg.nmap_opts.all_ports = all_ports
        if all_ports:
            cfg.nmap_opts.top_ports = 0
        else:
            cfg.nmap_opts.top_ports = 1000
        self._run_scan_with_cfg(cfg)

    def _op_subdomain_enum(self):
        """[05] Subdomain Enumeration."""
        console.print(Panel("[bold cyan]🔍  SUBDOMAIN ENUMERATION[/]", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(target, run_subdomains=True)
        cfg.wordlist_size = _prompt_optional(
            "Wordlist size", "small / medium / large", "medium") or "medium"
        self._run_scan_with_cfg(cfg)

    def _op_vuln_scan(self):
        """[06] Vulnerability Scan."""
        console.print(Panel("[bold cyan]💥  VULNERABILITY SCAN[/] — nuclei + CVE lookup",
                            border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        nvd_key = _prompt_optional("NVD API key", "optional, for higher rate limits", "")
        cfg = self._build_cfg(
            target,
            run_httpx=True,
            run_nuclei=True,
            run_cve_lookup=True,
            nvd_key=nvd_key,
        )
        self._run_scan_with_cfg(cfg)

    def _op_cloud_recon(self):
        """[07] Cloud Recon."""
        console.print(Panel("[bold cyan]☁️   CLOUD RECON[/] — S3 / Azure / GCP bucket enum",
                            border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(
            target,
            run_cloud_buckets=True,
            run_cloud_meta=True,
            run_cloud_deep=True,
        )
        self._run_scan_with_cfg(cfg)

    def _op_ad_recon(self):
        """[08] Active Directory Recon."""
        console.print(Panel("[bold cyan]🏢  ACTIVE DIRECTORY RECON[/]", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        dc = _prompt_optional("Domain controller IP", "e.g. 10.0.0.5", "")
        domain = _prompt_optional("AD domain", "e.g. corp.example.com", "")
        user = _prompt_optional("AD username", "optional, for authenticated enum", "")
        password = _prompt_optional("AD password", "optional", "")
        cfg = self._build_cfg(
            target,
            run_ad_recon=True,
            ad_dc=dc,
            ad_domain=domain,
            ad_user=user,
            ad_password=password,
        )
        self._run_scan_with_cfg(cfg)

    def _op_llm_recon(self):
        """[09] AI/LLM Endpoint Scan."""
        console.print(Panel("[bold cyan]🤖  AI/LLM ENDPOINT SCAN[/] — "
                            "discover exposed Ollama / Qdrant / MCP / LiteLLM",
                            border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        cfg = self._build_cfg(
            target,
            run_llm_recon=True,
            run_httpx=True,
        )
        self._run_scan_with_cfg(cfg)

    def _op_monitor(self):
        """[10] Continuous Monitoring."""
        console.print(Panel("[bold cyan]🔁  CONTINUOUS MONITORING[/]", border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        interval = _prompt_optional(
            "Re-scan interval", "1h / 6h / 24h", "24h") or "24h"
        passive_only = _confirm("Passive-only mode? (recommended for prod)", default=True)
        cfg = self._build_cfg(
            target,
            monitor_mode=True,
            monitor_interval=interval,
            monitor_passive_only=passive_only,
            run_whois=True,
            run_wayback=True,
            run_ssl=True,
            run_subdomains=True,
        )
        try:
            from core.monitor import run_monitor_loop
            from core.resume import set_active_config
            set_active_config(cfg)
            run_monitor_loop(cfg)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠ Monitor stopped by user.[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ Monitor failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_custom_scan(self):
        """[11] Custom Scan — pick phases interactively."""
        console.print(Panel("[bold cyan]🎯  CUSTOM SCAN[/] — pick phases",
                            border_style="cyan"))
        target = _prompt_target()
        if not target:
            return
        # Show a phase checklist and let the user toggle
        from gui.tui import PHASES  # reuse the TUI's phase catalogue
        console.print("\n[bold]Available phases (enter numbers, comma-separated):[/]\n")
        for i, (phase_id, label, _) in enumerate(PHASES, 1):
            console.print(f"  [bold yellow]{i:2}[/].  {label}")
        console.print()
        try:
            sel = Prompt.ask(
                "[bold green]► Phases to enable[/]  [dim](e.g. 1,3,5,12)[/]",
                console=console,
                default="",
            ).strip()
        except (KeyboardInterrupt, EOFError):
            return
        enabled = set()
        for tok in sel.split(","):
            tok = tok.strip()
            if tok.isdigit():
                idx = int(tok) - 1
                if 0 <= idx < len(PHASES):
                    enabled.add(PHASES[idx][0])
        if not enabled:
            console.print("[yellow]No phases selected — aborting.[/]")
            self._pause()
            return
        cfg = self._build_cfg(target)
        for phase_id, _, _ in PHASES:
            setattr(cfg, phase_id, phase_id in enabled)
        self._run_scan_with_cfg(cfg)

    def _op_resume(self):
        """[12] Resume Previous Scan."""
        console.print(Panel("[bold cyan]⏯   RESUME PREVIOUS SCAN[/]", border_style="cyan"))
        target = _prompt_target()
        state_path = None
        if target:
            try:
                from core.resume import find_latest_state
                state_path = find_latest_state(target)
            except Exception:
                state_path = None
        if state_path is None:
            state_path_str = _prompt_optional(
                "Path to state.json", "or press Enter to cancel", "")
            if not state_path_str:
                return
            state_path = state_path_str
        console.print(f"[dim]Resuming from: {state_path}[/]")
        try:
            from core.resume import load_state, set_active_config
            from core.orchestrator_v9 import run_scan
            loaded = load_state(state_path)
            if loaded is None:
                self._pause()
                return
            result, cfg, out_folder = loaded
            set_active_config(cfg)
            run_scan(cfg)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠ Resume interrupted.[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ Resume failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_diff_scans(self):
        """[13] Diff Two Scans."""
        console.print(Panel("[bold cyan]📊  DIFF TWO SCANS[/]", border_style="cyan"))
        old = _prompt_optional("Old state.json path", "")
        if not old:
            return
        new = _prompt_optional("New state.json path", "")
        if not new:
            return
        try:
            import reconninja
            reconninja._cmd_diff(old, new)
        except Exception as e:
            console.print(f"\n[bold red]✗ Diff failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_check_tools(self):
        """[14] Check Tools."""
        console.print(Panel("[bold cyan]🛠   CHECK TOOLS[/]", border_style="cyan"))
        try:
            import reconninja
            reconninja._cmd_check_tools()
        except Exception as e:
            console.print(f"\n[bold red]✗ Check-tools failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_self_update(self):
        """[15] Self-Update."""
        console.print(Panel("[bold cyan]⬆️   SELF-UPDATE[/]", border_style="cyan"))
        force = _confirm("Force update even if already on latest?", default=False)
        try:
            import reconninja
            reconninja._cmd_update(force=force)
        except Exception as e:
            console.print(f"\n[bold red]✗ Update failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_launch_gui(self):
        """[16] Launch GUI."""
        console.print(Panel("[bold cyan]🖥️   LAUNCH GUI[/] — Flask web interface",
                            border_style="cyan"))
        port_str = _prompt_optional("GUI port", "default 7117", "7117") or "7117"
        try:
            port = int(port_str)
        except ValueError:
            port = 7117
        try:
            from gui.app import launch_gui
            launch_gui(port=port)
        except Exception as e:
            console.print(f"\n[bold red]✗ GUI failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_launch_tui(self):
        """[17] Launch TUI."""
        console.print(Panel("[bold cyan]🎛️   LAUNCH TUI[/] — Textual terminal UI",
                            border_style="cyan"))
        try:
            from gui.tui import launch_tui, TEXTUAL_AVAILABLE
            if not TEXTUAL_AVAILABLE:
                console.print("[bold red]✗ Textual is not installed. "
                              "Run `pip install 'reconninja[tui]'` to enable.[/]")
                self._pause()
                return
            launch_tui()
        except Exception as e:
            console.print(f"\n[bold red]✗ TUI failed: {type(e).__name__}: {e}[/]")
        # No _pause() here because the TUI just ran interactively

    def _op_mcp_server(self):
        """[18] MCP Server."""
        console.print(Panel("[bold cyan]🔌  MCP SERVER[/] — JSON-RPC over SSE",
                            border_style="cyan"))
        port_str = _prompt_optional("Port", "default 8765", "8765") or "8765"
        try:
            port = int(port_str)
        except ValueError:
            port = 8765
        bind = _prompt_optional("Bind address", "default 127.0.0.1", "127.0.0.1") or "127.0.0.1"
        token = _prompt_optional("Bearer token", "optional, recommended for 0.0.0.0", "")
        try:
            from core.mcp_server import start_mcp_server
            from utils.models import ScanConfig
            cfg = ScanConfig(target="", mcp_server_port=port)
            start_mcp_server(port, cfg, bind=bind, token=token)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠ MCP server stopped.[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ MCP server failed: {type(e).__name__}: {e}[/]")
        self._pause()

    def _op_exit(self):
        """[99] Exit."""
        console.print("[bold red]Goodbye.[/]")
        self._running = False
        return 0


# ─── Public entry point ──────────────────────────────────────────────────────

def launch_menu() -> int:
    """Launch the fsociety-style interactive menu. Returns process exit code."""
    menu = InteractiveMenu()
    return menu.run()
