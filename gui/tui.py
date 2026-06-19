"""
ReconNinja v10.1 — Textual TUI
==============================

A premium interactive terminal interface for ReconNinja. Launches by default
when `reconninja` is run with no args (use --no-tui for the plain-Rich CLI).

Layout
──────

┌─ ReconNinja v10.1.0 ──────────────────────────────────── Phase: 0/0 ──┐
│  ████████ ASCII BANNER ████████                                       │
│                                                                       │
│  Target ┌────────────────────┐   Profile  [fast][std][thorough][full] │
│         └────────────────────┘                                         │
│                                                                       │
│  ┌─ Phases ──────────────────┐  ┌─ Live Log ────────────────────────┐ │
│  │ ☑ whois                   │  │ ▸ whois                           │ │
│  │ ☑ wayback                 │  │   ✔ whois (1.2s)                  │ │
│  │ ☐ subdomains              │  │ ▸ async_tcp                       │ │
│  │ ☐ httpx                   │  │   ✔ async_tcp (3.4s)              │ │
│  │ ...                       │  │ ▸ nmap                            │ │
│  └───────────────────────────┘  └───────────────────────────────────┘ │
│                                                                       │
│  ┌─ Findings ─────────────────────────────────────────────────────┐   │
│  │  CRIT 0    HIGH 0    MED 0    INFO 0      Subs 0   Hosts 0     │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  [Enter] Start   [Space] Toggle   [Tab] Cycle   [q] Quit   [?] Help  │
└───────────────────────────────────────────────────────────────────────┘

Keybindings
───────────
  Enter      Start scan (or resume if one is running)
  Space      Toggle currently-highlighted phase
  Tab        Cycle focus between target / phases / log
  p          Quick-pick profile: fast → standard → thorough → full_suite → fast
  r          Resume scan from latest state.json
  c          Clear log
  s          Save current state (only meaningful mid-scan)
  q / Esc    Quit
  ?          Toggle help overlay
"""
from __future__ import annotations

import queue
import threading
import time
import logging
from pathlib import Path
from typing import Optional

# Textual is an optional dep — fall back gracefully if missing.
try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import (
        Header, Footer, Input, Label, Button, Checkbox, Static, RichLog
    )
    from textual.widget import Widget
    from textual.reactive import reactive
    from textual.message import Message
    from textual import on, work
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from info import __version__

# ─── Phase catalogue ─────────────────────────────────────────────────────────
# (phase_id, label, default-on for STANDARD profile)
PHASES = [
    # Passive / OSINT
    ("run_subdomains",    "Subdomain enumeration",      False),
    ("run_whois",         "WHOIS lookup",               True),
    ("run_wayback",       "Wayback Machine",            True),
    ("run_github_osint",  "GitHub OSINT",               False),
    ("run_asn_map",       "ASN mapping",                False),
    ("run_breach_check",  "Breach check (HIBP)",        False),
    ("run_email_security","Email security (SPF/DKIM)",  False),
    ("run_linkedin",      "LinkedIn OSINT",             False),
    ("run_typosquat",     "Typosquatting domains",      False),
    # Port discovery
    ("run_rustscan",      "RustScan",                   False),
    ("run_masscan",       "Masscan",                    False),
    # Web
    ("run_httpx",         "HTTPX probe",                False),
    ("run_whatweb",       "WhatWeb fingerprint",        False),
    ("run_nikto",         "Nikto vuln scanner",         False),
    ("run_feroxbuster",   "Feroxbuster dirs",           False),
    ("run_ssl",           "SSL/TLS scan",               True),
    ("run_waf",           "WAF detection",              False),
    ("run_cors",          "CORS scan",                  False),
    ("run_js_extract",    "JS secret extraction",       False),
    ("run_graphql",       "GraphQL scan",               False),
    ("run_jwt_scan",      "JWT scan",                   False),
    # Vuln
    ("run_nuclei",        "Nuclei templates",           False),
    ("run_cve_lookup",    "CVE lookup (NVD)",           False),
    # Intelligence
    ("run_shodan",        "Shodan",                     False),
    ("run_virustotal",    "VirusTotal",                 False),
    ("run_censys",        "Censys",                     False),
    ("run_greynoise",     "GreyNoise",                  False),
    # Cloud / container
    ("run_cloud_buckets", "Cloud bucket enum",          False),
    ("run_cloud_meta",    "Cloud metadata probe",       False),
    ("run_cloud_deep",    "Deep cloud scan",            False),
    ("run_k8s_probe",     "Kubernetes probe",           False),
    ("run_container_deep","Container deep scan",        False),
    ("run_db_exposure",   "DB exposure (Redis/Mongo)",  False),
    ("run_devops_scan",   "DevOps (Jenkins/Terraform)", False),
    # Service enum
    ("run_smtp_enum",     "SMTP user enum",             False),
    ("run_snmp_scan",     "SNMP brute",                 False),
    ("run_ldap_enum",     "LDAP enum",                  False),
    ("run_dns_zone",      "DNS zone transfer",          False),
    ("run_dns_leak",      "DNS leak",                   False),
    # Modern attack surface
    ("run_llm_recon",     "AI/LLM endpoint scan",       False),
    ("run_iot_scan",      "IoT/ICS protocols",          False),
    ("run_ad_recon",      "Active Directory recon",     False),
    ("run_web3_scan",     "Web3 / smart contracts",     False),
    ("run_ens_lookup",    "ENS resolution",             False),
    # AI
    ("run_correlation",   "AI correlation pipeline",    False),
    ("run_ai_analysis",   "AI analysis (single model)", False),
    # Reports
    ("run_sarif_export",  "SARIF export",               False),
]

PROFILES = ["fast", "standard", "thorough", "full_suite"]


# ─── Log capture handler ─────────────────────────────────────────────────────
# A logging.Handler that pushes records into a thread-safe queue.  The TUI
# drains this queue on a timer and renders new lines into the RichLog widget.

class _QueueLogHandler(logging.Handler):
    def __init__(self, q: queue.Queue):
        super().__init__(level=logging.INFO)
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._q.put_nowait(record)
        except queue.Full:
            pass


# ─── TUI App ─────────────────────────────────────────────────────────────────

if TEXTUAL_AVAILABLE:

    CSS = """
    Screen {
        background: #0a0e14;
        color: #c8d3f5;
        layout: vertical;
    }

    #banner {
        color: #ff5370;
        text-align: center;
        padding: 0 1;
        height: 6;
        content-align: center middle;
        text-style: bold;
    }

    #subtitle {
        color: #82aaff;
        text-align: center;
        height: 1;
        text-style: italic;
    }

    .panel {
        border: round #1e2230;
        background: #0d1117;
        padding: 0 1;
        margin: 0 0;
    }

    #config-row {
        height: 3;
        layout: horizontal;
        margin: 0 0;
    }

    #target-panel {
        width: 1fr;
        border: round #1e2230;
        background: #0d1117;
        padding: 0 1;
    }

    #target-label {
        color: #c3e88d;
        text-style: bold;
        height: 1;
    }

    #target-input {
        border: solid #2a3147;
        background: #060a10;
        margin: 0;
        height: 1;
    }

    #target-input:focus {
        border: solid #82aaff;
    }

    #profile-panel {
        width: 2fr;
        border: round #1e2230;
        background: #0d1117;
        padding: 0 1;
        layout: horizontal;
    }

    #profile-label {
        color: #c3e88d;
        text-style: bold;
        width: 9;
        height: 1;
    }

    .profile-btn {
        border: solid #2a3147;
        background: #060a10;
        color: #c8d3f5;
        margin: 0 0 0 1;
        width: 12;
        height: 1;
    }

    .profile-btn.active {
        border: solid #c3e88d;
        background: #1a2332;
        color: #c3e88d;
        text-style: bold;
    }

    #main-row {
        height: 1fr;
        layout: horizontal;
        margin: 0 0;
    }

    #phases-panel {
        width: 1fr;
        border: round #1e2230;
        background: #0d1117;
        padding: 0 1;
    }

    #phases-title {
        color: #ffcb6b;
        text-style: bold;
        height: 1;
        background: #1a1f29;
        padding: 0 1;
    }

    #phases-scroll {
        height: 1fr;
    }

    .phase-line {
        height: 1;
        padding: 0 1;
    }

    .phase-line:focus {
        background: #1a2332;
    }

    .phase-line.selected .phase-check {
        color: #c3e88d;
    }

    .phase-line.running .phase-check {
        color: #ffcb6b;
        text-style: bold;
    }

    .phase-line.done .phase-check {
        color: #82aaff;
    }

    .phase-line.failed .phase-check {
        color: #ff5370;
    }

    #log-panel {
        width: 2fr;
        border: round #1e2230;
        background: #060a10;
        padding: 0 1;
    }

    #log-title {
        color: #ffcb6b;
        text-style: bold;
        height: 1;
        background: #1a1f29;
        padding: 0 1;
    }

    RichLog {
        background: #060a10;
        color: #c8d3f5;
        height: 1fr;
        scrollbar-size: 1 1;
    }

    #findings-panel {
        height: 3;
        border: round #1e2230;
        background: #0d1117;
        padding: 0 1;
        layout: horizontal;
    }

    .finding-cell {
        width: 1fr;
        height: 1;
        text-align: center;
        content-align: center middle;
    }

    .finding-cell .num {
        text-style: bold;
    }

    #finding-crit  { color: #ff5370; }
    #finding-high  { color: #ff9a3c; }
    #finding-med   { color: #ffcb6b; }
    #finding-info  { color: #82aaff; }
    #finding-subs  { color: #c3e88d; }
    #finding-hosts { color: #c792ea; }

    #status-bar {
        height: 1;
        background: #1a1f29;
        color: #676e95;
        padding: 0 1;
        text-align: center;
    }

    #status-bar.running {
        color: #c3e88d;
        text-style: bold;
    }

    #status-bar.error {
        color: #ff5370;
        text-style: bold;
    }

    Footer {
        background: #1a1f29;
        color: #c8d3f5;
    }
    """

    class PhaseLine(Static):
        """A single phase row with checkbox + label + status."""
        def __init__(self, phase_id: str, label: str, default_on: bool) -> None:
            super().__init__(classes="phase-line")
            self.phase_id = phase_id
            self.label = label
            self.enabled = default_on
            self.status = "idle"  # idle | running | done | failed
            self._update()

        def _update(self) -> None:
            if self.status == "running":
                mark = "▸"
                classes = "phase-line running"
            elif self.status == "done":
                mark = "✔"
                classes = "phase-line done"
            elif self.status == "failed":
                mark = "✗"
                classes = "phase-line failed"
            elif self.enabled:
                mark = "☑"
                classes = "phase-line selected"
            else:
                mark = "☐"
                classes = "phase-line"
            self.classes = classes
            self.update(f"[{self._color()}]{mark}[/]  {self.label}")

        def _color(self) -> str:
            return {
                "running": "#ffcb6b",
                "done":    "#82aaff",
                "failed":  "#ff5370",
                "idle":    "#c3e88d" if self.enabled else "#676e95",
            }[self.status]

        def toggle(self) -> None:
            if self.status == "idle":
                self.enabled = not self.enabled
                self._update()

        def set_status(self, status: str) -> None:
            self.status = status
            self._update()

    class ReconNinjaTUI(App):
        """ReconNinja v10.1 — premium interactive recon interface."""

        CSS = CSS

        BINDINGS = [
            Binding("tab",    "focus_next",       "Cycle",     show=False),
            Binding("escape", "quit",             "",          show=False, priority=True),
        ]

        # ── Reactive state ─────────────────────────────────────────────────
        profile_idx:  reactive[int] = reactive(1)  # default: standard
        scanning:     reactive[bool] = reactive(False)
        crit_count:   reactive[int] = reactive(0)
        high_count:   reactive[int] = reactive(0)
        med_count:    reactive[int] = reactive(0)
        info_count:   reactive[int] = reactive(0)
        subs_count:   reactive[int] = reactive(0)
        hosts_count:  reactive[int] = reactive(0)

        BANNER_ASCII = r"""
   ____  _____ ____ ___  _   _  _   _ ___ _   _     _
  |  _ \| ____/ ___/ _ \| \ | || \ | |_ _| \ | |   / \
  | |_) |  _|| |  | | | |  \| ||  \| || ||  \| |  / _ \
  |  _ <| |__| |__| |_| | |\  || |\  || || |\  | / ___ \
  |_| \_\_____\____\___/|_| \_||_| \_|___|_| \_|/_/   \_\
"""

        def __init__(self) -> None:
            super().__init__()
            self._log_queue: queue.Queue = queue.Queue(maxsize=2000)
            self._scan_thread: Optional[threading.Thread] = None
            self._scan_result = None
            self._drain_timer = None
            self._help_visible = False

        # ── Compose ────────────────────────────────────────────────────────
        def compose(self) -> ComposeResult:
            yield Header(show_clock=False, name=f"ReconNinja v{__version__}")
            yield Static(self._banner_text(), id="banner")
            yield Static(f"  Autonomous Security Recon Agent  ·  v{__version__}  ·  ExploitCraft",
                         id="subtitle")

            # Config row: target input + profile buttons
            with Horizontal(id="config-row"):
                with Vertical(id="target-panel"):
                    yield Label("► TARGET", id="target-label")
                    yield Input(placeholder="example.com or 1.2.3.4  (then press Enter)",
                                id="target-input")
                with Horizontal(id="profile-panel"):
                    yield Label("► PROFILE", id="profile-label")
                    for i, p in enumerate(PROFILES):
                        yield Button(p, id=f"profile-btn-{i}", classes="profile-btn")

            # Main row: phases (left) + live log (right)
            with Horizontal(id="main-row"):
                with Vertical(id="phases-panel"):
                    yield Label("► PHASES  (Space to toggle)", id="phases-title")
                    with VerticalScroll(id="phases-scroll"):
                        for phase_id, label, default_on in PHASES:
                            yield PhaseLine(phase_id, label, default_on)
                with Vertical(id="log-panel"):
                    yield Label("► LIVE LOG", id="log-title")
                    yield RichLog(id="live-log", markup=True, wrap=True, auto_scroll=True)

            # Findings bar
            with Horizontal(id="findings-panel"):
                yield Static(self._finding_cell("CRIT",   "crit",   "#ff5370"),
                             id="finding-crit",  classes="finding-cell")
                yield Static(self._finding_cell("HIGH",   "high",   "#ff9a3c"),
                             id="finding-high",  classes="finding-cell")
                yield Static(self._finding_cell("MEDIUM", "med",    "#ffcb6b"),
                             id="finding-med",   classes="finding-cell")
                yield Static(self._finding_cell("INFO",   "info",   "#82aaff"),
                             id="finding-info",  classes="finding-cell")
                yield Static(self._finding_cell("SUBS",   "subs",   "#c3e88d"),
                             id="finding-subs",  classes="finding-cell")
                yield Static(self._finding_cell("HOSTS",  "hosts",  "#c792ea"),
                             id="finding-hosts", classes="finding-cell")

            yield Static("● Ready  ·  Enter to start  ·  ? for help", id="status-bar")
            yield Footer()

        def _banner_text(self) -> str:
            return f"[#ff5370]{self.BANNER_ASCII}[/]"

        def _finding_cell(self, label: str, key: str, color: str) -> str:
            return f"[{color}]{label}[/] [b]0[/]"

        # ── Lifecycle ──────────────────────────────────────────────────────
        def on_mount(self) -> None:
            self.title = f"ReconNinja v{__version__}"
            self.sub_title = "● Ready"
            self._highlight_profile()
            # Focus the target input by default
            self.query_one("#target-input", Input).focus()
            # Start the log drain timer (10Hz)
            self._drain_timer = self.set_interval(0.1, self._drain_log)

        def on_unmount(self) -> None:
            if self._drain_timer:
                self._drain_timer.stop()

        # ── Global key handler ─────────────────────────────────────────────
        # We use on_key instead of BINDINGS because Textual's Input widget
        # consumes printable keys before they reach app-level bindings.  By
        # handling keys here we get consistent behaviour regardless of which
        # widget has focus.
        #
        # Special case: if the target Input has focus and the user types a
        # printable character, we let it pass through to the Input.  Enter
        # and Escape are always intercepted at the app level.
        def on_key(self, event) -> None:
            from textual.widgets import Input
            key = event.key
            target_focused = isinstance(self.focused, Input)

            # Enter always starts a scan (or triggers the focused button)
            if key == "enter":
                event.prevent_default()
                event.stop()
                self.action_start_scan()
                return

            # Escape always quits
            if key == "escape":
                event.prevent_default()
                event.stop()
                self.exit()
                return

            # If the user is typing in the target input, let printable keys
            # pass through — except our reserved action keys.
            if target_focused and key not in ("q", "p", "r", "c", "?", "space"):
                # Let the Input handle it
                return

            if key == "space":
                # Toggle phase if a phase line is focused; otherwise let
                # the focused widget handle it (e.g. button press).
                from gui.tui import PhaseLine
                if isinstance(self.focused, PhaseLine):
                    event.prevent_default()
                    event.stop()
                    self.focused.toggle()
                return

            if key == "p":
                event.prevent_default()
                event.stop()
                self.action_cycle_profile()
                return

            if key == "r":
                event.prevent_default()
                event.stop()
                self.action_resume_scan()
                return

            if key == "c":
                event.prevent_default()
                event.stop()
                self.action_clear_log()
                return

            if key == "q":
                event.prevent_default()
                event.stop()
                self.exit()
                return

            if key in ("?", "question_mark"):
                event.prevent_default()
                event.stop()
                self.action_toggle_help()
                return

        # ── Profile management ─────────────────────────────────────────────
        def _highlight_profile(self) -> None:
            for i, _ in enumerate(PROFILES):
                btn = self.query_one(f"#profile-btn-{i}", Button)
                if i == self.profile_idx:
                    btn.add_class("active")
                else:
                    btn.remove_class("active")

        def watch_profile_idx(self, _old: int, _new: int) -> None:
            self._highlight_profile()
            # Also toggle phase defaults to match the new profile
            self._apply_profile_defaults()

        def _apply_profile_defaults(self) -> None:
            """When user picks a profile via the TUI, set the phase checkboxes
            to match the profile's standard enable-set."""
            profile = PROFILES[self.profile_idx]
            enable_set = self._profile_enable_set(profile)
            for line in self.query(PhaseLine):
                line.enabled = line.phase_id in enable_set
                line.status = "idle"
                line._update()

        @staticmethod
        def _profile_enable_set(profile: str) -> set[str]:
            if profile == "fast":
                return {"run_whois", "run_wayback"}
            if profile == "standard":
                return {"run_whois", "run_wayback", "run_ssl"}
            if profile == "thorough":
                return {"run_subdomains", "run_whois", "run_wayback", "run_ssl",
                        "run_httpx", "run_nuclei", "run_cve_lookup"}
            if profile == "full_suite":
                return {p[0] for p in PHASES}
            return set()

        @on(Button.Pressed)
        def on_profile_button(self, event: Button.Pressed) -> None:
            for i, _ in enumerate(PROFILES):
                if event.button.id == f"profile-btn-{i}":
                    self.profile_idx = i
                    return

        def action_cycle_profile(self) -> None:
            self.profile_idx = (self.profile_idx + 1) % len(PROFILES)

        # ── Phase toggle ───────────────────────────────────────────────────
        def action_toggle_phase(self) -> None:
            focused = self.focused
            if isinstance(focused, PhaseLine):
                focused.toggle()

        def on_click(self, event) -> None:
            # Click a phase line to toggle it
            if isinstance(event.widget, PhaseLine):
                event.widget.toggle()

        # ── Build ScanConfig from TUI state ────────────────────────────────
        def _build_cfg(self):
            from utils.models import ScanConfig, ScanProfile, NmapOptions
            target = self.query_one("#target-input", Input).value.strip()
            if not target:
                self._set_status("✗ No target — type a domain or IP first", "error")
                return None

            profile_map = {
                "fast":       ScanProfile.FAST,
                "standard":   ScanProfile.STANDARD,
                "thorough":   ScanProfile.THOROUGH,
                "full_suite": ScanProfile.FULL_SUITE,
            }
            profile_str = PROFILES[self.profile_idx]
            cfg = ScanConfig(
                target=target,
                profile=profile_map.get(profile_str, ScanProfile.STANDARD),
                nmap_opts=NmapOptions(),
                output_format="all",
            )
            # Override profile-derived defaults with TUI checkbox state
            for line in self.query(PhaseLine):
                setattr(cfg, line.phase_id, line.enabled)
            return cfg

        # ── Scan thread ────────────────────────────────────────────────────
        @work(thread=True)
        def action_start_scan(self) -> None:
            if self.scanning:
                self._set_status("⚠ Already scanning — press q to abort", "running")
                return
            cfg = self._build_cfg()
            if cfg is None:
                return

            # Attach the queue handler to the recon_ninja logger so all
            # log.xxx() calls flow into the TUI's live log panel.
            logger = logging.getLogger("recon_ninja")
            handler = _QueueLogHandler(self._log_queue)
            logger.addHandler(handler)

            # v10.1: also intercept safe_print() output (the orchestrator
            # uses safe_print for phase banners, Rich tables, etc.) so the
            # TUI sees the same stream the headless CLI would.
            from utils.logger import add_safe_print_hook, remove_safe_print_hook
            def _safe_print_hook(text: str) -> None:
                self._log_queue.put(_make_record(text))
            add_safe_print_hook(_safe_print_hook)

            self.scanning = True
            self._set_status(f"▶ Scanning {cfg.target}  ·  profile={PROFILES[self.profile_idx]}",
                             "running")
            self._reset_phase_status()
            self._reset_counters()

            try:
                # Import orchestrator here so the TUI doesn't pay the import
                # cost on every render
                from core.orchestrator_v9 import run_scan
                from core.resume import set_active_config
                set_active_config(cfg)
                self._scan_result = run_scan(cfg)
                self._finalise_scan()
            except Exception as e:
                self._log_queue.put(_make_record(f"[ERROR] Scan aborted: {type(e).__name__}: {e}"))
                self._set_status(f"✗ Scan failed: {e}", "error")
            finally:
                logger.removeHandler(handler)
                remove_safe_print_hook(_safe_print_hook)
                self.scanning = False

        def _finalise_scan(self) -> None:
            """Pull findings counts from the scan result and update the TUI."""
            r = self._scan_result
            if r is None:
                return
            self.crit_count  = sum(1 for f in (r.nuclei_findings or [])
                                   if (f.severity or "").lower() == "critical")
            self.high_count  = sum(1 for f in (r.nuclei_findings or [])
                                   if (f.severity or "").lower() == "high")
            self.med_count   = sum(1 for f in (r.nuclei_findings or [])
                                   if (f.severity or "").lower() in ("medium", "moderate"))
            self.info_count  = sum(1 for f in (r.nuclei_findings or [])
                                   if (f.severity or "").lower() == "info")
            self.subs_count  = len(r.subdomains or [])
            self.hosts_count = len(r.hosts or [])
            self._set_status(f"✔ Scan complete  ·  {self.crit_count} crit / "
                             f"{self.high_count} high / {len(r.nuclei_findings or [])} total",
                             "running")
            # Mark all phases that completed successfully
            completed = set(r.phases_completed or [])
            for line in self.query(PhaseLine):
                # Map cfg flag name back to phase id (they share the prefix
                # 'run_' but phase_id in PHASES is the cfg flag name already)
                if line.phase_id.replace("run_", "") in completed \
                   or line.phase_id in completed:
                    line.set_status("done")

        def _reset_phase_status(self) -> None:
            for line in self.query(PhaseLine):
                line.set_status("idle")

        def _reset_counters(self) -> None:
            self.crit_count = 0
            self.high_count = 0
            self.med_count  = 0
            self.info_count = 0
            self.subs_count = 0
            self.hosts_count = 0

        # Reactive watchers — update the findings bar cells when counts change
        def watch_crit_count(self, _o, n):  self._update_finding_cell("crit", n)
        def watch_high_count(self, _o, n):  self._update_finding_cell("high", n)
        def watch_med_count(self, _o, n):   self._update_finding_cell("med", n)
        def watch_info_count(self, _o, n):  self._update_finding_cell("info", n)
        def watch_subs_count(self, _o, n):  self._update_finding_cell("subs", n)
        def watch_hosts_count(self, _o, n): self._update_finding_cell("hosts", n)

        def _update_finding_cell(self, key: str, n: int) -> None:
            try:
                widget = self.query_one(f"#finding-{key}", Static)
                colors = {"crit":"#ff5370","high":"#ff9a3c","med":"#ffcb6b",
                          "info":"#82aaff","subs":"#c3e88d","hosts":"#c792ea"}
                labels = {"crit":"CRIT","high":"HIGH","med":"MEDIUM",
                          "info":"INFO","subs":"SUBS","hosts":"HOSTS"}
                widget.update(f"[{colors[key]}]{labels[key]}[/]  [b]{n}[/]")
            except Exception:
                pass

        # ── Log drain ──────────────────────────────────────────────────────
        def _drain_log(self) -> None:
            """Pull all queued log records and render them into the RichLog."""
            try:
                log_widget = self.query_one("#live-log", RichLog)
            except Exception:
                return

            drained = 0
            while drained < 200:  # cap per-tick work
                try:
                    record = self._log_queue.get_nowait()
                except queue.Empty:
                    break
                # Also intercept safe_print output via a thread-safe capture
                from utils.logger import safe_print, console as _console
                msg = record.getMessage()
                # Color by level
                level = record.levelname
                if level == "ERROR" or level == "CRITICAL":
                    line = f"[#ff5370]✗ {msg}[/]"
                elif level == "WARNING":
                    line = f"[#ffcb6b]⚠ {msg}[/]"
                elif level == "INFO":
                    line = f"  {msg}"
                else:
                    line = f"[dim]{msg}[/]"
                # Try to detect phase start/done lines and update PhaseLines
                self._maybe_update_phase_status(msg)
                log_widget.write(line)
                drained += 1

        def _maybe_update_phase_status(self, msg: str) -> None:
            """Watch log lines like '▸ whois' or '✔ whois (1.2s)' and update
            the matching PhaseLine status."""
            msg = msg.strip()
            if not msg:
                return
            for line in self.query(PhaseLine):
                phase_short = line.phase_id.replace("run_", "")
                if msg.startswith(f"▸ {phase_short}"):
                    line.set_status("running")
                elif msg.startswith(f"✔ {phase_short}"):
                    line.set_status("done")
                elif msg.startswith(f"✗ {phase_short}"):
                    line.set_status("failed")

        # ── Resume ─────────────────────────────────────────────────────────
        @work(thread=True)
        def action_resume_scan(self) -> None:
            if self.scanning:
                self._set_status("⚠ Already scanning", "running")
                return
            from core.resume import find_latest_state, load_state, set_active_config
            from utils.logger import add_safe_print_hook, remove_safe_print_hook
            target = self.query_one("#target-input", Input).value.strip()
            state_path = find_latest_state(target) if target else None
            if state_path is None:
                self._set_status("✗ No prior state.json found for that target", "error")
                return
            loaded = load_state(state_path)
            if loaded is None:
                self._set_status("✗ Failed to load state", "error")
                return
            result, cfg, out_folder = loaded
            set_active_config(cfg)
            self._set_status(f"▶ Resuming scan for {cfg.target}", "running")
            self.scanning = True
            logger = logging.getLogger("recon_ninja")
            handler = _QueueLogHandler(self._log_queue)
            logger.addHandler(handler)
            def _safe_print_hook(text: str) -> None:
                self._log_queue.put(_make_record(text))
            add_safe_print_hook(_safe_print_hook)
            try:
                from core.orchestrator_v9 import run_scan
                self._scan_result = run_scan(cfg)
                self._finalise_scan()
            except Exception as e:
                self._log_queue.put(_make_record(f"[ERROR] Resume failed: {e}"))
                self._set_status(f"✗ Resume failed: {e}", "error")
            finally:
                logger.removeHandler(handler)
                remove_safe_print_hook(_safe_print_hook)
                self.scanning = False

        # ── Misc actions ───────────────────────────────────────────────────
        def action_clear_log(self) -> None:
            try:
                self.query_one("#live-log", RichLog).clear()
            except Exception:
                pass

        def action_toggle_help(self) -> None:
            self._help_visible = not self._help_visible
            if self._help_visible:
                self._show_help_overlay()
            else:
                self._hide_help_overlay()

        def _show_help_overlay(self) -> None:
            help_text = (
                "[bold #ffcb6b]RECONNINJA TUI — KEYBINDINGS[/]\n\n"
                "  [#c3e88d]Enter[/]   Start a scan (or resume if one is running)\n"
                "  [#c3e88d]Space[/]   Toggle the currently-focused phase\n"
                "  [#c3e88d]Tab[/]     Cycle focus between target / phases / log\n"
                "  [#c3e88d]p[/]       Cycle scan profile (fast → standard → thorough → full)\n"
                "  [#c3e88d]r[/]       Resume scan from latest state.json for the typed target\n"
                "  [#c3e88d]c[/]       Clear the live log panel\n"
                "  [#c3e88d]?[/]       Toggle this help overlay\n"
                "  [#c3e88d]q / Esc[/] Quit ReconNinja\n\n"
                "[dim]Press ? to dismiss.[/]"
            )
            self._push_help_screen(help_text)

        def _push_help_screen(self, text: str) -> None:
            from textual.screen import ModalScreen
            from textual.widgets import Static
            class HelpScreen(ModalScreen):
                CSS = """
                HelpScreen {
                    align: center middle;
                }
                #help-box {
                    width: 70;
                    height: 18;
                    border: round #ffcb6b;
                    background: #0d1117;
                    padding: 1 2;
                    color: #c8d3f5;
                }
                """
                def __init__(self, text):
                    super().__init__()
                    self._text = text
                def compose(self):
                    yield Static(self._text, id="help-box")
                def on_key(self, event):
                    if event.key in ("?", "escape", "q"):
                        self.app.pop_screen()
            self.push_screen(HelpScreen(text))

        def _hide_help_overlay(self) -> None:
            try:
                self.pop_screen()
            except Exception:
                self._help_visible = False

        # ── Status bar ─────────────────────────────────────────────────────
        def _set_status(self, text: str, state: str = "") -> None:
            try:
                bar = self.query_one("#status-bar", Static)
                bar.update(text)
                bar.classes = f"{state}" if state else ""
            except Exception:
                pass

        # ── Enter on target input starts scan ──────────────────────────────
        @on(Input.Submitted)
        def on_target_submitted(self, event: Input.Submitted) -> None:
            if event.input.id == "target-input":
                self.action_start_scan()


    def _make_record(msg: str) -> logging.LogRecord:
        return logging.LogRecord(
            name="recon_ninja", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=None, exc_info=None,
        )


# ─── Public entry point ──────────────────────────────────────────────────────

def launch_tui() -> int:
    """Launch the ReconNinja TUI. Returns process exit code.

    Falls back to the plain CLI (banner + help) if Textual isn't installed.
    """
    if not TEXTUAL_AVAILABLE:
        print("\n  ⚠ Textual is not installed — falling back to plain CLI.\n")
        print("    To enable the TUI, install the optional extra:")
        print("        pip install 'reconninja[tui]'")
        print("    …or just:")
        print("        pip install textual>=0.50.0\n")
        return 1
    app = ReconNinjaTUI()
    return app.run()
