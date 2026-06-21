ReconNinja v10.5.0 — Patch Release
==================================

This zip contains ONLY the files modified between v10.2.0 and v10.5.0.
Drop them into your existing v10.x checkout, overwriting the old files.

Files in this zip
-----------------

  version                → info/version            (bumped to 10.5.0)
  menu.py                → gui/menu.py             (NEW — fsociety-style menu)
  reconninja.py          → reconninja.py           (added --tui/--menu flags, menu is new default)
  test_v10_5_menu.py     → tests/test_v10_5_menu.py (NEW — 14 menu tests)
  CHANGELOG.md           → CHANGELOG.md
  README.md              → README.md               (badge bumped)
  PKGBUILD               → aur/PKGBUILD            (pkgver=10.5.0)
  .SRCINFO               → aur/.SRCINFO
  install.sh             → install.sh              (banner bumped)

What's new in v10.5.0
---------------------

NEW fsociety-style interactive CLI menu — running `reconninja` with no args
now drops you into a 19-option numbered menu instead of the v10.1 Textual
TUI or the v10.0 argparse wall.

    ╔════════════════════════════════════════════════════════════════════╗
    ║                       [ ASCII BANNER ]                             ║
    ║              v10.5.0  ·  ExploitCraft                            ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║   [01] ⚡  Full Scan              (all phases)                    ║
    ║   [02] 🚀  Quick Recon           (passive OSINT, ~2 min)         ║
    ║   [03] 🌐  Web Application Scan  (httpx + nuclei + feroxbuster)  ║
    ║   [04] 🔌  Port Scan Only        (rustscan + nmap)               ║
    ║   [05] 🔍  Subdomain Enum        (subfinder + amass + crt.sh)    ║
    ║   [06] 💥  Vulnerability Scan    (nuclei templates)              ║
    ║   [07] ☁️   Cloud Recon           (S3/Azure/GCP bucket enum)     ║
    ║   [08] 🏢  Active Directory      (Kerberoast + AS-REP)          ║
    ║   [09] 🤖  AI/LLM Endpoint Scan  (Ollama + Qdrant + LiteLLM)    ║
    ║   [10] 🔁  Continuous Monitor    (re-scan on interval)           ║
    ║   [11] 🎯  Custom Scan           (pick phases)                   ║
    ║   [12] ⏯   Resume Previous Scan                                   ║
    ║   [13] 📊  Diff Two Scans                                         ║
    ║   [14] 🛠   Check Tools                                           ║
    ║   [15] ⬆️   Self-Update                                           ║
    ║   [16] 🖥️   Launch GUI                                            ║
    ║   [17] 🎛️   Launch TUI                                            ║
    ║   [18] 🔌  MCP Server                                            ║
    ║   [99] 🚪  Exit                                                   ║
    ╚════════════════════════════════════════════════════════════════════╝

      ► Select option [1-18, 99]:

Each option prompts for any required inputs (target, API keys, etc.),
runs the scan, then returns to the menu so you can run another op.

New CLI flags
-------------

  reconninja            → launches the fsociety-style menu (NEW DEFAULT)
  reconninja --tui      → launches the Textual TUI (the v10.1 interface)
  reconninja --menu     → launches the menu explicitly
  reconninja --no-tui   → prints banner + help (v10.0 behaviour, for CI)

Zero new dependencies — the menu only uses Rich (already required) and
stdlib input(). The Textual TUI is still available via --tui for power
users who want the live log streaming experience.

Tests
-----

  14 new tests in tests/test_v10_5_menu.py covering:
    - MENU_OPTIONS has 19 entries with unique sequential numbers (01-18 + 99)
    - Every handler name resolves to a real method on InteractiveMenu
    - Dispatch accepts both "1" and "01" (zero-padded)
    - Dispatch rejects out-of-range numbers, letters, empty string
    - Exit handler stops the loop and returns 0
    - Banner contains version info

  Full suite: 616 passed, 1 skipped.

Apply
-----

    unzip ReconNinja-v10.5.0-patch.zip
    cp version              /path/to/ReconNinja/info/version
    cp menu.py              /path/to/ReconNinja/gui/menu.py
    cp reconninja.py        /path/to/ReconNinja/reconninja.py
    cp test_v10_5_menu.py   /path/to/ReconNinja/tests/test_v10_5_menu.py
    cp CHANGELOG.md         /path/to/ReconNinja/CHANGELOG.md
    cp README.md            /path/to/ReconNinja/README.md
    cp PKGBUILD             /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO             /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh           /path/to/ReconNinja/install.sh

    cd /path/to/ReconNinja
    python reconninja.py --version     # → ReconNinja v10.5.0
    python reconninja.py               # → launches the fsociety-style menu
    python -m pytest tests/            # → 616 passed, 1 skipped
