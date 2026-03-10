# Contributing to ReconNinja

**All contributions are welcome — bug fixes, new features, new plugins, and test improvements.**

> ⚠️ ReconNinja is for authorized security testing only. Contributions must not add functionality that facilitates unauthorized access.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Writing a Plugin](#writing-a-plugin)
- [Contribution Rules](#contribution-rules)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Test Policy](#test-policy)
- [Code Style](#code-style)

---

## Quick Start

```bash
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja
pip install rich
python3 reconninja.py --check-tools
python3 -m unittest discover -s tests -v
```

All tests must pass before you submit anything.

---

## Project Structure

```
ReconNinja/
├── reconninja.py        # Entry point — CLI + interactive mode
├── core/
│   ├── orchestrator.py  # Phase pipeline engine — the brain
│   ├── ports.py         # RustScan, AsyncTCP, Nmap
│   ├── subdomains.py    # Passive recon
│   ├── web.py           # httpx, WhatWeb, Nikto, dir scan
│   ├── vuln.py          # Nuclei, screenshots
│   ├── ai_analysis.py   # Groq/Ollama/Gemini/OpenAI
│   ├── cve_lookup.py    # NVD API
│   ├── resume.py        # Checkpoint save/load
│   └── updater.py       # Self-update from GitHub
├── output/
│   ├── report_html.py   # Dark-mode HTML report
│   └── reports.py       # JSON + Markdown reports
├── utils/
│   ├── models.py        # All dataclasses — ScanConfig, HostResult, etc.
│   ├── helpers.py       # Utility functions
│   └── logger.py        # Rich terminal logger
├── plugins/             # Drop .py files here to extend ReconNinja
└── tests/               # Full test suite — all passing
```

---

## Writing a Plugin

The fastest way to extend ReconNinja. Drop a `.py` file into `plugins/` — it loads automatically on the next scan.

### Minimal plugin skeleton

```python
# plugins/my_plugin.py

PLUGIN_NAME    = "my_plugin"
PLUGIN_VERSION = "1.0"


def run(target: str, out_folder, result, config) -> None:
    """
    Called after Phase 12 (post-Nuclei), before report generation.

    Args:
        target      — the scan target (domain, IP, CIDR)
        out_folder  — pathlib.Path to this scan's output directory
        result      — ReconResult object (mutate in-place to add findings)
        config      — ScanConfig object (read-only, use to check flags)
    """
    pass
```

### What you can do inside `run()`

```python
from utils.models import VulnFinding
from pathlib import Path

def run(target, out_folder, result, config):

    # 1. Read scan data
    for host in result.hosts:
        for port in host.open_ports:
            print(f"{host.ip}:{port.port} — {port.service} {port.version}")

    # 2. Add vulnerability findings
    result.nuclei_findings.append(VulnFinding(
        tool        = PLUGIN_NAME,
        severity    = "high",          # critical / high / medium / low / info
        title       = "My Finding",
        target      = f"{target}:80",
        details     = "Detailed description here",
        cve         = "CVE-2024-XXXX", # optional
    ))

    # 3. Write output files
    out_file = out_folder / f"{PLUGIN_NAME}_output.txt"
    out_file.write_text("my plugin output")

    # 4. Log errors (never raise — caught by orchestrator)
    result.errors.append(f"{PLUGIN_NAME}: something failed")

    # 5. Read config flags
    if config.run_nuclei:
        pass  # nuclei already ran, findings are in result.nuclei_findings
```

### Plugin contract

| Requirement | Detail |
|---|---|
| `PLUGIN_NAME` | String. Used in logs and reports. |
| `PLUGIN_VERSION` | String. Used in logs. |
| `run(target, out_folder, result, config)` | Must be callable. Return value is ignored. |
| Error handling | Catch your own exceptions. Unhandled exceptions are caught by the orchestrator and appended to `result.errors`. |
| No exit calls | Never call `sys.exit()` or `os._exit()` inside a plugin. |

### Real plugin example

See `plugins/cve_banner_check.py` — checks open port banners against known-vulnerable versions and appends CVE findings to `result.nuclei_findings`.

---

## Contribution Rules

### What we accept

- Bug fixes with regression tests
- New scan phases (add to `core/`, wire in `orchestrator.py`)
- New report formats (add to `output/`)
- New AI providers (add to `PROVIDERS` dict in `core/ai_analysis.py`)
- Plugin contributions (add to `plugins/`)
- Test improvements — more coverage is always welcome
- Documentation fixes

### What we reject

- Features with no tests
- Changes that break existing tests
- Code that enables unauthorized scanning
- Hardcoded credentials or API keys
- Changes to the plugin contract without updating `CONTRIBUTING.md`

---

## Submitting a Pull Request

1. **Fork** the repo and create a branch: `git checkout -b fix/my-fix`
2. **Make your changes** — follow the code style below
3. **Write tests** — see Test Policy
4. **Run the full suite**: `python3 -m unittest discover -s tests -v` — must be green
5. **Update `README.md`** if you added features or changed flags
6. **Open a PR** against `main` with a clear title and description

PR title format:
```
fix: <what was broken and how you fixed it>
feat: <what new capability was added>
test: <what coverage was added>
docs: <what documentation was updated>
```

---

## Test Policy

> **Every code change ships with tests. No exceptions.**

| Step | Action |
|---|---|
| 1 | Fix the source file |
| 2 | Run existing tests — confirm nothing broke |
| 3 | Add tests for your change — bug fixes get regression tests, new features get unit tests |
| 4 | Run all tests again — must be 0 failures |

### Test file ownership

| File | What to test here |
|---|---|
| `tests/test_models.py` | New fields on `ScanConfig`, `HostResult`, etc. |
| `tests/test_resume.py` | Any change to `core/resume.py` |
| `tests/test_orchestrator.py` | Any change to `core/orchestrator.py` |
| `tests/test_ports.py` | Any change to `core/ports.py` |
| `tests/test_cve_lookup.py` | Any change to `core/cve_lookup.py` |
| `tests/test_ai_analysis.py` | Any change to `core/ai_analysis.py` |
| `tests/test_report_html.py` | Any change to `output/report_html.py` |

### Running tests

```bash
# Full suite
python3 -m unittest discover -s tests -v

# Single file
python3 -m unittest tests.test_orchestrator -v

# Single test
python3 -m unittest tests.test_orchestrator.TestPhaseSkipLogic.test_rustscan_not_called_when_in_phases_completed -v

python3 -m unittest discover tests/
```

---

## Code Style

- **Python 3.10+** — use `match/case`, `X | Y` unions, `from __future__ import annotations`
- **Type hints** on all function signatures
- **Dataclasses** for all data — no raw dicts passed between modules
- **`safe_print()` not `print()`** — respects the thread lock in concurrent phases
- **`log.warning()` / `log.debug()`** for non-critical messages, never `print()` for errors
- **No bare `except:`** — always catch specific exceptions
- **No hardcoded paths** — use `pathlib.Path` throughout
- **Imports at top of file** — no inline imports except inside `if TYPE_CHECKING:` blocks

### Adding a new phase

1. Implement the logic in the appropriate `core/` module
2. Add a phase name string constant to `utils/models.py` `Phase` enum
3. Wire it into `orchestrator.py` with the standard skip guard:
   ```python
   if cfg.run_my_phase and "my_phase" not in result.phases_completed:
       console.print(Panel.fit("[phase] PHASE N — My Phase [/]"))
       # ... do work ...
       result.phases_completed.append("my_phase")
       save_state(result, cfg, out_folder)
   elif "my_phase" in result.phases_completed:
       safe_print("[dim]Phase N — My Phase: already completed, skipping[/]")
   ```
4. Add the flag to `ScanConfig` in `utils/models.py`
5. Add the CLI flag to `parse_args()` in `reconninja.py`
6. Add tests to `tests/test_orchestrator.py`

---

**Questions?** Open an issue. Tag it `question`.

**Found a security vulnerability in ReconNinja itself?** Open a private security advisory on GitHub — do not open a public issue.
