<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:00d4ff,100:7c3aed&height=200&section=header&text=ReconNinja&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=v3.2.2%20%E2%80%94%20Elite%20Recon%20Framework&descSize=20&descAlignY=60&descColor=00d4ff&animation=fadeIn" />

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.2.2-00d4ff?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/YouTubers777/ReconNinja/releases)
[![Tests](https://img.shields.io/badge/Tests-262%20passing-22c55e?style=for-the-badge&logo=checkmarx&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-7c3aed?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/YouTubers777/ReconNinja?style=for-the-badge&logo=github&color=ff6b6b&logoColor=white)](https://github.com/YouTubers777/ReconNinja/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/YouTubers777/ReconNinja/python-package-conda.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/YouTubers777/ReconNinja/actions)

<br/>

> **⚡ Automated all-in-one recon framework for pentesters & bug bounty hunters.**
> 14-phase pipeline: subdomain enum → async TCP → RustScan → Nmap service scan →
> CVE lookup → httpx → dir brute → Nuclei → AI threat analysis → HTML report.

<br/>

```
⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠️
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal. The author is not responsible for misuse.
```

</div>

---

## 📋 Table of Contents

- [What's New in v3.2.2](#-whats-new-in-v322)
- [What's New in v3.2.1](#-whats-new-in-v321)
- [Features](#-features)
- [Pipeline](#-pipeline)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [AI Analysis](#-ai-analysis)
- [CVE Lookup](#-cve-lookup)
- [HTML Reports](#-html-reports)
- [Resume Scans](#-resume-scans)
- [Self-Update](#-self-update)
- [Scan Profiles](#-scan-profiles)
- [All CLI Flags](#-all-cli-flags)
- [Testing](#-testing)
- [File Structure](#-file-structure)
- [Changelog](#-changelog)
- [Legal](#-legal)

---

## 🆕 What's New in v3.2.2

> Bug fix release. All v3.2.1 features are intact — these are correctness and completeness fixes only.

| # | File | Fix | Impact |
|---|---|---|---|
| 1 | `reconninja.py` | `VERSION` bumped from `3.2.0` → `3.2.2` | Banner was lying to users |
| 2 | `reconninja.py` | `--cve` flag added to argparse | `--cve` caused "unrecognized argument" crash on every invocation |
| 3 | `reconninja.py` | `--update-branch` flag added to argparse | Documented in README but argparse rejected it |
| 4 | `reconninja.py` | `--force-update` flag added to argparse | Same — docs lying |
| 5 | `reconninja.py` | `run_update(VERSION)` → `run_update(force=...)` | String passed as bool — forced a re-download on every single `--update` call |
| 6 | `reconninja.py` | `--nvd-key` wired into `ScanConfig` | Flag was accepted but silently discarded — NVD always ran at free-tier rate |
| 7 | `reconninja.py` + `orchestrator.py` | `orchestrate()` gains `resume_result` + `resume_folder` params | `--resume` crashed with `TypeError` every time — identical bug to v3.2.0 |
| 8 | `orchestrator.py` | CVE Phase 4b actually calls `lookup_cves_for_host_result()` | `--cve` flag was set in `ScanConfig` but orchestrator never executed the phase |
| 9 | `orchestrator.py` | `save_state()` called after every phase | No checkpoints were ever written — `--resume` had nothing to load |
| 10 | `orchestrator.py` | Phase 11 calls `run_ai_analysis()` from `core/ai_analysis.py` | `--ai` always used the local rule-based fallback, never the real LLM |
| 11 | `updater.py` | `print_update_status()` wrapped in `try/except` | Any network error at startup crashed the whole tool |
| 12 | `resume.py` | `_dict_to_config` uses `.get()` not `.pop()` | `pop()` mutated the caller's dict — double-loading state caused `KeyError` crash |

---

## 🆕 What's New in v3.2.1

| Fix | Description |
|---|---|
| 🤖 **AI Analysis wired** | `core/ai_analysis.py` module added with Groq/Ollama/Gemini/OpenAI support |
| 🔑 **`--nvd-key` added to models** | `ScanConfig` gains `run_cve_lookup`, `ai_provider`, `ai_key`, `ai_model`, `nvd_key` fields |
| 💾 **Resume field restoration** | `_dict_to_config()` restores all 5 new fields — old state files load cleanly with safe defaults |
| ⏱️ **NVD rate limit fixed** | `delay` corrected from `0.7s` → `6.5s` (was firing 43 req/30s against a 5 req/30s limit) |
| 🔍 **CVE function name fixed** | Orchestrator referenced `lookup_cves_for_hosts` (didn't exist) — corrected to `lookup_cves_for_host_result` |
| 🏷️ **Version banner** | Internal docstring updated |

---

## ✨ Features

<table>
<tr>
<td>

**🔎 Reconnaissance**
- Subdomain enumeration (subfinder, amass, assetfinder, crt.sh)
- DNS brute force with 100 concurrent threads
- Certificate Transparency passive lookup

</td>
<td>

**🔌 Port Scanning**
- **RustScan** — primary full-range scanner (65535 ports)
- **Async TCP** — pure Python fallback, no root required
- **Nmap** — service + version fingerprinting only
- **Masscan** — optional high-speed sweep

</td>
</tr>
<tr>
<td>

**🌐 Web Analysis**
- httpx — live host detection + tech fingerprinting
- WhatWeb — CMS, framework, server detection
- Nikto — web server vulnerability scanner
- feroxbuster / ffuf / dirsearch — directory brute force

</td>
<td>

**🚨 Vulnerability Detection**
- Nuclei — 9000+ vulnerability templates
- **CVE Lookup** — NVD API, free, no key required (`--cve`)
- **AI Analysis** — Groq / Ollama / Gemini / OpenAI (`--ai`)
- Screenshots via gowitness / aquatone

</td>
</tr>
<tr>
<td>

**📊 Reporting**
- **HTML report** — dark-mode dashboard, auto-generated
- JSON export — machine-readable structured data
- Markdown report — for documentation
- Per-scan log file

</td>
<td>

**⚙️ Quality of Life**
- **--resume** — checkpoint after every phase, zero data loss
- **--update** — self-update from GitHub with backup
- Plugin system — drop `.py` into `plugins/`
- Interactive mode + full CLI mode
- CIDR and target list file support

</td>
</tr>
</table>

---

## 🔄 Pipeline

```
Target Input
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1  │  Subdomain Enumeration (subfinder, amass, crt.sh)   │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2  │  RustScan — ALL 65535 ports (PRIMARY)               │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2b │  Async TCP — gap fill / fallback (no root)          │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3  │  Masscan — optional high-speed sweep                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4  │  Nmap — service analysis on confirmed open ports    │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4b │  CVE Lookup — NVD API for each service+version      │  ← fixed v3.2.2
├─────────────────────────────────────────────────────────────────┤
│  Phase 5  │  httpx — live web detection + tech stack            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 6  │  Directory Brute Force (feroxbuster/ffuf/dirsearch) │
├─────────────────────────────────────────────────────────────────┤
│  Phase 7  │  WhatWeb — technology fingerprinting                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 8  │  Nikto — web vulnerability scan                     │
├─────────────────────────────────────────────────────────────────┤
│  Phase 9  │  Nuclei — 9000+ vuln templates                      │
├─────────────────────────────────────────────────────────────────┤
│  Phase 10 │  Screenshots (gowitness / aquatone)                  │
├─────────────────────────────────────────────────────────────────┤
│  Phase 11 │  AI Threat Analysis (Groq / Ollama / Gemini)        │  ← fixed v3.2.2
├─────────────────────────────────────────────────────────────────┤
│  Phase 12 │  Plugins                                            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 13 │  HTML + JSON + Markdown Report Generation           │
└─────────────────────────────────────────────────────────────────┘
         ↑
         state.json saved after EVERY phase  ← fixed v3.2.2
```

---

## 📦 Requirements

### System Requirements

| Tool | Purpose | Required |
|---|---|---|
| Python 3.10+ | Runtime | ✅ Required |
| nmap | Service fingerprinting | ✅ Required |
| rustscan | Primary port scanner | ⭐ Recommended |
| subfinder | Subdomain enumeration | ⭐ Recommended |
| httpx | Web detection | ⭐ Recommended |
| nuclei | Vulnerability scan | ⭐ Recommended |
| masscan | Fast port sweep | Optional |
| feroxbuster | Directory brute force | Optional |
| ffuf | Directory brute force fallback | Optional |
| nikto | Web vulnerability scan | Optional |
| whatweb | Tech fingerprinting | Optional |
| gowitness | Screenshots | Optional |

### Python Dependencies

```
rich>=13.0.0
```

---

## 🚀 Installation

### One-Line Install (Recommended)

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
chmod +x install.sh
./install.sh
```

**Activate the alias:**
```bash
source ~/.bashrc    # bash
source ~/.zshrc     # zsh
```

**Then just run:**
```bash
ReconNinja
```

### Manual Install

```bash
git clone https://github.com/YouTubers777/ReconNinja.git
cd ReconNinja
pip install rich
python3 reconninja.py --check-tools
```

### Verify Install

```bash
ReconNinja --check-tools
ReconNinja --version
```

---

## 💻 Usage

### Interactive Mode

```bash
ReconNinja
```

### CLI Mode

```bash
# Standard scan
ReconNinja -t example.com

# Full suite — everything enabled
ReconNinja -t example.com --profile full_suite

# With AI analysis (Groq — free)
ReconNinja -t example.com --ai --ai-provider groq --ai-key gsk_xxx

# With CVE lookup (free, no key needed)
ReconNinja -t example.com --cve

# With NVD API key (50 req/30s instead of 5)
ReconNinja -t example.com --cve --nvd-key YOUR_NVD_KEY

# Everything
ReconNinja -t example.com --profile full_suite --ai --cve \
           --ai-provider groq --ai-key gsk_xxx --nvd-key nvd_xxx

# Resume a crashed scan (auto-detect latest checkpoint)
ReconNinja -t example.com --resume

# Resume from a specific state file
ReconNinja --resume reports/example.com/20240115_143022/state.json

# Force update even if already latest
ReconNinja --update --force-update

# Update from a specific branch
ReconNinja --update --update-branch dev

# Skip confirmation (automation / CI)
ReconNinja -t example.com --profile standard -y
```

---

## 🤖 AI Analysis

AI analysis is **completely optional** — only activates when you pass `--ai`.

### Supported Providers

| Provider | Free | Speed | Setup |
|---|---|---|---|
| `groq` | ✅ Free tier | ⚡⚡⚡ Fastest | [console.groq.com](https://console.groq.com) |
| `ollama` | ✅ Free (local) | ⚡ Local speed | [ollama.ai](https://ollama.ai) |
| `gemini` | ✅ Free tier | ⚡⚡ Fast | [ai.google.dev](https://ai.google.dev) |
| `openai` | 💳 Paid | ⚡⚡ Fast | [platform.openai.com](https://platform.openai.com) |

```bash
# Groq (recommended — free)
ReconNinja -t target.com --ai --ai-provider groq --ai-key gsk_xxxxxxxxxxxx

# Or set env var (key never appears in shell history)
export GROQ_API_KEY="gsk_xxxxxxxxxxxx"
ReconNinja -t target.com --ai

# Ollama (local — no internet required)
ollama pull llama3
ReconNinja -t target.com --ai --ai-provider ollama

# Gemini (free tier)
export GEMINI_API_KEY="AIzaxxxxxxxxxx"
ReconNinja -t target.com --ai --ai-provider gemini

# Custom model override
ReconNinja -t target.com --ai --ai-provider groq --ai-model llama3-8b-8192
```

---

## 🔍 CVE Lookup

Automatically queries the [NVD](https://nvd.nist.gov) for CVEs matching every service version Nmap detects. Results are merged into the vulnerability findings and included in all reports.

```bash
# Enable CVE lookup (free, no key needed)
ReconNinja -t target.com --cve

# Alias — both flags work
ReconNinja -t target.com --cve-lookup

# With optional NVD API key (50 req/30s instead of 5 req/30s)
# Free key: nvd.nist.gov/developers/request-an-api-key
ReconNinja -t target.com --cve --nvd-key YOUR_NVD_KEY
```

> **Rate limiting:** Without an API key, NVD allows 5 requests per 30 seconds. ReconNinja enforces a 6.5 second delay between requests to stay within this limit. With `--nvd-key` the delay stays the same but you effectively never hit the cap.

---

## 📊 HTML Reports

Generated automatically after every scan — no extra flags needed.

```
reports/
└── example.com_2024-01-15_143022/
    ├── report.html       ← open in browser
    ├── report.json
    ├── report.md
    ├── state.json        ← resume checkpoint (written after EVERY phase)
    └── scan.log
```

---

## 💾 Resume Scans

`state.json` is written after **every single phase** completes. If a scan crashes at any point — power loss, network drop, Ctrl+C — resume from exactly where it stopped.

```bash
# Auto-detect latest checkpoint for target
ReconNinja -t example.com --resume

# Point at a specific state file
ReconNinja --resume reports/example.com/20240115_143022/state.json
```

Phases already completed are skipped automatically. All data — subdomains, hosts, ports, web findings, CVEs, Nuclei results — is fully restored.

---

## ⬆️ Self-Update

```bash
# Check and install latest version
ReconNinja --update

# Update from a specific branch
ReconNinja --update --update-branch dev

# Force re-download even if already on latest
ReconNinja --update --force-update
```

---

## 🎯 Scan Profiles

| Profile | Ports | Features | Use Case |
|---|---|---|---|
| `fast` | Top 100 | No scripts | Quick triage |
| `standard` | Top 1000 | Scripts + versions | Default |
| `thorough` | All 65535 | OS + scripts + versions | Deep dive |
| `stealth` | Top 1000 | SYN scan, T2 timing | Evasion |
| `web_only` | — | httpx + dirs + nuclei | Web targets |
| `port_only` | All | RustScan + Masscan + Nmap | Port recon only |
| `full_suite` | All 65535 | Everything | Full pentest |
| `custom` | User defined | User defined | Flexible |

---

## 🚩 All CLI Flags

```
TARGET & PROFILE
  -t, --target            Target: domain, IP, CIDR, or path/to/list.txt
  -p, --profile           fast|standard|thorough|stealth|custom|full_suite|web_only|port_only

NMAP / PORT SCANNING
  --all-ports             Scan all 65535 ports (-p-)
  --top-ports N           Scan top N ports (default: 1000)
  --timing                T1-T5 nmap timing (default: T4)
  --async-concurrency N   Async TCP scanner coroutines (default: 1000)
  --async-timeout F       Async TCP connect timeout in seconds (default: 1.5)

FEATURE FLAGS
  --subdomains            Enable subdomain enumeration
  --rustscan              Enable RustScan
  --ferox                 Enable feroxbuster directory scan
  --masscan               Enable masscan sweep
  --httpx                 Enable httpx web detection
  --nuclei                Enable Nuclei vulnerability scan
  --nikto                 Enable Nikto web scan
  --whatweb               Enable WhatWeb fingerprinting
  --aquatone              Enable screenshots

AI ANALYSIS
  --ai                    Enable AI threat analysis
  --ai-provider           groq|ollama|gemini|openai (default: groq)
  --ai-key                API key (or set GROQ_API_KEY / GEMINI_API_KEY env var)
  --ai-model              Override AI model name

CVE LOOKUP
  --cve                   Enable NVD CVE lookup for detected services
  --cve-lookup            Alias for --cve (backwards compatibility)
  --nvd-key               Optional NVD API key — raises rate limit from 5 to 50 req/30s
                          Free key: nvd.nist.gov/developers/request-an-api-key

RESUME
  --resume [STATE_FILE]   Resume interrupted scan. Omit path to auto-detect latest
                          checkpoint for --target, or pass exact path to state.json

SELF-UPDATE
  --update                Update to latest version from GitHub
  --update-branch BRANCH  Branch to pull from (default: main)
  --force-update          Update even if already on latest version

OUTPUT
  --output DIR            Output directory (default: reports)
  --no-html-report        Skip HTML report generation
  --wordlist-size         small|medium|large (default: medium)

MISC
  --threads N             Worker threads (default: 20)
  --masscan-rate N        Masscan packets/sec (default: 5000)
  --check-tools           Show which tools are installed
  --yes, -y               Skip permission confirmation (automation)
```

---

## 🧪 Testing

ReconNinja ships with a comprehensive test suite. No external tools or API keys required — all network calls are mocked.

### Run Tests

```bash
# With pytest (recommended)
pip install pytest
pytest tests/ -v

# Without pytest
python3 -m unittest discover tests/
```

### Test Coverage

| File | Tests | Covers |
|---|---|---|
| `tests/test_models.py` | 105 | All dataclasses, `ScanConfig` including all v3.2.1 fields, constants |
| `tests/test_resume.py` | 83 | `save_state`, `load_state`, all v3.2.1 field round-trips, backward-compat with old state files |
| `tests/test_cve_lookup.py` | 47 | `CVEResult`, NVD API parsing, rate limit enforcement (≥6.0s), function name regressions |
| `tests/test_ai_analysis.py` | — | All 4 AI providers, prompt building, JSON parsing, error handling |
| `tests/test_report_html.py` | — | HTML structure, badge generation, full/empty result rendering |
| **Total** | **262** | **0 failures** |

### Test Policy

> **Every code change ships with updated tests. No exceptions.**

1. Fix the source file
2. Run existing tests — confirm nothing broke
3. Update the relevant test file — new fields get new tests, bug fixes get regression tests
4. Run all tests again — must be green before delivery
5. Source files and test files shipped together, always

### Key Regression Tests

These exist specifically to prevent fixed bugs from returning:

```python
# test_cve_lookup.py — catches v3.2.0 rate limit bug (0.7s → 403 errors)
def test_default_delay_at_least_6_seconds(self):
    assert delay >= 6.0

# test_cve_lookup.py — catches v3.2.0/v3.2.1 wrong function name in orchestrator
def test_wrong_function_name_does_not_exist(self):
    assert not hasattr(module, "lookup_cves_for_hosts")

# test_resume.py — catches v3.2.0 field-drop on resume
def test_missing_new_fields_get_defaults(self):
    cfg2 = _dict_to_config({"target": "old.com", "profile": "standard", "nmap_opts": {}})
    assert cfg2.run_cve_lookup is False
    assert cfg2.ai_provider    == "groq"
```

---

## 📁 File Structure

```
ReconNinja/
├── reconninja.py           # Main entry point + CLI                  ← updated v3.2.2
├── install.sh              # Installer
├── requirements.txt        # Python dependencies
├── environment.yml         # Conda environment
├── pytest.ini              # Test config
│
├── core/
│   ├── orchestrator.py     # Phase-based pipeline engine             ← updated v3.2.2
│   ├── ports.py            # RustScan + Async TCP + Nmap
│   ├── subdomains.py       # Subdomain enumeration
│   ├── web.py              # httpx, WhatWeb, Nikto, dir scan
│   ├── vuln.py             # Nuclei, aquatone, gowitness
│   ├── ai_analysis.py      # AI threat analysis — Groq/Ollama/Gemini/OpenAI
│   ├── cve_lookup.py       # NVD CVE lookup                          ← updated v3.2.1
│   ├── resume.py           # Checkpoint / resume                     ← updated v3.2.2
│   └── updater.py          # Self-update from GitHub                 ← updated v3.2.2
│
├── output/
│   ├── report_html.py      # HTML report generator
│   └── reports.py          # JSON + Markdown reports
│
├── utils/
│   ├── models.py           # Dataclasses — ScanConfig, PortInfo etc. ← updated v3.2.1
│   ├── helpers.py          # Utility functions
│   └── logger.py           # Rich terminal logger
│
├── plugins/                # Drop .py files here to extend ReconNinja
│
└── tests/
    ├── conftest.py         # Shared fixtures                         ← updated v3.2.2
    ├── test_models.py      # 105 tests                               ← updated v3.2.2
    ├── test_resume.py      # 83 tests                                ← updated v3.2.2
    ├── test_cve_lookup.py  # 47 tests                                ← updated v3.2.2
    ├── test_ai_analysis.py # AI provider tests
    ├── test_ports.py       # Port scanning tests
    └── test_report_html.py # HTML report tests
```

---

## 📝 Changelog

### v3.2.2 — Bug Fix Release
- ✅ **12 bugs fixed** — see table at top of this section
- ✅ `--cve`, `--update-branch`, `--force-update` flags added to argparse
- ✅ `--nvd-key` fully wired from CLI → `ScanConfig` → CVE lookup
- ✅ `run_update()` call fixed — `--update` no longer force-downloads on every run
- ✅ `orchestrate()` signature fixed — `--resume` no longer crashes with `TypeError`
- ✅ CVE Phase 4b actually executes — `--cve` now does what it says
- ✅ `save_state()` called after every phase — checkpoints actually written
- ✅ Phase 11 calls `run_ai_analysis()` from `core/ai_analysis.py` — `--ai` uses real LLM
- ✅ `print_update_status()` wrapped in `try/except` — network error no longer crashes startup
- ✅ `_dict_to_config()` uses `.get()` not `.pop()` — no dict mutation on state load
- ✅ **262 tests, 0 failures** — test suite updated for all 12 fixes

### v3.2.1 — Bug Fix Release
- ✅ `core/ai_analysis.py` added — real LLM integration (Groq/Ollama/Gemini/OpenAI)
- ✅ `ScanConfig` gains `run_cve_lookup`, `ai_provider`, `ai_key`, `ai_model`, `nvd_key`
- ✅ `_dict_to_config()` restores all new fields — old state files load with safe defaults
- ✅ NVD rate limit delay corrected from `0.7s` → `6.5s`
- ✅ CVE function name corrected: `lookup_cves_for_host_result` (was `lookup_cves_for_hosts`)

### v3.2.0
- ✅ `--ai` flag — Groq / Ollama / Gemini / OpenAI AI threat analysis
- ✅ `--cve-lookup` — NVD CVE auto-query after nmap `-sV`
- ✅ `--resume` — JSON checkpoint saves after phases
- ✅ `--update` — self-update from GitHub with backup
- ✅ HTML Reports — dark-mode dashboard auto-generated every scan

### v3.1.0
- ✅ Built-in AsyncTCPScanner — pure Python, no root required
- ✅ Async scan feeds confirmed ports directly to nmap (`-p<ports>`)
- ✅ RustScan + async results merged (union) for maximum coverage
- ✅ Nmap only scans confirmed-open ports — dramatically faster

### v3.0.0
- ✅ RustScan integration
- ✅ httpx for live web service detection
- ✅ crt.sh Certificate Transparency subdomain source
- ✅ Plugin system
- ✅ Phase-based orchestration

---

## ⚖️ Legal

> **This tool is for authorized security testing only.**
>
> - ✅ Authorized penetration testing engagements
> - ✅ Your own systems and infrastructure
> - ✅ Bug bounty programs where you have explicit permission
> - ❌ Systems you do not own or have explicit written permission to test
> - ❌ Any illegal or unauthorized use
>
> The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

---

<div align="center">

**Made by [YouTubers777](https://github.com/YouTubers777)**

⭐ If this tool helped you, please give it a star!

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7c3aed,50:00d4ff,100:0d0d0d&height=100&section=footer" />

</div>
