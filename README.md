<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:00d4ff,100:7c3aed&height=200&section=header&text=ReconNinja&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=v3.2%20%E2%80%94%20Elite%20Recon%20Framework&descSize=20&descAlignY=60&descColor=00d4ff&animation=fadeIn" />

<br/>

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
```

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.2.0-00d4ff?style=for-the-badge&logo=buffer&logoColor=white)](https://github.com/YouTubers777/ReconNinja/releases)
[![License](https://img.shields.io/badge/License-MIT-7c3aed?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/YouTubers777/ReconNinja?style=for-the-badge&logo=github&color=ff6b6b&logoColor=white)](https://github.com/YouTubers777/ReconNinja/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/YouTubers777/ReconNinja/python-package-conda.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/YouTubers777/ReconNinja/actions)
[![Status](https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/YouTubers777/ReconNinja)

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

- [What's New in v3.2](#-whats-new-in-v32)
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
- [File Structure](#-file-structure)
- [Changelog](#-changelog)
- [Legal](#-legal)

---

## 🆕 What's New in v3.2

| Feature | Description |
|---|---|
| 🤖 **AI Threat Analysis** | Optional AI risk assessment via Groq (free), Ollama (local), Gemini, or OpenAI. Use `--ai --ai-provider groq --ai-key YOUR_KEY` |
| 🔍 **CVE Lookup** | Auto-queries NVD for CVEs matching detected service versions after nmap `-sV`. Use `--cve` |
| 💾 **--resume** | Saves phase-by-phase checkpoints. If scan crashes, resume from exactly where it stopped |
| ⬆️ **--update** | One-command self-update from GitHub. Backs up current install, pulls latest, reinstalls deps |
| 📊 **HTML Reports** | Professional dark-mode HTML report auto-generated every scan with dashboard, tables, and CVE links |

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
- **Nmap** — service + version fingerprinting only (`-sT -Pn -sV -sC`)
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
- **CVE Lookup** — NVD API, free, no key required
- **AI Analysis** — Groq / Ollama / Gemini / OpenAI
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
- **--resume** — checkpoint-based scan recovery
- **--update** — self-update from GitHub
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
│           │  nmap -sT -Pn -sV -sC -p<ports>                     │
├─────────────────────────────────────────────────────────────────┤
│  Phase 5  │  CVE Lookup — NVD API for each service+version      │
├─────────────────────────────────────────────────────────────────┤
│  Phase 6  │  httpx — live web detection + tech stack            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 7  │  WhatWeb — technology fingerprinting                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 8  │  Directory Brute Force (feroxbuster/ffuf/dirsearch) │
├─────────────────────────────────────────────────────────────────┤
│  Phase 9  │  Nikto — web vulnerability scan                     │
├─────────────────────────────────────────────────────────────────┤
│  Phase 10 │  Nuclei — 9000+ vuln templates                      │
├─────────────────────────────────────────────────────────────────┤
│  Phase 11 │  Screenshots (gowitness / aquatone)                  │
├─────────────────────────────────────────────────────────────────┤
│  Phase 12 │  AI Threat Analysis (Groq / Ollama / Gemini)        │
├─────────────────────────────────────────────────────────────────┤
│  Phase 13 │  HTML + JSON + Markdown Report Generation           │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
reports/<target>_<timestamp>/
    ├── report.html      ← dark-mode dashboard
    ├── report.json      ← structured data
    ├── report.md        ← markdown
    ├── checkpoint.json  ← resume state
    └── scan.log         ← full log
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
| amass | Subdomain enum | Optional |
| assetfinder | Subdomain enum | Optional |

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

The installer will:
- Detect your OS (Kali, Ubuntu, Arch, Fedora, macOS, etc.)
- Install all system tools automatically
- Copy the tool to `~/.reconninja/`
- Create the `ReconNinja` alias in your shell

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

### Interactive Mode (Recommended for Beginners)

```bash
ReconNinja
```

Launches a guided menu to select profile, target, and options.

### CLI Mode (Recommended for Automation)

```bash
# Standard scan
ReconNinja -t example.com

# Full suite scan
ReconNinja -t example.com --profile full_suite

# With AI analysis (Groq — free)
ReconNinja -t example.com --ai --ai-provider groq --ai-key gsk_xxx

# With CVE lookup
ReconNinja -t example.com --cve

# Everything at once
ReconNinja -t example.com --profile full_suite --ai --cve --ai-provider groq --ai-key gsk_xxx

# Scan IP range
ReconNinja -t 192.168.1.0/24 --profile fast

# Scan from a list of targets
ReconNinja -t targets.txt --profile standard

# Skip confirmation prompt (for scripts/automation)
ReconNinja -t example.com --profile standard -y

# Resume a crashed scan
ReconNinja -t example.com --resume

# Thorough scan, all ports
ReconNinja -t example.com --profile thorough --all-ports
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

### Groq (Recommended — Free)

```bash
# Get free key at console.groq.com → API Keys → Create

# Method 1: pass key directly
ReconNinja -t target.com --ai --ai-provider groq --ai-key gsk_xxxxxxxxxxxx

# Method 2: set env var (key never appears in shell history)
export GROQ_API_KEY="gsk_xxxxxxxxxxxx"
ReconNinja -t target.com --ai
```

### Ollama (Local — No Internet Required)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3

# Run scan (no key needed)
ReconNinja -t target.com --ai --ai-provider ollama

# Use a different local model
ReconNinja -t target.com --ai --ai-provider ollama --ai-model mistral
```

### Gemini (Free Tier)

```bash
# Get free key at ai.google.dev
export GEMINI_API_KEY="AIzaxxxxxxxxxx"
ReconNinja -t target.com --ai --ai-provider gemini
```

### What the AI Produces

```
╔══ AI Threat Analysis (groq / llama3-70b-8192) ══╗
║  ● HIGH RISK                                      ║
║                                                   ║
║  Target exposes SSH on port 22 running OpenSSH    ║
║  8.2p1 (CVE-2023-38408), Apache 2.4.49 with known ║
║  path traversal, and an exposed phpMyAdmin panel. ║
╚═══════════════════════════════════════════════════╝

┌─ 🚨 Critical Findings ──────────────────────────┐
│  • Apache 2.4.49 vulnerable to CVE-2021-41773    │
│  • phpMyAdmin exposed without auth on port 8080  │
└──────────────────────────────────────────────────┘

┌─ ⚡ Attack Vectors ─────────────────────────────┐
│  • Path traversal → RCE via Apache CVE-2021-41773│
│  • Brute force SSH using default credentials     │
└──────────────────────────────────────────────────┘

┌─ 🔧 Recommendations ────────────────────────────┐
│  • Update Apache to 2.4.51+ immediately          │
│  • Restrict phpMyAdmin to localhost only         │
│  • Disable SSH password auth, use keys only      │
└──────────────────────────────────────────────────┘
```

---

## 🔍 CVE Lookup

Automatically queries the [NVD (National Vulnerability Database)](https://nvd.nist.gov) for CVEs matching every service version nmap detects.

```bash
# Enable CVE lookup
ReconNinja -t target.com --cve

# With optional NVD API key (raises rate limit from 5 to 50 req/30s)
# Free key: nvd.nist.gov/developers/request-an-api-key
ReconNinja -t target.com --cve --nvd-key YOUR_NVD_KEY

# Combine with AI for maximum coverage
ReconNinja -t target.com --cve --ai --ai-provider groq --ai-key gsk_xxx
```

**Example output:**
```
╔═══════════════════════════════════════════════════════════╗
║  CVEs — 192.168.1.10:80                                   ║
╠══════════════╦══════╦══════════╦════════════╦═════════════╣
║ CVE ID       ║ CVSS ║ Severity ║ Published  ║ Summary     ║
╠══════════════╬══════╬══════════╬════════════╬═════════════╣
║ CVE-2021-41773 ║ 7.5 ║ HIGH   ║ 2021-10-05 ║ Path trav.. ║
║ CVE-2021-42013 ║ 9.8 ║ CRITICAL║ 2021-10-07 ║ RCE via..  ║
╚══════════════╩══════╩══════════╩════════════╩═════════════╝
```

No API key required for basic usage. Rate limited to 5 requests/30 seconds.

---

## 📊 HTML Reports

A professional HTML report is automatically generated after every scan. No extra flags needed.

```
reports/
└── example.com_2024-01-15_143022/
    ├── report.html       ← open this in your browser
    ├── report.json
    ├── report.md
    ├── checkpoint.json
    └── scan.log
```

**Report includes:**
- 📈 Dashboard — risk summary, open port count, vuln counts
- 🔌 Port & service table with severity badges
- 🚨 Vulnerability table with CVE links to NVD
- 🌐 Web services with technology fingerprints
- 🔍 Subdomains grid
- 🤖 AI analysis section (if `--ai` was used)
- ⚠️ Errors and warnings

To disable HTML report generation:
```bash
ReconNinja -t target.com --no-html-report
```

---

## 💾 Resume Scans

If a scan crashes or you kill it mid-way, resume from exactly where it stopped:

```bash
# Original command
ReconNinja -t example.com --profile full_suite

# ... scan crashes during nuclei phase ...

# Resume — skips all completed phases, continues from crash point
ReconNinja -t example.com --resume
```

ReconNinja saves a `checkpoint.json` after each phase completes:

```json
{
  "target": "example.com",
  "profile": "full_suite",
  "phases_completed": ["subdomains", "rustscan", "async_tcp", "nmap", "cve"],
  "open_ports": [22, 80, 443, 8080],
  "subdomains": ["www.example.com", "mail.example.com"],
  "last_updated": "2024-01-15 14:32:01"
}
```

---

## ⬆️ Self-Update

```bash
# Update to latest release
ReconNinja --update

# Update from a specific branch
ReconNinja --update --update-branch dev

# Force update even if already latest
ReconNinja --update --force-update

# Check version and update status
ReconNinja --version
```

Update process:
1. Checks GitHub releases API for latest version
2. Uses `git pull` if installed as a git clone
3. Falls back to downloading the release zip
4. Backs up current install to `~/.reconninja_backup_v<version>`
5. Installs new files (never overwrites `reports/`)
6. Reinstalls Python dependencies

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

```bash
ReconNinja -t target.com --profile full_suite
ReconNinja -t target.com --profile web_only
ReconNinja -t target.com --profile stealth
```

---

## 🚩 All CLI Flags

```
TARGET & PROFILE
  -t, --target          Target: domain, IP, CIDR, or path/to/list.txt
  -p, --profile         fast|standard|thorough|stealth|custom|full_suite|web_only|port_only

NMAP / PORT SCANNING
  --all-ports           Scan all 65535 ports (-p-)
  --top-ports N         Scan top N ports (default: 1000)
  --timing              T1-T5 nmap timing (default: T4)
  --async-concurrency N Async TCP scanner coroutines (default: 1000)
  --async-timeout F     Async TCP connect timeout in seconds (default: 1.5)

FEATURE FLAGS
  --subdomains          Enable subdomain enumeration
  --rustscan            Enable RustScan
  --ferox               Enable feroxbuster directory scan
  --masscan             Enable masscan sweep
  --httpx               Enable httpx web detection
  --nuclei              Enable Nuclei vulnerability scan
  --nikto               Enable Nikto web scan
  --whatweb             Enable WhatWeb fingerprinting
  --aquatone            Enable screenshots

AI ANALYSIS (optional)
  --ai                  Enable AI threat analysis
  --ai-provider         groq|ollama|gemini|openai (default: groq)
  --ai-key              API key (or set GROQ_API_KEY env var)
  --ai-model            Override AI model name

CVE LOOKUP
  --cve                 Enable NVD CVE lookup for detected services
  --nvd-key             Optional NVD API key (higher rate limit)

RESUME / PERSISTENCE
  --resume              Resume an interrupted scan from checkpoint

SELF-UPDATE
  --update              Update to latest version from GitHub
  --update-branch       Branch to pull from (default: main)
  --force-update        Update even if already on latest version

OUTPUT
  --output DIR          Output directory (default: reports)
  --no-html-report      Skip HTML report generation
  --wordlist-size       small|medium|large (default: medium)

MISC
  --threads N           Worker threads (default: 20)
  --masscan-rate N      Masscan packets/sec (default: 5000)
  --check-tools         Show which tools are installed
  --version, -v         Show version and check for updates
  --yes, -y             Skip permission confirmation (for automation)
```

---

## 📁 File Structure

```
ReconNinja/
├── reconninja.py           # Main entry point + CLI
├── install.sh              # Installer (all OS except Windows)
├── requirements.txt        # Python dependencies
├── environment.yml         # Conda environment
├── pytest.ini              # Test config
│
├── core/
│   ├── orchestrator.py     # Phase-based pipeline engine
│   ├── ports.py            # RustScan + Async TCP + Nmap
│   ├── subdomains.py       # Subdomain enumeration
│   ├── web.py              # httpx, WhatWeb, Nikto, dir scan
│   ├── vuln.py             # Nuclei, aquatone, gowitness
│   ├── ai_analysis.py      # AI threat analysis (v3.2)
│   ├── cve_lookup.py       # NVD CVE lookup (v3.2)
│   ├── resume.py           # Checkpoint / resume (v3.2)
│   └── updater.py          # Self-update from GitHub (v3.2)
│
├── output/
│   ├── report_html.py      # HTML report generator (v3.2)
│   ├── reports.py          # JSON + Markdown reports
│   └── reports/            # Generated scan output
│
├── utils/
│   ├── models.py           # Dataclasses (ScanConfig, PortInfo, etc.)
│   ├── helpers.py          # Utility functions
│   └── logger.py           # Rich terminal logger
│
├── plugins/                # Drop .py files here to extend ReconNinja
│
└── tests/
    ├── conftest.py
    ├── test_models.py
    └── test_ports.py
```

---

## 📝 Changelog

### v3.2.0
- ✅ **AI Analysis** — Groq (free), Ollama (local), Gemini, OpenAI via `--ai`
- ✅ **CVE Lookup** — NVD API auto-queries after nmap `-sV` via `--cve`
- ✅ **--resume** — JSON checkpoint saves after every phase
- ✅ **--update** — self-update from GitHub with backup
- ✅ **HTML Reports** — auto-generated dark-mode dashboard every scan

### v3.1.0
- ✅ Built-in AsyncTCPScanner — pure Python, no root required
- ✅ Async scan feeds confirmed ports to nmap (`-p<ports>`)
- ✅ Banner grabbing for instant service hints
- ✅ `--async-concurrency` and `--async-timeout` CLI flags
- ✅ RustScan + async results merged (union) for max coverage
- ✅ Nmap only scans confirmed-open ports — dramatically faster

### v3.0.0
- ✅ RustScan integration for ultra-fast port pre-discovery
- ✅ httpx for live web service detection
- ✅ gowitness as aquatone fallback
- ✅ crt.sh Certificate Transparency subdomain source
- ✅ Plugin system
- ✅ CIDR and list-file target input
- ✅ Phase-based orchestration

---

## ⚖️ Legal

> **This tool is for authorized security testing only.**
>
> - ✅ Authorized penetration testing engagements
> - ✅ Your own systems and infrastructure
> - ✅ Bug bounty programs where you have permission
> - ❌ Systems you do not own or have explicit written permission to test
> - ❌ Any illegal or unauthorized use
>
> The author assumes no liability and is not responsible for any misuse or damage caused by this tool. Use responsibly.

---

<div align="center">

**Made by [YouTubers777](https://github.com/YouTubers777)**

⭐ If this tool helped you, please give it a star!

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7c3aed,50:00d4ff,100:0d0d0d&height=100&section=footer" />

</div>
