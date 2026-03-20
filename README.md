<div align="center">

# ReconNinja

**21-phase automated reconnaissance framework for authorized security testing.**

[![Version](https://img.shields.io/badge/version-6.0.0-6366f1?style=flat-square)](https://github.com/ExploitCraft/ReconNinja/releases)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=flat-square)](tests/)
[![License](https://img.shields.io/badge/license-MIT-f4f4f5?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-ExploitCraft-a78bfa?style=flat-square)](https://github.com/ExploitCraft)
[![Docs](https://img.shields.io/badge/docs-doc.emonpersonal.xyz-00e5ff?style=flat-square)](http://doc.emonpersonal.xyz/)

> ⚠ Use only against targets you own or have explicit written permission to test.

📄 **Documentation at [doc.emonpersonal.xyz](https://doc.emonpersonal.xyz/)**
[![Changelog](https://img.shields.io/badge/Changelog-View-blue)](CHANGELOG.md)

</div>

---

## What it does

ReconNinja automates every phase of a reconnaissance engagement into a single command. Point it at a domain or IP and it drives the full pipeline — passive OSINT, port scanning, web discovery, vulnerability scanning, cloud intelligence, credential hunting, and AI-powered threat analysis — then generates HTML, JSON, and Markdown reports.

---

## Install

```bash
# From GitHub (always latest)
pip install git+https://github.com/ExploitCraft/ReconNinja.git

# From PyPI
pip install ReconNinja

# From source (recommended)
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja && chmod +x install.sh && ./install.sh

# With optional dependencies
pip install "ReconNinja[full]"    # AI providers + Shodan + dnspython
pip install "ReconNinja[ai]"      # AI providers only
pip install "ReconNinja[dns]"     # dnspython for zone transfer
```

---

## Quick start

```bash
# Interactive mode — guided setup
ReconNinja

# Standard scan
ReconNinja -t example.com

# Full 21-phase pipeline
ReconNinja -t example.com --profile full_suite -y

# v5 intelligence (no keys needed)
ReconNinja -t example.com --whois --wayback --ssl -y

# v6 new modules (no keys needed)
ReconNinja -t example.com --github-osint --js-extract \
  --cloud-buckets --dns-zone --waf --cors -y

# Full v6 with notifications
ReconNinja -t example.com --profile full_suite \
  --shodan --shodan-key KEY --vt --vt-key KEY \
  --ai --ai-provider groq --ai-key KEY \
  --github-osint --github-token TOKEN \
  --notify slack://hooks.slack.com/services/xxx \
  -y

# Compare two scans
ReconNinja --diff reports/example.com/20260101/report.json \
                  reports/example.com/20260301/report.json
```

---

## Scan profiles

| Profile | What runs |
|---|---|
| `fast` | Top 100 ports, no scripts |
| `standard` | Top 1000 ports, scripts + versions *(default)* |
| `thorough` | All ports, OS detection, aggressive scripts |
| `stealth` | SYN scan, low timing, no banners |
| `web_only` | httpx + dir scan + nuclei |
| `port_only` | RustScan + Masscan + Nmap |
| `full_suite` | All 21 phases |
| `custom` | Interactive builder |

---

## Pipeline — 21 phases

```
Phase 1    Passive Recon         subdomain enum (amass, subfinder, crt.sh)
Phase 2    RustScan              ultra-fast port discovery (all 65535 ports)
Phase 2b   Async TCP             pure-Python fallback, no root required
Phase 3    Masscan               optional SYN sweep (root required)
Phase 4    Nmap                  deep service / version / script analysis
Phase 4b   CVE Lookup            NVD API CVE matching on detected services
Phase 5    httpx                 live web detection + tech fingerprint
Phase 5b   WAF Detection         passive headers + wafw00f (v6 NEW)
Phase 5c   CORS Scanner          misconfiguration probe (v6 NEW)
Phase 6    Dir Scan              feroxbuster → ffuf → dirsearch fallback
Phase 6b   JS Extraction         endpoint + secret extraction from JS (v6 NEW)
Phase 7    WhatWeb               technology fingerprinting
Phase 8    Nikto                 classic web vulnerability scanner
Phase 9    Nuclei                template-based vulnerability detection
Phase 10   Screenshots           aquatone → gowitness fallback
Phase 11   AI Analysis           Groq / Ollama / Gemini / OpenAI
Phase 12   Intelligence          WHOIS · Wayback · SSL · VirusTotal · Shodan
Phase 13a  GitHub OSINT          secret / config file exposure (v6 NEW)
Phase 13b  Cloud Buckets         AWS S3 / Azure / GCS enumeration (v6 NEW)
Phase 13c  DNS Zone Transfer     AXFR vulnerability check (v6 NEW)
Phase 14   Plugins               drop .py into plugins/ to extend
Phase 15   Reports               HTML · JSON · Markdown
```

---

## What's new in v6.0.0

### 8 bugs fixed

| # | Severity | Fix |
|---|---|---|
| 1 | **Critical** | `subdomains.py` — `_dns_brute` args passed in wrong order; `BUILTIN_SUBS` landing in `out_file` slot → `TypeError` at runtime |
| 2 | **High** | `orchestrator.py` — rustscan ports not persisted; on `--resume` `all_open_ports` was empty → Nmap skipped entirely |
| 3 | **High** | `updater.py` — `backup` variable referenced before assignment on fresh install → `UnboundLocalError` |
| 4 | **High** | `orchestrator.py` — AI fallback `_generate_ai_analysis` was dead code; condition always `True` → users with no key got raw error object in report |
| 5 | **Medium** | `ports.py` — banner grabber sent `HEAD / HTTP/1.0` to every port immediately; SSH/FTP/SMTP/Redis disconnected → banner capture failed on all non-HTTP ports |
| 6 | **Medium** | `orchestrator.py` — aquatone received `sub_file` (bare hostnames) instead of `url_file` (full URLs) → screenshots broken |
| 7 | **Medium** | `cve_lookup.py` — NVD rate-limit delay only fired on hits; no-result queries burst past 5 req/30s → silent 403s |
| 8 | **Low** | `utils/updater.py` — stale duplicate, never imported, missing `timeout=300` on pip subprocess → deleted |

### 6 new recon modules

| Module | Flag | Description |
|---|---|---|
| GitHub OSINT | `--github-osint` | Search GitHub for exposed secrets, API keys, config files |
| JS Extraction | `--js-extract` | Crawl live pages, download JS files, extract endpoints + secrets |
| Cloud Buckets | `--cloud-buckets` | Probe AWS S3, Azure Blob, GCS for public/authenticated buckets |
| DNS Zone Transfer | `--dns-zone` | AXFR vulnerability check against all nameservers |
| WAF Detection | `--waf` | Passive header + wafw00f fingerprinting |
| CORS Scanner | `--cors` | Crafted Origin probe for ACAO misconfiguration |

### 2 new utilities

| Utility | Flag | Description |
|---|---|---|
| Scan Diff | `--diff A.json B.json` | Compare two scan reports — new ports, new vulns, new subdomains |
| Notifications | `--notify URL` | Mid-scan alerts to Slack, Discord, or any webhook |

---

## All flags

```
Target
  -t, --target           Domain, IP, CIDR, or path to list file
  -p, --profile          Scan profile (see above)
  -y, --yes              Skip confirmation (CI/automation)

Port scanning
  --all-ports            Scan all 65535 ports
  --top-ports N          Top N ports (default: 1000)
  --timing T1-T5         Nmap timing (default: T4)
  --rustscan             Enable RustScan pre-scan
  --masscan              Enable Masscan sweep (root)
  --masscan-rate N       Masscan pps (default: 5000)
  --async-concurrency N  Async TCP concurrency (default: 1000)
  --async-timeout N      Async TCP timeout seconds (default: 1.5)

Web & discovery
  --httpx                Live service detection
  --whatweb              WhatWeb fingerprinting
  --ferox                Feroxbuster directory scan
  --nikto                Nikto scanner
  --nuclei               Nuclei vulnerability templates
  --aquatone             Screenshots
  --subdomains           Subdomain enumeration
  --wordlist-size        small | medium | large

Vulnerability intelligence
  --cve                  NVD CVE lookup for detected services
  --nvd-key KEY          NVD API key (50 req/30s vs 5)

v5 integrations
  --shodan               Shodan host intelligence
  --shodan-key KEY       Shodan API key
  --vt                   VirusTotal reputation
  --vt-key KEY           VirusTotal API key
  --whois                WHOIS lookup (no key)
  --wayback              Wayback Machine URL discovery (no key)
  --ssl                  SSL/TLS certificate analysis (no key)

v6 new modules
  --github-osint         GitHub secret/config exposure search
  --github-token KEY     GitHub token (raises rate limit 60→5000/hr)
  --js-extract           JS endpoint and secret extraction
  --cloud-buckets        Cloud bucket enumeration (AWS/Azure/GCS)
  --dns-zone             DNS zone transfer (AXFR) check
  --waf                  WAF detection
  --cors                 CORS misconfiguration scanner

AI analysis
  --ai                   Enable AI threat analysis
  --ai-provider          groq | ollama | gemini | openai (default: groq)
  --ai-key KEY           API key for AI provider
  --ai-model MODEL       Override default model

Output & notifications
  --output DIR           Output directory (default: reports/)
  --output-format FMT    all | html | json | md | txt (default: all)
  --exclude PHASES       Comma-separated phases to skip
  --notify URL           Webhook alerts: slack://... discord://... https://...
  --timeout N            Global per-op timeout seconds (default: 30)
  --rate-limit N         Seconds between requests (default: 0)

Scan management
  --resume FILE          Resume from state.json checkpoint
  --diff A.json B.json   Compare two scan reports
  --update               Check GitHub for updates
  --force-update         Update even if already latest
  --check-tools          Show tool availability
```

---

## Output

Each scan creates a timestamped folder:

```
reports/
└── example.com_20260320_120000/
    ├── report.html         ← dark-mode dashboard
    ├── report.json         ← full machine-readable results
    ├── report.md           ← markdown summary
    ├── scan_config.json    ← exact config used
    ├── scan.log            ← full execution log
    ├── state.json          ← resume checkpoint
    ├── subdomains/
    ├── nmap/
    ├── nuclei/
    ├── js_extract/         ← v6: downloaded JS files
    ├── cloud_buckets/      ← v6: bucket findings
    ├── dns_zone/           ← v6: zone transfer records
    ├── waf/                ← v6: WAF detection output
    └── cors/               ← v6: CORS findings
```

---

## Scan diff

```bash
# Run a baseline scan
ReconNinja -t example.com -y

# Run again after changes
ReconNinja -t example.com -y

# See exactly what changed
ReconNinja --diff reports/example.com/20260101_120000/report.json \
                  reports/example.com/20260320_120000/report.json
```

Output: new open ports, closed ports, new subdomains, new vulnerabilities, new technologies, changed service versions.

---

## Notifications

```bash
# Slack
ReconNinja -t example.com --notify slack://hooks.slack.com/services/T.../B.../xxx -y

# Discord
ReconNinja -t example.com --notify discord://discord.com/api/webhooks/xxx/yyy -y

# Generic JSON webhook
ReconNinja -t example.com --notify https://your-server.com/webhook -y
```

Fires alerts mid-scan for: critical ports found, critical vulnerabilities, public cloud buckets, CORS issues, GitHub exposures, zone transfer vulnerabilities, and scan completion.

---

## Resume interrupted scans

```bash
# Scan crashes after Phase 9 — resume from last checkpoint
ReconNinja --resume reports/example.com_20260320_120000/state.json
```

All results (ports, findings, v5 intelligence, v6 new module data) are checkpointed after every phase and fully restored on resume.

---

## Plugin system

Drop a `.py` file into `plugins/` to extend the pipeline after all phases complete.

```python
# plugins/my_check.py
PLUGIN_NAME    = "my_check"
PLUGIN_VERSION = "1.0"

def run(target, out_folder, result, cfg):
    print(f"Custom: {len(result.github_findings)} GitHub findings")
    print(f"Custom: {len(result.bucket_findings)} bucket findings")
```

---

## Tool dependencies

Only `rich` is required. All external tools are optional — ReconNinja detects availability and falls back gracefully.

```bash
ReconNinja --check-tools
```

Optional tools: `nmap`, `rustscan`, `masscan`, `amass`, `subfinder`, `httpx`, `feroxbuster`, `ffuf`, `dirsearch`, `whatweb`, `nikto`, `nuclei`, `aquatone`, `gowitness`, `wafw00f`, `dig`

Optional Python packages: `dnspython` (zone transfer), `shodan`, `groq`, `openai`, `google-generativeai`

---

## Development

```bash
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja
chmod +x install.sh && ./install.sh

# Run tests
python3 -m pytest tests/ -v
python3 -m pytest tests/test_orchestrator.py -v
python3 -m pytest tests/test_models.py -v
```

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**[ExploitCraft](https://github.com/ExploitCraft)** · Bangladesh · Building tools that matter

📄 Full documentation at **[doc.emonpersonal.xyz](http://doc.emonpersonal.xyz/)**

</div>
