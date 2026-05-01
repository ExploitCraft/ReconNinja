<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
```

**38-phase automated reconnaissance framework for authorized security testing.**

[![Version](https://img.shields.io/badge/version-8.2.0-e74c3c?style=flat-square)](https://github.com/ExploitCraft/ReconNinja/releases)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=flat-square)](tests/)
[![License](https://img.shields.io/badge/license-MIT-f4f4f5?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-ExploitCraft-a78bfa?style=flat-square)](https://github.com/ExploitCraft)
[![Docs](https://img.shields.io/badge/docs-doc.emonpersonal.xyz-00e5ff?style=flat-square)](https://doc.emonpersonal.xyz/)
[![Changelog](https://img.shields.io/badge/changelog-CHANGELOG.md-orange?style=flat-square)](CHANGELOG.md)

> ⚠️ **Use only against targets you own or have explicit written permission to test.**

</div>

---

## What it does

ReconNinja turns a single command into a full recon engagement. Point it at a domain or IP and it drives the complete pipeline — passive OSINT, port scanning, web discovery, vulnerability scanning, cloud intelligence, credential hunting, and AI-powered threat analysis — then generates HTML, JSON, Markdown, and SARIF reports.

**v8.0.0** added a local desktop GUI: launch `ReconNinja --gui`, open your browser, and run scans point-and-click with real-time progress streaming and an in-app findings dashboard.

---

## Install

```bash
# Recommended — full install with all system tools
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja && chmod +x install.sh && ./install.sh

# Python + alias only (skip Go/Rust tools)
./install.sh --python-only

# Skip Go tools
./install.sh --skip-go

# Skip RustScan
./install.sh --skip-rust

# From PyPI
pip install ReconNinja

# From GitHub (latest commit)
pip install git+https://github.com/ExploitCraft/ReconNinja.git

# With optional extras
pip install "ReconNinja[full]"   # AI providers + Shodan + dnspython
pip install "ReconNinja[ai]"     # AI providers only
pip install "ReconNinja[dns]"    # dnspython for zone transfer
```

> **Arch Linux:** if `paru` is found it's used exclusively (official + AUR, no sudo needed).
> Optionally add the **BlackArch** repo when prompted — unlocks 2800+ security tools via `pacman`.

---

## Quick start

```bash
# Interactive mode — guided setup, no flags needed
ReconNinja

# Standard scan
ReconNinja -t example.com

# Full 38-phase pipeline, no prompts
ReconNinja -t example.com --profile full_suite -y

# Desktop GUI (opens browser on http://127.0.0.1:7117)
ReconNinja --gui

# Passive intel only — no keys required
ReconNinja -t example.com --whois --wayback --ssl -y

# v6 modules — no keys required
ReconNinja -t example.com --github-osint --js-extract \
  --cloud-buckets --dns-zone --waf --cors -y

# Full scan with keys + Slack alerts
ReconNinja -t example.com --profile full_suite \
  --shodan --shodan-key KEY \
  --vt --vt-key KEY \
  --ai --ai-provider groq --ai-key KEY \
  --github-osint --github-token TOKEN \
  --notify slack://hooks.slack.com/services/xxx \
  -y

# Diff two scan reports
ReconNinja --diff reports/example.com/20260101/report.json \
                  reports/example.com/20260301/report.json
```

---

## GUI — v8.0.0

```bash
ReconNinja --gui
# Opens http://127.0.0.1:7117
```

The GUI is a local Flask web app — nothing leaves your machine.

| Feature | Detail |
|---|---|
| Scan configuration | Target, profile, custom module picker, output formats, timeout |
| Live progress | Real-time log stream via SSE — no page refresh |
| Findings dashboard | Severity breakdown, findings table with Critical / High / Medium / Low / Info |
| Scan history | Browse previous runs, re-open output directories |

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
| `full_suite` | All 38 phases |
| `custom` | Interactive module builder |

---

## Pipeline — 38 phases

```
Phase  1    Passive Recon      subdomain enum — amass, subfinder, crt.sh
Phase  2    RustScan           ultra-fast port discovery (all 65535 ports)
Phase  2b   Async TCP          pure-Python fallback, no root required
Phase  3    Masscan            optional SYN sweep (root required)
Phase  4    Nmap               deep service / version / script analysis
Phase  4b   CVE Lookup         NVD API CVE matching on detected services
Phase  5    httpx              live web detection + tech fingerprint
Phase  5b   WAF Detection      passive headers + wafw00f
Phase  5c   CORS Scanner       misconfiguration probe
Phase  6    Dir Scan           feroxbuster → ffuf → dirsearch fallback chain
Phase  6b   JS Extraction      endpoint + secret extraction from JS files
Phase  7    WhatWeb            technology fingerprinting
Phase  8    Nikto              classic web vulnerability scanner
Phase  9    Nuclei             template-based vulnerability detection
Phase  10   Screenshots        aquatone → gowitness fallback
Phase  11   AI Analysis        Groq / Ollama / Gemini / OpenAI
Phase  12   Intelligence       WHOIS · Wayback · SSL · VirusTotal · Shodan
Phase  13a  GitHub OSINT       secret / config file exposure search
Phase  13b  Cloud Buckets      AWS S3 / Azure Blob / GCS enumeration
Phase  13c  DNS Zone Transfer  AXFR vulnerability check
Phase  14a  Email Security     SPF / DKIM / DMARC + spoofability score 0–100
Phase  14b  Breach Check       HaveIBeenPwned domain breach lookup
Phase  14c  Cloud Metadata     AWS / Azure / GCP IMDS SSRF probe
Phase  14d  GraphQL Scanner    endpoint discovery + introspection dump
Phase  14e  JWT Scanner        none-algorithm bypass + weak HMAC secret cracker
Phase  14f  ASN / BGP Map      owned IP CIDRs via RIPE Stat
Phase  14g  Supply Chain       vulnerable JS libs + npm squatting check
Phase  14h  K8s / Docker Probe unauthenticated Kubernetes / Docker API detection
Phase  14i  DB Exposure        Redis / Elasticsearch / MongoDB / Memcached unauth
Phase  14j  SMTP Enum          user enumeration via VRFY / EXPN / RCPT TO
Phase  14k  SNMP Scan          community string brute-force + MIB walk
Phase  14l  LDAP Enum          anonymous bind + user / group / attribute dump
Phase  14m  DevOps Scan        Terraform state file exposure + Jenkins anon access
Phase  14n  GreyNoise          IP noise / RIOT / unknown tagging
Phase  14o  Typosquat          200+ lookalike domain variants, live DNS-resolved
Phase  14p  Censys             host intelligence (free API credentials)
Phase  14q  DNS History        historical resolutions via VirusTotal PDNS
Phase  15   Plugins            drop a .py into plugins/ to extend the pipeline
Phase  16   Reports            HTML · JSON · Markdown · SARIF 2.1.0
```

---

## All flags

```
Target
  -t, --target           Domain, IP, CIDR, or path to list file
  -p, --profile          Scan profile (see above)
  -y, --yes              Skip confirmation prompt (CI / automation)

Port scanning
  --all-ports            Scan all 65535 ports
  --top-ports N          Top N ports (default: 1000)
  --timing T1-T5         Nmap timing template (default: T4)
  --rustscan             Enable RustScan pre-scan
  --masscan              Enable Masscan sweep (requires root)
  --masscan-rate N       Masscan packets per second (default: 5000)
  --async-concurrency N  Async TCP concurrency (default: 1000)
  --async-timeout N      Async TCP timeout in seconds (default: 1.5)

Web & discovery
  --httpx                Live service detection
  --whatweb              WhatWeb technology fingerprinting
  --ferox                Feroxbuster directory scan
  --nikto                Nikto web scanner
  --nuclei               Nuclei vulnerability templates
  --aquatone             Screenshots
  --subdomains           Subdomain enumeration
  --wordlist-size        small | medium | large

Vulnerability intelligence
  --cve                  NVD CVE lookup for detected services
  --nvd-key KEY          NVD API key (50 req/30s vs 5 without key)

v5 integrations
  --shodan               Shodan host intelligence
  --shodan-key KEY       Shodan API key
  --vt                   VirusTotal reputation check
  --vt-key KEY           VirusTotal API key
  --whois                WHOIS lookup (no key needed)
  --wayback              Wayback Machine URL discovery (no key needed)
  --ssl                  SSL/TLS certificate analysis (no key needed)

v6 modules
  --github-osint         GitHub secret / config file exposure search
  --github-token KEY     GitHub token (raises rate limit 60 → 5000 req/hr)
  --js-extract           JS endpoint and secret extraction
  --cloud-buckets        Cloud bucket enumeration (AWS / Azure / GCS)
  --dns-zone             DNS zone transfer (AXFR) check
  --waf                  WAF detection
  --cors                 CORS misconfiguration scanner

v7 modules
  --email-security       SPF / DKIM / DMARC validation + spoofability score
  --breach-check         HaveIBeenPwned domain breach check
  --hibp-key KEY         HIBP API key for email-level lookup
  --cloud-meta           AWS / Azure / GCP metadata SSRF probe
  --graphql              GraphQL endpoint discovery + introspection
  --jwt-scan             JWT none-alg bypass + weak HMAC secret cracker
  --asn-map              BGP / ASN → all owned IP CIDRs
  --supply-chain         Vulnerable JS libs + npm squat check
  --k8s-probe            Kubernetes / Docker unauthenticated API detection
  --db-exposure          Unauthenticated Redis / Elasticsearch / MongoDB / Memcached
  --smtp-enum            SMTP user enumeration (VRFY / RCPT TO)
  --snmp-scan            SNMP community string brute-force + MIB walk
  --ldap-enum            LDAP anonymous bind + user / group dump
  --devops-scan          Terraform state file + Jenkins exposure
  --greynoise            GreyNoise IP noise / RIOT / unknown tagging
  --greynoise-key KEY    GreyNoise API key (optional — community tier is free)
  --typosquat            Lookalike domain variant detection
  --censys               Censys host intelligence
  --censys-id ID         Censys API ID
  --censys-secret KEY    Censys API secret
  --dns-history          DNS history via VirusTotal PDNS (requires --vt-key)
  --sarif                Export findings as SARIF 2.1.0

v8 features
  --gui                  Launch local desktop GUI on http://127.0.0.1:7117

AI analysis
  --ai                   Enable AI threat analysis
  --ai-provider          groq | ollama | gemini | openai (default: groq)
  --ai-key KEY           API key for the selected AI provider
  --ai-model MODEL       Override the default model

Output & notifications
  --output DIR           Output directory (default: reports/)
  --output-format FMT    all | html | json | md | txt (default: all)
  --exclude PHASES       Comma-separated phase numbers to skip
  --notify URL           Webhook: slack://... discord://... https://...
  --timeout N            Per-operation timeout in seconds (default: 30)
  --rate-limit N         Seconds between requests (default: 0)

Scan management
  --resume FILE          Resume from a state.json checkpoint
  --diff A.json B.json   Compare two scan reports
  --update               Check GitHub for a newer version
  --force-update         Force update even if already on latest
  --check-tools          Show availability of all external tools
```

---

## Output

Each scan creates a timestamped folder:

```
reports/
└── example.com_20260320_120000/
    ├── report.html          ← dark-mode dashboard
    ├── report.json          ← full machine-readable results
    ├── report.md            ← markdown summary
    ├── report.sarif         ← SARIF 2.1.0 for GitHub / VSCode / Azure DevOps
    ├── scan_config.json     ← exact config used for this run
    ├── scan.log             ← full execution log
    ├── state.json           ← resume checkpoint
    ├── subdomains/
    ├── nmap/
    ├── nuclei/
    ├── js_extract/          ← downloaded JS files + extracted secrets
    ├── cloud_buckets/       ← bucket findings
    ├── dns_zone/            ← zone transfer records
    ├── waf/                 ← WAF detection output
    └── cors/                ← CORS findings
```

---

## Scan diff

```bash
# Baseline scan
ReconNinja -t example.com -y

# Scan again after changes
ReconNinja -t example.com -y

# See exactly what changed
ReconNinja --diff reports/example.com/20260101_120000/report.json \
                  reports/example.com/20260320_120000/report.json
```

Diff output covers: new / closed ports, new subdomains, new vulnerabilities, new technologies, changed service versions.

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

Fires mid-scan alerts for: critical ports, critical vulnerabilities, public cloud buckets, CORS issues, GitHub secret exposure, zone transfer vulnerabilities, and scan completion.

---

## Resume interrupted scans

```bash
# Pick up from last checkpoint after a crash or Ctrl-C
ReconNinja --resume reports/example.com_20260320_120000/state.json
```

All results — ports, findings, intelligence data, module output — are checkpointed after every phase and fully restored on resume.

---

## Plugin system

Drop a `.py` file into `plugins/` and it runs automatically after all phases complete.

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

Only `rich` and `python-dotenv` are required. All external tools are optional — ReconNinja auto-detects availability and falls back gracefully.

```bash
ReconNinja --check-tools
```

| Type | Tools |
|---|---|
| Port scanning | `nmap` · `rustscan` · `masscan` |
| Subdomain enum | `amass` · `subfinder` |
| Web | `httpx` · `feroxbuster` · `ffuf` · `dirsearch` · `whatweb` · `nikto` · `nuclei` · `wafw00f` |
| Screenshots | `aquatone` · `gowitness` |
| DNS | `dig` |
| GUI | `flask` |
| Optional Python | `dnspython` · `shodan` · `groq` · `openai` · `google-generativeai` |

---

## Development

```bash
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja
chmod +x install.sh && ./install.sh

# Run all tests
python3 -m pytest tests/ -v

# Run specific test suites
python3 -m pytest tests/test_orchestrator.py -v
python3 -m pytest tests/test_models.py -v
```

---

## Changelog highlights

### v8.0.0
- **Desktop GUI** — `ReconNinja --gui` launches a local Flask web app on port 7117 with real-time SSE progress, findings dashboard, and scan history

### v7.1.0
- Fixed `NameError` at runtime for every v7 phase — 19 module-level functions were called but never imported in `orchestrator.py`

### v7.0.0
- 17 new modules across Phases 14a–14q (email security, breach check, cloud metadata, GraphQL, JWT, ASN, supply chain, K8s, DB exposure, SMTP/SNMP/LDAP enum, DevOps scan, GreyNoise, typosquat, Censys, DNS history)
- SARIF 2.1.0 export for GitHub / VSCode / Azure DevOps integration

### v6.0.0
- GitHub OSINT, JS extraction, cloud bucket enumeration, WAF detection, CORS scanner, DNS zone transfer, scan diff

> Full history in [CHANGELOG.md](CHANGELOG.md)

---

## Part of the ExploitCraft Ecosystem

| Tool | Description |
|---|---|
| [envleaks](https://github.com/ExploitCraft/envleaks) | Codebase & git history secret scanner |
| [gitdork](https://github.com/ExploitCraft/gitdork) | Google / Shodan dork generator |
| [wifi-passview](https://github.com/ExploitCraft/wifi-passview) | Cross-platform WiFi credential dumper |
| [VaultHound](https://github.com/ExploitCraft/VaultHound) | Secret & credential scanner |
| **ReconNinja** | 38-phase recon framework ← you are here |

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**[ExploitCraft](https://github.com/ExploitCraft)** · Bangladesh · Building tools that matter

📄 Full documentation → **[doc.emonpersonal.xyz](https://doc.emonpersonal.xyz/)**

</div>
