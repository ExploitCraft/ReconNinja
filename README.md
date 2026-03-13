<div align="center">

# ReconNinja

**14-phase automated reconnaissance framework for authorized security testing.**

[![Version](https://img.shields.io/badge/version-5.1.1-6366f1?style=flat-square)](https://github.com/ExploitCraft/ReconNinja/releases)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=flat-square)](tests/)
[![License](https://img.shields.io/badge/license-MIT-f4f4f5?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-ExploitCraft-a78bfa?style=flat-square)](https://github.com/ExploitCraft)
[![Docs](https://img.shields.io/badge/docs-doc.emonpersonal.xyz-00e5ff?style=flat-square)](http://doc.emonpersonal.xyz/)

> ⚠ Use only against targets you own or have explicit written permission to test.

📄 **Documentation available at [doc.emonpersonal.xyz](http://doc.emonpersonal.xyz/)**

</div>

---

## What it does

ReconNinja automates every phase of a reconnaissance engagement into a single command. Point it at a domain or IP and it drives the full pipeline — passive OSINT, port scanning, web discovery, vulnerability scanning, credential intelligence, and AI-powered threat analysis — then generates HTML, JSON, and Markdown reports.

---

## Install

```bash
# From GitHub (always latest)
pip install git+https://github.com/ExploitCraft/ReconNinja.git

# From PIP
pip install ReconNinja

# From install file (RECOMMENDED)
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja && chmod +x install.sh && ./install.sh
```

---

## API key setup

ReconNinja supports loading API keys from a `.env` file so you never have to paste them in the terminal or risk leaking them into your shell history.

Create a `.env` file in your project root:

```env
SHODAN_API_KEY=your_shodan_key_here
VT_API_KEY=your_virustotal_key_here
GROQ_API_KEY=your_groq_key_here
NVD_API_KEY=your_nvd_key_here        # optional — raises rate limit
```

Then add `.env` to your `.gitignore`:

```bash
echo ".env" >> .gitignore
```

Keys are resolved in this order: **CLI flag → `.env` file → empty string**. CLI flags always win, so you can still override a `.env` value on a per-run basis.

| Key in `.env` | CLI flag equivalent |
|---|---|
| `SHODAN_API_KEY` | `--shodan-key` |
| `VT_API_KEY` | `--vt-key` |
| `GROQ_API_KEY` | `--ai-key` |
| `NVD_API_KEY` | `--nvd-key` |

Where to get each key:
- **Shodan** → [account.shodan.io](https://account.shodan.io)
- **VirusTotal** → [virustotal.com](https://www.virustotal.com/gui/sign-in) — profile → API Key
- **Groq** → [console.groq.com](https://console.groq.com) — free tier, generous limits
- **NVD** → [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) — optional

---

## Quick start

```bash
# Interactive mode — guided setup
reconninja

# Standard scan
reconninja -t example.com

# Full 14-phase pipeline
reconninja -t example.com --profile full_suite -y

# v5: WHOIS + Wayback + SSL — no keys needed
reconninja -t example.com --whois --wayback --ssl -y

# v5: Full intelligence — keys loaded from .env automatically
reconninja -t example.com --profile full_suite \
  --whois --wayback --ssl \
  --shodan --vt \
  --ai --ai-provider groq \
  -y

# Override a specific key at runtime
reconninja -t example.com --shodan --shodan-key YOUR_KEY -y
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
| `full_suite` | All 14 phases |
| `custom` | Interactive builder |

---

## Pipeline

```
Phase 1   Passive Recon      subdomain enum (amass, subfinder, crt.sh)
Phase 2   RustScan           ultra-fast port discovery (all 65535 ports)
Phase 2b  Async TCP          asyncio fallback, no root required
Phase 3   Masscan            optional SYN sweep (root required)
Phase 4   Nmap               deep service / version / script analysis
Phase 4b  CVE Lookup         NVD API CVE matching on detected services
Phase 5   httpx              live web detection + tech fingerprint
Phase 6   Dir Scan           feroxbuster → ffuf → dirsearch fallback chain
Phase 7   WhatWeb            technology fingerprinting
Phase 8   Nikto              classic web vulnerability scanner
Phase 9   Nuclei             template-based vulnerability detection
Phase 10  Screenshots        aquatone → gowitness fallback
Phase 12  v5 Integrations    WHOIS · Wayback · SSL · VirusTotal · Shodan
Phase 14  AI Analysis        Groq / Ollama / Gemini / OpenAI threat summary
```

---

## What's new in v5.1.1

- `.env` file support — store API keys outside the terminal and out of shell history
- `python-dotenv` added as a dependency
- CLI flags always override `.env` values — zero behaviour change for existing workflows

## What's new in v5.0.0

**5 new intelligence modules — 3 need zero API keys:**

| Module | Flag | API Key |
|---|---|---|
| WHOIS lookup | `--whois` | None |
| Wayback Machine URL discovery | `--wayback` | None |
| SSL/TLS certificate analysis | `--ssl` | None |
| VirusTotal reputation | `--vt --vt-key KEY` | Free tier |
| Shodan host intelligence | `--shodan --shodan-key KEY` | Free tier |

**Output control (new flags):**

```bash
--output-format html      # html | json | md | txt | all
--exclude passive,vuln    # skip specific phases
--timeout 60              # global per-operation timeout
--rate-limit 1.0          # seconds between requests
```

---

## All flags

```
Target
  -t, --target          Domain, IP, CIDR, or path to list file
  -p, --profile         Scan profile (see above)
  -y, --yes             Skip confirmation prompt (CI/automation)

Port scanning
  --all-ports           Scan all 65535 ports
  --top-ports N         Scan top N ports (default: 1000)
  --timing T1-T5        Nmap timing template (default: T4)
  --rustscan            Enable RustScan pre-scan
  --masscan             Enable Masscan sweep (root required)
  --masscan-rate N      Masscan packets/sec (default: 5000)
  --async-concurrency   Async TCP concurrency (default: 1000)
  --async-timeout       Async TCP timeout seconds (default: 1.5)

Web & discovery
  --httpx               httpx live service detection
  --whatweb             WhatWeb fingerprinting
  --ferox               Feroxbuster directory scan
  --nikto               Nikto scanner
  --nuclei              Nuclei vulnerability templates
  --aquatone            Screenshots
  --subdomains          Subdomain enumeration
  --wordlist-size       small | medium | large

Vulnerability intelligence
  --cve                 NVD CVE lookup for detected services
  --nvd-key KEY         NVD API key (raises rate limit 5→50 req/30s)

v5 integrations
  --shodan              Shodan host intelligence
  --shodan-key KEY      Shodan API key (or set SHODAN_API_KEY in .env)
  --vt                  VirusTotal reputation
  --vt-key KEY          VirusTotal API key (or set VT_API_KEY in .env)
  --whois               WHOIS lookup (no key needed)
  --wayback             Wayback Machine URL discovery (no key needed)
  --ssl                 SSL/TLS certificate analysis (no key needed)

AI analysis
  --ai                  Enable AI threat analysis
  --ai-provider         groq | ollama | gemini | openai (default: groq)
  --ai-key KEY          API key for AI provider (or set GROQ_API_KEY in .env)
  --ai-model MODEL      Override default model

Output
  --output DIR          Output directory (default: reports/)
  --output-format FMT   all | html | json | md | txt (default: all)
  --exclude PHASES      Comma-separated phases to skip
  --timeout N           Global per-operation timeout seconds (default: 30)
  --rate-limit N        Seconds between requests (default: 0)

Scan management
  --resume FILE         Resume interrupted scan from state.json
  --update              Check GitHub for updates
  --force-update        Update even if already on latest
  --check-tools         Show tool availability
```

---

## Output

Each scan creates a timestamped folder:

```
reports/
└── example.com_20260307_120000/
    ├── report.html         ← dark-mode dashboard
    ├── report.json         ← full machine-readable results (includes v5 intelligence data)
    ├── report.md           ← markdown summary
    ├── scan_config.json    ← exact config used
    ├── scan.log            ← full execution log
    ├── state.json          ← resume checkpoint
    ├── subdomains/
    ├── nmap/
    └── nuclei/
```

---

## Resume interrupted scans

```bash
# Scan crashes after Phase 8 — resume from last checkpoint
reconninja --resume reports/example.com_20260307_120000/state.json
```

All v5 results (WHOIS, Wayback, SSL, VT, Shodan) are preserved in `state.json` and restored on resume.

---

## Plugin system

Drop a `.py` file into `plugins/` to extend the pipeline. It receives the full `ReconResult` and `ScanConfig` after all phases complete.

```python
# plugins/custom.py
def run(target, out_folder, result, cfg):
    print(f"Custom: {len(result.hosts)} hosts, {len(result.shodan_results)} Shodan entries")
```

---

## Tool dependencies

Only `rich` and `python-dotenv` are required. All external tools are optional — ReconNinja detects what's available and falls back gracefully.

```bash
reconninja --check-tools    # show availability
```

Optional tools: `nmap`, `rustscan`, `masscan`, `amass`, `subfinder`, `httpx`, `feroxbuster`, `ffuf`, `dirsearch`, `whatweb`, `nikto`, `nuclei`, `aquatone`, `gowitness`

---

## Development

```bash
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja
chmod +x install.sh
./install.sh
python3 -m unittest discover -s tests -v    # run all tests
python3 -m unittest tests.test_v4_modules -v
python3 -m unittest tests.test_orchestrator -v
```

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**[ExploitCraft](https://github.com/ExploitCraft)** · Bangladesh · Building tools that matter

📄 Full documentation at **[doc.emonpersonal.xyz](http://doc.emonpersonal.xyz/)**

</div>
