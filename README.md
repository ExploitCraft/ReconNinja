<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
```

**Autonomous multi-phase security reconnaissance framework.**

[![Version](https://img.shields.io/badge/version-10.2.0-e74c3c?style=flat-square)](https://github.com/ExploitCraft/ReconNinja/releases)
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

ReconNinja turns a single command into a full recon engagement. Point it at a domain or IP and it drives the complete pipeline — passive OSINT, port scanning, web discovery, vulnerability scanning, cloud intelligence, Active Directory enumeration, AI surface discovery, and agentic threat analysis — then generates HTML, JSON, Markdown, SARIF, and interactive D3 reports.

**v10.0.0** is a major reliability release — every v9 signature-mismatch TypeError that crashed real scans has been fixed via a uniform `PhaseContext` adapter layer; save/load resume now round-trips ALL fields (with `schema_version=3` for forward migration); the monitor mode and GUI are actually wired up; the AUR `pkgver()` reads `info/version` directly; the MCP server binds to 127.0.0.1 by default with optional bearer-token auth; and the plugin SDK has a path-traversal guard + SHA-256 verification + atomic write.

**v9.0.0** introduced autonomous agent mode, parallel phase scheduling, a directed finding graph, 6 new recon modules, agentic AI correlation, and MCP server integration for Claude Code / Cursor.

---

## Install

```bash
# Arch Linux (recommended)
paru -S reconninja
# or
yay -S reconninja

# Manual
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja && chmod +x install.sh && ./install.sh

# Python only (skip Go/Rust tools)
./install.sh --python-only

```

> **Arch Linux:** if `paru` is found it's used exclusively. Optionally add **BlackArch** when prompted.

---

## Quick start

```bash
# Standard scan
reconninja example.com

# Agent mode — LLM adaptively decides what to run next
reconninja example.com --agent --nuclei --subdomains --ai-key $GROQ_KEY

# Classic mode — identical sequential v8 behaviour
reconninja example.com --nuclei --subdomains --classic

# Full pipeline, no prompts
reconninja example.com --profile full_suite

# Passive only
reconninja example.com --whois --wayback --ssl

# Diff two scans (v10: now actually implemented)
reconninja --diff reports/example.com/20260101_120000/state.json \
                  reports/example.com/20260501_120000/state.json

# Check which external tools are installed (v10)
reconninja --check-tools

# Self-update from GitHub (v10)
reconninja --update

# Launch the local Flask GUI (v10: now actually works)
reconninja --gui
```

---

## Scan profiles

| Profile | What it runs |
|---|---|
| `fast` | Top 100 ports, no scripts, no subdomains |
| `standard` | Top 1000 ports, scripts, version detection *(default)* |
| `thorough` | All ports, subdomains, httpx, nuclei, CVE lookup, correlation, interactive report |
| `stealth` | SYN scan, T2 timing, low-noise rate profile |
| `custom` | Your flags only |
| `web_only` | httpx, whatweb, nuclei, feroxbuster, CORS, JS extract |
| `port_only` | RustScan pre-scan only |
| `full_suite` | Everything enabled |

---

## What's New in v9.0.0

### Autonomous Agent Mode
```bash
# Supervisor reads findings after each phase and decides what to run next
reconninja example.com --agent --nuclei --subdomains --ai-key $GROQ_KEY

# Budget-controlled: max 50 LLM calls, pause for approval before each decision
reconninja example.com --agent --agent-budget 30 --require-approval

# Parallel phase execution (4 workers by default)
reconninja example.com --parallel-phases 8 --nuclei --subdomains --cloud-deep

# Classic v8 sequential mode
reconninja example.com --nuclei --subdomains --classic
```

### New Modules
```bash
# Active Directory recon (Kerberoast, AS-REP, ACL abuse, BloodHound)
reconninja example.com --ad-recon --ad-dc 10.0.0.5 \
  --ad-domain corp.example.com --ad-user pentester --ad-password 'P@ss!'

# Deep cloud: AWS S3/ECR, Azure Blob/AppService, GCP/Firebase
reconninja example.com --cloud-deep

# Exposed AI endpoints (Ollama, Qdrant, MCP servers, OpenWebUI)
reconninja example.com --llm-recon

# OT/ICS scan (Modbus, DNP3, BACnet, EtherNet/IP)
reconninja example.com --iot-scan

# Container/K8s deep scan (Docker socket, kubelet, etcd)
reconninja example.com --container-deep

# Passive wireless OSINT + dark web mentions
reconninja example.com --wireless-osint --wigle-token $WIGLE \
                        --darkweb-osint --telegram-token $BOT_TOKEN
```

### AI Correlation Pipeline
```bash
# Full agentic correlation: finds attack chains with MITRE TTPs + probability scores
reconninja example.com --nuclei --correlation --ai-key $GROQ_KEY

# Local LLM (Ollama) — no cloud needed
reconninja example.com --nuclei --correlation \
  --ai-provider ollama --local-llm-url http://localhost:11434

# Suppress low-probability findings (EPSS < 5%)
reconninja example.com --nuclei --epss-threshold 0.05
```

### MCP Server — Claude Code / Cursor Integration
```bash
# Start ReconNinja as an MCP server
reconninja mcp-server --port 8765

# Or via scan flag
reconninja example.com --mcp-server --mcp-server-port 8765
```

Add to Claude Code (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "reconninja": { "url": "http://localhost:8765" }
  }
}
```

Claude Code can then: start scans, check status, query findings by severity, explore the attack graph, and read attack chains — all natively.

### Interactive HTML Report
```bash
reconninja example.com --nuclei --correlation --interactive-report
# Produces a self-contained HTML with:
# · D3.js force-directed attack surface graph
# · MITRE ATT&CK technique heatmap
# · Filterable findings table (severity / tool / CVE search)
# · Attack chain cards with probability meters
# · Remediation plan
# · Dark / light mode toggle
```

### Scope Enforcement
```bash
# scope.yaml:
#   allowed: [10.0.0.0/24, example.com]
#   excluded: [10.0.0.1]
#   strict: true
reconninja 10.0.0.0/24 --scope-file scope.yaml --scope-strict

# Inline exclusions
reconninja example.com --exclude 192.168.1.1 10.0.0.0/8
```

### Continuous Monitoring
```bash
# Re-run every 6 hours, alert on new critical findings
reconninja example.com --monitor --monitor-interval 6h \
  --notify https://hooks.slack.com/xxx

# Passive-only monitoring (no active scanning in prod)
reconninja example.com --monitor --monitor-passive-only --monitor-interval 1h
```

### New Integrations
```bash
--defectdojo-url https://dojo.corp --defectdojo-key $KEY   # Push to DefectDojo
--notion-token $TOKEN --notion-db-id $DB_ID                 # Notion database pages
--obsidian-export --obsidian-vault ~/vault                   # Obsidian Markdown notes
--graph-export neo4j --neo4j-url bolt://localhost:7687       # Neo4j graph DB
--graph-export graphml                                        # GraphML for yEd / Gephi
--graph-export json-ld                                        # JSON-LD semantic graph
--compliance pci-dss                                          # PCI-DSS gap report
--compliance iso27001                                         # ISO 27001:2022 gap report
```

---

## All flags

```
Target & core
  target                 Domain, IP, CIDR, or list file
  --profile              fast | standard | thorough | stealth | custom | full_suite | web_only | port_only
  --output-dir DIR       Output directory (default: reports)
  --output-format        all | json | html | md (default: all)
  --global-timeout N     Per-request timeout in seconds (default: 30)
  --threads N            Worker threads (default: 20)
  --wordlist-size        small | medium | large (default: medium)
  --exclude-phases       Phases to skip
  --check-tools          Check which external tools are installed

Nmap
  --all-ports            Scan all 65535 ports (-p-)
  --top-ports N          Top N ports (default: 1000)
  --no-scripts           Disable nmap scripts (-sC)
  --os-detection         Enable OS detection (-O)
  --timing T1-T5         Nmap timing T1 (stealthy) to T5 (fastest), default T4
  --stealth              SYN stealth scan (-sS, requires root)
  --aggressive           Aggressive scan (-A)
  --script-args ARGS     Custom nmap script arguments

Discovery
  --subdomains           Subdomain enum via subfinder/amass/crt.sh
  --rustscan             RustScan pre-scan for fast port discovery
  --masscan              Masscan sweep (requires root)
  --masscan-rate N       Masscan pps (default: 5000)
  --aquatone             Web screenshots across all hosts

Web
  --httpx                HTTP/HTTPS probing and fingerprinting
  --whatweb              WhatWeb technology detection
  --nikto                Nikto web vulnerability scanner
  --feroxbuster          Feroxbuster directory brute-force
  --nuclei               Nuclei template scanner
  --cve-lookup           NVD CVE lookup for discovered services
  --nvd-key KEY          NVD API key for higher rate limits
  --waf                  WAF/CDN detection
  --cors                 CORS misconfiguration scan
  --js-extract           JS secret and endpoint extraction
  --api-fuzz             REST API fuzzing (injection, auth bypass, IDOR)
  --oauth-scan           OAuth flow misconfiguration scan
  --web-vulns            SQLi, XSS, SSRF, path traversal tests
  --open-redirect        Open redirect parameter scan
  --graphql              GraphQL endpoint discovery + introspection
  --jwt-scan             JWT alg:none, weak secrets, misconfig

Intelligence
  --shodan               Shodan host intelligence
  --shodan-key KEY
  --virustotal           VirusTotal domain/IP reputation
  --vt-key KEY
  --whois                WHOIS registrar and expiry lookup
  --wayback              Wayback Machine URL discovery
  --ssl                  SSL/TLS cert and cipher analysis
  --github-osint         GitHub secret and config exposure search
  --github-token TOKEN
  --cloud-buckets        Public cloud bucket enumeration
  --dns-zone             DNS zone transfer (AXFR)
  --email-security       SPF, DKIM, DMARC analysis
  --breach-check         HaveIBeenPwned domain breach check
  --hibp-key KEY
  --cloud-meta           AWS/Azure/GCP metadata SSRF probe
  --asn-map              BGP/ASN → owned CIDR mapping
  --supply-chain         JS/npm vulnerable dependency check
  --k8s-probe            Kubernetes API server probe
  --db-exposure          Redis, MongoDB, Elasticsearch exposure
  --smtp-enum            SMTP user enumeration (VRFY/RCPT)
  --snmp-scan            SNMP community string bruteforce
  --ldap-enum            LDAP anonymous bind + user/group dump
  --devops-scan          Jenkins, Terraform state exposure
  --greynoise            GreyNoise IP threat context
  --greynoise-key KEY
  --typosquat            Lookalike domain detection
  --censys               Censys host intelligence
  --censys-api-id ID
  --censys-api-secret KEY
  --dns-history          Historical DNS records
  --sarif-export         SARIF 2.1.0 output for GitHub Code Scanning
  --linkedin             LinkedIn employee OSINT
  --paste-monitor        Pastebin domain mention monitoring
  --se-osint             Social engineering OSINT
  --apk PATH             APK static analysis
  --app-store            App Store / Google Play recon
  --anon-detect          Tor / VPN exit node detection
  --dns-leak             DNS leak vulnerability test
  --web3                 Web3 smart contract and DeFi recon
  --ens                  ENS domain to wallet resolution

── v9 NEW ──────────────────────────────────────────────────────────────────────

Agent mode
  --agent                Autonomous agent mode (LLM-driven adaptive routing)
  --classic              Sequential v8-compatible mode
  --require-approval     Pause for operator approval before each supervisor decision
  --agent-budget N       Max supervisor LLM calls (default: 50)
  --parallel-phases N    Phase scheduler workers (default: 4)

New modules
  --ad-recon             Active Directory: Kerberoast, AS-REP, ACL, delegation, BloodHound
  --ad-dc IP             Domain controller IP
  --ad-domain DOMAIN     AD domain name
  --ad-user USER         AD username
  --ad-password PASS     AD password
  --ad-bloodhound-output DIR
  --cloud-deep           Deep cloud: AWS S3/IAM/ECR, Azure Blob, GCP/Firebase
  --llm-recon            Exposed AI endpoints (Ollama, Qdrant, MCP, OpenWebUI)
  --iot-scan             OT/ICS: Modbus, DNP3, BACnet, EtherNet/IP, IEC61850
  --container-deep       Docker socket, kubelet, etcd, kube-apiserver checks
  --wireless-osint       Passive Wigle SSID OSINT + rogue AP detection
  --wigle-token TOKEN
  --darkweb-osint        Ransomwatch + Telegram dark web monitoring
  --telegram-token TOKEN

AI upgrades
  --correlation          Agentic correlation pipeline (AttackChains + MITRE TTPs)
  --local-llm-url URL    Ollama/llama.cpp base URL (default: http://localhost:11434)
  --epss-threshold FLOAT Suppress findings below this EPSS score
  --ai-analysis          AI-powered analysis of scan findings
  --ai-provider          groq | openai | gemini | ollama (default: groq)
  --ai-key KEY
  --ai-model MODEL
  --ai-consensus         Multi-model AI consensus
  --attack-paths         AI attack path generation
  --ai-remediate         AI remediation recommendations

Output & integrations
  --interactive-report   Interactive HTML (D3 graph, MITRE heatmap, filter bar)
  --mcp-server           Start as MCP server for Claude Code / Cursor
  --mcp-server-port PORT (default: 8765)
  --defectdojo-url URL
  --defectdojo-key KEY
  --defectdojo-product NAME
  --notion-token TOKEN
  --notion-db-id ID
  --obsidian-export      Export to Obsidian vault as Markdown notes
  --obsidian-vault PATH
  --monitor              Continuous monitoring with finding diffs
  --monitor-interval     Re-scan interval: 1h | 6h | 24h (default: 24h)
  --monitor-passive-only Passive phases only during monitoring
  --report-template      technical | executive | compliance (default: technical)
  --compliance FRAMEWORK pci-dss | iso27001 | nist-csf
  --graph-export         neo4j | graphml | json-ld
  --neo4j-url URL        (default: bolt://localhost:7687)
  --pdf                  Generate PDF report

Scope enforcement
  --scope-file PATH      YAML scope policy (allowed/excluded CIDRs and domains)
  --scope-strict         Exit immediately on out-of-scope attempt
  --exclude TARGET...    Inline exclusions

Evidence
  --evidence             SHA-256 HTTP evidence capture per finding
  --evidence-sign-key ID GPG key ID for signing evidence files

Rate limiting
  --rate-profile         aggressive | standard | low-noise | paranoid (default: aggressive)
  --jitter SECS          Random delay between requests
  --proxy-list FILE      Proxy rotation file

Observability
  --log-format           text | json (default: text)
  --metrics-port PORT    Prometheus metrics endpoint
  --otlp-endpoint URL    OpenTelemetry traces

Plugins
  --plugin-registry-url  Community registry URL

GUI (v8)
  --gui                  Launch local web GUI on port 7117
  --gui-port PORT        GUI port (default: 7117)
  --check-tools          Check which external tools are installed

Notify
  --notify URL           Webhook for real-time finding alerts (Slack/Discord/Teams)
```

---

## Output

Every scan creates a timestamped folder under `reports/<target>/<timestamp>/`:

| File | Description |
|---|---|
| `report.html` | Full HTML report with all findings |
| `report.json` | Machine-readable JSON |
| `report.md` | Markdown for wikis and tickets |
| `report.sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `report_interactive_*.html` | Interactive D3 report (`--interactive-report`) |
| `recon_graph.graphml` | GraphML attack graph (`--graph-export graphml`) |
| `recon_graph.jsonld` | JSON-LD graph (`--graph-export json-ld`) |
| `evidence/` | HTTP captures + screenshots (`--evidence`) |
| `evidence_manifest.json` | SHA-256 hashes of all evidence files |
| `ad_data/` | BloodHound JSON (`--ad-recon`) |
| `monitor_diffs/` | Finding diff reports (`--monitor`) |
| `reconninja_state.json` | Resume checkpoint |
| `scan.log` | Full scan log |

---

## Scan diff

```bash
reconninja --diff reports/example.com/20260101/report.json \
                  reports/example.com/20260501/report.json
```

Produces: new findings, resolved findings, new subdomains, port changes.

---

## Notifications

```bash
# Slack
reconninja example.com --nuclei --notify https://hooks.slack.com/services/xxx

# Discord
reconninja example.com --nuclei --notify https://discord.com/api/webhooks/xxx

# Generic webhook (POST JSON)
reconninja example.com --nuclei --notify https://your.server/webhook
```

---

## Resume interrupted scans

```bash
# Find latest state file
reconninja resume reports/example.com/20260521_143022/reconninja_state.json
```

All completed phases are skipped; the scan continues from where it left off.

---

## Plugin system

### v9 — Plugin SDK v2

```python
# plugins/my_plugin.py
from plugins.sdk import register, ReconPlugin

@register(
    name="my_plugin",
    version="1.0.0",
    description="Does something useful",
    tags=["custom", "osint"],
)
class MyPlugin(ReconPlugin):
    def run(self, target, out_folder, result, config):
        resp = self.http_get(f"https://api.example.com/check?domain={target}")
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("risky"):
                self.add_vuln(result, tool="my_plugin", severity="high",
                              title="Risk detected", target=target,
                              details=str(data))
```

```bash
# CLI plugin management
reconninja plugin list
reconninja plugin install my_plugin
reconninja plugin registry
```

### v8 plugins (still supported)

```python
PLUGIN_NAME    = "my_plugin"
PLUGIN_VERSION = "1.0.0"

def run(target, out_folder, result, config):
    ...
```

---

## Tool dependencies

| Tool | Required for | Install |
|---|---|---|
| `nmap` | Port scanning | `sudo pacman -S nmap` |
| `rustscan` | Fast port pre-scan | `cargo install rustscan` |
| `masscan` | High-speed sweep | `sudo pacman -S masscan` |
| `nuclei` | Vuln templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `httpx` | Web probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `feroxbuster` | Dir brute-force | `cargo install feroxbuster` |
| `subfinder` | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `nikto` | Web scanner | `sudo pacman -S nikto` |
| `whatweb` | Tech fingerprint | `sudo pacman -S whatweb` |
| `aquatone` | Screenshots | `go install github.com/michenriksen/aquatone@latest` |
| `gowitness` | Evidence screenshots | `go install github.com/sensepost/gowitness@latest` |
| `bloodhound-python` | AD collection | `pip install bloodhound` |
| `impacket` | Kerberoast/AS-REP | `pip install impacket` |

All Go/Rust tools are installed automatically by `install.sh`.

---

## Development

```bash
git clone https://github.com/ExploitCraft/ReconNinja.git
cd ReconNinja
chmod +x install.sh && ./install.sh

# Run all tests
python3 -m pytest tests/ -v

# Specific suites
python3 -m pytest tests/test_orchestrator.py -v
python3 -m pytest tests/test_v8_2_release.py -v
python3 -m pytest tests/test_models.py -v
```

---

## Changelog highlights

### v9.0.0
- Autonomous agent mode (PhaseScheduler + SupervisorAgent)
- 6 new modules: AD recon, cloud deep, LLM recon, IoT/OT, container deep, wireless/darkweb OSINT
- EPSS + CVSSv4 + REI scoring on every scan
- Agentic correlation pipeline → AttackChain objects with MITRE TTPs + probability scores
- Interactive HTML report v2 (D3 attack graph, MITRE heatmap, filterable table)
- MCP server mode (Claude Code / Cursor native integration)
- DefectDojo, Notion, Obsidian export integrations
- Continuous monitoring with finding diffs
- Scope enforcement engine (YAML policy, pre-flight validation)
- Evidence collection (SHA-256 + GPG signing)
- Rate limiting profiles + Prometheus metrics + OpenTelemetry traces
- Plugin SDK v2 (`@register` decorator, `ReconPlugin` base class, community registry)
- ReconGraph (directed finding graph, Neo4j/GraphML/JSON-LD export)

### v8.4.0
- 6 bug fixes: `result.vuln_findings` AttributeError, `--output` flag no-op, `ai_config` never populated, hardcoded version strings

### v8.3.0
- Centralised version into `info/version`

### v8.0.0
- Desktop GUI (`reconninja --gui`, port 7117)
- 13 new scan modules

### v7.0.0
- 17 new modules (SMTP, SNMP, LDAP, DevOps, GreyNoise, Censys, and more)

### v6.0.0
- GitHub OSINT, JS extraction, cloud buckets, WAF, CORS, DNS zone transfer, scan diff

> Full history in [CHANGELOG.md](CHANGELOG.md)

---

## Part of the ExploitCraft Ecosystem

| Tool | Description |
|---|---|
| [envleaks](https://github.com/ExploitCraft/envleaks) | Codebase & git history secret scanner |
| [gitdork](https://github.com/ExploitCraft/gitdork) | Google / Shodan dork generator |
| [wifi-passview](https://github.com/ExploitCraft/wifi-passview) | Cross-platform WiFi credential dumper |
| [VaultHound](https://github.com/ExploitCraft/VaultHound) | Secret & credential scanner |
| **ReconNinja** | Autonomous recon framework ← you are here |

---

## License

MIT — see [LICENSE](LICENSE)
