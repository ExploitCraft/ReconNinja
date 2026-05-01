<div align="center">

# 🥷 ReconNinja

**v8.0.0** — Automated reconnaissance framework for authorized security testing

![Version](https://img.shields.io/badge/version-8.0.0-red?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Stars](https://img.shields.io/github/stars/yourusername/ReconNinja?style=flat-square)

</div>

> **For authorized security testing only. Always obtain written permission before scanning.**

---

## What's New in v8.0.0

| Category | Features |
|---|---|
| 🔑 **API Security** | REST API fuzzer, OAuth/OIDC scanner, web vuln probes (XSS/SQLi/LFI/SSRF), open redirect |
| 🕵️ **OSINT** | LinkedIn employee recon, paste site monitor, SE OSINT (email/phone harvest) |
| 📱 **Mobile** | APK static analysis, Google Play + App Store scraper |
| 🔒 **Privacy** | Tor/VPN/proxy detection, DNS leak checker |
| ⛓️ **Web3** | Smart contract scanner, ENS domain lookup |
| 🤖 **AI** | Multi-model consensus, MITRE ATT&CK attack paths, CVSSv3 remediation engine |
| 🖥️ **GUI** | Local desktop GUI (`--gui`), Windows `.exe` build |
| 📤 **Output** | PDF reports, Jira/GitHub Issues push, Splunk/Elastic SIEM streaming |

---

## Installation

```bash
# From PyPI
pip install ReconNinja

# From source
git clone https://github.com/yourusername/ReconNinja
cd ReconNinja
pip install -r requirements.txt

# Optional: GUI support
pip install flask

# Optional: PDF export
pip install weasyprint   # or: pip install fpdf2
```

### Windows (.exe)
Download the pre-built `ReconNinja.exe` from the [Releases](../../releases) page.  
No Python install required — just run it.

---

## Quick Start

```bash
# Standard scan
python reconninja.py -t example.com

# GUI mode (non-technical users)
python reconninja.py --gui

# Full scan — all 48 phases
python reconninja.py -t example.com --profile full_suite

# v8 new modules
python reconninja.py -t example.com --api-fuzz --oauth-scan --web-vulns --open-redirect
python reconninja.py -t example.com --linkedin --paste-monitor --se-osint
python reconninja.py -t example.com --web3-scan --ens-lookup --anon-detect --dns-leak
python reconninja.py -t example.com --ai-consensus --attack-paths --ai-remediate
python reconninja.py -t example.com --pdf-report --jira https://jira.co:email:token:SEC
python reconninja.py --apk-scan /path/to/app.apk
```

---

## All Flags

<details>
<summary><strong>Discovery & Enumeration</strong></summary>

| Flag | Description |
|---|---|
| `--subdomains` | Subdomain enumeration (amass, subfinder, dnsx) |
| `--rustscan` | Fast port scan via RustScan |
| `--masscan` | High-speed port scan via Masscan |
| `--httpx` | HTTP probing + tech fingerprinting |
| `--whatweb` | Web technology detection |
| `--ferox` | Directory/file brute-force (feroxbuster) |
| `--nikto` | Web server vulnerability scan |
| `--waf` | WAF detection (passive + wafw00f) |
| `--cors` | CORS misconfiguration scanner |
| `--ssl` | SSL/TLS certificate analysis |
| `--dns-zone` | DNS zone transfer (AXFR) check |
| `--wayback` | Wayback Machine URL discovery |
| `--js-extract` | Extract endpoints and secrets from JS files |
| `--graphql` | GraphQL endpoint discovery + introspection |
| `--typosquat` | Typosquatting domain variant detection |

</details>

<details>
<summary><strong>Vulnerability Scanning</strong></summary>

| Flag | Description |
|---|---|
| `--nuclei` | Nuclei template-based vulnerability scanner |
| `--cve` | NVD CVE lookup for detected services |
| `--jwt-scan` | JWT vulnerability scanner (none-alg, weak secrets) |
| `--db-exposure` | Unauthenticated Redis/ES/MongoDB/Memcached detection |
| `--api-fuzz` | **[v8]** REST API fuzzer — IDOR, auth bypass, mass assignment |
| `--oauth-scan` | **[v8]** OAuth 2.0/OIDC misconfiguration scanner |
| `--web-vulns` | **[v8]** XSS, SQLi, LFI, SSRF probe suite |
| `--open-redirect` | **[v8]** Open redirect vulnerability scanner |

</details>

<details>
<summary><strong>OSINT & Intelligence</strong></summary>

| Flag | Description |
|---|---|
| `--github-osint` | GitHub secret/config file search |
| `--shodan` | Shodan host intelligence |
| `--censys` | Censys host intelligence |
| `--virustotal` / `--vt` | VirusTotal domain/IP lookup |
| `--greynoise` | GreyNoise IP context (noise vs targeted) |
| `--whois` | WHOIS domain registration data |
| `--breach-check` | HaveIBeenPwned domain breach check |
| `--asn-map` | BGP/ASN IP range mapping |
| `--cloud-buckets` | Cloud bucket enumeration (S3/Azure/GCS) |
| `--cloud-meta` | AWS/Azure/GCP metadata SSRF probe |
| `--supply-chain` | Outdated JS libraries + npm squatting |
| `--linkedin` | **[v8]** LinkedIn employee OSINT + tech stack inference |
| `--paste-monitor` | **[v8]** Paste site credential/secret leak scanner |
| `--se-osint` | **[v8]** Social engineering contact harvesting |
| `--app-store` | **[v8]** Google Play + Apple App Store metadata |

</details>

<details>
<summary><strong>Infrastructure & Cloud</strong></summary>

| Flag | Description |
|---|---|
| `--k8s-probe` | Kubernetes/Docker API exposure |
| `--smtp-enum` | SMTP user enumeration (VRFY/RCPT TO) |
| `--snmp-scan` | SNMP community string brute-force |
| `--ldap-enum` | LDAP anonymous bind + attribute dump |
| `--devops-scan` | Terraform state + Jenkins exposure |
| `--anon-detect` | **[v8]** Tor/VPN/proxy/hosting IP detection |
| `--dns-leak` | **[v8]** DNS leak: rebinding, open resolver, internal exposure |

</details>

<details>
<summary><strong>Mobile & Web3</strong></summary>

| Flag | Description |
|---|---|
| `--apk-scan PATH` | **[v8]** APK static analysis — secrets, dangerous APIs, permissions |
| `--web3-scan` | **[v8]** Smart contract recon, ABI exposure, on-chain data |
| `--ens-lookup` | **[v8]** ENS domain + on-chain social profile resolution |

</details>

<details>
<summary><strong>AI Analysis</strong></summary>

| Flag | Description |
|---|---|
| `--ai` | AI-powered findings analysis (Groq/OpenAI/Gemini/Ollama) |
| `--ai-consensus` | **[v8]** Multi-model consensus + disagreement flagging |
| `--attack-paths` | **[v8]** MITRE ATT&CK kill-chain attack path generation |
| `--ai-remediate` | **[v8]** Per-finding remediation + CVSSv3 scoring |

</details>

<details>
<summary><strong>Output & Integrations</strong></summary>

| Flag | Description |
|---|---|
| `--output-format` | `all` / `html` / `json` / `md` / `pdf` / `sarif` |
| `--pdf-report` | **[v8]** Export pentest-ready PDF report |
| `--sarif` | Export SARIF 2.1.0 report |
| `--jira URL:EMAIL:TOKEN:PROJECT` | **[v8]** Push findings to Jira |
| `--gh-issues TOKEN:OWNER/REPO` | **[v8]** Push findings to GitHub Issues |
| `--siem URL:TOKEN[:type]` | **[v8]** Stream to Splunk/Elastic HEC |
| `--notify URL` | Webhook alerts (Slack/Discord/HTTPS) |
| `--diff A.json B.json` | Compare two scan reports |

</details>

<details>
<summary><strong>GUI & Performance</strong></summary>

| Flag | Description |
|---|---|
| `--gui` | **[v8]** Launch local desktop GUI |
| `--gui-port N` | GUI port (default: 7117) |
| `--timeout N` | Per-operation timeout in seconds (default: 30) |
| `--threads N` | Thread pool size (default: 20) |
| `--async-concurrency N` | Async port scan concurrency (default: 1000) |
| `--rate-limit N` | Seconds between requests (default: 0) |
| `--resume DIR` | Resume interrupted scan from checkpoint |
| `--profile` | `standard` / `full_suite` / `stealth` |
| `--exclude` | Comma-separated phases to skip |

</details>

---

## Architecture

```
reconninja.py          ← CLI entry point
gui/app.py             ← Desktop GUI (Flask + SSE)
core/                  ← 43 scan modules
  orchestrator.py      ← 48-phase pipeline with resume + checkpointing
output/                ← report_html, reports, sarif_export, integrations
plugins/               ← drop-in .py extension modules
utils/                 ← models, helpers, logger, notify
tests/                 ← pytest suite
```

---

## Version History

| Version | Highlights |
|---|---|
| **8.0.0** | GUI, 13 new modules, AI consensus+attack paths+remediation, PDF/Jira/SIEM, 17 bug fixes |
| 7.1.0 | Critical import bug fix (all v7 phases were NameError) |
| 7.0.0 | 19 new modules: cloud meta, GraphQL, JWT, ASN, supply chain, K8s, DB exposure, SMTP, SNMP, LDAP, DevOps, GreyNoise, typosquat, Censys |
| 6.0.0 | Resume/checkpoint, scan diff, email security, breach check, SARIF export, plugins |
| 5.0.0 | Shodan, VirusTotal, WHOIS, Wayback, SSL, GitHub OSINT, JS extractor, cloud buckets, WAF, CORS |

---

## License

MIT — For authorized security testing only.
