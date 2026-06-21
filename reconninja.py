#!/usr/bin/env python3
r"""
ReconNinja v{VERSION} — CLI Entrypoint
All v8.4.x flags preserved. --classic mode: identical sequential behaviour.
New v9 flags marked with  ▸ v9  in --help output.
"""
from __future__ import annotations

from utils.models import ScanConfig, NmapOptions, ScanProfile
from info import __version__
import argparse
import os
import sys

VERSION = __version__

BANNER = rf"""
 ____  _____ ____ ___  _   _  _   _ ___ _   _     _
|  _ \| ____/ ___/ _ \| \ | || \ | |_ _| \ | |   / \
| |_) |  _|| |  | | | |  \| ||  \| || ||  \| |  / _ \
|  _ <| |__| |__| |_| | |\  || |\  || || |\  | / ___ \
|_| \_\_____\____\___/|_| \_||_| \_|___|_| \_|/_/   \_\

       v{VERSION}  ─  Autonomous Security Recon Agent
       ExploitCraft / HackerInc ReconNinja Project
"""


# ─── Argument parser ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    """Legacy combined parser — kept for backwards compat with tests that
    introspect _build_parser(). Use _build_scan_parser / _build_plugin_parser
    / _build_resume_parser / _build_mcp_parser for actual CLI dispatch."""
    p = _build_scan_parser()
    return p


def _build_scan_parser() -> argparse.ArgumentParser:
    """Top-level scan parser. v10 fix: this parser has NO subparsers — the
    pre-dispatch in main() handles 'plugin' / 'resume' / 'mcp-server' as
    separate subcommand parsers. This means `reconninja example.com --nuclei`
    works (was broken in v9 because the subparser consumed 'example.com' as
    a subcommand name and errored)."""
    p = argparse.ArgumentParser(
        prog="reconninja",
        description=f"ReconNinja v{__version__} — Autonomous Security Reconnaissance",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"ReconNinja v{__version__}")
    p.add_argument("--check-tools", action="store_true",
                   help="Check which external tools (nmap, nuclei, rustscan, etc.) are installed")
    p.add_argument("--update", action="store_true",
                   help="Self-update ReconNinja via git pull (or GitHub release zip fallback)")
    p.add_argument("--force-update", action="store_true",
                   help="Force update even if already on the latest version")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                   help="Diff two scan state.json files and print new/resolved findings")
    p.add_argument("--gui", action="store_true",
                   help="Launch the local Flask GUI (browser-based scan launcher)")

    # Scan args (target + ~120 flags)
    _add_scan_args(p)
    return p


def _build_plugin_parser() -> argparse.ArgumentParser:
    """Parser for `reconninja plugin [list | install <name> | registry]`."""
    p = argparse.ArgumentParser(
        prog="reconninja plugin",
        description="ReconNinja plugin management",
    )
    sub = p.add_subparsers(dest="plugin_cmd", required=True)
    sub.add_parser("list",     help="List installed plugins")
    pi = sub.add_parser("install", help="Install plugin from community registry")
    pi.add_argument("plugin_name")
    sub.add_parser("registry", help="Browse community registry")
    return p


def _build_resume_parser() -> argparse.ArgumentParser:
    """Parser for `reconninja resume <state_file>`."""
    p = argparse.ArgumentParser(
        prog="reconninja resume",
        description="Resume a ReconNinja scan from a saved state file",
    )
    p.add_argument("state_file", help="Path to state.json file")
    return p


def _build_mcp_parser() -> argparse.ArgumentParser:
    """Parser for `reconninja mcp-server [--port N] [--bind ADDR] [--token T]`."""
    p = argparse.ArgumentParser(
        prog="reconninja mcp-server",
        description="Start ReconNinja as an MCP server (JSON-RPC over SSE)",
    )
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--bind", default="127.0.0.1",
                   help="Bind address (default 127.0.0.1; use 0.0.0.0 with caution)")
    p.add_argument("--token", default="",
                   help="Bearer token required on every request (recommended for 0.0.0.0)")
    return p


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    # ── Core ──────────────────────────────────────────────────────────────────
    p.add_argument("target", nargs="?", help="Target domain or IP")
    p.add_argument("--profile",
                   help="Scan profile: fast/standard/thorough/stealth/custom/full_suite/web_only/port_only",
                   choices=["fast","standard","thorough","stealth","custom","full_suite","web_only","port_only"],
                   default="standard")
    p.add_argument("--output-dir",    default="reports", metavar="DIR",
                   help="Output directory for reports (default: reports)")
    p.add_argument("--output-format", choices=["all","json","html","md"], default="all",
                   help="Report output format: all/json/html/md (default: all)")
    p.add_argument("--global-timeout",type=int, default=30,
                   help="Global per-request timeout in seconds (default: 30)")
    p.add_argument("--threads",       type=int, default=20,
                   help="Worker threads for parallel tasks (default: 20)")
    p.add_argument("--wordlist-size", choices=["small","medium","large"], default="medium",
                   help="Wordlist size for directory brute-force: small/medium/large (default: medium)")
    p.add_argument("--exclude-phases",nargs="*", default=[], metavar="PHASE",
                   help="Phases to skip even if their flag is set")

    # ── Nmap ──────────────────────────────────────────────────────────────────
    p.add_argument("--all-ports",     action="store_true",
                   help="Scan all 65535 ports instead of top-N (-p-)")
    p.add_argument("--top-ports",     type=int, default=1000,
                   help="Number of top ports to scan (default: 1000)")
    p.add_argument("--no-scripts",    action="store_true",
                   help="Disable nmap default scripts (-sC)")
    p.add_argument("--os-detection",  action="store_true",
                   help="Enable nmap OS detection (-O)")
    p.add_argument("--timing",        choices=["T1","T2","T3","T4","T5"], default="T4",
                   help="Nmap timing template T1 (slowest/stealthy) to T5 (fastest/noisy), default T4")
    p.add_argument("--stealth",       action="store_true",
                   help="Use SYN stealth scan (-sS, requires root)")
    p.add_argument("--aggressive",    action="store_true",
                   help="Enable aggressive scan (-A: OS, version, scripts, traceroute)")
    p.add_argument("--script-args",   default=None, metavar="ARGS",
                   help="Pass custom args to nmap scripts (--script-args)")

    # ── Discovery ─────────────────────────────────────────────────────────────
    p.add_argument("--subdomains",    action="store_true", dest="run_subdomains",
                   help="Run subdomain enumeration via subfinder/amass/crt.sh")
    p.add_argument("--rustscan",      action="store_true", dest="run_rustscan",
                   help="Run rustscan for fast port discovery before nmap")
    p.add_argument("--masscan",       action="store_true", dest="run_masscan",
                   help="Run masscan for high-speed port scan (requires root)")
    p.add_argument("--masscan-rate",  type=int, default=5000,
                   help="Masscan packet rate (default: 5000 pps)")
    p.add_argument("--aquatone",      action="store_true", dest="run_aquatone",
                   help="Run aquatone for web screenshots across discovered hosts")

    # ── Web ───────────────────────────────────────────────────────────────────
    p.add_argument("--httpx",         action="store_true", dest="run_httpx",
                   help="Run httpx to probe HTTP/HTTPS services and fingerprint web tech")
    p.add_argument("--whatweb",       action="store_true", dest="run_whatweb",
                   help="Run whatweb to identify web technologies and CMS")
    p.add_argument("--nikto",         action="store_true", dest="run_nikto",
                   help="Run nikto web server vulnerability scanner")
    p.add_argument("--feroxbuster",   action="store_true", dest="run_feroxbuster",
                   help="Run feroxbuster for recursive directory and file brute-forcing")
    p.add_argument("--nuclei",        action="store_true", dest="run_nuclei",
                   help="Run nuclei vulnerability scanner with community templates")
    p.add_argument("--cve-lookup",    action="store_true", dest="run_cve_lookup",
                   help="Look up CVEs for discovered service versions via NVD API")
    p.add_argument("--nvd-key",       default="", metavar="KEY",
                   help="NVD API key for higher rate limits on CVE lookups")
    p.add_argument("--waf",           action="store_true", dest="run_waf",
                   help="Detect WAF/CDN protecting the target")
    p.add_argument("--cors",          action="store_true", dest="run_cors",
                   help="Scan for CORS misconfiguration on discovered endpoints")
    p.add_argument("--js-extract",    action="store_true", dest="run_js_extract",
                   help="Extract secrets, endpoints, and tokens from JavaScript files")

    # ── AI (v8) ───────────────────────────────────────────────────────────────
    p.add_argument("--ai-analysis",   action="store_true", dest="run_ai_analysis",
                   help="Run AI-powered analysis of scan findings (requires --ai-key)")
    p.add_argument("--ai-provider",   choices=["groq","openai","gemini","ollama"], default="groq",
                   help="AI provider for analysis: groq/openai/gemini/ollama (default: groq)")
    p.add_argument("--ai-key",        default="", metavar="KEY",
                   help="API key for AI provider (or set RECONNINJA_AI_KEY env var)")
    p.add_argument("--ai-model",      default="", metavar="MODEL",
                   help="Override the default AI model for the selected provider")
    p.add_argument("--ai-consensus",  action="store_true", dest="run_ai_consensus",
                   help="Run multi-model AI consensus analysis across findings")
    p.add_argument("--attack-paths",  action="store_true", dest="run_attack_paths",
                   help="Generate AI-assisted attack path hypotheses from findings")
    p.add_argument("--ai-remediate",  action="store_true", dest="run_ai_remediate",
                   help="Generate AI-powered remediation recommendations for findings")

    # ── Intelligence ──────────────────────────────────────────────────────────
    p.add_argument("--shodan",        action="store_true", dest="run_shodan",
                   help="Query Shodan for host intelligence and exposed services")
    p.add_argument("--shodan-key",    default="", metavar="KEY",
                   help="Shodan API key (or set SHODAN_KEY env var)")
    p.add_argument("--virustotal",    action="store_true", dest="run_virustotal",
                   help="Query VirusTotal for domain/IP reputation and detection stats")
    p.add_argument("--vt-key",        default="", metavar="KEY",
                   help="VirusTotal API key")
    p.add_argument("--whois",         action="store_true", dest="run_whois",
                   help="Perform WHOIS lookup for registrar, expiry, and nameserver info")
    p.add_argument("--wayback",       action="store_true", dest="run_wayback",
                   help="Query Wayback Machine for historical URLs and interesting paths")
    p.add_argument("--ssl",           action="store_true", dest="run_ssl",
                   help="Scan SSL/TLS configuration for weak ciphers, expired certs, and misconfigs")
    p.add_argument("--github-osint",  action="store_true", dest="run_github_osint",
                   help="Search GitHub for leaked secrets, API keys, and sensitive code")
    p.add_argument("--github-token",  default="", metavar="TOKEN",
                   help="GitHub personal access token for authenticated API searches")
    p.add_argument("--cloud-buckets", action="store_true", dest="run_cloud_buckets",
                   help="Enumerate public cloud storage buckets (S3, GCS, Azure Blob)")
    p.add_argument("--dns-zone",      action="store_true", dest="run_dns_zone",
                   help="Attempt DNS zone transfer (AXFR) against discovered nameservers")
    p.add_argument("--email-security",action="store_true", dest="run_email_security",
                   help="Check email security: SPF, DKIM, DMARC, and MX record analysis")
    p.add_argument("--breach-check",  action="store_true", dest="run_breach_check",
                   help="Check if email addresses appear in known data breaches (HIBP)")
    p.add_argument("--hibp-key",      default="", metavar="KEY",
                   help="Have I Been Pwned API key for breach lookup")
    p.add_argument("--cloud-meta",    action="store_true", dest="run_cloud_meta",
                   help="Probe cloud metadata endpoints (AWS/Azure/GCP IMDS)")
    p.add_argument("--graphql",       action="store_true", dest="run_graphql",
                   help="Discover and fingerprint GraphQL endpoints, test introspection")
    p.add_argument("--jwt-scan",      action="store_true", dest="run_jwt_scan",
                   help="Scan for JWT vulnerabilities: alg:none, weak secrets, misconfigs")
    p.add_argument("--asn-map",       action="store_true", dest="run_asn_map",
                   help="Map target ASN and discover associated IP ranges and peers")
    p.add_argument("--supply-chain",  action="store_true", dest="run_supply_chain",
                   help="Analyse npm/PyPI supply chain risk for detected dependencies")
    p.add_argument("--k8s-probe",     action="store_true", dest="run_k8s_probe",
                   help="Probe Kubernetes API server and cluster components")
    p.add_argument("--db-exposure",   action="store_true", dest="run_db_exposure",
                   help="Check for exposed databases: Redis, MongoDB, Elasticsearch, etc.")
    p.add_argument("--smtp-enum",     action="store_true", dest="run_smtp_enum",
                   help="Enumerate SMTP users via VRFY/EXPN/RCPT on port 25")
    p.add_argument("--snmp-scan",     action="store_true", dest="run_snmp_scan",
                   help="SNMP community string bruteforce and MIB enumeration")
    p.add_argument("--ldap-enum",     action="store_true", dest="run_ldap_enum",
                   help="Enumerate LDAP for users, groups, and directory structure")
    p.add_argument("--devops-scan",   action="store_true", dest="run_devops_scan",
                   help="Scan for exposed DevOps tools: Jenkins, GitLab, Terraform state, etc.")
    p.add_argument("--greynoise",     action="store_true", dest="run_greynoise",
                   help="Enrich IPs with GreyNoise threat intelligence context")
    p.add_argument("--greynoise-key", default="", metavar="KEY",
                   help="GreyNoise API key")
    p.add_argument("--typosquat",     action="store_true", dest="run_typosquat",
                   help="Discover typosquatting domains that impersonate the target")
    p.add_argument("--censys",        action="store_true", dest="run_censys",
                   help="Query Censys for internet-wide scan data on target hosts")
    p.add_argument("--censys-api-id", default="", metavar="ID",
                   help="Censys API ID (or set CENSYS_API_ID env var)")
    p.add_argument("--censys-api-secret", default="", metavar="SECRET",
                   help="Censys API secret (or set CENSYS_API_SECRET env var)")
    p.add_argument("--dns-history",   action="store_true", dest="run_dns_history",
                   help="Retrieve historical DNS records to find past IPs and infrastructure")
    p.add_argument("--sarif-export",  action="store_true", dest="run_sarif_export",
                   help="Export findings in SARIF format for GitHub Code Scanning integration")
    p.add_argument("--api-fuzz",      action="store_true", dest="run_api_fuzz",
                   help="Fuzz REST API endpoints for injection, auth bypass, and IDOR")
    p.add_argument("--oauth-scan",    action="store_true", dest="run_oauth_scan",
                   help="Scan OAuth flows for misconfigurations: open redirect, token leak")
    p.add_argument("--web-vulns",     action="store_true", dest="run_web_vulns",
                   help="Test for common web vulnerabilities: SQLi, XSS, SSRF, path traversal")
    p.add_argument("--open-redirect", action="store_true", dest="run_open_redirect",
                   help="Scan for open redirect vulnerabilities in URL parameters")
    p.add_argument("--linkedin",      action="store_true", dest="run_linkedin",
                   help="OSINT: collect employee names and roles from LinkedIn")
    p.add_argument("--paste-monitor", action="store_true", dest="run_paste_monitor",
                   help="Monitor pastebin sites for target domain mentions and credential leaks")
    p.add_argument("--se-osint",      action="store_true", dest="run_se_osint",
                   help="Social engineering OSINT: employee info, org chart, email formats")
    p.add_argument("--apk",           default=None, dest="apk_path", metavar="PATH",
                   help="Path to an APK file for static mobile security analysis")
    p.add_argument("--app-store",     action="store_true", dest="run_app_store",
                   help="Search App Store and Google Play for target app listings")
    p.add_argument("--anon-detect",   action="store_true", dest="run_anon_detect",
                   help="Detect Tor exit nodes, VPN exit IPs, and proxies serving the target")
    p.add_argument("--dns-leak",      action="store_true", dest="run_dns_leak",
                   help="Test for DNS leak vulnerabilities exposing internal infrastructure")
    p.add_argument("--web3",          action="store_true", dest="run_web3_scan",
                   help="Scan for Web3 assets: smart contracts, wallets, DeFi endpoints")
    p.add_argument("--ens",           action="store_true", dest="run_ens_lookup",
                   help="Resolve Ethereum Name Service (ENS) domains to wallet addresses")
    p.add_argument("--notify",        default="", dest="notify_url", metavar="URL",
                   help="Webhook URL for real-time finding notifications (Slack/Discord/Teams)")
    p.add_argument("--pdf",           action="store_true", dest="run_pdf_report",
                   help="Generate a PDF report in addition to HTML/JSON/MD outputs")

    # ── v8 compat ─────────────────────────────────────────────────────────────
    p.add_argument("--gui-port",       type=int, default=7117, metavar="PORT",
                   help="Port for the local GUI server (default: 7117)")

    # ── ▸ v9 — Agent mode ─────────────────────────────────────────────────────
    p.add_argument("--agent",         action="store_true", dest="agent_mode",
                   help="▸ v9  LLM-driven adaptive routing (SupervisorAgent)")
    p.add_argument("--classic",       action="store_true", dest="classic_mode",
                   help="▸ v9  Sequential v8-compatible mode (no scheduler)")
    p.add_argument("--require-approval", action="store_true",
                   help="▸ v9  Pause for operator approval before each supervisor decision")
    p.add_argument("--agent-budget",  type=int, default=50, metavar="N",
                   help="▸ v9  Max LLM calls supervisor may make (default: 50)")
    p.add_argument("--parallel-phases", type=int, default=4, metavar="N",
                   help="▸ v9  Phase scheduler worker threads (default: 4)")

    # ── ▸ v9 — New modules ────────────────────────────────────────────────────
    p.add_argument("--ad-recon",      action="store_true", dest="run_ad_recon",
                   help="▸ v9  Active Directory: Kerberoast, AS-REP, ACL, delegation, BloodHound")
    p.add_argument("--ad-dc",         default="", metavar="IP",
                   help="Domain controller IP or hostname for AD recon")
    p.add_argument("--ad-domain",     default="", metavar="DOMAIN",
                   help="Active Directory domain name (e.g. corp.example.com)")
    p.add_argument("--ad-user",       default="", metavar="USER",
                   help="AD username for authenticated enumeration")
    p.add_argument("--ad-password",   default="", metavar="PASS",
                   help="AD password for authenticated enumeration")
    p.add_argument("--ad-bloodhound-output", default="ad_data", metavar="DIR",
                   help="Output directory for BloodHound JSON collection (default: ad_data)")
    p.add_argument("--cloud-deep",    action="store_true", dest="run_cloud_deep",
                   help="▸ v9  Deep cloud: AWS S3/IAM/ECR, Azure Blob, GCP/Firebase")
    p.add_argument("--llm-recon",     action="store_true", dest="run_llm_recon",
                   help="▸ v9  Discover exposed AI endpoints (Ollama, Qdrant, MCP, OpenWebUI)")
    p.add_argument("--iot-scan",      action="store_true", dest="run_iot_scan",
                   help="▸ v9  OT/ICS protocol scan (Modbus, DNP3, BACnet, EtherNet/IP)")
    p.add_argument("--container-deep",action="store_true", dest="run_container_deep",
                   help="▸ v9  Container/K8s deep scan (Docker socket, kubelet, etcd, RBAC)")
    p.add_argument("--wireless-osint",action="store_true", dest="run_wireless_osint",
                   help="▸ v9  Passive wireless OSINT via Wigle API")
    p.add_argument("--wigle-token",   default="", metavar="TOKEN",
                   help="▸ v9  Wigle.net API token")
    p.add_argument("--darkweb-osint", action="store_true", dest="run_darkweb_osint",
                   help="▸ v9  Dark web OSINT (ransomwatch, Telegram)")
    p.add_argument("--telegram-token",default="", metavar="TOKEN",
                   help="Telegram bot token for dark web channel monitoring")

    # ── ▸ v9 — AI upgrades ────────────────────────────────────────────────────
    p.add_argument("--correlation",   action="store_true", dest="run_correlation",
                   help="▸ v9  Agentic correlation: CorrelationAgent→HypothesisAgent→ReportAgent")
    p.add_argument("--local-llm-url", default="http://localhost:11434", metavar="URL",
                   help="▸ v9  Ollama/llama.cpp URL (default: http://localhost:11434)")
    p.add_argument("--epss-threshold",type=float, default=0.0, metavar="FLOAT",
                   help="▸ v9  Suppress findings below EPSS score (e.g. 0.05)")

    # ── ▸ v9 — Output & integrations ──────────────────────────────────────────
    p.add_argument("--interactive-report", action="store_true", dest="run_interactive_report",
                   help="▸ v9  Interactive HTML report (D3 graph + MITRE heatmap + filter bar)")
    p.add_argument("--mcp-server",     action="store_true", dest="mcp_server_mode",
                   help="▸ v9  Start as MCP server for Claude Code / Cursor integration")
    p.add_argument("--mcp-server-port",type=int, default=8765, metavar="PORT",
                   help="Port for the MCP server (default: 8765)")
    p.add_argument("--defectdojo-url", default="", metavar="URL",
                   help="DefectDojo base URL for pushing findings")
    p.add_argument("--defectdojo-key", default="", metavar="KEY",
                   help="DefectDojo API token (or set DEFECTDOJO_KEY env var)")
    p.add_argument("--defectdojo-product", default="", metavar="NAME",
                   help="DefectDojo product name to push findings into")
    p.add_argument("--notion-token",   default="", metavar="TOKEN",
                   help="Notion integration token for database export")
    p.add_argument("--notion-db-id",   default="", metavar="ID",
                   help="Notion database ID to export findings into")
    p.add_argument("--obsidian-export",action="store_true", dest="run_obsidian_export",
                   help="▸ v9  Export to Obsidian vault as interlinked Markdown notes")
    p.add_argument("--obsidian-vault", default="vault", dest="obsidian_vault_path", metavar="PATH",
                   help="Path to Obsidian vault root directory (default: vault)")
    p.add_argument("--monitor",        action="store_true", dest="monitor_mode",
                   help="▸ v9  Continuous monitoring — re-runs scan on interval, diffs findings")
    p.add_argument("--monitor-interval",default="24h", metavar="INTERVAL",
                   help="▸ v9  Re-scan interval: 1h, 6h, 24h (default: 24h)")
    p.add_argument("--monitor-passive-only", action="store_true",
                   help="▸ v9  Monitoring: passive phases only")
    p.add_argument("--report-template",choices=["technical","executive","compliance"],
                   default="technical",
                   help="Report template style: technical/executive/compliance (default: technical)")
    p.add_argument("--compliance",     default="", dest="compliance_framework",
                   metavar="FRAMEWORK",
                   help="▸ v9  pci-dss | iso27001 | nist-csf")
    p.add_argument("--graph-export",   choices=["neo4j","graphml","json-ld"], default="",
                   help="▸ v9  Export ReconGraph format")
    p.add_argument("--neo4j-url",      default="bolt://localhost:7687", metavar="URL",
                   help="Neo4j bolt URL for graph export (default: bolt://localhost:7687)")

    # ── ▸ v9 — Scope enforcement ──────────────────────────────────────────────
    p.add_argument("--scope-file",     default="", metavar="PATH",
                   help="▸ v9  YAML file with allowed/excluded CIDRs and domains")
    p.add_argument("--scope-strict",   action="store_true",
                   help="▸ v9  Exit immediately on any out-of-scope attempt")
    p.add_argument("--exclude",        nargs="*", default=[], dest="exclude_targets",
                   metavar="TARGET")

    # ── ▸ v9 — Evidence ───────────────────────────────────────────────────────
    p.add_argument("--evidence",       action="store_true", dest="run_evidence",
                   help="▸ v9  Collect HTTP evidence with SHA-256 hashes")
    p.add_argument("--evidence-sign-key", default="", metavar="KEYID",
                   help="▸ v9  GPG key ID for signing evidence files")

    # ── ▸ v9 — Rate limiting ──────────────────────────────────────────────────
    p.add_argument("--rate-profile",   choices=["aggressive","standard","low-noise","paranoid"],
                   default="aggressive",
                   help="▸ v9  Request rate profile (default: aggressive = unlimited)")
    p.add_argument("--jitter",         type=float, default=0.0, metavar="SECS",
                   help="Random delay jitter added between requests (seconds, default: 0.0)")
    p.add_argument("--proxy-list",     default="", metavar="FILE",
                   help="File containing proxy list for request rotation (one per line)")

    # ── ▸ v9 — Observability ──────────────────────────────────────────────────
    p.add_argument("--log-format",     choices=["text","json"], default="text",
                   help="Log output format: text or json for SIEM ingestion (default: text)")
    p.add_argument("--metrics-port",   type=int, default=0, metavar="PORT",
                   help="▸ v9  Prometheus metrics port (0 = disabled)")
    p.add_argument("--otlp-endpoint",  default="", metavar="URL",
                   help="▸ v9  OpenTelemetry collector URL for traces")

    # ── ▸ v10.5 — Interactive menu / TUI ──────────────────────────────────────
    p.add_argument("--no-tui",         action="store_true",
                   help="▸ v9   Disable Textual TUI; use plain Rich output")
    p.add_argument("--tui",            action="store_true",
                   help="▸ v10.5  Launch the Textual TUI explicitly (otherwise no-args "
                        "shows the interactive numbered menu)")
    p.add_argument("--menu",           action="store_true",
                   help="▸ v10.5  Launch the fsociety-style interactive numbered menu "
                        "(this is the default when no args are given)")

    # ── ▸ v9 — Plugin registry ────────────────────────────────────────────────
    p.add_argument("--plugin-registry-url",
                   default="https://plugins.reconinja.dev", metavar="URL",
                   help="Community plugin registry URL (default: https://plugins.reconinja.dev)")


# ─── Config builder ───────────────────────────────────────────────────────────

def _build_config(args) -> ScanConfig:
    profile_map = {
        "fast":       ScanProfile.FAST,
        "standard":   ScanProfile.STANDARD,
        "thorough":   ScanProfile.THOROUGH,
        "stealth":    ScanProfile.STEALTH,
        "full_suite": ScanProfile.FULL_SUITE,
        "web_only":   ScanProfile.WEB_ONLY,
        "port_only":  ScanProfile.PORT_ONLY,
    }

    nmap_opts = NmapOptions(
        all_ports=args.all_ports,
        top_ports=args.top_ports,
        scripts=not args.no_scripts,
        os_detection=args.os_detection,
        aggressive=args.aggressive,
        stealth=args.stealth,
        timing=args.timing,
        script_args=args.script_args,
    )

    # Pull secrets from environment if not passed on CLI
    def _env(attr: str, env: str) -> str:
        return getattr(args, attr, "") or os.environ.get(env, "")

    cfg = ScanConfig(
        target            = args.target or "",
        profile           = profile_map.get(getattr(args, "profile", "standard"), ScanProfile.STANDARD),
        nmap_opts         = nmap_opts,
        output_dir        = args.output_dir,
        output_format     = args.output_format,
        global_timeout    = args.global_timeout,
        threads           = args.threads,
        wordlist_size     = args.wordlist_size,
        exclude_phases    = args.exclude_phases or [],
        masscan_rate      = args.masscan_rate,
        # discovery
        run_subdomains    = args.run_subdomains,
        run_rustscan      = args.run_rustscan,
        run_masscan       = args.run_masscan,
        run_aquatone      = args.run_aquatone,
        # web
        run_httpx         = args.run_httpx,
        run_whatweb       = args.run_whatweb,
        run_nikto         = args.run_nikto,
        run_feroxbuster   = args.run_feroxbuster,
        run_nuclei        = args.run_nuclei,
        run_cve_lookup    = args.run_cve_lookup,
        run_waf           = args.run_waf,
        run_cors          = args.run_cors,
        run_js_extract    = args.run_js_extract,
        nvd_key           = _env("nvd_key", "NVD_KEY"),
        # AI
        run_ai_analysis   = args.run_ai_analysis,
        ai_provider       = args.ai_provider,
        ai_key            = _env("ai_key", "RECONNINJA_AI_KEY"),
        ai_model          = args.ai_model,
        run_ai_consensus  = args.run_ai_consensus,
        run_attack_paths  = args.run_attack_paths,
        run_ai_remediate  = args.run_ai_remediate,
        # intel
        run_shodan        = args.run_shodan,
        shodan_key        = _env("shodan_key", "SHODAN_KEY"),
        run_virustotal    = args.run_virustotal,
        vt_key            = args.vt_key,
        run_whois         = args.run_whois,
        run_wayback       = args.run_wayback,
        run_ssl           = args.run_ssl,
        run_github_osint  = args.run_github_osint,
        github_token      = _env("github_token", "GITHUB_TOKEN"),
        run_cloud_buckets = args.run_cloud_buckets,
        run_dns_zone      = args.run_dns_zone,
        run_email_security= args.run_email_security,
        run_breach_check  = args.run_breach_check,
        hibp_key          = _env("hibp_key", "HIBP_KEY"),
        run_cloud_meta    = args.run_cloud_meta,
        run_graphql       = args.run_graphql,
        run_jwt_scan      = args.run_jwt_scan,
        run_asn_map       = args.run_asn_map,
        run_supply_chain  = args.run_supply_chain,
        run_k8s_probe     = args.run_k8s_probe,
        run_db_exposure   = args.run_db_exposure,
        run_smtp_enum     = args.run_smtp_enum,
        run_snmp_scan     = args.run_snmp_scan,
        run_ldap_enum     = args.run_ldap_enum,
        run_devops_scan   = args.run_devops_scan,
        run_greynoise     = args.run_greynoise,
        greynoise_key     = _env("greynoise_key", "GREYNOISE_KEY"),
        run_typosquat     = args.run_typosquat,
        run_censys        = args.run_censys,
        censys_api_id     = _env("censys_api_id", "CENSYS_API_ID"),
        censys_api_secret = _env("censys_api_secret", "CENSYS_API_SECRET"),
        run_dns_history   = args.run_dns_history,
        run_sarif_export  = args.run_sarif_export,
        run_api_fuzz      = args.run_api_fuzz,
        run_oauth_scan    = args.run_oauth_scan,
        run_web_vulns     = args.run_web_vulns,
        run_open_redirect = args.run_open_redirect,
        run_linkedin      = args.run_linkedin,
        run_paste_monitor = args.run_paste_monitor,
        run_se_osint      = args.run_se_osint,
        apk_path          = args.apk_path,
        run_app_store     = args.run_app_store,
        run_anon_detect   = args.run_anon_detect,
        run_dns_leak      = args.run_dns_leak,
        run_web3_scan     = args.run_web3_scan,
        run_ens_lookup    = args.run_ens_lookup,
        notify_url        = args.notify_url,
        run_pdf_report    = args.run_pdf_report,
        # ── v9 agent ──────────────────────────────────────────────────────────
        agent_mode          = args.agent_mode,
        classic_mode        = args.classic_mode,
        require_approval    = args.require_approval,
        agent_budget        = args.agent_budget,
        parallel_phases     = args.parallel_phases,
        # ── v9 modules ────────────────────────────────────────────────────────
        run_ad_recon            = args.run_ad_recon,
        ad_dc                   = args.ad_dc,
        ad_domain               = args.ad_domain,
        ad_user                 = args.ad_user,
        ad_password             = args.ad_password,
        ad_bloodhound_output    = args.ad_bloodhound_output,
        run_cloud_deep          = args.run_cloud_deep,
        run_llm_recon           = args.run_llm_recon,
        run_iot_scan            = args.run_iot_scan,
        run_container_deep      = args.run_container_deep,
        run_wireless_osint      = args.run_wireless_osint,
        wigle_api_token         = _env("wigle_token", "WIGLE_TOKEN"),
        run_darkweb_osint       = args.run_darkweb_osint,
        telegram_token          = _env("telegram_token", "TELEGRAM_TOKEN"),
        # ── v9 AI upgrades ────────────────────────────────────────────────────
        run_correlation         = args.run_correlation,
        local_llm_url           = args.local_llm_url,
        epss_threshold          = args.epss_threshold,
        # ── v9 output ─────────────────────────────────────────────────────────
        run_interactive_report  = args.run_interactive_report,
        mcp_server_mode         = args.mcp_server_mode,
        mcp_server_port         = args.mcp_server_port,
        defectdojo_url          = args.defectdojo_url,
        defectdojo_key          = _env("defectdojo_key", "DEFECTDOJO_KEY"),
        defectdojo_product      = args.defectdojo_product,
        notion_token            = _env("notion_token", "NOTION_TOKEN"),
        notion_db_id            = args.notion_db_id,
        run_obsidian_export     = args.run_obsidian_export,
        obsidian_vault_path     = args.obsidian_vault_path,
        monitor_mode            = args.monitor_mode,
        monitor_interval        = args.monitor_interval,
        monitor_passive_only    = args.monitor_passive_only,
        report_template         = args.report_template,
        compliance_framework    = args.compliance_framework,
        graph_export            = args.graph_export,
        neo4j_url               = args.neo4j_url,
        # ── v9 scope ──────────────────────────────────────────────────────────
        scope_file              = args.scope_file,
        scope_strict            = args.scope_strict,
        exclude_targets         = args.exclude_targets or [],
        # ── v9 evidence ───────────────────────────────────────────────────────
        run_evidence            = args.run_evidence,
        evidence_sign_key       = args.evidence_sign_key,
        # ── v9 rate ───────────────────────────────────────────────────────────
        rate_profile            = args.rate_profile,
        jitter                  = args.jitter,
        proxy_list              = args.proxy_list,
        # ── v9 observability ──────────────────────────────────────────────────
        log_format              = args.log_format,
        metrics_port            = args.metrics_port,
        otlp_endpoint           = args.otlp_endpoint,
        # ── v9 UX ─────────────────────────────────────────────────────────────
        no_tui                  = args.no_tui,
        plugin_registry_url     = args.plugin_registry_url,
    )

    _apply_profile(cfg)
    return cfg


def _apply_profile(cfg: "ScanConfig") -> None:
    p = cfg.profile
    if p == ScanProfile.FAST:
        cfg.run_subdomains = False
        cfg.nmap_opts.top_ports = 100
        cfg.nmap_opts.scripts = False
    elif p == ScanProfile.THOROUGH:
        cfg.run_subdomains = True
        cfg.run_httpx = True
        cfg.run_nuclei = True
        cfg.run_cve_lookup = True
        cfg.run_ssl = True
        cfg.nmap_opts.all_ports = True
        cfg.nmap_opts.version_detection = True
        cfg.run_correlation = True
        cfg.run_interactive_report = True
    elif p == ScanProfile.STEALTH:
        cfg.nmap_opts.stealth = True
        cfg.nmap_opts.timing = "T2"
        cfg.rate_profile = "low-noise"
        cfg.jitter = 0.3
    elif p == ScanProfile.FULL_SUITE:
        for attr in vars(cfg):
            if attr.startswith("run_") and not attr.startswith("run_ai_"):
                setattr(cfg, attr, True)
        cfg.run_correlation = True
        cfg.run_interactive_report = True
        cfg.nmap_opts.all_ports = True
    elif p == ScanProfile.WEB_ONLY:
        cfg.run_httpx = True
        cfg.run_whatweb = True
        cfg.run_nuclei = True
        cfg.run_feroxbuster = True
        cfg.run_cors = True
        cfg.run_js_extract = True
    elif p == ScanProfile.PORT_ONLY:
        cfg.run_rustscan = True


# ─── Entrypoint ───────────────────────────────────────────────────────────────

def main() -> None:
    # ── Pre-dispatch: separate top-level subcommands from a bare `reconninja
    #    <target> --flags` invocation.  v9 used subparsers on the same root
    #    parser as the `target` positional, which made `reconninja example.com`
    #    fail with "invalid choice: 'example.com' (choose from scan, plugin,
    #    resume, mcp-server)".  v10 pre-checks sys.argv for a known subcommand
    #    and dispatches accordingly; if no subcommand is present, everything is
    #    treated as a scan.
    SUBCOMMANDS = {"scan", "plugin", "resume", "mcp-server"}
    argv = sys.argv[1:]
    subcommand = None
    subcommand_idx = None
    for i, a in enumerate(argv):
        if a.startswith("-"):
            # Some flags take values — skip the value too if it's a known
            # value-taking flag. We don't need to be perfect here, just need
            # to find the first bare positional that could be a subcommand.
            continue
        if a in SUBCOMMANDS:
            subcommand = a
            subcommand_idx = i
        break

    if subcommand == "plugin":
        # Parse plugin subcommand
        plugin_parser = _build_plugin_parser()
        args = plugin_parser.parse_args(argv[subcommand_idx + 1:])
        _cmd_plugin(args)
        return

    if subcommand == "resume":
        resume_parser = _build_resume_parser()
        args = resume_parser.parse_args(argv[subcommand_idx + 1:])
        from core.resume import load_state, set_active_config
        from core.orchestrator_v9 import run_scan
        loaded = load_state(args.state_file)
        if loaded is None:
            sys.exit(1)
        result, cfg, out_folder = loaded
        set_active_config(cfg)
        print(f"[resume] Resuming: {result.target}")
        run_scan(cfg)
        return

    if subcommand == "mcp-server":
        mcp_parser = _build_mcp_parser()
        args = mcp_parser.parse_args(argv[subcommand_idx + 1:])
        from core.mcp_server import start_mcp_server
        from utils.models import ScanConfig
        cfg = ScanConfig(target="", mcp_server_port=args.port)
        start_mcp_server(args.port, cfg,
                         bind=getattr(args, "bind", "127.0.0.1"),
                         token=getattr(args, "token", ""))
        return

    if subcommand == "scan":
        # Strip the 'scan' literal and parse the rest as a scan.
        argv = argv[:subcommand_idx] + argv[subcommand_idx + 1:]

    # ── Build the scan parser (no subparsers — just positionals + flags) ────
    parser = _build_scan_parser()
    args, _ = parser.parse_known_args(argv)

    # ── Meta-commands (do not print banner) ──────────────────────────────────
    if getattr(args, "check_tools", False):
        _cmd_check_tools()
        return

    if getattr(args, "update", False) or getattr(args, "force_update", False):
        _cmd_update(force=getattr(args, "force_update", False))
        return

    if getattr(args, "diff", None):
        _cmd_diff(args.diff[0], args.diff[1])
        return

    if getattr(args, "gui", False):
        _cmd_gui(getattr(args, "gui_port", 7117))
        return

    # ── v10.5: --tui explicitly launches the Textual TUI ────────────────────
    if getattr(args, "tui", False):
        try:
            from gui.tui import launch_tui, TEXTUAL_AVAILABLE
            if TEXTUAL_AVAILABLE:
                sys.exit(launch_tui())
            print("[gui] Textual is not installed — run `pip install 'reconninja[tui]'`")
            sys.exit(1)
        except ImportError as e:
            print(f"[gui] TUI unavailable: {e}")
            sys.exit(1)

    # ── v10.5: --menu explicitly launches the fsociety-style numbered menu ──
    if getattr(args, "menu", False):
        try:
            from gui.menu import launch_menu
            sys.exit(launch_menu())
        except ImportError as e:
            print(f"[menu] Interactive menu unavailable: {e}")
            sys.exit(1)

    # ── v10.5: no-target invocation launches the fsociety-style menu ────────
    # The interactive menu is the new default. It needs no extra deps (just
    # Rich, which is already required) and gives the user a 19-option picker.
    # `--no-tui` reverts to the v10.0 behaviour of printing banner + help.
    if not args.target:
        if not getattr(args, "no_tui", False):
            # Launch the interactive menu (or TUI if --tui was passed).
            try:
                from gui.menu import launch_menu
                sys.exit(launch_menu())
            except ImportError as e:
                # Menu depends only on Rich (already required) so this should
                # never happen — but fall back gracefully if it does.
                print(f"[menu] Interactive menu unavailable: {e}")
                print(BANNER)
                parser.print_help()
                sys.exit(0)
        # --no-tui: print banner + help (the v10 behaviour)
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    print(BANNER)

    cfg = _build_config(args)

    # MCP server mode (via scan flags)
    if cfg.mcp_server_mode:
        from core.mcp_server import start_mcp_server
        start_mcp_server(cfg.mcp_server_port, cfg)
        return

    # Continuous monitoring
    if cfg.monitor_mode:
        from core.monitor import run_monitor_loop
        run_monitor_loop(cfg)
        return

    # Prometheus metrics
    if cfg.metrics_port > 0:
        _start_metrics(cfg.metrics_port)

    # Main scan
    from core.orchestrator_v9 import run_scan
    from core.resume import set_active_config
    set_active_config(cfg)
    run_scan(cfg)


def _cmd_plugin(args) -> None:
    from plugins import discover_plugins, install_plugin, list_registry_plugins
    registry_url = getattr(args, "plugin_registry_url", "https://plugins.reconinja.dev")

    if args.plugin_cmd == "list":
        plugins = discover_plugins()
        print(f"Installed plugins ({len(plugins)}):")
        for name, _ in plugins:
            print(f"  ✔ {name}")

    elif args.plugin_cmd == "install":
        install_plugin(args.plugin_name, registry_url)

    elif args.plugin_cmd == "registry":
        plugins = list_registry_plugins(registry_url)
        print(f"Community registry ({len(plugins)} plugins):")
        for p in plugins:
            print(f"  {p.get('name'):30} {p.get('description','')}")

    else:
        print("Usage: reconninja plugin [list | install <name> | registry]")


def _start_metrics(port: int) -> None:
    try:
        from prometheus_client import start_http_server  # type: ignore
        import threading
        threading.Thread(target=start_http_server, args=(port,), daemon=True).start()
        print(f"[metrics] Prometheus metrics → http://localhost:{port}/metrics")
    except ImportError:
        print("[metrics] prometheus_client not installed — metrics disabled")


# ─── v10 meta-commands ────────────────────────────────────────────────────────

def _cmd_check_tools() -> None:
    """Print a table of which external tools are installed and which are missing."""
    from utils.helpers import tool_exists
    from rich.console import Console
    from rich.table import Table
    console = Console()
    table = Table(title=f"ReconNinja v{VERSION} — External Tool Inventory",
                  show_header=True, header_style="bold cyan")
    table.add_column("Tool")
    table.add_column("Installed")
    table.add_column("Used by")
    tools = [
        ("nmap",         "ports.py (nmap_worker)"),
        ("masscan",      "ports.py (run_masscan)"),
        ("rustscan",     "ports.py (run_rustscan)"),
        ("subfinder",    "subdomains.py (_subfinder)"),
        ("amass",        "subdomains.py (_amass)"),
        ("assetfinder",  "subdomains.py (_assetfinder)"),
        ("httpx",        "web.py (run_httpx) — note: also accepts httpx-toolkit"),
        ("whatweb",      "web.py (run_whatweb)"),
        ("nikto",        "web.py (run_nikto)"),
        ("feroxbuster",  "web.py (run_dir_scan)"),
        ("nuclei",       "vuln.py (run_nuclei)"),
        ("aquatone",     "vuln.py (run_aquatone)"),
        ("gowitness",    "vuln.py (run_gowitness)"),
        ("wafw00f",      "waf_detect.py (detect_waf)"),
        ("dig",          "dns_zone_transfer.py"),
        ("whois",        "whois_lookup.py"),
        ("gpg",          "scope_evidence.py (evidence signing)"),
        ("bloodhound-python", "ad_recon.py (_run_bloodhound)"),
    ]
    installed = 0
    for name, used_by in tools:
        ok = tool_exists(name) or name in ("httpx",) and tool_exists("httpx-toolkit")
        if ok:
            installed += 1
        table.add_row(name,
                      "[green]✔ installed[/green]" if ok else "[red]✗ missing[/red]",
                      used_by)
    console.print(table)
    print(f"\n{installed}/{len(tools)} tools installed.")
    if installed < len(tools):
        print("Tip: run `bash install.sh` to install missing tools on Debian/Arch/Fedora.")


def _cmd_update(force: bool = False) -> None:
    """Trigger core.updater.run_update."""
    try:
        from core.updater import run_update, print_update_status
        print_update_status()
        run_update(force=force)
    except Exception as e:
        print(f"[update] failed: {type(e).__name__}: {e}")
        sys.exit(1)


def _cmd_diff(old_path: str, new_path: str) -> None:
    """Diff two state.json files and print new/resolved findings."""
    import json
    from pathlib import Path
    from rich.console import Console
    from rich.table import Table

    console = Console()
    try:
        old = json.loads(Path(old_path).read_text())
        new = json.loads(Path(new_path).read_text())
    except Exception as e:
        print(f"[diff] failed to load state files: {e}")
        sys.exit(1)

    old_result = old.get("result", old)
    new_result = new.get("result", new)
    old_titles = {f.get("title") for f in old_result.get("nuclei_findings", [])}
    new_titles = {f.get("title") for f in new_result.get("nuclei_findings", [])}

    new_findings = [f for f in new_result.get("nuclei_findings", [])
                    if f.get("title") not in old_titles]
    resolved = [f for f in old_result.get("nuclei_findings", [])
                if f.get("title") not in new_titles]

    table = Table(title="ReconNinja v10 — Scan Diff", show_header=True,
                  header_style="bold cyan")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_row("New findings",      str(len(new_findings)))
    table.add_row("Resolved findings", str(len(resolved)))
    table.add_row("Old subdomains",    str(len(old_result.get("subdomains", []))))
    table.add_row("New subdomains",    str(len(new_result.get("subdomains", []))))
    console.print(table)

    if new_findings:
        print("\nNew findings:")
        for f in new_findings[:20]:
            print(f"  [{(f.get('severity') or 'info').upper()}] {f.get('title')} @ {f.get('target')}")
    if resolved:
        print("\nResolved findings:")
        for f in resolved[:20]:
            print(f"  [{(f.get('severity') or 'info').upper()}] {f.get('title')}")


def _cmd_gui(port: int) -> None:
    """Launch the local Flask GUI."""
    try:
        from gui.app import launch_gui
        launch_gui(port=port)
    except ImportError as e:
        print(f"[gui] Flask not installed — pip install flask. ({e})")
        sys.exit(1)
    except Exception as e:
        print(f"[gui] failed to start: {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
