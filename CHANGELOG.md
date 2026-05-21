# Changelog

---
## [9.1.0] — 2026-05-21 [PATCH]

### Bug Fixes
- **PYPL removed** — Removed deprecated PYPL code and references

---
## [9.0.0] — 2026-05-19 [MAJOR]

### ⚠ Generational architecture release.
All v8.4.x flags preserved. Use `--classic` for identical v8 sequential behaviour.

### Architecture
- **PhaseScheduler** — DAG parallel phase execution, 3–5× speedup on full-suite scans
- **SupervisorAgent** — LLM-driven adaptive routing (Groq/OpenAI/Gemini/Ollama)
- **ReconGraph** — Directed finding graph: hosts→ports→services→CVEs→cloud resources
- **`--agent`** — Autonomous agent mode
- **`--classic`** — Sequential v8-compatible mode
- **`--parallel-phases N`** — Scheduler worker threads (default: 4)

### New Modules (6)
- **`--ad-recon`** — Active Directory: Kerberoast, AS-REP, ACL abuse, delegation, BloodHound
- **`--cloud-deep`** — AWS S3/IAM/ECR, Azure Blob/AppService, GCP/Firebase
- **`--llm-recon`** — Exposed AI endpoints: Ollama, Qdrant, MCP, OpenWebUI, LiteLLM
- **`--iot-scan`** — OT/ICS: Modbus, DNP3, BACnet, EtherNet/IP, IEC61850 + NVD CVE correlation
- **`--container-deep`** — Docker socket, kubelet, etcd, kube-apiserver anonymous access
- **`--wireless-osint`** / **`--darkweb-osint`** — Wigle SSID OSINT + ransomwatch/Telegram

### AI Upgrades
- **`--correlation`** — CorrelationAgent→HypothesisAgent→ReportAgent pipeline, produces AttackChain objects with MITRE TTPs and probability scores
- **EPSS + CVSSv4 + REI** — FIRST.org EPSS scores, NVD CVSSv4 enrichment, ReconNinja Exploitability Index (REI = 0.4×EPSS + 0.3×CVSS + 0.3×context)
- **`--epss-threshold FLOAT`** — Suppress low-probability findings
- **`--local-llm-url`** — Route AI calls to Ollama/llama.cpp

### Output & Integrations
- **`--interactive-report`** — Self-contained HTML with D3 attack graph, MITRE heatmap, filterable findings table, dark/light mode
- **`--mcp-server`** — MCP server mode (Claude Code / Cursor native integration), 6 tools: scan/status/findings/graph/chains/report
- **`--defectdojo-url/key/product`** — Push findings to DefectDojo via REST API
- **`--notion-token/db-id`** — Export findings as Notion database pages (with EPSS, REI properties)
- **`--obsidian-export`** — Interlinked Markdown notes in Obsidian vault
- **`--monitor`** — Continuous monitoring with interval re-scan and finding diff alerts
- **`--graph-export [neo4j|graphml|json-ld]`** — ReconGraph export
- **`--compliance [pci-dss|iso27001|nist-csf]`** — Compliance gap mapping

### Plugin SDK v2
- **`@register` decorator** — Replaces manual PLUGIN_NAME globals
- **`ReconPlugin` base class** — `add_vuln()`, `add_error()`, `http_get()` helpers
- **CLI**: `reconninja plugin list|install <name>|registry`
- Full v8 plugin backwards compat retained

### Scope & Evidence
- **`--scope-file`** — YAML scope policy (CIDRs, domains, globs)
- **`--scope-strict`** — Exit on out-of-scope attempt
- **`--evidence`** — SHA-256 HTTP evidence capture + GPG signing
- Pre-flight scope validation on every scan

### Rate Limiting & Observability
- **`--rate-profile [aggressive|standard|low-noise|paranoid]`** — Named request rate profiles with jitter
- **`--metrics-port`** — Prometheus metrics endpoint
- **`--otlp-endpoint`** — OpenTelemetry traces
- **`--log-format json`** — Structured logging for SIEM ingestion

### New Dependencies
Required: `flask` (MCP server), `ldap3` (AD recon — was already optional, now required baseline)
Optional extras: `[ad]` (impacket, bloodhound), `[neo4j]`, `[metrics]`, `[tracing]`, `[tui]`

---
## [8.4.1] — 2026-05-17 [PATCH]

### Bug Fixes
- Internal fixes

## [8.4.0] — 2026-05-16 [PATCH]

### Bug Fixes (6 bugs fixed)

- **Bug 1 — `result.vuln_findings` AttributeError** (`output/integrations.py`, `core/orchestrator.py`): PDF export, SIEM push, Jira integration, and GitHub Issues push all referenced `result.vuln_findings` — an attribute that does not exist on `ReconResult`. This caused an `AttributeError` crash on every invocation of `--pdf-report`, `--jira`, `--gh-issues`, or `--siem`. Fixed: all references replaced with `result.nuclei_findings`.

- **Bug 2 — `result.open_ports` AttributeError** (`output/integrations.py`): `open_ports` is a property on `HostResult`, not `ReconResult`. PDF and HTML integrations called `result.open_ports` directly, crashing on any scan with hosts. Fixed: replaced with `[p for h in result.hosts for p in h.open_ports]` at the call site.

- **Bug 3 — `--output-format txt/pdf/sarif` silently skipped** (`core/orchestrator.py`): The CLI accepted `txt`, `pdf`, and `sarif` as valid `--output-format` choices but the report-generation block only handled `all`, `json`, `html`, and `md`. Selecting any of the three unhandled values produced zero output files with no error. Fixed: added explicit handling for `txt` (writes plain-text via `generate_markdown_report`), `pdf` (calls `export_pdf`), and `sarif` (calls `export_sarif`).

- **Bug 4 — `ai_config` never populated from CLI args** (`reconninja.py`): `ScanConfig.ai_config` was always `{}` because `build_config_from_args()` never set it. The orchestrator gates all three v8 AI features (`--ai-consensus`, `--attack-paths`, `--ai-remediate`) on `_ai_cfg` being truthy — so all three were permanently disabled regardless of `--ai-key` / `--ai-provider`. Fixed: `ai_config` is now built from `ai_provider`, `ai_key`, and `ai_model` when a key is present or provider is `ollama`.

- **Bug 5 — `--output` flag had no effect** (`core/orchestrator.py`): `ScanConfig.output_dir` was correctly set from `--output` but the orchestrator hardcoded `REPORTS_DIR = Path("reports")` and never read `cfg.output_dir`. All scans wrote to `reports/` regardless of the flag. Fixed: `out_folder` now uses `Path(cfg.output_dir)` as the base directory.

- **Bug 6 — `--top-ports 0` emitted alongside `-p-`** (`utils/models.py`): When the interactive builder set `all_ports=True`, it also set `top_ports=0` as a sentinel. `as_nmap_args()` checked `elif self.top_ports:` — `0` is falsy in Python so this accidentally worked, but only because `0 == False`. The correct intent is `> 0`. Fixed: changed to `elif self.top_ports > 0:` for clarity and correctness.

---

## [8.3.0] — 2026-05-02 [PATCH]

### Bug Fixes (14 bugs catalogued and resolved)

- **Bug 1 — `cfg.timeout` AttributeError** (`core/orchestrator.py`): All 13 v8 module calls passed `cfg.timeout` but `ScanConfig` only has `global_timeout`. Every v8 phase threw `AttributeError` at runtime. Fixed: replaced all occurrences with `cfg.global_timeout`.

- **Bug 2 — v8 phases ignored `--resume`** (`core/orchestrator.py`): All 13 v8 phases (api_fuzz, oauth_scan, web_vulns, open_redirect, linkedin, paste_monitor, se_osint, apk_scan, app_store, anon_detect, dns_leak, web3_scan, ens_lookup) had no `phases_completed` guard. On `--resume`, they all re-ran unconditionally. Fixed: added `"phase_id" not in result.phases_completed` guard to every v8 phase block.

- **Bug 3 — v8 result fields on wrong dataclass** (`utils/models.py`): The 15 v8 result fields (`api_fuzz`, `oauth_scan`, `web_vulns`, `open_redirect`, `linkedin`, `paste_monitor`, `se_osint`, `apk_scan`, `app_store`, `anon_detect`, `dns_leak`, `web3_scan`, `ens_lookup`, `attack_paths`, `remediations`) were defined on `ScanConfig` instead of `ReconResult`. Orchestrator wrote `result.api_fuzz = ...` as a dynamic attribute — invisible to `asdict()`, lost on `save_state()`, absent from all reports. Fixed: removed from `ScanConfig`, added as proper typed `list[dict]` fields on `ReconResult`.

- **Bug 4 — SMTP/SNMP never marked complete when ports absent** (`core/orchestrator.py`): Both phases appended to `result.phases_completed` inside the inner port-check `if` block. When ports 25/587/161 were closed, the outer resume guard (`"v7-smtp" not in result.phases_completed`) remained true forever, causing re-execution on every `--resume`. Fixed: moved `phases_completed.append` and `save_state()` outside the inner `if` for both phases.

- **Bug 5 — AI analysis banner hardcodes `v7.0.0`** (`core/orchestrator.py`): `_generate_ai_analysis()` opened its output with a hardcoded `"=== ReconNinja v7.0.0 AI Analysis ==="` banner. Fixed: now uses `f"v{VERSION}"`.

- **Bug 6 — `_v7()` helper dead code** (`core/orchestrator.py`): A `_v7(phase_id, flag, exclude_key, fn)` helper was defined in the orchestrator but never called — all v7 phases use inline `if` blocks instead. The dead function created a misleading expectation that phases used it. Fixed: removed the function, added a clarifying comment.

- **Bug 7 — Completion banner hardcodes `— v8.0.0`** (`core/orchestrator.py`): Final panel printed `✔ ReconNinja v{VERSION} Complete — v8.0.0`, mixing a dynamic `VERSION` with a hardcoded suffix. Fixed: removed the hardcoded suffix.

- **Bug 8 — `utils/notify.py` has 4 hardcoded `v7.0.0` strings**: Slack footer, Discord footer, generic JSON payload `"version"` field, and HTTP `User-Agent` header all sent `v7.0.0` to webhook endpoints regardless of actual version. Fixed: all four now use `__version__` from `info`.

- **Bug 9 — `_dict_to_config` missing all v8 flags** (`core/resume.py`): `_dict_to_config()` restored a saved `ScanConfig` from state JSON but omitted all 22 v8 flags (`run_api_fuzz`, `run_oauth_scan`, `run_web_vulns`, `run_open_redirect`, `run_linkedin`, `run_paste_monitor`, `run_se_osint`, `apk_path`, `run_app_store`, `run_anon_detect`, `run_dns_leak`, `run_web3_scan`, `run_ens_lookup`, `run_ai_consensus`, `run_attack_paths`, `run_ai_remediate`, `ai_config`, `run_pdf_report`, `jira_config`, `github_issues_config`, `siem_config`). Every `--resume` silently disabled every v8 module. Fixed: all 22 fields added.

- **Bug 10 — `_dict_to_result` missing v8 result fields** (`core/resume.py`): `_dict_to_result()` reconstructed `ReconResult` from state JSON but skipped all 15 v8 result fields. Any v8 scan data completed before a crash was wiped on resume. Fixed: all 15 v8 fields added.

- **Bug 11 — `save_state` hardcodes `"version": "7.0.0"`** (`core/resume.py`): Every checkpoint file was stamped with a hardcoded version. Fixed: now uses `__version__`.

- **Bug 12 — `core/resume.py` docstring hardcodes `v7.0.0`**: Fixed to `(version → see info/version)`.

- **Bug 13 — `utils/models.py` docstring hardcodes `v7.0.0`**: Fixed to `(version → see info/version)`.

- **Bug 14 — `core/ai_analysis.py` docstring hardcodes `v7.0.0`**: Fixed to `(version → see info/version)`.

### Improvements

- **Version centralization** — version string was hardcoded independently in six separate files (`reconninja.py`, `core/orchestrator.py`, `output/reports.py`, `output/sarif_export.py`, `gui/app.py`, `pyproject.toml`), each drifting out of sync over releases. Introduced `info/version` (plain-text, one line) as the single source of truth and an `info/__init__.py` that exposes `__version__`. All files now import from `info` — bumping `info/version` is the only change needed for a release.
  - `reconninja.py` — `VERSION = "8.2.1"` → `from info import __version__; VERSION = __version__`
  - `core/orchestrator.py` — same fix; was stuck on `"8.0.0"`
  - `output/reports.py` — same fix; was stuck on `"7.0.0"`
  - `output/sarif_export.py` — same fix; was stuck on `"7.0.0"`
  - `output/report_html.py` — 3 spots fixed (subtitle badge, footer link); was stuck on `"7.0.0"`
  - `gui/app.py` — 5 spots fixed: docstring, `<title>`, header badge, progress-log ready message, `launch_gui()` print; was stuck on `"8.1.0"` throughout
  - `utils/notify.py` — 4 spots fixed: Slack footer, Discord footer, generic payload, User-Agent header; was stuck on `"7.0.0"` (also counted as Bug 8 above)
  - `pyproject.toml` — switched from `version = "8.2.1"` to `dynamic = ["version"]` with `[tool.setuptools.dynamic] version = {file = "info/version"}` so `pip install` always picks up the correct version
- **core/updater.py** — `_get_current_version()` previously scraped `VERSION = "..."` out of `reconninja.py` with string parsing (fragile, broke when the line was removed). Now does `from info import __version__` with a fallback to reading `info/version` directly from the install directory.
- **tests/test_v8_2_release.py** — `test_pyproject_version` updated to assert dynamic versioning is correctly wired.

---

## [8.2.1] — 2026-05-01 [PATCH]

### Bug Fixes

- **just some Pyproject fix**


## [8.2.0] — 2026-05-01 [PATCH]

### Bug Fixes

- **requirements.txt** — Only `rich` and `python-dotenv` were declared; the tool silently crashed on first use of almost every scan module because 9 additional core dependencies were missing. Added all required packages: `requests`, `dnspython`, `beautifulsoup4`, `cryptography`, `flask`, `pyyaml`, `python-whois`, `ipwhois`, `ldap3`.
- **pyproject.toml** — `[project.dependencies]` matched the broken `requirements.txt` — only listed `rich`. Updated to declare all 11 core runtime dependencies so `pip install ReconNinja` works out of the box without a separate `pip install -r requirements.txt` step.

### Improvements

- **reconninja.py** — 17 `argparse` arguments were missing `help=` text, rendering `--help` mostly useless for new users. All arguments now have descriptive help strings:
  - `--profile` — describes each mode (fast, standard, thorough, stealth, web_only, port_only, full_suite, custom)
  - `--all-ports` — clarifies it scans all 65 535 ports and warns of speed impact
  - `--top-ports` — shows default (1000)
  - `--timing` — maps T1–T5 to human labels (paranoid → insane)
  - `--threads` — shows default (20)
  - `--subdomains` — lists which tools are invoked
  - `--rustscan` — notes external binary requirement
  - `--ferox` — names the underlying tool (feroxbuster)
  - `--masscan` — notes root requirement
  - `--httpx` — describes probing behaviour
  - `--nuclei` — mentions template-based scanning
  - `--nikto` — names the web scanner
  - `--whatweb` — describes technology fingerprinting
  - `--aquatone` — describes visual recon / screenshots
  - `--wordlist-size` — shows approximate wordlist sizes (~1 K / ~10 K / ~100 K)
  - `--masscan-rate` — shows default (5 000 pps) and caution note
  - `--check-tools` — clarifies it checks installed binaries then exits

---

## [8.1.0] — 2026-05-01 [PATCH]

### Bug Fixes
- **reconninja.py** — `VERSION` was incorrectly set to `"7.0.0"` despite being v8 code; affected the startup banner, argparse description, and `--update` version comparison — fixed to `"8.1.0"`
- **reconninja.py** — Module docstring header still read `ReconNinja v7.0.0` — updated to v8.1.0
- **gui/app.py** — `autocomplete="of"` typo on the target input field — corrected to `autocomplete="off"` (browsers were showing autocomplete suggestions)
- **gui/app.py** — SSE keepalive message was sent as `type: "log"` with text `"…"`, causing the progress log to fill with noise every 30 s of idle time — changed to `type: "keepalive"` which the JS client correctly ignores
- **gui/app.py** — `_scan_queues` and `_scan_results` dicts were never pruned after a scan completed, causing an unbounded memory leak in long-running GUI sessions — entries are now removed in the `run_scan` `finally` block once the sentinel is enqueued

---

## [8.0.0] — 2026-05-01 [MAJOR]

### Bug Fixes (pre-8.0.0 audit — 17 bugs fixed across 13 files)
- **core/orchestrator.py** — 19 v7 module functions called but never imported (`NameError` on every v7 phase) — fixed all missing imports
- **core/smtp_enum.py, supply_chain.py, snmp_scan.py, cloud_meta.py, jwt_scan.py, devops_scan.py, greynoise.py, graphql_scan.py, censys_lookup.py, typosquat.py, cors_scan.py** — 12 broken f-strings with no placeholders (pyflakes F601) — stripped spurious `f` prefix
- **core/typosquat.py** — `out_file` assigned but never passed to `run_cmd` — dnstwist output now written to disk
- **core/db_exposure.py** — `slabs` memcached response captured but discarded; fixed to include in `data=` field; dead `sev` accumulation assignment removed
- **core/asn_map.py** — `socket` removed then still referenced; import order corrected
- **output/sarif_export.py** — `VulnFinding as VF` re-imported inside loop on every iteration (shadow); moved to module-level alias
- **13 files** — unused imports cleaned (`field`, `log`, `Optional`, `run_cmd`, `tool_exists`, `socket`, `struct`, `re`, `json`, `safe_print`, `itertools`)

### New Modules (13 new `core/` modules — 13 new phases)

#### API Security
- **`--api-fuzz`** (`core/api_fuzz.py`) — REST API fuzzer: OpenAPI/Swagger discovery, endpoint enumeration, IDOR probes, auth-bypass header testing, mass assignment, method confusion, sensitive key detection
- **`--oauth-scan`** (`core/oauth_scan.py`) — OAuth 2.0/OIDC misconfiguration scanner: implicit flow detection, PKCE enforcement check, open redirect in `redirect_uri`, state CSRF, token endpoint CORS, exposed client credentials in JS
- **`--web-vulns`** (`core/web_vulns.py`) — Web vulnerability probe suite: reflected XSS, error-based + time-based SQLi, LFI/path traversal, SSRF (IMDS detection)
- **`--open-redirect`** (`core/open_redirect.py`) — Open redirect scanner across 30 common redirect params with bypass-payload variants

#### Social Engineering Intel
- **`--linkedin`** (`core/linkedin_osint.py`) — LinkedIn employee enumeration via Google dorking, tech stack inference from job postings, high-value target identification (IT/security roles), email format guessing
- **`--paste-monitor`** (`core/paste_monitor.py`) — Pastebin / GitHub Gist / paste.ee credential dump scanner: AWS keys, GitHub tokens, OpenAI keys, passwords, base64 blobs
- **`--se-osint`** (`core/se_osint.py`) — Social engineering OSINT: email address and phone number harvesting from contact pages, Hunter.io, and Google

#### Mobile / APK
- **`--apk-scan APK_PATH`** (`core/apk_scan.py`) — APK static analysis: manifest permissions (dangerous perm flagging), hardcoded secrets (10 patterns), dangerous API calls (WebView JS bridge, TrustAllCerts, delegatecall, selfdestruct), embedded URL extraction, internal IP exposure
- **`--app-store`** (`core/app_store.py`) — Google Play + Apple App Store metadata: app IDs, version history, install counts, developer email/website (iTunes Search API — no key required)

#### Privacy / Anonymity
- **`--anon-detect`** (`core/anon_detect.py`) — Tor exit node detection via DNSEL, VPN/proxy detection via ip-api, datacenter/hosting ASN identification
- **`--dns-leak`** (`core/dns_leak.py`) — DNS leak checker: DNS rebinding (TTL=0/low), open resolver (port 53 open), internal IP exposure via public DNS, wildcard DNS detection, DoH endpoint exposure

#### Blockchain / Web3
- **`--web3-scan`** (`core/web3_scan.py`) — Smart contract recon: Ethereum address harvesting from target, Etherscan source verification, Solidity vulnerability pattern scanning (reentrancy, tx.origin, selfdestruct, delegatecall, outdated pragma), ABI file exposure check, ENS name detection
- **`--ens-lookup`** (`core/ens_lookup.py`) — ENS domain resolution: resolves ETH addresses, Twitter/GitHub/email records, links social handles, discovers ENS names from target website

### AI Upgrades (3 new AI capabilities)
- **`--ai-consensus`** (`core/ai_enhanced.py`) — Multi-model consensus: run Groq + OpenAI + Gemini + Ollama in parallel, synthesize agreement, flag model disagreements
- **`--attack-paths`** — AI-generated MITRE ATT&CK kill-chain attack narratives: chained findings → structured attack paths with TTP codes, prerequisites, step-by-step execution
- **`--ai-remediate`** — Per-finding AI remediation engine: fix summaries, detailed remediation steps, effort estimate, CVSSv3.1 base score and vector string for every finding

### GUI (major new surface)
- **`--gui`** (`gui/app.py`) — Local desktop GUI via Flask: dark-themed single-page app, point-and-click scan config, 4 scan profiles (Quick/Standard/Full/Custom), real-time SSE progress log, live findings table with severity badges, scan history, per-module checkbox selection
- **`--gui-port N`** — Configure GUI port (default 7117)
- **Windows `.exe`** — PyInstaller build pipeline (see `build_exe.py`): single-file portable executable, bundles all dependencies, no Python install required

### Output & Integrations (4 new outputs)
- **`--pdf-report`** (`output/integrations.py`) — Pentest-ready PDF: executive summary, severity stats, full findings table with colour-coded severity; uses weasyprint → fpdf2 → HTML fallback
- **`--jira URL:EMAIL:TOKEN:PROJECT`** — Push all findings to Jira as Bug issues with severity labels and CVSSv3 data
- **`--gh-issues TOKEN:OWNER/REPO`** — Push all findings to GitHub Issues with severity labels
- **`--siem URL:TOKEN[:type]`** — Stream findings as structured JSON events to Splunk HEC or Elasticsearch (type: `splunk` | `elastic`)

### Models / Config
- `ScanConfig` — 22 new fields for all v8 modules and integrations
- `ReconResult` — 15 new optional result fields for v8 module outputs
- Output format choices expanded: `pdf` and `sarif` added to `--output-format`

---

## [7.1.0] — 2026-04-04 [BUGFIX]

### Bug Fixes

- **Bug #1 (Medium)** `core/orchestrator.py` — 19 module-level functions introduced in v7.0.0 were
  called inside phase guards but never imported at the top of the file. Every v7 feature phase
  (`email_security_scan`, `breach_check`, `cloud_meta_scan`, `graphql_scan`, `jwt_scan`, `asn_map`,
  `supply_chain_scan`, `k8s_probe`, `db_exposure_scan`, `smtp_enum`, `snmp_scan`, `ldap_enum`,
  `terraform_state_scan`, `jenkins_scan`, `greynoise_lookup`, `typosquat_scan`, `censys_bulk_lookup`,
  `dns_history_lookup`, `export_sarif`) raised `NameError` at runtime, silently skipping or crashing
  the phase. All 17 missing `from core.* import …` / `from output.* import …` statements added.
  `smtp_user_enum` aliased as `smtp_enum` to match existing call sites without touching phase code.

### Code quality
- `flake8 --select=F821` exits clean (0 undefined-name errors) across all source files.

---

## [7.0.0] — 2026-04-04

### Bug Fixes

- **Bug #1 (Medium)** `core/js_extractor.py` — `_extract_secrets()` used a `seen_labels: set[str]` that
  deduplicated on label name alone. A JS file containing two distinct AWS Access Keys would only report
  the first. Fixed to dedup on `(label, match[:20])` key so all unique credential instances per type
  are captured. Also switched from `pat.search()` to `pat.finditer()` so multiple matches per pattern
  are not silently dropped.

- **Bug #2 (Low)** `core/dns_zone_transfer.py` — `_get_nameservers()` fallback branch called
  `socket.getaddrinfo(domain, None)` and assigned the result to `infos`, which was never read.
  The comment claimed this "won't actually give NS records" — which is correct, so the whole block
  was dead misleading code. Removed; function now falls through cleanly to `_get_nameservers_via_dig`.

- **Bug #3 (Low — cosmetic)** Version string rot across 37 source files — headers still said
  `ReconNinja v3`, `ReconNinja v3.3`, `v6 AI Analysis`, `ReconNinja/6.0.0` in User-Agent strings,
  notification footers, and HTML report strings. All updated to `v7.0.0`.

### New Modules (17 files, 25 features)

| ID | Module | Feature | Flag |
|----|--------|---------|------|
| V7-01 | `core/email_security.py` | SPF/DKIM/DMARC validation + spoofability score 0-100 | `--email-security` |
| V7-02 | `core/breach_check.py` | HaveIBeenPwned domain + email breach check | `--breach-check` |
| V7-03/04 | `core/cloud_meta.py` | AWS/Azure/GCP metadata SSRF probe (IMDSv1/v2) | `--cloud-meta` |
| V7-05 | `core/graphql_scan.py` | GraphQL endpoint discovery, introspection, batching, field-suggestion | `--graphql` |
| V7-06 | `core/jwt_scan.py` | JWT none-algorithm + weak HMAC secret cracker | `--jwt-scan` |
| V7-07 | `core/asn_map.py` | BGP/ASN → all owned IP CIDRs via RIPE Stat API | `--asn-map` |
| V7-08 | `core/supply_chain.py` | Vulnerable JS library detection (jQuery/Angular/Lodash/polyfill.io) | `--supply-chain` |
| V7-09 | `core/k8s_probe.py` | Kubernetes/Docker unauthenticated API detection | `--k8s-probe` |
| V7-10 | `core/db_exposure.py` | Elasticsearch unauthenticated cluster/index access | `--db-exposure` |
| V7-11 | `core/db_exposure.py` | Redis unauthenticated PING/INFO/CONFIG dump | `--db-exposure` |
| V7-12 | `core/db_exposure.py` | MongoDB unauthenticated listDatabases | `--db-exposure` |
| V7-13 | `core/smtp_enum.py` | SMTP user enumeration via VRFY/EXPN/RCPT TO | `--smtp-enum` |
| V7-14 | `core/db_exposure.py` | Memcached unauthenticated stats + amplification flag | `--db-exposure` |
| V7-15 | `core/snmp_scan.py` | SNMP community string brute-force + MIB walk | `--snmp-scan` |
| V7-16 | `output/sarif_export.py` | SARIF 2.1.0 export for GitHub/VSCode/Azure DevOps | `--sarif` |
| V7-18 | `core/censys_lookup.py` | Censys host intelligence + DNS history via VT PDNS | `--censys` |
| V7-19 | `core/censys_lookup.py` | DNS resolution history via VirusTotal PDNS | `--dns-history` |
| V7-20 | `core/typosquat.py` | 200+ lookalike domain variants + live DNS resolution check | `--typosquat` |
| V7-21 | `core/ldap_enum.py` | LDAP anonymous bind, user/group/attribute dump | `--ldap-enum` |
| V7-22 | `core/devops_scan.py` | Terraform state file exposure detection | `--devops-scan` |
| V7-23 | `core/devops_scan.py` | Jenkins exposure: anon jobs, users, script console (RCE) | `--devops-scan` |
| V7-24 | `core/greynoise.py` | GreyNoise IP tagging: noise / RIOT / unknown | `--greynoise` |
| V7-25 | `core/supply_chain.py` | npm package name squatting detection | `--supply-chain` |

### New Orchestrator Phases (14a–14q)

17 new phases inserted between the v6 intelligence block and the plugin system.
All phases are checkpoint-saved to `state.json` and fully resumed with `--resume`.
All phases respect `--exclude` flags.

### Models (`utils/models.py`)

`ScanConfig` gains 25 new boolean flags and 8 new key fields.
`ReconResult` gains 17 new result list fields (all default to `[]` — forward-compatible with v6 state files).

### Resume (`core/resume.py`)

`_dict_to_result()` and `_dict_to_config()` extended for all v7 fields with safe `.get()` defaults.

### Output (`output/sarif_export.py`)

New SARIF 2.1.0 exporter covering nuclei findings, high/critical port findings,
CORS misconfigurations, and GitHub OSINT exposures.

### CLI (`reconninja.py`)

25 new flags documented under `v7 new modules` group. All v7 flags also fire in `full_suite` profile.

### Version (`pyproject.toml`, all source files)

`6.0.0 → 7.0.0` across all 37 Python, TOML, and Markdown files.

---

## [6.0.0] — 2026-03-20

### Bug Fixes

- **Bug #1 (Critical)** `core/subdomains.py` — `_dns_brute` received arguments in the wrong order when invoked via the `_try()` helper with `BUILTIN_SUBS`. `out_file` was receiving a `list` and `custom_list` was receiving a `Path`, causing a `TypeError` at runtime on any machine without SecLists or external subdomain tools. Fixed by wrapping in a closure so `_try` appends `tmp` to the correct positional slot.
- **Bug #2 (High)** `core/orchestrator.py` — RustScan results were never persisted to `ReconResult`. On `--resume`, the rustscan phase was marked complete but `all_open_ports` remained empty, causing Nmap to be skipped entirely. Fixed by adding `result.rustscan_ports: list[int]` field (serialised to `state.json`) and restoring it on resume.
- **Bug #3 (High)** `core/updater.py` — `backup` variable was only assigned inside `if INSTALL_DIR.exists()`. On a fresh install the `except` handler referenced it before assignment → `UnboundLocalError`, burying the real failure. Fixed by initialising `backup = None` before the conditional.
- **Bug #4 (High)** `core/orchestrator.py` — AI fallback `_generate_ai_analysis()` was dead code. The condition `if cfg.ai_provider and cfg.ai_provider != ""` was always `True` (default `"groq"`). Users with no API key received a raw error dict in their report instead of the useful rule-based summary. Fixed: attempt LLM only when `bool(cfg.ai_key)` or `provider == "ollama"`; always fall back to rule-based if no analysis produced.
- **Bug #5 (Medium)** `core/ports.py` — Banner grabber sent `HEAD / HTTP/1.0` immediately on every open port. SSH, FTP, SMTP, Redis etc. disconnect on unexpected HTTP input → banner capture failed on all non-HTTP ports. Fixed: wait for the server greeting first; only send HTTP probe if no greeting arrives within `BANNER_TIMEOUT`.
- **Bug #6 (Medium)** `core/orchestrator.py` — Aquatone received `sub_file` (bare hostnames) instead of `url_file` (full `http://` URLs). Fixed: both aquatone and gowitness now receive `url_file`.
- **Bug #7 (Medium)** `core/cve_lookup.py` — NVD rate-limit delay only fired when CVEs were found. Empty-result queries fired back-to-back, hitting the 5 req/30s cap and causing silent 403s. Fixed: `time.sleep(delay)` now unconditional.
- **Bug #8 (Low)** `utils/updater.py` — Stale duplicate of `core/updater.py`, never imported, missing `timeout=300` on pip subprocess. Deleted.

### New Modules (6)

- **`core/github_osint.py`** — Search GitHub for exposed secrets, API keys, config files, and database URLs belonging to the target org. Probes 10 secret query patterns and 6 sensitive file patterns. Optional `--github-token` for 5000 req/hr vs 60. `--github-osint`
- **`core/js_extractor.py`** — Crawl live web pages, download JS files, extract API endpoint paths, and scan for credentials (AWS keys, GitHub tokens, Stripe keys, connection strings, generic API keys). `--js-extract`
- **`core/cloud_buckets.py`** — Enumerate AWS S3, Azure Blob Storage, and Google Cloud Storage buckets using ~60 name candidates derived from the target domain. Identifies public (listable) and authenticated-only buckets. Pure Python, no API keys needed. `--cloud-buckets`
- **`core/dns_zone_transfer.py`** — Attempt AXFR against each nameserver. Uses `dnspython` if available, falls back to raw TCP DNS socket probe. Saves leaked zone records to disk. `--dns-zone`
- **`core/waf_detect.py`** — Detect WAF presence via passive header/cookie/body fingerprinting (20 WAF signatures) plus active blocking test. Uses `wafw00f` if installed, falls back to pure Python. `--waf`
- **`core/cors_scan.py`** — Probe live endpoints with 6 crafted `Origin` headers. Detects: arbitrary origin reflection, wildcard + credentials (critical), null origin allowed, subdomain bypass vectors. `--cors`

### New Utilities (2)

- **`core/scan_diff.py`** — Compare any two ReconNinja JSON reports. Outputs: new/closed ports, changed service versions, new/gone subdomains, new/fixed vulnerabilities, new web services, new technologies. CLI: `--diff old.json new.json`
- **`utils/notify.py`** — Thread-safe webhook notifications for Slack, Discord, and generic JSON endpoints. Fires mid-scan on critical findings (high-risk ports, critical vulns, public buckets, CORS issues, GitHub secrets, zone transfer). CLI: `--notify URL`

### Version Migration

- All `v5.2.2` / `v5.0.0` / `5.2.2` / `5.0.0` references updated to `v6.0.0` / `6.0.0` across all source files, configs, and comments
- `pyproject.toml`: `version` bumped `5.2.2 → 6.0.0`; description updated to "21-phase"; `[dns]` optional dependency group added (`dnspython>=2.4.0`)
- `reconninja.py`: `VERSION = "6.0.0"`, new CLI flags wired
- `core/orchestrator.py`: Phase count 14 → 21; banner updated; summary includes GitHub hits and public bucket count
- `core/resume.py`: state file `version` field `5.2.2 → 6.0.0`; v6 result and config fields serialised/deserialised
- `output/reports.py`: `VERSION = "6.0.0"`; v6 fields included in JSON payload
- `output/report_html.py`: subtitle and footer updated to `v6.0.0`
- `utils/models.py`: `ScanConfig` — 8 new fields; `ReconResult` — 6 new fields + `rustscan_ports`

### Breaking Changes

- `utils/updater.py` removed — import path was `utils.updater` (never used in practice; canonical path is `core.updater`)
- `ReconResult` gains 7 new fields — existing `state.json` files from v5 are forward-compatible (all new fields default to `[]`)

---


---

## [5.2.2] — 2026-03-18 [BUGFIX]

### Fixed

- **Bug #1** `reconninja.py` — `--resume` silently did nothing when given a missing or corrupt state file; now prints a clear `[danger]` error message before exiting
- **Bug #2** `output/report_html.py` — HTML report footer and brand subtitle still said `ReconNinja v3.3`; updated to `v5.2.2`
- **Bug #3** `reconninja.py` — Module docstring said `ReconNinja v5.0.0`; updated to `v5.2.2`
- **Bug #4** `reconninja.py` — `print_update_status` imported from `core.updater` but never called; removed unused import
- **Bug #5** `reconninja.py` — `log` imported from `utils.logger` but never used; removed
- **Bug #6** `core/orchestrator.py` — 7 dead imports removed: `log`, `ScanProfile`, `PortInfo`, `NmapOptions`, `SEVERITY_PORTS`, `run_nmap`, `NMAP_PER_TARGET_TIMEOUT`
- **Bug #7** `core/wayback.py:75` — `status` variable assigned from CDX row but never read; replaced with `_` discard
- **Bug #8** `core/ssl_scan.py` — `der_cert = ssock.getpeercert(binary_form=True)` assigned but never used; line removed
- **Bug #9** `core/subdomains.py:179` — `tmp_builtin` assigned but immediately discarded; dead assignment removed
- **Bug #10** `output/reports.py` — 4 static strings had unnecessary `f`-string prefix with no placeholders (lines 381, 382, 433, 480); `f` prefix removed
- **Bug #11** `core/updater.py` — 2 static strings with unnecessary `f`-string prefix (lines 187, 200); `f` prefix removed
- **Bug #12** `utils/models.py:55` — Static error message had unnecessary `f`-string prefix; `f` prefix removed
- **Bug #13** `core/resume.py` — `from typing import Any` unused; removed
- **Bug #14** `core/ports.py` — `import socket` and `from dataclasses import asdict` unused; removed
- **Bug #15** Remaining unused imports cleaned: `console` from `ai_analysis.py` · `BUILTIN_DIRS` + `WEB_PORTS` from `web.py` · `detect_seclists` from `subdomains.py` · `Optional` from `virustotal.py` + `whois_lookup.py` · `os` from `updater.py` · `sys` from `helpers.py`

### Code quality
- `pyflakes` exits clean (0 warnings) across all 21 source files

---

## [5.2.1] — 2026-03-13 [BUGFIX]

### Fixed
- **Bug #1** `orchestrator.py` — `--exclude` flag was parsed but never applied; all phase guards now check `cfg.exclude_phases`
- **Bug #2** `orchestrator.py` — VirusTotal always called `vt_domain_lookup` even on IP targets; now routes to `vt_ip_lookup` correctly via `ipaddress.ip_address()` check
- **Bug #3** `orchestrator.py` — Screenshots phase skipped entirely when no subdomain file existed; now uses `web_findings` URLs as primary target list with main domain as fallback
- **Bug #4** `reconninja.py`, `reports.py`, `orchestrator.py`, `resume.py` — Version hardcoded as `5.0.0` in multiple files; all updated to `5.2.1`
- **Bug #5** `orchestrator.py` — Dead imports (`signal`, `sys`, `asdict`) removed
- **Bug #6** `updater.py` — `subprocess.run` calls missing `timeout` parameter; added `timeout=300` to prevent hung processes
- **Bug #7** `tests/test_v4_modules.py` — Version assertion tests expected old `5.0.0`; updated to `5.2.1`
- **Bug #8** `tests/test_orchestrator.py` — `test_save_state_called_after_passive_recon` used wrong source anchor causing false failure; fixed to anchor on `phases_completed.append` line
- **Bug #9** `orchestrator.py` — Phase 2b Async TCP ran even when `port` phase was excluded; wrapped in `exclude_phases` guard
- `resume.py` — State file `version` field was hardcoded `5.0.0`; updated to `5.2.1`
- `requirements.txt` — Added `python-dotenv>=1.0.0` dependency

### Tests
- 597/597 pytest passing (100%)
- All version assertions updated to `5.2.1`

---

## [5.0.0] — 2026-03-09

### Bug Fixes
- **`core/ports.py`** — Removed duplicate port 587 from `_NMAP_TOP_PORTS` preset list.
- **`core/web.py: run_whatweb`** — Added missing `ensure_dir(out_folder)` call to prevent crashes when output directory does not exist.
- **`core/web.py: run_nikto`** — Added missing `ensure_dir(out_folder)` call (same fix as `run_whatweb`).
- **`plugins/__init__.py`** — Removed erroneous `@staticmethod` decorator from module-level function `_load_module`.

### Version
- Bumped 4.0.0 → 5.0.0 across `reconninja.py`, `pyproject.toml`, `output/reports.py`.

---

## [4.0.0] — 2026-03-07

### Added

- **`core/shodan_lookup.py`** — Shodan host intelligence. Pulls org, ISP, city, hostnames, domains, open ports, tags, and known CVEs per IP. `--shodan --shodan-key KEY`
- **`core/virustotal.py`** — VirusTotal domain and IP reputation. Reports malicious/suspicious engine counts, reputation score, ASN, registrar. `--vt --vt-key KEY`
- **`core/whois_lookup.py`** — WHOIS via system `whois` CLI or python-whois fallback. No API key required. Extracts registrar, expiry, nameservers, emails, country, registrant. `--whois`
- **`core/wayback.py`** — Wayback Machine CDX API URL discovery. Categorizes historical URLs by extension (`.php`, `.sql`, `.env`, `.bak`) and path (`/admin`, `/api`, `/config`). No API key required. `--wayback`
- **`core/ssl_scan.py`** — SSL/TLS analysis using Python stdlib only. Checks certificate expiry, self-signed flag, weak ciphers (RC4, DES, 3DES, NULL, EXPORT), old protocols (TLSv1, TLSv1.1), key size. `--ssl`
- `--output-format all|html|json|md|txt` — only generate what you need
- `--exclude PHASES` — skip specific pipeline phases
- `--timeout N` — global per-operation timeout
- `--rate-limit N` — seconds between requests
- `pyproject.toml` + `MANIFEST.in` — full pip install support
- `[ai]` and `[full]` optional dependency groups
- `tests/test_v4_modules.py` — 80+ tests covering all 5 new modules + resume round-trips + report generation

### Fixed

- **`core/resume.py: _dict_to_result`** — intelligence result fields were not restored on resume. Critical data loss on scan resume.
- **`core/resume.py: _dict_to_config`** — intelligence config fields were not restored on resume. All intelligence phases would silently skip on resume.
- **`core/resume.py: save_state`** — version string updated `"3.2"` → `"4.0.0"`.
- **`output/reports.py`** — VERSION updated `"3.0.0"` → `"4.0.0"`. HTML header updated "v3" → "v4.0.0". MD report header updated.
- **`output/reports.py: generate_json_report`** — intelligence result fields missing from JSON output payload. Now included.
- **`output/reports.py: generate_html_report`** — intelligence sections (WHOIS, Wayback, SSL, VirusTotal, Shodan) missing from HTML report.
- **`output/reports.py: generate_markdown_report`** — intelligence sections missing from Markdown report.
- **`core/wayback.py`** — now consistently returns `{}` for all no-data cases.
- **`core/orchestrator.py`** — duplicate "Phase 13" comment fixed. Reports now correctly labeled "Phase 14".
- **`utils/logger.py: setup_file_logger`** — moved to module-level import to allow mocking in tests.
- **`core/orchestrator.py: passive_recon`** — shortened panel text to fix regression test window.

### Changed

- `full_suite` profile auto-enables `--whois`, `--wayback`, `--ssl` (Shodan/VT require keys)
- Completion banner updated to v4.0.0

---

## [3.3.0] — 2026-01-15

### Added
- `--ai` with Groq / Ollama / Gemini / OpenAI support (`--ai-provider`, `--ai-key`, `--ai-model`)
- `--cve-lookup` auto-queries NVD for detected port services (no key needed, key optional for higher rate limit)
- `--resume <state.json>` — resume interrupted scans from last checkpoint
- `--update` — self-update from GitHub
- `--nvd-key` — optional NVD API key (rate limit 5→50 req/30s)

### Fixed
- All 13 phases now correctly skip on resume (`phases_completed` check on every phase)
- `run_rustscan` flag honoured — Phase 2 no longer fires unconditionally
- Masscan ports rehydrated from `result.masscan_ports` on resume
- `lookup_cves_for_host_result` correct function name (was `lookup_cves_for_hosts`)
- `save_state` called after every phase

---

## [3.2.0] — 2025-12-01

### Added
- `AsyncTCPScanner` — pure Python asyncio TCP connect, no root required
- Async scan runs before Nmap, confirmed open ports fed to Nmap (`-p<ports>`)
- Banner grabbing on discovered open ports
- `--async-concurrency`, `--async-timeout` CLI flags

### Changed
- RustScan + async results merged (union) for maximum coverage
- Nmap only analyses confirmed-open ports — dramatically faster

### Fixed
- `masscan_rate` crash on non-integer input
- `full_suite` profile no longer triggers custom Nmap builder

---

## [3.1.0] — 2025-10-15

### Added
- RustScan integration for ultra-fast port pre-discovery
- httpx for live web service detection and tech fingerprinting
- gowitness as aquatone fallback for screenshots
- dirsearch as third fallback dir scanner
- crt.sh Certificate Transparency passive subdomain source
- Plugin system (drop `.py` into `plugins/`)
- Rule-based AI analysis engine (no API required)
- Structured `VulnFinding` dataclass (severity, CVE, target)
- Per-scan file logger (`scan.log` in output dir)
- CIDR and list-file target input

---

## [2.1.0] — 2025-08-01

Initial public release under ExploitCraft organization.
