# Changelog

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
