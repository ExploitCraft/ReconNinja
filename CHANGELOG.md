# Changelog

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
