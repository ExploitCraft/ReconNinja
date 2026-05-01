"""
core/js_extractor.py — ReconNinja v7.0.0
JavaScript endpoint and secret extraction from live web services.

After httpx discovers live URLs, this module:
  1. Crawls each page for <script src> references
  2. Downloads each .js file
  3. Extracts API endpoints (paths, full URLs) via regex
  4. Scans for potential secrets (API keys, tokens, credentials)

No external tools required — pure Python stdlib.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print, log

# ── Regex patterns ────────────────────────────────────────────────────────────

# API endpoint patterns — match relative and absolute URL paths
ENDPOINT_PATTERNS = [
    re.compile(r"""[\"'`](/(?:api|v\d+|graphql|rest|service|endpoint)[\w/\-%.?=&]*)""", re.I),
    re.compile(r"""[\"'`](https?://[a-zA-Z0-9._\-]+(?:/[\w/\-%.?=&]*)?)"""),
    re.compile(r"""fetch\s*\(\s*[\"'`]([^\"'`]+)"""),
    re.compile(r"""axios\.[a-z]+\s*\(\s*[\"'`]([^\"'`]+)"""),
    re.compile(r"""url\s*[=:]\s*[\"'`]([^\"'`]+)""", re.I),
    re.compile(r"""path\s*[=:]\s*[\"'`](/[^\"'`]+)""", re.I),
]

# Secret patterns — (label, regex)
SECRET_PATTERNS = [
    ("AWS Access Key",        re.compile(r"""(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])""")),
    ("AWS Secret Key",        re.compile(r"""aws[_\-. ]?secret[_\-. ]?(?:access)?[_\-. ]?key\s*[=:]\s*[\"'`]?([A-Za-z0-9+/=]{40})""", re.I)),
    ("Generic API key",       re.compile(r"""api[_\-.]?key\s*[=:]\s*[\"'`]([A-Za-z0-9_\-]{20,})""", re.I)),
    ("Generic token",         re.compile(r"""(?:access|auth|bearer|secret)[_\-.]?token\s*[=:]\s*[\"'`]([A-Za-z0-9_\-]{20,})""", re.I)),
    ("Private key header",    re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")),
    ("Google API key",        re.compile(r"""AIza[0-9A-Za-z_\-]{35}""")),
    ("Slack token",           re.compile(r"""xox[baprs]-[0-9A-Za-z]{10,48}""")),
    ("GitHub token",          re.compile(r"""gh[pousr]_[0-9A-Za-z]{36}""")),
    ("Stripe key",            re.compile(r"""(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}""")),
    ("Password in JS",        re.compile(r"""password\s*[=:]\s*[\"'`]([^\"'`]{8,})""", re.I)),
    ("Connection string",     re.compile(r"""(?:mongodb|mysql|postgres|redis)://[^\s\"'`]+""", re.I)),
]

# Script src pattern
SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*[\"']([^\"']+\.js[^\"']*)""", re.I)


@dataclass
class JSFinding:
    url:       str        # JS file URL
    endpoints: list[str] = field(default_factory=list)
    secrets:   list[dict] = field(default_factory=list)   # [{label, match, context}]


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 10, max_bytes: int = 512_000) -> str:
    """Fetch URL and return text content (capped at max_bytes)."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ReconNinja/7.0.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes).decode(errors="ignore")
    except Exception as e:
        log.debug(f"JS fetch error {url}: {e}")
        return ""


def _abs_url(base: str, src: str) -> str:
    """Resolve a relative script src against the page's base URL."""
    if src.startswith("//"):
        scheme = urllib.parse.urlsplit(base).scheme or "https"
        return f"{scheme}:{src}"
    return urllib.parse.urljoin(base, src)


# ── Core extraction ───────────────────────────────────────────────────────────

def _extract_endpoints(js_text: str) -> list[str]:
    """Extract unique API endpoint paths from JS source."""
    found: set[str] = set()
    for pat in ENDPOINT_PATTERNS:
        for m in pat.finditer(js_text):
            raw = m.group(1).strip()
            if len(raw) > 3 and not raw.endswith((".png", ".jpg", ".css", ".ico")):
                found.add(raw)
    return sorted(found)[:100]   # cap output


def _extract_secrets(js_text: str) -> list[dict]:
    """Scan JS source for potential credentials/tokens."""
    found: list[dict] = []
    seen_keys: set[str] = set()   # BUG-FIX v7: dedup on (label, match prefix) not label alone
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(js_text):
            match_val = m.group(1) if m.lastindex else m.group(0)
            dedup_key = f"{label}:{match_val[:20]}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            start   = max(0, m.start() - 50)
            end     = min(len(js_text), m.end() + 50)
            context = js_text[start:end].replace("\n", " ").replace("\r", "")
            found.append({
                "label":   label,
                "match":   match_val[:80],
                "context": context[:200],
            })
    return found


# ── Script URL discovery ──────────────────────────────────────────────────────

def _find_script_urls(html: str, base_url: str) -> list[str]:
    """Extract absolute JS file URLs from HTML."""
    urls = []
    for m in SCRIPT_SRC.finditer(html):
        src = m.group(1).strip()
        if src.startswith("data:") or not src:
            continue
        abs_url = _abs_url(base_url, src)
        if abs_url not in urls:
            urls.append(abs_url)
    return urls[:20]   # cap per-page


# ── Public API ────────────────────────────────────────────────────────────────

def extract_js_findings(
    web_urls: list[str],
    out_folder: Path,
    timeout: int = 10,
    max_js_per_target: int = 10,
) -> list[JSFinding]:
    """
    Extract JS endpoints and secrets from live web services.

    Args:
        web_urls:          list of live URLs (from httpx)
        out_folder:        output directory for raw JS files
        timeout:           HTTP timeout per request
        max_js_per_target: max JS files to fetch per URL

    Returns:
        list of JSFinding with endpoints and secrets per JS file
    """
    ensure_dir(out_folder)
    all_findings: list[JSFinding] = []
    processed_js: set[str] = set()
    total_secrets = 0
    total_endpoints = 0

    safe_print(f"[info]▶ JS Extractor — scanning {len(web_urls)} web service(s)[/]")

    for page_url in web_urls[:15]:   # cap pages
        html = _fetch(page_url, timeout=timeout)
        if not html:
            continue

        script_urls = _find_script_urls(html, page_url)

        for js_url in script_urls[:max_js_per_target]:
            if js_url in processed_js:
                continue
            processed_js.add(js_url)

            js_text = _fetch(js_url, timeout=timeout)
            if not js_text or len(js_text) < 50:
                continue

            endpoints = _extract_endpoints(js_text)
            secrets   = _extract_secrets(js_text)

            if endpoints or secrets:
                finding = JSFinding(
                    url       = js_url,
                    endpoints = endpoints,
                    secrets   = secrets,
                )
                all_findings.append(finding)
                total_endpoints += len(endpoints)
                total_secrets   += len(secrets)

                # Save JS file to disk for manual review
                safe_name = re.sub(r"[^\w._-]", "_", js_url)[-60:]
                (out_folder / f"{safe_name}.txt").write_text(
                    js_text[:100_000], encoding="utf-8", errors="ignore"
                )

    if total_secrets:
        safe_print(
            f"  [danger]⚠  JS Extractor: {total_secrets} potential secret(s) "
            f"in {len(all_findings)} JS file(s)[/]"
        )
    safe_print(
        f"[success]✔ JS Extractor: {total_endpoints} endpoint(s), "
        f"{total_secrets} secret(s) across {len(processed_js)} JS files[/]"
    )
    return all_findings
