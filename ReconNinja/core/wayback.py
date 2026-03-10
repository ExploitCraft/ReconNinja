"""
core/wayback.py — ReconNinja v5.0.0
Wayback Machine / CDX API URL discovery.
No API key needed — fully free.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict

from utils.logger import safe_print, log

CDX_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url={domain}/*"
    "&output=json"
    "&fl=original,statuscode,mimetype,timestamp"
    "&collapse=urlkey"
    "&limit={limit}"
    "&filter=statuscode:200"
)

INTERESTING_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".env", ".config", ".conf", ".xml", ".json",
    ".bak", ".backup", ".sql", ".log", ".txt",
    ".zip", ".tar", ".gz", ".key", ".pem",
}

INTERESTING_PATHS = {
    "admin", "login", "api", "config", "backup",
    "debug", "test", "dev", "staging", "internal",
    "secret", "private", "upload", "uploads", "console",
}


def wayback_lookup(domain: str, limit: int = 500) -> dict:
    """
    Query Wayback Machine CDX API for historical URLs of a domain.
    Returns categorized URL findings.
    """
    safe_print(f"[info]  Wayback: fetching historical URLs for {domain}...[/]")

    url = CDX_URL.format(domain=urllib.parse.quote(domain), limit=limit)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ReconNinja/5.0.0 Security Scanner"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        log.warning(f"Wayback HTTP {e.code} for {domain}")
        return {}
    except Exception as e:
        log.warning(f"Wayback error for {domain}: {e}")
        return {}

    if not data or len(data) < 2:
        return {}

    # Skip header row
    rows    = data[1:]
    all_urls: list[str] = []
    interesting: list[dict] = []
    by_type: dict[str, list[str]] = defaultdict(list)

    for row in rows:
        if len(row) < 4:
            continue
        orig_url, status, mimetype, timestamp = row[0], row[1], row[2], row[3]
        all_urls.append(orig_url)

        # Categorize
        lower = orig_url.lower()
        ext   = "." + lower.rsplit(".", 1)[-1].split("?")[0] if "." in lower.rsplit("/", 1)[-1] else ""

        reason = None
        if ext in INTERESTING_EXTENSIONS:
            reason = f"extension: {ext}"
            by_type[ext].append(orig_url)
        else:
            for path in INTERESTING_PATHS:
                if f"/{path}" in lower or f"/{path}." in lower:
                    reason = f"path: /{path}"
                    by_type[path].append(orig_url)
                    break

        if reason:
            interesting.append({
                "url":       orig_url,
                "reason":    reason,
                "timestamp": timestamp,
                "mimetype":  mimetype,
            })

    result = {
        "domain":      domain,
        "total":       len(all_urls),
        "interesting": interesting[:100],
        "by_type":     {k: v[:10] for k, v in by_type.items()},
        "urls":        all_urls[:200],
    }

    safe_print(
        f"  [info]Wayback:[/] {domain} — "
        f"[cyan]{len(all_urls)}[/] URLs found, "
        f"[danger]{len(interesting)}[/] interesting"
    )
    return result
