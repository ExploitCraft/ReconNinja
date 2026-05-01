"""
core/open_redirect.py — ReconNinja v8.0.0
Open Redirect Scanner.

Probes URL parameters that commonly contain redirect destinations
and tests whether the server forwards to attacker-controlled URLs.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import safe_print


@dataclass
class RedirectFinding:
    url: str
    parameter: str
    payload: str
    redirect_to: str
    severity: str
    detail: str


@dataclass
class OpenRedirectResult:
    target: str
    findings: list[RedirectFinding] = field(default_factory=list)
    params_tested: int = 0


REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirectUrl", "redirect_uri", "redirectUri",
    "return", "returnUrl", "return_url", "returnTo", "return_to",
    "next", "next_url", "goto", "go", "destination", "dest",
    "to", "target", "link", "forward", "location", "out",
    "site", "page", "ref", "referrer", "continue", "callback",
    "success_url", "cancel_url", "logout_redirect",
]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/",
    "/\\evil.com",
    "/%09/evil.com",
    "https:evil.com",
    "\x00https://evil.com",
    "evil.com%0d%0aLocation: https://evil.com",
]

MARKER = "evil.com"


def _fetch_no_follow(url: str, timeout: int = 6) -> tuple[int, str]:
    """Fetch without following redirects — return (status, Location header)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect(),
                                             urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location", "")
    except Exception:
        return 0, ""


def _build_test_urls(base_url: str) -> list[tuple[str, str]]:
    """Build (test_url, param_name) pairs by appending redirect params."""
    pairs = []
    parsed = urllib.parse.urlparse(base_url)
    existing_params = list(urllib.parse.parse_qs(parsed.query).keys())

    for param in REDIRECT_PARAMS:
        test_url = base_url
        if "?" in base_url:
            test_url = base_url + f"&{param}=PLACEHOLDER"
        else:
            test_url = base_url + f"?{param}=PLACEHOLDER"
        pairs.append((test_url, param))

    # Also check existing params
    for p in existing_params:
        if any(kw in p.lower() for kw in ["url", "redirect", "return", "next", "goto"]):
            parsed2 = urllib.parse.urlparse(base_url)
            qs = urllib.parse.parse_qs(parsed2.query, keep_blank_values=True)
            qs[p] = ["PLACEHOLDER"]
            test_url = urllib.parse.urlunparse(
                parsed2._replace(query=urllib.parse.urlencode(qs, doseq=True))
            )
            pairs.append((test_url, p))

    return pairs


def open_redirect_scan(target: str, extra_urls: list[str], out_folder: Path,
                       timeout: int = 8) -> OpenRedirectResult:
    """Scan target and discovered URLs for open redirect vulnerabilities."""
    if not target.startswith("http"):
        base_url = f"https://{target}"
    else:
        base_url = target

    result = OpenRedirectResult(target=target)
    safe_print(f"[info]▶ Open Redirect Scanner — {base_url}[/]")

    # Build test URL list
    test_pairs = _build_test_urls(base_url)
    for eu in extra_urls[:20]:
        for param in REDIRECT_PARAMS[:8]:
            if "?" in eu:
                test_pairs.append((eu + f"&{param}=PLACEHOLDER", param))
            else:
                test_pairs.append((eu + f"?{param}=PLACEHOLDER", param))

    # Deduplicate
    seen = set()
    deduped = []
    for url, param in test_pairs:
        key = (urllib.parse.urlparse(url).path, param)
        if key not in seen:
            seen.add(key)
            deduped.append((url, param))

    result.params_tested = len(deduped)
    safe_print(f"  [dim]Testing {len(deduped)} redirect param candidates...[/]")

    for template_url, param in deduped[:60]:
        for payload in PAYLOADS[:4]:
            test_url = template_url.replace("PLACEHOLDER",
                                            urllib.parse.quote(payload, safe=""))
            code, location = _fetch_no_follow(test_url, timeout)

            if code in (301, 302, 303, 307, 308) and MARKER in location:
                severity = "high"
                if any(p in payload for p in ["//", "https:", "\\"]):
                    severity = "critical"
                result.findings.append(RedirectFinding(
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    redirect_to=location,
                    severity=severity,
                    detail=f"Server redirected to attacker-controlled domain via {param}={payload!r}",
                ))
                break  # one finding per param

    crit = sum(1 for f in result.findings if f.severity == "critical")
    if result.findings:
        safe_print(f"  [warning]⚠  Open Redirect: {len(result.findings)} findings "
                   f"({crit} critical)[/]")
    else:
        safe_print("  [dim]Open Redirect: no redirect vulnerabilities found[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    out_file = out_folder / "open_redirect.txt"
    lines = ["# Open Redirect Scan Results\n",
             f"Target: {base_url}\n",
             f"Params tested: {result.params_tested}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] Open redirect via param: {f.parameter}\n")
        lines.append(f"  URL:      {f.url}\n")
        lines.append(f"  Payload:  {f.payload}\n")
        lines.append(f"  Redirect: {f.redirect_to}\n")
        lines.append(f"  Detail:   {f.detail}\n\n")
    out_file.write_text("".join(lines), encoding="utf-8")

    return result
