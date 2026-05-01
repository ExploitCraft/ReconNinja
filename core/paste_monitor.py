"""
core/paste_monitor.py — ReconNinja v8.0.0
Paste Site Monitor — scans Pastebin, GitHub Gist, and other paste sites
for credential dumps, API keys, and sensitive mentions of the target domain.
"""
from __future__ import annotations
import re, urllib.parse, urllib.request, urllib.error, ssl, json
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class PasteFinding:
    url: str
    paste_type: str
    matched_pattern: str
    severity: str
    snippet: str

@dataclass
class PasteMonitorResult:
    target: str
    findings: list[PasteFinding] = field(default_factory=list)
    pastes_checked: int = 0

PASTE_SEARCH_ENGINES = [
    ("https://www.google.com/search?q=site:pastebin.com+{domain}", "Pastebin/Google"),
    ("https://www.google.com/search?q=site:gist.github.com+{domain}", "Gist/Google"),
    ("https://www.google.com/search?q=site:paste.ee+{domain}", "paste.ee/Google"),
    ("https://www.google.com/search?q={domain}+password+OR+apikey+OR+secret+OR+credentials", "Google/Creds"),
]
SENSITIVE_PATTERNS = [
    (re.compile(r'password\s*[=:]\s*\S+', re.I), "password", "critical"),
    (re.compile(r'api.?key\s*[=:]\s*\S{10,}', re.I), "api_key", "critical"),
    (re.compile(r'secret\s*[=:]\s*\S{8,}', re.I), "secret", "high"),
    (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}', re.I), "base64_blob", "medium"),
    (re.compile(r'(AKIA|ASIA)[A-Z0-9]{16}', re.I), "aws_key", "critical"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}', re.I), "github_token", "critical"),
    (re.compile(r'sk-[A-Za-z0-9]{32,}', re.I), "openai_key", "critical"),
]

def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(32768).decode(errors="ignore")
    except Exception: return ""

def paste_monitor(target: str, out_folder: Path, timeout: int = 12) -> PasteMonitorResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = PasteMonitorResult(target=target)
    safe_print(f"[info]▶ Paste Monitor — {domain}[/]")
    for tmpl, source in PASTE_SEARCH_ENGINES:
        url = tmpl.replace("{domain}", urllib.parse.quote(domain))
        body = _fetch(url, timeout)
        result.pastes_checked += 1
        for pat, ptype, sev in SENSITIVE_PATTERNS:
            m = pat.search(body)
            if m:
                result.findings.append(PasteFinding(url=url, paste_type=source,
                    matched_pattern=ptype, severity=sev,
                    snippet=body[max(0,m.start()-30):m.end()+50]))
    if result.findings:
        safe_print(f"  [warning]⚑  Paste Monitor: {len(result.findings)} potential leaks found[/]")
    else:
        safe_print("  [dim]Paste Monitor: no credential leaks found[/]")
    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# Paste Monitor — {domain}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.matched_pattern} @ {f.paste_type}\n  URL: {f.url}\n  Snippet: {f.snippet[:120]}\n\n")
    (out_folder/"paste_monitor.txt").write_text("".join(lines), encoding="utf-8")
    return result
