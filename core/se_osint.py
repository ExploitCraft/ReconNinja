"""
core/se_osint.py — ReconNinja v8.0.0
Social Engineering OSINT — phone numbers, email addresses, and public PII
associated with the target domain, discovered via public sources.
"""
from __future__ import annotations
import re, urllib.parse, urllib.request, ssl
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class ContactFinding:
    type: str       # email / phone / handle
    value: str
    source: str
    context: str = ""

@dataclass
class SeOsintResult:
    target: str
    contacts: list[ContactFinding] = field(default_factory=list)
    domain_age: str = ""
    registrant_info: list[str] = field(default_factory=list)

EMAIL_PAT = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
PHONE_PAT = re.compile(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]')
HANDLE_PAT = re.compile(r'@([A-Za-z0-9_]{3,20})')

def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(32768).decode(errors="ignore")
    except Exception: return ""

def se_osint(target: str, out_folder: Path, timeout: int = 12) -> SeOsintResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = SeOsintResult(target=target)
    safe_print(f"[info]▶ SE OSINT — contact data for {domain}[/]")
    sources = [
        (f"https://{domain}/contact", "contact page"),
        (f"https://{domain}/about", "about page"),
        (f"https://{domain}/team", "team page"),
        (f"https://www.google.com/search?q=contact+email+{urllib.parse.quote(domain)}", "Google"),
        (f"https://hunter.io/domain-search?domain={domain}", "Hunter.io"),
    ]
    seen_vals = set()
    for url, source in sources:
        body = _fetch(url, timeout)
        for m in EMAIL_PAT.finditer(body):
            v = m.group()
            if domain in v or v not in seen_vals:
                seen_vals.add(v)
                result.contacts.append(ContactFinding(type="email", value=v, source=source,
                    context=body[max(0,m.start()-30):m.end()+30]))
        for m in PHONE_PAT.finditer(body):
            v = m.group().strip()
            if len(v) >= 10 and v not in seen_vals:
                seen_vals.add(v)
                result.contacts.append(ContactFinding(type="phone", value=v, source=source))
    # Deduplicate
    result.contacts = result.contacts[:50]
    safe_print(f"  [dim]SE OSINT: {len(result.contacts)} contacts found[/]")
    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# SE OSINT — {domain}\n\n"]
    for c in result.contacts:
        lines.append(f"[{c.type.upper()}] {c.value}  (source: {c.source})\n")
        if c.context:
            lines.append(f"  Context: {c.context[:80]}\n")
    (out_folder/"se_osint.txt").write_text("".join(lines), encoding="utf-8")
    return result
