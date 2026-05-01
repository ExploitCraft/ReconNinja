"""
core/dns_leak.py — ReconNinja v8.0.0
DNS Leak Checker — detects resolver exposure, split-horizon leaks,
and DNS-over-HTTPS misconfigurations.
"""
from __future__ import annotations
import socket, ssl, urllib.request, json, random, string
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class DnsLeakFinding:
    issue: str
    severity: str
    detail: str
    evidence: str = ""

@dataclass
class DnsLeakResult:
    target: str
    findings: list[DnsLeakFinding] = field(default_factory=list)
    resolvers_found: list[str] = field(default_factory=list)
    doh_supported: bool = False
    zone_transfer_possible: bool = False

def _fetch(url: str, timeout: int = 8) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(8192).decode(errors="ignore")
    except Exception: return ""

def _check_doh(domain: str, timeout: int) -> tuple[bool, list[str]]:
    """Check if target supports DNS-over-HTTPS (exposes resolver)."""
    doh_paths = [
        f"https://{domain}/dns-query?name=test.{domain}&type=A",
        f"https://{domain}/resolve?name=test.{domain}&type=A",
    ]
    for url in doh_paths:
        body = _fetch(url, timeout)
        if '"Status"' in body or '"Answer"' in body:
            return True, [url]
    return False, []

def _check_open_resolver(domain: str, timeout: int) -> bool:
    """Check if the target's DNS server acts as an open resolver."""
    try:
        # Try resolving google.com via the target's IP (open resolver check)
        target_ip = socket.gethostbyname(domain)
        # We can't easily send raw DNS without dnspython, so use a heuristic:
        # Check if TCP port 53 is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, 53))
        sock.close()
        return result == 0
    except Exception:
        return False

def _check_dns_rebinding_risk(domain: str, timeout: int) -> list[DnsLeakFinding]:
    """Look for TTL=0 or very low TTL responses that enable rebinding."""
    findings = []
    try:
        # Use public DoH to get TTL info
        url = f"https://dns.google/resolve?name={domain}&type=A"
        body = _fetch(url, timeout)
        data = json.loads(body)
        for ans in data.get("Answer", []):
            ttl = ans.get("TTL", 300)
            if ttl < 60 and ttl > 0:
                findings.append(DnsLeakFinding(
                    issue="Very low DNS TTL — DNS rebinding risk",
                    severity="medium",
                    detail=f"TTL={ttl}s for {domain} — enables DNS rebinding attacks",
                    evidence=f"Record: {ans}",
                ))
            elif ttl == 0:
                findings.append(DnsLeakFinding(
                    issue="Zero DNS TTL — DNS rebinding vector",
                    severity="high",
                    detail=f"TTL=0 for {domain} — classic DNS rebinding setup",
                    evidence=str(ans),
                ))
    except Exception:
        pass
    return findings

def _check_internal_hostnames(domain: str, timeout: int) -> list[DnsLeakFinding]:
    """Check if DNS returns RFC-1918 addresses or internal hostnames."""
    findings = []
    internal_pats = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "127.", "169.254."]
    subdomains = [f"internal.{domain}", f"intranet.{domain}",
                  f"admin.{domain}", f"vpn.{domain}", f"corp.{domain}"]
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            if any(ip.startswith(p) for p in internal_pats):
                findings.append(DnsLeakFinding(
                    issue="Internal IP exposed via public DNS",
                    severity="high",
                    detail=f"{sub} resolves to internal IP {ip} via public DNS — split-horizon leak",
                    evidence=f"{sub} → {ip}",
                ))
        except Exception:
            pass
    return findings

def _check_wildcard_dns(domain: str) -> list[DnsLeakFinding]:
    findings = []
    rand_sub = ''.join(random.choices(string.ascii_lowercase, k=12)) + f".{domain}"
    try:
        ip = socket.gethostbyname(rand_sub)
        findings.append(DnsLeakFinding(
            issue="Wildcard DNS configured",
            severity="low",
            detail=f"Random subdomain {rand_sub} resolves to {ip} — wildcard DNS active",
            evidence=f"{rand_sub} → {ip}",
        ))
    except Exception:
        pass
    return findings

def dns_leak_check(target: str, out_folder: Path, timeout: int = 10) -> DnsLeakResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = DnsLeakResult(target=target)
    safe_print(f"[info]▶ DNS Leak Check — {domain}[/]")

    # DNS-over-HTTPS exposure
    doh, doh_urls = _check_doh(domain, timeout)
    if doh:
        result.doh_supported = True
        result.findings.append(DnsLeakFinding(
            issue="DNS-over-HTTPS endpoint exposed",
            severity="info",
            detail="Target serves DoH — may expose resolver identity",
            evidence=str(doh_urls),
        ))

    # Open resolver check
    if _check_open_resolver(domain, timeout):
        result.findings.append(DnsLeakFinding(
            issue="Port 53 open — possible open DNS resolver",
            severity="medium",
            detail=f"TCP port 53 open on {domain} — may act as open resolver (amplification DDoS risk)",
        ))

    # DNS rebinding TTL check
    result.findings.extend(_check_dns_rebinding_risk(domain, timeout))

    # Internal hostname leak
    result.findings.extend(_check_internal_hostnames(domain, timeout))

    # Wildcard DNS
    result.findings.extend(_check_wildcard_dns(domain))

    high = sum(1 for f in result.findings if f.severity in ("high","critical"))
    safe_print(f"  [dim]DNS Leak: {len(result.findings)} findings ({high} high+)[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# DNS Leak Check — {domain}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.issue}\n  {f.detail}\n")
        if f.evidence:
            lines.append(f"  Evidence: {f.evidence}\n")
        lines.append("\n")
    (out_folder / "dns_leak.txt").write_text("".join(lines), encoding="utf-8")
    return result
