"""
core/anon_detect.py — ReconNinja v8.0.0
Tor / VPN / Proxy / Hosting Detection.

Checks target IPs against public Tor exit node lists,
known VPN/hosting ranges, and open proxy databases.
"""
from __future__ import annotations
import socket, ssl, urllib.request, urllib.error, json
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class AnonFinding:
    ip: str
    type: str       # tor / vpn / proxy / hosting / clean
    confidence: str # high / medium / low
    detail: str
    source: str

@dataclass
class AnonDetectResult:
    target: str
    ips_checked: list[str] = field(default_factory=list)
    findings: list[AnonFinding] = field(default_factory=list)
    is_tor: bool = False
    is_vpn: bool = False
    is_hosting: bool = False

# Known hosting/datacenter ASN prefixes (a subset of common ones)
HOSTING_ASNS = [
    "AS14061",  # DigitalOcean
    "AS16509",  # Amazon AWS
    "AS15169",  # Google Cloud
    "AS8075",   # Microsoft Azure
    "AS20473",  # Vultr
    "AS63949",  # Linode
    "AS46606",  # Unified Layer / Bluehost
    "AS32400",  # Leaseweb
    "AS7922",   # Comcast (not hosting but common VPN exit)
]

def _fetch(url: str, timeout: int = 8) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(16384).decode(errors="ignore")
    except Exception: return ""

def _resolve_ips(domain: str) -> list[str]:
    try:
        return list({r[4][0] for r in socket.getaddrinfo(domain, None)})
    except Exception: return []

def _check_tor(ip: str) -> bool:
    """Query Tor Project's DNSEL to check if IP is a Tor exit node."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.dnsel.torproject.org"
        socket.gethostbyname(query)
        return True  # resolved = it's a Tor exit
    except socket.gaierror:
        return False  # NXDOMAIN = not Tor

def _check_ipqualityscore(ip: str, timeout: int) -> dict:
    """Use IPQualityScore free API (no key needed for basic checks)."""
    url = f"https://ipqualityscore.com/api/json/ip/YOUR_KEY/{ip}"
    # Fallback to ip-api which has free tier
    url = f"http://ip-api.com/json/{ip}?fields=status,isp,org,as,hosting,proxy,query"
    body = _fetch(url, timeout)
    try:
        return json.loads(body)
    except Exception:
        return {}

def _check_ipapi(ip: str, timeout: int) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=status,isp,org,as,hosting,proxy,query"
    body = _fetch(url, timeout)
    try:
        return json.loads(body)
    except Exception:
        return {}

def anon_detect(target: str, extra_ips: list[str], out_folder: Path, timeout: int = 10) -> AnonDetectResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = AnonDetectResult(target=target)
    safe_print("[info]▶ Anonymity Detection — Tor/VPN/Proxy check[/]")

    ips = _resolve_ips(domain) + extra_ips
    ips = list(dict.fromkeys(ips))[:10]
    result.ips_checked = ips

    for ip in ips:
        # Tor check
        if _check_tor(ip):
            result.is_tor = True
            result.findings.append(AnonFinding(
                ip=ip, type="tor", confidence="high",
                detail=f"{ip} is a registered Tor exit node",
                source="Tor Project DNSEL",
            ))
            continue

        # ip-api check
        data = _check_ipapi(ip, timeout)
        if data.get("status") == "success":
            asn = data.get("as", "")
            isp = data.get("isp", "")
            is_hosting = data.get("hosting", False)
            is_proxy = data.get("proxy", False)

            if is_proxy:
                result.is_vpn = True
                result.findings.append(AnonFinding(
                    ip=ip, type="proxy/vpn", confidence="high",
                    detail=f"{ip} detected as proxy/VPN by ip-api ({isp})",
                    source="ip-api.com",
                ))
            elif is_hosting:
                result.is_hosting = True
                result.findings.append(AnonFinding(
                    ip=ip, type="hosting", confidence="medium",
                    detail=f"{ip} is a datacenter/hosting IP ({isp}, {asn})",
                    source="ip-api.com",
                ))
            elif any(a in asn for a in HOSTING_ASNS):
                result.is_hosting = True
                result.findings.append(AnonFinding(
                    ip=ip, type="hosting", confidence="medium",
                    detail=f"{ip} belongs to known hosting ASN: {asn}",
                    source="ASN list",
                ))

    safe_print(f"  [dim]Checked {len(ips)} IPs — Tor:{result.is_tor}, "
               f"VPN/Proxy:{result.is_vpn}, Hosting:{result.is_hosting}[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# Anonymity Detection — {domain}\n\n",
             f"IPs checked: {', '.join(ips)}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.type.upper()}] {f.ip}\n  {f.detail}\n  Source: {f.source}\n\n")
    (out_folder / "anon_detect.txt").write_text("".join(lines), encoding="utf-8")
    return result
