"""
core/ens_lookup.py — ReconNinja v8.0.0
ENS / On-chain Recon — resolves ENS domains, fetches wallet history
metadata, and links to social handles via on-chain profile records.
"""
from __future__ import annotations
import re, json, ssl, urllib.request, urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class EnsRecord:
    name: str
    address: str = ""
    content_hash: str = ""
    twitter: str = ""
    github: str = ""
    email: str = ""
    url: str = ""
    description: str = ""
    avatar: str = ""

@dataclass
class EnsLookupResult:
    target: str
    ens_records: list[EnsRecord] = field(default_factory=list)
    linked_wallets: list[str] = field(default_factory=list)
    social_handles: dict[str, str] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)

def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(32768).decode(errors="ignore")
    except Exception: return ""

def _resolve_ens_via_api(name: str, timeout: int) -> EnsRecord:
    """Use ENS public API / The Graph to resolve ENS name."""
    record = EnsRecord(name=name)
    # Use ENS metadata API
    url = f"https://metadata.ens.domains/mainnet/0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85/{urllib.parse.quote(name)}"
    body = _fetch(url, timeout)
    try:
        data = json.loads(body)
        record.description = data.get("description", "")
        record.url = data.get("url", "")
        attrs = {a["trait_type"]: a["value"] for a in data.get("attributes", [])}
        record.twitter = attrs.get("com.twitter", "")
        record.github = attrs.get("com.github", "")
        record.email = attrs.get("email", "")
        record.avatar = data.get("image", "")
    except Exception:
        pass

    # Try ENS subgraph for resolver/address
    subgraph = "https://api.thegraph.com/subgraphs/name/ensdomains/ens"
    query = json.dumps({"query": """{
        domains(where: {{name: "{name}"}}) {{
            name resolvedAddress {{ id }}
            owner {{ id }}
            registrant {{ id }}
        }}
    }"""}).encode()
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(subgraph, data=query, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            gdata = json.loads(r.read(8192).decode())
            domains = gdata.get("data", {}).get("domains", [])
            if domains:
                d = domains[0]
                if d.get("resolvedAddress"):
                    record.address = d["resolvedAddress"]["id"]
    except Exception:
        pass

    return record

def _guess_ens_names(domain: str) -> list[str]:
    """Guess likely ENS names from a domain."""
    base = domain.split(".")[0].lower()
    return [
        f"{base}.eth",
        f"{base}dao.eth",
        f"{base}protocol.eth",
        f"{base}finance.eth",
        f"the{base}.eth",
    ]

def ens_lookup(target: str, out_folder: Path, timeout: int = 12) -> EnsLookupResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = EnsLookupResult(target=target)
    safe_print(f"[info]▶ ENS / On-chain Recon — {domain}[/]")

    # Guess and resolve ENS names
    candidates = _guess_ens_names(domain)
    # Also check if target itself is an ENS name
    if domain.endswith(".eth"):
        candidates.insert(0, domain)

    safe_print(f"  [dim]Probing {len(candidates)} ENS candidates...[/]")
    for name in candidates:
        record = _resolve_ens_via_api(name, timeout)
        if record.address or record.twitter or record.github or record.description:
            result.ens_records.append(record)
            if record.address:
                result.linked_wallets.append(record.address)
            if record.twitter:
                result.social_handles["twitter"] = record.twitter
            if record.github:
                result.social_handles["github"] = record.github

    # Scan target website for ENS references
    body = _fetch(f"https://{domain}", timeout)
    ens_pat = re.compile(r'[a-zA-Z0-9\-]+\.eth\b')
    web_ens = list(dict.fromkeys(ens_pat.findall(body)))[:10]
    for name in web_ens:
        if not any(r.name == name for r in result.ens_records):
            record = _resolve_ens_via_api(name, timeout)
            result.ens_records.append(record)

    if result.ens_records:
        result.findings.append(
            f"{len(result.ens_records)} ENS records resolved — "
            f"{len(result.linked_wallets)} wallets, "
            f"{len(result.social_handles)} social handles"
        )
    safe_print(f"  [dim]ENS: {len(result.ens_records)} records found, "
               f"{len(result.linked_wallets)} wallet addresses[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# ENS / On-chain Recon — {domain}\n\n"]
    for r in result.ens_records:
        lines.append(f"## {r.name}\n")
        if r.address: lines.append(f"  Wallet:      {r.address}\n")
        if r.twitter: lines.append(f"  Twitter:     @{r.twitter}\n")
        if r.github:  lines.append(f"  GitHub:      {r.github}\n")
        if r.email:   lines.append(f"  Email:       {r.email}\n")
        if r.url:     lines.append(f"  URL:         {r.url}\n")
        if r.description: lines.append(f"  Description: {r.description[:100]}\n")
        lines.append("\n")
    if result.linked_wallets:
        lines.append("## Linked Wallets\n")
        for w in result.linked_wallets:
            lines.append(f"  {w}\n")
    (out_folder / "ens_lookup.txt").write_text("".join(lines), encoding="utf-8")
    return result
