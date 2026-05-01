"""
core/web3_scan.py — ReconNinja v8.0.0
Blockchain / Web3 Scanner — smart contract source exposure,
ABI scraping, Solidity vulnerability flags via Etherscan API,
and on-chain metadata collection.
"""
from __future__ import annotations
import re, json, ssl, urllib.request, urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class Web3Finding:
    issue: str
    severity: str
    detail: str
    address: str = ""
    evidence: str = ""

@dataclass
class Web3ScanResult:
    target: str
    contracts_found: list[dict] = field(default_factory=list)
    findings: list[Web3Finding] = field(default_factory=list)
    wallet_addresses: list[str] = field(default_factory=list)
    ens_names: list[str] = field(default_factory=list)

ETH_ADDRESS_PAT = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
ETH_TX_PAT = re.compile(r'\b0x[a-fA-F0-9]{64}\b')
ENS_PAT = re.compile(r'[a-zA-Z0-9\-]+\.eth\b')

# Solidity vulnerability patterns (in source code)
SOLIDITY_VULN_PATTERNS = [
    (re.compile(r'\.call\{value'), "Reentrancy risk — .call{value} without mutex", "high"),
    (re.compile(r'tx\.origin'), "tx.origin auth bypass risk", "high"),
    (re.compile(r'block\.timestamp.*(?:==|<|>)'), "Timestamp dependence", "medium"),
    (re.compile(r'selfdestruct\('), "selfdestruct present — contract can be destroyed", "high"),
    (re.compile(r'delegatecall\('), "delegatecall — proxy vulnerability risk", "high"),
    (re.compile(r'assembly\s*\{'), "Inline assembly — requires manual audit", "medium"),
    (re.compile(r'pragma solidity.*\^0\.[1-4]\.'), "Outdated Solidity version", "medium"),
    (re.compile(r'suicide\('), "Deprecated suicide() — use selfdestruct", "low"),
    (re.compile(r'transfer\(\s*msg\.sender'), "Unchecked transfer to msg.sender", "medium"),
]

def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(65536).decode(errors="ignore")
    except Exception: return ""

def _etherscan_lookup(address: str, timeout: int) -> dict:
    """Query Etherscan public API (no key for basic lookups)."""
    url = (f"https://api.etherscan.io/api?module=contract&action=getsourcecode"
           f"&address={address}&apikey=YourApiKeyToken")
    body = _fetch(url, timeout)
    try:
        data = json.loads(body)
        if data.get("status") == "1" and data.get("result"):
            return data["result"][0]
    except Exception:
        pass
    return {}

def _check_contract_source(address: str, source: str) -> list[Web3Finding]:
    findings = []
    for pat, label, sev in SOLIDITY_VULN_PATTERNS:
        if pat.search(source):
            findings.append(Web3Finding(
                issue=label, severity=sev,
                detail=f"Pattern found in contract source: {address}",
                address=address,
            ))
    return findings

def _scan_target_for_web3(target: str, timeout: int) -> tuple[list[str], list[str], list[str]]:
    """Scrape target website for Ethereum addresses, TX hashes, ENS names."""
    if not target.startswith("http"):
        url = f"https://{target}"
    else:
        url = target
    body = _fetch(url, timeout)
    addresses = list(dict.fromkeys(ETH_ADDRESS_PAT.findall(body)))[:20]
    ens_names = list(dict.fromkeys(ENS_PAT.findall(body)))[:10]
    # Also check /robots.txt, /sitemap.xml for contract addresses
    for path in ["/robots.txt", "/sitemap.xml", "/whitepaper.pdf"]:
        extra = _fetch(url.rstrip("/") + path, timeout)
        for addr in ETH_ADDRESS_PAT.findall(extra):
            if addr not in addresses:
                addresses.append(addr)
    return addresses, ens_names, []

def _check_abi_exposure(target: str, timeout: int) -> list[Web3Finding]:
    """Check for exposed ABI files on the web server."""
    findings = []
    if not target.startswith("http"):
        base = f"https://{target}"
    else:
        base = target
    paths = ["/abi.json", "/contracts/abi.json", "/static/abi.json",
              "/artifacts/contracts/Token.sol/Token.json",
              "/build/contracts/Token.json"]
    for path in paths:
        url = base.rstrip("/") + path
        body = _fetch(url, timeout)
        if '"inputs"' in body and '"outputs"' in body and '"type"' in body:
            findings.append(Web3Finding(
                issue="ABI file publicly exposed",
                severity="medium",
                detail=f"Contract ABI accessible at {url} — reveals full contract interface",
                evidence=body[:200],
            ))
    return findings

def web3_scan(target: str, out_folder: Path, timeout: int = 12) -> Web3ScanResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    result = Web3ScanResult(target=target)
    safe_print(f"[info]▶ Web3 Scanner — {domain}[/]")

    # Scan target for on-chain references
    safe_print("  [dim]Scanning for Ethereum addresses and ENS names...[/]")
    addresses, ens_names, _ = _scan_target_for_web3(target, timeout)
    result.wallet_addresses = addresses
    result.ens_names = ens_names

    if addresses:
        safe_print(f"  [dim]{len(addresses)} ETH addresses found — querying Etherscan...[/]")
    for addr in addresses[:5]:  # cap API calls
        info = _etherscan_lookup(addr, timeout)
        if info:
            contract_data = {
                "address": addr,
                "name": info.get("ContractName", ""),
                "compiler": info.get("CompilerVersion", ""),
                "verified": bool(info.get("SourceCode")),
                "proxy": info.get("Proxy", "0") == "1",
            }
            result.contracts_found.append(contract_data)
            if info.get("SourceCode"):
                source = info["SourceCode"]
                result.findings.extend(_check_contract_source(addr, source))
            if info.get("Proxy") == "1":
                result.findings.append(Web3Finding(
                    issue="Upgradeable proxy contract detected",
                    severity="medium",
                    detail=f"Contract {addr} is a proxy — implementation can be changed by owner",
                    address=addr,
                ))

    # ABI exposure check
    result.findings.extend(_check_abi_exposure(target, timeout))

    # ENS findings
    if ens_names:
        result.findings.append(Web3Finding(
            issue="ENS domain names found",
            severity="info",
            detail=f"ENS names linked to target: {', '.join(ens_names[:5])}",
        ))

    safe_print(f"  [dim]Web3: {len(result.contracts_found)} contracts, "
               f"{len(result.findings)} findings[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# Web3 Scan — {domain}\n\n",
             f"ETH Addresses: {len(result.wallet_addresses)}\n"
             f"Contracts (verified): {len(result.contracts_found)}\n"
             f"ENS Names: {', '.join(result.ens_names) or 'none'}\n\n"]
    for c in result.contracts_found:
        lines.append(f"Contract: {c['address']}\n  Name: {c['name']}  "
                     f"Verified: {c['verified']}  Proxy: {c['proxy']}\n\n")
    lines.append("## Findings\n")
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.issue}\n  {f.detail}\n\n")
    (out_folder / "web3_scan.txt").write_text("".join(lines), encoding="utf-8")
    return result
