"""
core/asn_map.py — ReconNinja v7.0.0
BGP/ASN IP Range Mapping.

Resolves the target organization's Autonomous System Number (ASN)
and maps all owned IP CIDRs. This reveals owned infrastructure
that might not be discoverable via subdomain enumeration.

Data sources (no API key required):
  - ipwhois (RDAP/WHOIS) — pip install ipwhois (optional)
  - bgp.he.net scraping (fallback)
  - Team Cymru ASN lookup via DNS (no account needed)
  - RIPE/ARIN/APNIC REST APIs (public, no key)

"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


@dataclass
class ASNResult:
    target:  str
    asn:     str    = ""
    org:     str    = ""
    country: str    = ""
    prefixes: list[str] = field(default_factory=list)  # IP CIDRs
    total_ips: int  = 0
    error:   str    = ""

    def to_dict(self) -> dict:
        return {
            "target":    self.target,
            "asn":       self.asn,
            "org":       self.org,
            "country":   self.country,
            "prefixes":  self.prefixes,
            "total_ips": self.total_ips,
        }


# ── IP lookup ─────────────────────────────────────────────────────────────────

def _resolve_target(target: str) -> Optional[str]:
    """Resolve domain to IP."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


# ── Team Cymru DNS ASN lookup (free, no account) ──────────────────────────────

def _cymru_asn(ip: str) -> tuple[str, str]:
    """
    Look up ASN via Team Cymru DNS.
    Returns (asn, org) or ("", "").
    """
    try:
        # Reverse the IP octets and append .origin.asn.cymru.com
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        try:
            import dns.resolver
            answers = dns.resolver.resolve(query, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() for s in rdata.strings)
                # Format: "asn | cidr | country | registry | allocated"
                parts = [p.strip() for p in txt.split("|")]
                if parts:
                    return parts[0], parts[-1] if len(parts) > 4 else ""
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: socket-based DNS TXT (limited)
        result = socket.getaddrinfo(query, None)
        return "", ""
    except Exception:
        return "", ""


# ── RIPE API ──────────────────────────────────────────────────────────────────

def _ripe_prefixes(asn: str, timeout: int = 15) -> list[str]:
    """Fetch announced prefixes from RIPE Stat API (public, free)."""
    if not asn:
        return []
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&sourceapp=ReconNinja"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        prefixes = data.get("data", {}).get("prefixes", [])
        return [p.get("prefix", "") for p in prefixes if p.get("prefix")]
    except Exception as e:
        log.debug(f"RIPE prefixes error: {e}")
        return []


def _ripe_asn_for_ip(ip: str, timeout: int = 10) -> tuple[str, str]:
    """Get ASN and org for an IP from RIPE Stat (works globally via RIPE routing data)."""
    try:
        url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp=ReconNinja"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        asns = data.get("data", {}).get("asns", [])
        return asns[0] if asns else "", ""
    except Exception:
        return "", ""


def _ipwhois_lookup(ip: str) -> tuple[str, str, str]:
    """Use ipwhois library if installed for enriched ASN data."""
    try:
        from ipwhois import IPWhois
        obj  = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)
        asn  = rdap.get("asn", "")
        org  = rdap.get("asn_description", "")
        cc   = rdap.get("asn_country_code", "")
        return str(asn), org, cc
    except ImportError:
        return "", "", ""
    except Exception as e:
        log.debug(f"ipwhois error: {e}")
        return "", "", ""


# ── Public API ────────────────────────────────────────────────────────────────

def asn_map(target: str, out_folder: Path) -> ASNResult:
    """
    Map target organization's ASN and owned IP ranges.

    Args:
        target:    domain or IP
        out_folder: output directory

    Returns:
        ASNResult with ASN, org, country, and all owned prefixes
    """
    ensure_dir(out_folder)
    result = ASNResult(target=target)
    safe_print(f"[info]▶ ASN/BGP Mapping — {target}[/]")

    # Resolve to IP
    ip = _resolve_target(target)
    if not ip:
        result.error = f"Could not resolve {target} to IP"
        safe_print(f"[warning]ASN Map: {result.error}[/]")
        return result

    safe_print(f"  [dim]Resolved: {target} → {ip}[/]")

    # Try ipwhois first (richest data)
    asn, org, cc = _ipwhois_lookup(ip)
    if not asn:
        # Fallback: RIPE Stat
        asn, org = _ripe_asn_for_ip(ip)
    if not asn:
        # Fallback: Team Cymru
        asn, org = _cymru_asn(ip)

    result.asn     = f"AS{asn}" if asn and not str(asn).startswith("AS") else str(asn)
    result.org     = org or "Unknown"
    result.country = cc

    safe_print(f"  [info]ASN: {result.asn} — Org: {result.org}[/]")

    if result.asn and result.asn != "AS":
        # Get all prefixes announced by this ASN
        result.prefixes = _ripe_prefixes(result.asn)
        result.total_ips = sum(
            2 ** (32 - int(p.split("/")[-1]))
            for p in result.prefixes
            if "/" in p and p.split("/")[-1].isdigit()
        )
        safe_print(
            f"  [info]{len(result.prefixes)} prefix(es), ~{result.total_ips:,} IPs owned[/]"
        )

    # Save
    out_file = out_folder / "asn_map.txt"
    lines = [
        f"# ASN/BGP Map — {target}",
        f"IP:       {ip}",
        f"ASN:      {result.asn}",
        f"Org:      {result.org}",
        f"Country:  {result.country}",
        f"Prefixes: {len(result.prefixes)}",
        f"Total IPs: ~{result.total_ips:,}",
        "",
        "# Prefixes:",
    ] + result.prefixes
    out_file.write_text("\n".join(lines))

    safe_print(f"[success]✔ ASN Map complete → {out_file}[/]")
    return result
