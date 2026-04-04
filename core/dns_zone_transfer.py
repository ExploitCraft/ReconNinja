"""
core/dns_zone_transfer.py — ReconNinja v7.0.0
DNS Zone Transfer (AXFR) check.

Attempts an AXFR query against each nameserver for the target domain.
A successful zone transfer leaks the entire DNS zone — all hostnames,
IPs, mail servers, and internal subdomains.

No external tools required — pure Python using dnspython (optional) or
raw socket fallback.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


@dataclass
class ZoneTransferResult:
    nameserver:   str
    vulnerable:   bool
    records:      list[str] = field(default_factory=list)
    error:        str = ""


@dataclass
class ZoneTransferScanResult:
    domain:       str
    nameservers:  list[str] = field(default_factory=list)
    results:      list[ZoneTransferResult] = field(default_factory=list)
    vulnerable_ns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain":        self.domain,
            "nameservers":   self.nameservers,
            "vulnerable_ns": self.vulnerable_ns,
            "results":       [
                {
                    "nameserver": r.nameserver,
                    "vulnerable": r.vulnerable,
                    "record_count": len(r.records),
                    "error": r.error,
                }
                for r in self.results
            ],
        }


# ── NS lookup ─────────────────────────────────────────────────────────────────

def _get_nameservers(domain: str) -> list[str]:
    """Resolve NS records for a domain using dnspython or socket fallback."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except ImportError:
        pass
    except Exception as e:
        log.debug(f"dnspython NS lookup failed: {e}")

    # Fallback: cannot get NS records without dnspython — caller will use dig
    return []


def _get_nameservers_via_dig(domain: str) -> list[str]:
    """Use system dig/nslookup as last resort for NS records."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "NS", domain],
            capture_output=True, text=True, timeout=10,
        )
        return [line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True, text=True, timeout=10,
        )
        ns_list = []
        for line in result.stdout.splitlines():
            if "nameserver" in line.lower() and "=" in line:
                ns = line.split("=")[-1].strip().rstrip(".")
                if ns:
                    ns_list.append(ns)
        return ns_list
    except Exception:
        return []


# ── AXFR via dnspython ────────────────────────────────────────────────────────

def _axfr_dnspython(domain: str, nameserver: str, timeout: int = 10) -> ZoneTransferResult:
    try:
        import dns.query
        import dns.zone
        import dns.exception
        ns_ip = socket.gethostbyname(nameserver)
        zone  = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
        records = [f"{name} {rdataset}" for name, rdataset in zone.iterate_rdatasets()]
        return ZoneTransferResult(
            nameserver=nameserver,
            vulnerable=True,
            records=records[:500],
        )
    except ImportError:
        return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                   error="dnspython not installed")
    except Exception as e:
        err_str = str(e).lower()
        if "refused" in err_str or "notimp" in err_str or "servfail" in err_str:
            return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                       error=f"AXFR refused: {e}")
        return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                   error=str(e))


# ── AXFR raw socket fallback ──────────────────────────────────────────────────

def _axfr_raw(domain: str, nameserver: str, timeout: int = 10) -> ZoneTransferResult:
    """
    Minimal raw TCP DNS AXFR probe.
    Only checks if the server responds with a non-REFUSED answer to AXFR.
    """
    try:
        ns_ip = socket.gethostbyname(nameserver)

        # Build a minimal AXFR DNS query
        def encode_name(name: str) -> bytes:
            parts = name.rstrip(".").split(".")
            encoded = b""
            for part in parts:
                encoded += bytes([len(part)]) + part.encode()
            return encoded + b"\x00"

        tx_id    = b"\xab\xcd"
        flags    = b"\x00\x00"
        question = encode_name(domain) + b"\x00\xfc\x00\x01"  # QTYPE=AXFR, QCLASS=IN
        query    = tx_id + flags + b"\x00\x01" + b"\x00\x00" * 3 + question
        length   = struct.pack(">H", len(query))
        payload  = length + query

        with socket.create_connection((ns_ip, 53), timeout=timeout) as sock:
            sock.sendall(payload)
            resp_len_data = sock.recv(2)
            if len(resp_len_data) < 2:
                return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                           error="No response")
            resp_len = struct.unpack(">H", resp_len_data)[0]
            response = b""
            while len(response) < min(resp_len, 4096):
                chunk = sock.recv(min(resp_len - len(response), 4096))
                if not chunk:
                    break
                response += chunk

        if len(response) < 4:
            return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                       error="Response too short")

        rcode = response[3] & 0x0F
        if rcode == 5:  # REFUSED
            return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                       error="AXFR refused by server")
        if rcode == 0 and len(response) > 50:
            return ZoneTransferResult(
                nameserver=nameserver,
                vulnerable=True,
                records=["[raw probe] AXFR not refused — install dnspython for full zone"],
            )
        return ZoneTransferResult(nameserver=nameserver, vulnerable=False,
                                   error=f"RCODE={rcode}")
    except Exception as e:
        return ZoneTransferResult(nameserver=nameserver, vulnerable=False, error=str(e))


# ── Public API ────────────────────────────────────────────────────────────────

def dns_zone_transfer_scan(
    domain: str,
    out_folder: Path,
    timeout: int = 10,
) -> ZoneTransferScanResult:
    """
    Check each nameserver for DNS zone transfer vulnerability.

    Args:
        domain:     target domain (e.g. "example.com")
        out_folder: output directory
        timeout:    per-NS timeout in seconds

    Returns:
        ZoneTransferScanResult
    """
    ensure_dir(out_folder)
    scan = ZoneTransferScanResult(domain=domain)

    # Discover nameservers
    ns_list = _get_nameservers(domain)
    if not ns_list:
        ns_list = _get_nameservers_via_dig(domain)
    if not ns_list:
        safe_print(f"[dim]DNS Zone Transfer: could not resolve NS records for {domain}[/]")
        return scan

    scan.nameservers = ns_list
    safe_print(
        f"[info]▶ DNS Zone Transfer — testing {len(ns_list)} nameserver(s) "
        f"for {domain}[/]"
    )

    for ns in ns_list[:6]:
        # Try dnspython first, fall back to raw socket
        result = _axfr_dnspython(domain, ns, timeout)
        if "not installed" in result.error:
            result = _axfr_raw(domain, ns, timeout)

        scan.results.append(result)

        if result.vulnerable:
            scan.vulnerable_ns.append(ns)
            safe_print(
                f"  [danger]⚠  VULNERABLE: {ns} allows AXFR! "
                f"{len(result.records)} record(s) leaked[/]"
            )
            # Save leaked zone
            zone_file = out_folder / f"zone_{ns.replace('.', '_')}.txt"
            zone_file.write_text("\n".join(result.records))
        else:
            safe_print(f"  [success]✔ {ns} — AXFR refused ({result.error or 'secure'})[/]")

    if scan.vulnerable_ns:
        safe_print(
            f"[danger]DNS Zone Transfer: {len(scan.vulnerable_ns)} vulnerable NS! "
            f"Full zone leaked.[/]"
        )
    else:
        safe_print(f"[success]✔ DNS Zone Transfer: all {len(ns_list)} NS refuse AXFR[/]")

    return scan
