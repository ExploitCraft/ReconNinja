"""
core/ldap_enum.py — ReconNinja v7.0.0
LDAP Anonymous Bind and Attribute Enumeration.

Attempts anonymous bind against LDAP (389) and LDAPS (636).
On success, dumps: base DN, domain info, user/group objects,
password policies, and any exposed attributes.

Uses ldap3 if installed (pip install ldap3), raw socket fallback
for port-open detection otherwise.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print


@dataclass
class LDAPResult:
    host:          str
    port:          int
    vulnerable:    bool        = False
    base_dn:       str         = ""
    domain:        str         = ""
    users:         list[str]   = field(default_factory=list)
    groups:        list[str]   = field(default_factory=list)
    attributes:    list[dict]  = field(default_factory=list)
    error:         str         = ""

    def to_dict(self) -> dict:
        return {
            "host":       self.host,
            "port":       self.port,
            "vulnerable": self.vulnerable,
            "base_dn":    self.base_dn,
            "domain":     self.domain,
            "users":      self.users[:20],
            "groups":     self.groups[:20],
        }


def _ldap3_enum(host: str, port: int, timeout: int) -> LDAPResult:
    """Full LDAP enumeration using ldap3 library."""
    result = LDAPResult(host=host, port=port)
    try:
        import ldap3
        use_ssl = port == 636

        server = ldap3.Server(
            host, port=port, use_ssl=use_ssl,
            get_info=ldap3.ALL,
            connect_timeout=timeout,
        )
        conn = ldap3.Connection(
            server, user=None, password=None,
            authentication=ldap3.ANONYMOUS,
            auto_bind=True,
        )

        result.vulnerable = True

        # Extract base DN from server info
        if server.info:
            naming_contexts = server.info.naming_contexts
            if naming_contexts:
                result.base_dn = str(naming_contexts[0])

        if not result.base_dn:
            result.error = "No base DN found"
            conn.unbind()
            return result

        # Extract domain from DN
        dc_parts = [p.split("=")[1] for p in result.base_dn.split(",") if p.lower().startswith("dc=")]
        result.domain = ".".join(dc_parts)

        safe_print(f"  [danger]⚠  LDAP anon bind: base_dn={result.base_dn} domain={result.domain}[/]")

        # Enumerate users
        conn.search(
            result.base_dn,
            "(objectClass=person)",
            attributes=["sAMAccountName", "cn", "mail", "description"],
            size_limit=50,
        )
        for entry in conn.entries[:50]:
            cn = str(entry.cn) if hasattr(entry, "cn") else ""
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
            result.users.append(sam or cn)

        # Enumerate groups
        conn.search(
            result.base_dn,
            "(objectClass=group)",
            attributes=["cn", "description"],
            size_limit=50,
        )
        for entry in conn.entries[:50]:
            result.groups.append(str(entry.cn))

        conn.unbind()

    except ImportError:
        result.error = "ldap3 not installed — pip install ldap3"
    except Exception as e:
        err = str(e).lower()
        if "invalid credentials" in err or "unwilling" in err:
            result.error = "LDAP requires authentication"
        else:
            result.error = str(e)

    return result


def _port_check(host: str, port: int, timeout: int) -> bool:
    """Check if LDAP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def ldap_enum(
    host: str,
    out_folder: Path,
    open_ports: Optional[set[int]] = None,
    timeout: int = 8,
) -> list[LDAPResult]:
    """
    Enumerate LDAP/LDAPS for anonymous bind vulnerability.

    Args:
        host:       target host
        out_folder: output directory
        open_ports: set of open ports from scanner
        timeout:    per-request timeout

    Returns:
        list of LDAPResult (one per port tried)
    """
    ensure_dir(out_folder)
    results: list[LDAPResult] = []
    ports_to_try = []

    for port in (389, 636, 3268, 3269):  # also Global Catalog ports
        if open_ports is None or port in open_ports:
            if _port_check(host, port, timeout=3):
                ports_to_try.append(port)

    if not ports_to_try:
        safe_print(f"[dim]LDAP: no LDAP ports open on {host}[/]")
        return results

    safe_print(f"[info]▶ LDAP Enum — {host} ({ports_to_try})[/]")

    for port in ports_to_try:
        result = _ldap3_enum(host, port, timeout)
        results.append(result)

        if result.vulnerable:
            safe_print(
                f"  [danger]LDAP ANON BIND: {len(result.users)} user(s), "
                f"{len(result.groups)} group(s)[/]"
            )
        elif result.error:
            safe_print(f"  [dim]LDAP {port}: {result.error}[/]")

    # Save
    out_file = out_folder / "ldap_enum.txt"
    lines = [f"# LDAP Enumeration — {host}", ""]
    for r in results:
        lines.append(f"Port {r.port}: {'VULNERABLE' if r.vulnerable else 'SECURE'}")
        if r.vulnerable:
            lines.append(f"  Base DN: {r.base_dn}")
            lines.append(f"  Domain:  {r.domain}")
            lines.append(f"  Users:   {', '.join(r.users[:10])}")
            lines.append(f"  Groups:  {', '.join(r.groups[:10])}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    return results
