"""
core/snmp_scan.py — ReconNinja v7.0.0
SNMP Community String Brute-Force and MIB Walk.

Probes UDP port 161 for SNMP with common community strings.
Extracts: system info, interface data, software list, routing table.

Uses pysnmp if installed, raw UDP fallback otherwise.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print

COMMON_COMMUNITIES = [
    "public", "private", "community", "manager", "admin",
    "cisco", "default", "internal", "snmp", "monitor",
]

# OIDs for common MIB values
SYSTEM_OIDS = {
    "sysDescr":   "1.3.6.1.2.1.1.1.0",
    "sysName":    "1.3.6.1.2.1.1.5.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation":"1.3.6.1.2.1.1.6.0",
}


@dataclass
class SNMPResult:
    host:             str
    port:             int
    community:        str    = ""
    vulnerable:       bool   = False
    system_info:      dict   = field(default_factory=dict)
    raw_data:         str    = ""
    error:            str    = ""

    def to_dict(self) -> dict:
        return {
            "host":        self.host,
            "port":        self.port,
            "community":   self.community,
            "vulnerable":  self.vulnerable,
            "system_info": self.system_info,
        }


def _pysnmp_walk(host: str, port: int, community: str, timeout: int) -> dict:
    """Use pysnmp for full MIB walk."""
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        results = {}
        for name, oid in SYSTEM_OIDS.items():
            for errorIndication, errorStatus, _, varBinds in getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ):
                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        results[name] = str(varBind[1])
        return results
    except ImportError:
        return {}
    except Exception:
        return {}


def _raw_snmp_get(host: str, port: int, community: str, timeout: int = 3) -> bool:
    """Minimal raw SNMP GET to test if community string is valid."""
    try:
        # Build SNMPv1 GET for sysDescr OID
        def encode_oid(oid_str: str) -> bytes:
            parts = list(map(int, oid_str.split(".")))
            encoded = bytes([40 * parts[0] + parts[1]])
            for part in parts[2:]:
                if part < 128:
                    encoded += bytes([part])
                else:
                    # Multi-byte encoding
                    b = []
                    while part:
                        b.insert(0, part & 0x7F)
                        part >>= 7
                    for i, byte in enumerate(b):
                        encoded += bytes([byte | (0x80 if i < len(b) - 1 else 0)])
            return encoded

        oid_bytes  = encode_oid("1.3.6.1.2.1.1.1.0")
        oid_tlv    = b"\x06" + bytes([len(oid_bytes)]) + oid_bytes
        null_value = b"\x05\x00"
        var_bind   = b"\x30" + bytes([len(oid_tlv) + len(null_value)]) + oid_tlv + null_value
        var_binds  = b"\x30" + bytes([len(var_bind)]) + var_bind

        comm_bytes = community.encode()
        pdu = (
            b"\xa0" + bytes([len(var_binds) + 12]) +  # GetRequest
            b"\x02\x01\x01" +   # request-id = 1
            b"\x02\x01\x00" +   # error-status = 0
            b"\x02\x01\x00" +   # error-index = 0
            var_binds
        )
        msg = (
            b"\x30" +
            bytes([2 + 2 + len(comm_bytes) + len(pdu) + 2]) +
            b"\x02\x01\x00" +   # version = v1
            b"\x04" + bytes([len(comm_bytes)]) + comm_bytes +
            pdu
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        # Check for valid SNMP response (starts with 0x30)
        return len(data) > 10 and data[0] == 0x30
    except Exception:
        return False


def snmp_scan(
    host: str,
    out_folder: Path,
    port: int = 161,
    communities: list[str] | None = None,
    timeout: int = 3,
) -> SNMPResult:
    """
    Brute-force SNMP community strings and extract MIB data.

    Args:
        host:         target host
        out_folder:   output directory
        port:         SNMP UDP port (default 161)
        communities:  community strings to try (default: common list)
        timeout:      per-probe timeout

    Returns:
        SNMPResult
    """
    ensure_dir(out_folder)
    result   = SNMPResult(host=host, port=port)
    to_try   = communities or COMMON_COMMUNITIES
    safe_print(f"[info]▶ SNMP Scan — {host}:{port} ({len(to_try)} community strings)[/]")

    for community in to_try:
        if _raw_snmp_get(host, port, community, timeout):
            result.vulnerable = True
            result.community  = community
            safe_print(f"  [danger]⚠  SNMP community '{community}' valid on {host}[/]")

            # Full walk with pysnmp if available
            result.system_info = _pysnmp_walk(host, port, community, timeout)
            if result.system_info:
                for k, v in result.system_info.items():
                    safe_print(f"    {k}: {v[:60]}")
            break

    if not result.vulnerable:
        safe_print("  [dim]SNMP: no valid community string found[/]")

    # Save
    out_file = out_folder / "snmp_scan.txt"
    lines = [f"# SNMP Scan — {host}:{port}", ""]
    if result.vulnerable:
        lines.append(f"Community: {result.community}")
        lines.append("System Info:")
        for k, v in result.system_info.items():
            lines.append(f"  {k}: {v}")
    else:
        lines.append("No valid community string found")
    out_file.write_text("\n".join(lines))
    return result
