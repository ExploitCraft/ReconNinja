"""
ReconNinja v9 — IoT / OT / ICS Recon  (--iot-scan)
Protocol detection: Modbus (502), DNP3 (20000), EtherNet/IP (44818),
BACnet (47808), IEC 61850 (102).
Shodan ICS filter integration, CVE correlation via NVD.
"""
from __future__ import annotations

import socket
from pathlib import Path

import requests

from utils.logger import log, safe_print
from utils.models import IoTFinding, ReconResult, ScanConfig

ICS_PORTS: dict[int, str] = {
    502:   "modbus",
    20000: "dnp3",
    44818: "ethernet-ip",
    47808: "bacnet",
    102:   "iec61850",
    4840:  "opcua",
    1962:  "pcworx",
    2455:  "wago",
    9600:  "omron-fins",
}

ICS_BANNERS: dict[str, dict] = {
    "siemens":     {"vendor": "Siemens",    "severity": "critical"},
    "rockwell":    {"vendor": "Rockwell",   "severity": "critical"},
    "schneider":   {"vendor": "Schneider",  "severity": "critical"},
    "honeywell":   {"vendor": "Honeywell",  "severity": "critical"},
    "ge electric": {"vendor": "GE",         "severity": "critical"},
    "allen-bradley": {"vendor": "Rockwell", "severity": "critical"},
    "omron":       {"vendor": "Omron",      "severity": "high"},
    "wago":        {"vendor": "WAGO",       "severity": "high"},
}


def iot_scan(target: str, result: ReconResult, cfg: ScanConfig, out_folder: Path) -> list[IoTFinding]:
    findings: list[IoTFinding] = []
    safe_print("[module]🏭  IoT / OT / ICS Scan...[/]")

    hosts = [target] + [h.ip for h in result.hosts[:20]]

    for host in hosts:
        for port, protocol in ICS_PORTS.items():
            if _port_open(host, port, timeout=3):
                banner = _grab_banner(host, port)
                vendor, severity = _identify_vendor(banner)
                cves = _fetch_ics_cves(vendor, protocol) if vendor else []
                findings.append(IoTFinding(
                    protocol=protocol,
                    host=host,
                    port=port,
                    vendor=vendor,
                    firmware=_extract_firmware(banner),
                    cves=cves,
                    severity=severity,
                ))

    # Shodan ICS queries if key available
    if cfg.shodan_key:
        findings += _shodan_ics_query(target, cfg)

    result.iot_findings.extend(findings)
    safe_print(f"[success]  ✔ IoT/OT scan: {len(findings)} ICS findings[/]")
    return findings


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _grab_banner(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(b"\x00" * 4)
            return s.recv(256).decode("latin-1", errors="replace").lower()
    except Exception:
        return ""


def _identify_vendor(banner: str) -> tuple[str, str]:
    for key, info in ICS_BANNERS.items():
        if key in banner:
            return info["vendor"], info["severity"]
    return "", "high"


def _extract_firmware(banner: str) -> str:
    import re
    m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
    return m.group(1) if m else ""


def _fetch_ics_cves(vendor: str, protocol: str) -> list[str]:
    if not vendor:
        return []
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"{vendor} {protocol}", "resultsPerPage": 5},
            timeout=15,
        )
        data = resp.json()
        return [v["cve"]["id"] for v in data.get("vulnerabilities", [])]
    except Exception:
        return []


def _shodan_ics_query(target: str, cfg: ScanConfig) -> list[IoTFinding]:
    findings: list[IoTFinding] = []
    try:
        import shodan  # type: ignore
        api = shodan.Shodan(cfg.shodan_key)
        results = api.search(f"net:{target} tag:ics")
        for match in results.get("matches", []):
            findings.append(IoTFinding(
                protocol=match.get("transport", "unknown"),
                host=match.get("ip_str", ""),
                port=match.get("port", 0),
                vendor=match.get("product", ""),
                firmware=match.get("version", ""),
                severity="critical",
            ))
    except ImportError:
        log.warning("[iot_scan] shodan package not installed")
    except Exception as e:
        log.warning(f"[iot_scan] Shodan query error: {e}")
    return findings
