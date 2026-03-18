"""
core/ssl_scan.py — ReconNinja v5.0.0
SSL/TLS certificate analysis — no external tools required.
Uses Python ssl + socket stdlib only.
"""
from __future__ import annotations

import ssl
import socket
import datetime
from typing import Optional

from utils.logger import safe_print, log


def _get_cert(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """Retrieve SSL certificate from host:port."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert     = ssock.getpeercert()
                cipher   = ssock.cipher()
                version  = ssock.version()
                return {
                    "cert":    cert,
                    "cipher":  cipher,
                    "version": version,
                }
    except ssl.SSLError as e:
        log.warning(f"SSL error {host}:{port} — {e}")
        return None
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        log.debug(f"SSL connect failed {host}:{port} — {e}")
        return None


def _check_weak_cipher(cipher_name: str) -> list[str]:
    issues = []
    weak   = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"]
    for w in weak:
        if w in cipher_name.upper():
            issues.append(f"Weak cipher: {w}")
    return issues


def ssl_scan(host: str, ports: Optional[list[int]] = None) -> dict:
    """
    Scan SSL/TLS configuration on a host.
    Checks certificate validity, expiry, weak ciphers, protocol version.
    """
    if ports is None:
        ports = [443, 8443]

    result = {
        "host":     host,
        "findings": [],
        "certs":    [],
        "issues":   [],
    }

    for port in ports:
        data = _get_cert(host, port)
        if not data:
            continue

        cert    = data["cert"]
        cipher  = data["cipher"]   # (name, protocol, bits)
        version = data["version"]  # e.g. TLSv1.2

        cert_info: dict = {
            "port":       port,
            "version":    version,
            "cipher":     cipher[0] if cipher else "",
            "bits":       cipher[2] if cipher and len(cipher) > 2 else 0,
            "subject":    {},
            "issuer":     {},
            "san":        [],
            "not_before": "",
            "not_after":  "",
            "days_left":  0,
            "expired":    False,
            "self_signed":False,
            "issues":     [],
        }

        if cert:
            # Subject
            subj = dict(x[0] for x in cert.get("subject", []))
            cert_info["subject"] = subj
            cert_info["issuer"]  = dict(x[0] for x in cert.get("issuer", []))

            # SANs
            cert_info["san"] = [
                v for t, v in cert.get("subjectAltName", []) if t == "DNS"
            ]

            # Expiry
            fmt = "%b %d %H:%M:%S %Y %Z"
            try:
                not_after  = datetime.datetime.strptime(cert.get("notAfter", ""), fmt)
                not_before = datetime.datetime.strptime(cert.get("notBefore", ""), fmt)
                days_left  = (not_after - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                cert_info["not_after"]  = str(not_after.date())
                cert_info["not_before"] = str(not_before.date())
                cert_info["days_left"]  = days_left
                cert_info["expired"]    = days_left < 0

                if cert_info["expired"]:
                    cert_info["issues"].append("EXPIRED certificate")
                    result["issues"].append({"severity": "critical", "detail": f"Port {port}: Certificate EXPIRED"})
                elif days_left < 14:
                    cert_info["issues"].append(f"Expires in {days_left} days")
                    result["issues"].append({"severity": "high", "detail": f"Port {port}: Certificate expires in {days_left} days"})
                elif days_left < 30:
                    cert_info["issues"].append(f"Expires soon ({days_left} days)")
                    result["issues"].append({"severity": "medium", "detail": f"Port {port}: Certificate expires in {days_left} days"})

            except ValueError:
                pass

            # Self-signed check
            if cert_info["subject"] == cert_info["issuer"]:
                cert_info["self_signed"] = True
                cert_info["issues"].append("Self-signed certificate")
                result["issues"].append({"severity": "medium", "detail": f"Port {port}: Self-signed certificate"})

        # Protocol version checks
        old_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
        if version in old_protocols:
            cert_info["issues"].append(f"Outdated protocol: {version}")
            result["issues"].append({"severity": "high", "detail": f"Port {port}: Outdated protocol {version}"})

        # Cipher checks
        if cipher:
            weak_issues = _check_weak_cipher(cipher[0])
            cert_info["issues"].extend(weak_issues)
            for w in weak_issues:
                result["issues"].append({"severity": "high", "detail": f"Port {port}: {w}"})

            if cert_info["bits"] and cert_info["bits"] < 128:
                cert_info["issues"].append(f"Weak key size: {cert_info['bits']} bits")
                result["issues"].append({"severity": "high", "detail": f"Port {port}: Weak key size {cert_info['bits']} bits"})

        result["certs"].append(cert_info)

    if result["certs"]:
        issue_count = len(result["issues"])
        sev_color   = "danger" if issue_count > 0 else "success"
        safe_print(
            f"  [info]SSL:[/] {host} — "
            f"[{sev_color}]{issue_count} issue(s)[/] "
            f"cert=[cyan]{result['certs'][0].get('subject', {}).get('commonName', '?')}[/]"
        )

    return result
