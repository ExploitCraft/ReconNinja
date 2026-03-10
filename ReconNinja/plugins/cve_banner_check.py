"""
ReconNinja v3 — Example Plugin: CVE Banner Check
Checks open port banners against a minimal known-vulnerable version list.
"""

PLUGIN_NAME    = "cve_banner_check"
PLUGIN_VERSION = "1.0"

# Minimal example mapping: (service, keyword_in_banner) → CVE info
KNOWN_VULNS = [
    ("openssh",  "OpenSSH_7.2",  "CVE-2016-6515", "OpenSSH 7.2 DoS"),
    ("vsftpd",   "vsftpd 2.3.4", "CVE-2011-2523", "vsftpd 2.3.4 backdoor"),
    ("apache",   "Apache/2.4.49","CVE-2021-41773","Apache path traversal"),
    ("apache",   "Apache/2.4.50","CVE-2021-42013","Apache RCE"),
]


def run(target, out_folder, result, config):
    """Scan port banners for known vulnerable service versions."""
    from utils.models import VulnFinding

    for host in result.hosts:
        for port in host.open_ports:
            banner = f"{port.product} {port.version}".lower()
            for svc, keyword, cve, desc in KNOWN_VULNS:
                if keyword.lower() in banner:
                    finding = VulnFinding(
                        tool=PLUGIN_NAME,
                        severity="high",
                        title=desc,
                        target=f"{host.ip}:{port.port}",
                        details=f"Banner: {port.product} {port.version}",
                        cve=cve,
                    )
                    result.nuclei_findings.append(finding)
