"""
tests/conftest.py — ReconNinja v5.0.0
Shared fixtures for all test modules.

v5.0.0 additions:
  - basic_config: now includes run_cve_lookup, ai_provider, ai_key, ai_model, nvd_key
  - full_config:  new fixture with all v5.0.0 AI/CVE fields populated
"""
import pytest
import sys
import tempfile
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.models import (
    ScanConfig, ScanProfile, NmapOptions,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
)


# ── Port fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def basic_port():
    return PortInfo(port=80, protocol="tcp", state="open", service="http",
                    product="Apache", version="2.4.52")

@pytest.fixture
def ssh_port():
    return PortInfo(port=22, protocol="tcp", state="open", service="ssh",
                    product="OpenSSH", version="8.9p1")

@pytest.fixture
def closed_port():
    return PortInfo(port=443, protocol="tcp", state="closed")


# ── Host fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def basic_host(basic_port, ssh_port, closed_port):
    return HostResult(
        ip="192.168.1.100",
        hostnames=["example.com"],
        os_guess="Linux 5.x",
        os_accuracy="95",
        ports=[basic_port, ssh_port, closed_port],
    )


# ── Web / vuln fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def basic_web_finding():
    return WebFinding(url="http://example.com", status_code=200,
                      title="Home Page", technologies=["Apache","PHP 8.1"],
                      server="Apache/2.4.52", content_length=4096)

@pytest.fixture
def basic_vuln():
    return VulnFinding(tool="nuclei", severity="high",
                       title="Apache Path Traversal",
                       target="http://example.com",
                       details="CVE-2021-41773 path traversal",
                       cve="CVE-2021-41773")

@pytest.fixture
def cve_vuln():
    """NVD-sourced finding fixture."""
    return VulnFinding(tool="nvd", severity="critical",
                       title="CVE-2021-41773 (CVSS 7.5)",
                       target="192.168.1.100:80",
                       cve="CVE-2021-41773")


# ── Result fixture ────────────────────────────────────────────────────────────

@pytest.fixture
def basic_result(basic_host, basic_web_finding, basic_vuln):
    return ReconResult(
        target="example.com",
        start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com", "mail.example.com", "dev.example.com"],
        hosts=[basic_host],
        web_findings=[basic_web_finding],
        nuclei_findings=[basic_vuln],
        phases_completed=["subdomains","ports","web","vuln"],
    )


# ── Config fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def basic_config():
    """Standard config with v5.0.0 defaults (all new fields present)."""
    return ScanConfig(
        target="example.com",
        profile=ScanProfile.STANDARD,
        nmap_opts=NmapOptions(),
        # v5.0.0 fields — defaults
        run_cve_lookup=False,
        ai_provider="groq",
        ai_key="",
        ai_model="",
        nvd_key="",
    )

@pytest.fixture
def full_config():
    """Full-suite config with all v5.0.0 AI/CVE fields populated."""
    return ScanConfig(
        target="example.com",
        profile=ScanProfile.FULL_SUITE,
        nmap_opts=NmapOptions(timing="T4", scripts=True, version_detection=True),
        run_subdomains=True,
        run_rustscan=True,
        run_nuclei=True,
        run_httpx=True,
        run_ai_analysis=True,
        run_cve_lookup=True,    # v5.0.0
        ai_provider="groq",     # v5.0.0
        ai_key="gsk_testkey",   # v5.0.0
        ai_model="llama3-70b",  # v5.0.0
        nvd_key="nvd_testkey",  # v5.0.0
        threads=20,
        masscan_rate=5000,
    )

@pytest.fixture
def cve_config():
    """Minimal config focused on CVE lookup testing."""
    return ScanConfig(
        target="example.com",
        profile=ScanProfile.STANDARD,
        run_cve_lookup=True,
        nvd_key="",
    )


# ── Temp dir ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)
