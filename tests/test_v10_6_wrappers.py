"""
v10.6.0 — Comprehensive phase-wrapper smoke tests.

Mocks every v8 module that orchestrator_v9 imports and invokes every
_w_<phase> wrapper with controlled inputs. Catches type-mismatch bugs
like the v10.5.2 `list + set` TypeError in _w_rustscan before they
reach end users.

Each test:
  1. Patches the v8 module function to return a representative value
     of the correct type.
  2. Invokes the wrapper with a fresh ScanConfig + ReconResult.
  3. Asserts the wrapper ran without raising and that the result field
     was populated correctly.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Skip the entire module if orchestrator deps aren't installed.
def _try_import(name):
    try:
        __import__(name); return True
    except ImportError:
        return False

_REQUIRED = ["requests", "yaml", "dns", "bs4", "cryptography", "ldap3", "whois", "ipwhois"]
_MISSING = [m for m in _REQUIRED if _try_import(m) is False]
pytestmark = pytest.mark.skipif(
    bool(_MISSING),
    reason=f"missing deps: {_MISSING} — run `pip install -r requirements.txt`",
)

from utils.models import (
    ReconResult, ScanConfig, HostResult, PortInfo, NmapOptions, ScanProfile,
)
from core.resume import set_active_config


def _cfg(target="example.com", **kw):
    c = ScanConfig(target=target, profile=ScanProfile.STANDARD, nmap_opts=NmapOptions())
    for k, v in kw.items():
        if hasattr(c, k):
            setattr(c, k, v)
    return c

def _result(target="example.com"):
    return ReconResult(target=target, start_time="2026-06-21T00:00:00")


# ─── Port-scan wrappers (the v10.5.2 bug area) ──────────────────────────────

def test_w_rustscan_handles_set_return_value(tmp_path):
    """v10.5.2 bug: run_rustscan returns a set[int], but the wrapper did
    `list + set` which raises TypeError. v10.6.0 must use set-union."""
    from core.orchestrator_v9 import _w_rustscan
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_rustscan", return_value={22, 80, 443}):
        _w_rustscan(cfg, result, tmp_path)
    assert result.rustscan_ports == [22, 80, 443]


def test_w_rustscan_handles_empty_set(tmp_path):
    """Empty set return must not raise (e.g. host unreachable)."""
    from core.orchestrator_v9 import _w_rustscan
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_rustscan", return_value=set()):
        _w_rustscan(cfg, result, tmp_path)
    assert result.rustscan_ports == []


def test_w_rustscan_merges_with_existing_ports(tmp_path):
    """Pre-existing ports in result.rustscan_ports must be preserved."""
    from core.orchestrator_v9 import _w_rustscan
    cfg = _cfg()
    result = _result()
    result.rustscan_ports = [22, 80]
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_rustscan", return_value={443, 8080}):
        _w_rustscan(cfg, result, tmp_path)
    assert result.rustscan_ports == [22, 80, 443, 8080]


def test_w_masscan_handles_set_return_value(tmp_path):
    """Same list+set bug as rustscan — masscan also returns set[int]."""
    from core.orchestrator_v9 import _w_masscan
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_masscan", return_value=(None, {22, 80})):
        _w_masscan(cfg, result, tmp_path)
    assert result.masscan_ports == [22, 80]


def test_w_masscan_handles_empty_set(tmp_path):
    from core.orchestrator_v9 import _w_masscan
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_masscan", return_value=(None, set())):
        _w_masscan(cfg, result, tmp_path)
    assert result.masscan_ports == []


def test_w_async_tcp_creates_host_result(tmp_path):
    """v10.5.1 fix: async_tcp must create a HostResult so the report shows
    open ports even when nmap isn't installed."""
    from core.orchestrator_v9 import _w_async_tcp
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    port_infos = [
        PortInfo(port=80, protocol="tcp", state="open", service="http"),
        PortInfo(port=443, protocol="tcp", state="open", service="https"),
    ]
    with patch("core.orchestrator_v9.async_port_scan", return_value=(port_infos, [])):
        _w_async_tcp(cfg, result, tmp_path)
    assert len(result.hosts) == 1
    assert result.hosts[0].hostnames == ["example.com"]
    assert len(result.hosts[0].ports) == 2
    assert result.rustscan_ports == [80, 443]


def test_w_nmap_skips_when_no_open_ports(tmp_path):
    """v10.5.1 fix: nmap must NOT be called when no open ports were found."""
    from core.orchestrator_v9 import _w_nmap
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    # result.rustscan_ports + result.masscan_ports are both empty
    with patch("core.orchestrator_v9.nmap_worker") as mock_nmap:
        _w_nmap(cfg, result, tmp_path)
        mock_nmap.assert_not_called()


def test_w_nmap_merges_into_existing_host(tmp_path):
    """v10.5.1 fix: nmap should merge its richer port info into the HostResult
    created by async_tcp, not append a duplicate."""
    from core.orchestrator_v9 import _w_nmap
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    result.rustscan_ports = [22, 80]
    existing_host = HostResult(ip="1.2.3.4", hostnames=["example.com"],
                                ports=[PortInfo(port=22, protocol="tcp", state="open")])
    result.hosts.append(existing_host)
    richer_host = HostResult(ip="1.2.3.4", hostnames=["example.com"], ports=[
        PortInfo(port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH"),
        PortInfo(port=80, protocol="tcp", state="open", service="http", product="nginx"),
    ])
    with patch("core.orchestrator_v9.nmap_worker", return_value=("example.com", [richer_host], [])):
        _w_nmap(cfg, result, tmp_path)
    # Should NOT have appended a second host
    assert len(result.hosts) == 1
    # Existing host's ports should now be the richer nmap ports
    assert len(result.hosts[0].ports) == 2
    assert result.hosts[0].ports[0].service == "ssh"


# ─── Passive OSINT wrappers ─────────────────────────────────────────────────

def test_w_whois_appends_dict(tmp_path):
    from core.orchestrator_v9 import _w_whois
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.whois_lookup", return_value={"registrar": "Test"}):
        _w_whois(cfg, result, tmp_path)
    assert len(result.whois_results) == 1
    assert result.whois_results[0]["registrar"] == "Test"


def test_w_wayback_appends_dict(tmp_path):
    from core.orchestrator_v9 import _w_wayback
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.wayback_lookup", return_value={"urls": ["http://x"]}):
        _w_wayback(cfg, result, tmp_path)
    assert len(result.wayback_results) == 1


def test_w_ssl_appends_dict(tmp_path):
    from core.orchestrator_v9 import _w_ssl
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.ssl_scan", return_value={"host": "x", "findings": []}):
        _w_ssl(cfg, result, tmp_path)
    assert len(result.ssl_results) == 1


def test_w_subdomains_extends_list(tmp_path):
    from core.orchestrator_v9 import _w_subdomains
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.subdomain_enum", return_value=["a.example.com", "b.example.com"]):
        _w_subdomains(cfg, result, tmp_path)
    assert "a.example.com" in result.subdomains
    assert "b.example.com" in result.subdomains


def test_w_github_osint_handles_list_and_dict(tmp_path):
    from core.orchestrator_v9 import _w_github_osint
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.github_osint", return_value=[{"repo": "x"}]):
        _w_github_osint(cfg, result, tmp_path)
    assert len(result.github_findings) == 1
    # Also accept a single dict
    result.github_findings = []
    with patch("core.orchestrator_v9.github_osint", return_value={"repo": "y"}):
        _w_github_osint(cfg, result, tmp_path)
    assert len(result.github_findings) == 1


def test_w_shodan_with_no_hosts_falls_back_to_single_lookup(tmp_path):
    """v10.5.0+ behaviour: when result.hosts is empty, fall back to a single
    shodan_host_lookup against cfg.target instead of shodan_bulk_lookup."""
    from core.orchestrator_v9 import _w_shodan
    cfg = _cfg()
    cfg.shodan_key = "fake-key"
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.shodan_host_lookup", return_value={"ip": "1.2.3.4"}) as mock_single:
        with patch("core.orchestrator_v9.shodan_bulk_lookup") as mock_bulk:
            _w_shodan(cfg, result, tmp_path)
            mock_single.assert_called_once_with("example.com", "fake-key")
            mock_bulk.assert_not_called()
    assert len(result.shodan_results) == 1


def test_w_shodan_with_hosts_uses_bulk_lookup(tmp_path):
    from core.orchestrator_v9 import _w_shodan
    cfg = _cfg()
    cfg.shodan_key = "fake-key"
    result = _result()
    result.hosts = [HostResult(ip="1.2.3.4", hostnames=["example.com"], ports=[])]
    set_active_config(cfg)
    with patch("core.orchestrator_v9.shodan_host_lookup") as mock_single:
        with patch("core.orchestrator_v9.shodan_bulk_lookup", return_value=[{"ip": "1.2.3.4"}]) as mock_bulk:
            _w_shodan(cfg, result, tmp_path)
            mock_bulk.assert_called_once()
            mock_single.assert_not_called()
    assert len(result.shodan_results) == 1


def test_w_shodan_raises_without_key(tmp_path):
    """Without a Shodan key, the wrapper should record a RuntimeError to
    result.errors (caught by @phase_wrap), not crash the scan."""
    from core.orchestrator_v9 import _w_shodan
    cfg = _cfg()
    cfg.shodan_key = ""
    result = _result()
    set_active_config(cfg)
    _w_shodan(cfg, result, tmp_path)
    # @phase_wrap should have caught the RuntimeError and appended to errors
    assert any("shodan" in e.lower() or "api key" in e.lower() for e in result.errors)


def test_w_virustotal_iterates_subdomains_and_hosts(tmp_path):
    from core.orchestrator_v9 import _w_virustotal
    cfg = _cfg()
    cfg.vt_key = "fake-key"
    result = _result()
    result.subdomains = ["a.example.com", "b.example.com"]
    result.hosts = [HostResult(ip="1.2.3.4", hostnames=[], ports=[])]
    set_active_config(cfg)
    with patch("core.orchestrator_v9.vt_domain_lookup", return_value={"malicious": 0}) as mock_dom:
        with patch("core.orchestrator_v9.vt_ip_lookup", return_value={"malicious": 1}):
            _w_virustotal(cfg, result, tmp_path)
    # 2 subdomains + 1 host = 3 lookups
    assert mock_dom.call_count == 2
    assert len(result.vt_results) == 3


# ─── Web-phase wrappers — accept list or dict returns ───────────────────────

@pytest.mark.parametrize("wrapper_name,fn_name,result_field", [
    ("_w_httpx",       "run_httpx",       "web_findings"),
    ("_w_whatweb",     "run_whatweb",     "whatweb_findings"),
    ("_w_nikto",       "run_nikto",       "nikto_findings"),
    ("_w_dir_scan",    "run_dir_scan",    "dir_findings"),
    ("_w_cloud_buckets","enumerate_buckets","bucket_findings"),
    ("_w_dns_zone",    "dns_zone_transfer_scan","dns_zone_results"),
    ("_w_dns_leak",    "dns_leak_check",  "dns_leak"),
    ("_w_ens_lookup",  "ens_lookup",      "ens_lookup"),
    ("_w_anon_detect", "anon_detect",     "anon_detect"),
    ("_w_web3_scan",   "web3_scan",       "web3_scan"),
    ("_w_app_store",   "app_store_scan",  "app_store"),
    ("_w_paste_monitor","paste_monitor",  "paste_monitor"),
    ("_w_se_osint",    "se_osint",        "se_osint"),
    ("_w_linkedin",    "linkedin_osint",  "linkedin"),
    ("_w_asn_map",     "asn_map",         "asn_results"),
    ("_w_typosquat",   "typosquat_scan",  "typosquat_data"),
    ("_w_email_security","email_security_scan","email_security"),
    ("_w_breach_check","breach_check",    "breach_results"),
    ("_w_smtp_enum",   "smtp_enum",       "smtp_findings"),
    ("_w_snmp_scan",   "snmp_scan",       "snmp_findings"),
    ("_w_ldap_enum",   "ldap_enum",       "ldap_findings"),
    ("_w_aquatone",    "run_aquatone",    "aquatone_results"),
    ("_w_apk_scan",    "apk_scan",        "apk_scan"),
])
def test_wrapper_handles_list_and_dict_returns(wrapper_name, fn_name, result_field, tmp_path):
    """Every wrapper must accept both list and dict return values from its
    underlying v8 module without raising."""
    from core import orchestrator_v9 as orch
    wrapper = getattr(orch, wrapper_name)
    fn = getattr(orch, fn_name)

    cfg = _cfg()
    result = _result()
    set_active_config(cfg)

    # Test with list return
    with patch(f"core.orchestrator_v9.{fn_name}", return_value=[{"x": 1}]):
        wrapper(cfg, result, tmp_path)
    field = getattr(result, result_field)
    assert len(field) == 1

    # Reset and test with dict return
    setattr(result, result_field, type(field)())
    with patch(f"core.orchestrator_v9.{fn_name}", return_value={"x": 2}):
        wrapper(cfg, result, tmp_path)
    field = getattr(result, result_field)
    assert len(field) == 1


# ─── Web-vuln wrappers that take web_urls list ──────────────────────────────

@pytest.mark.parametrize("wrapper_name,fn_name,result_field", [
    ("_w_cors",         "scan_cors",         "cors_findings"),
    ("_w_js_extract",   "extract_js_findings","js_findings"),
    ("_w_graphql",      "graphql_scan",      "graphql_findings"),
    ("_w_jwt_scan",     "jwt_scan",          "jwt_findings"),
    ("_w_api_fuzz",     "api_fuzz_scan",     "api_fuzz"),
    ("_w_oauth_scan",   "oauth_scan",        "oauth_scan"),
    ("_w_web_vulns",    "web_vuln_scan",     "web_vulns"),
    ("_w_open_redirect","open_redirect_scan","open_redirect"),
])
def test_web_vuln_wrapper_handles_list_return(wrapper_name, fn_name, result_field, tmp_path):
    from core import orchestrator_v9 as orch
    wrapper = getattr(orch, wrapper_name)
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch(f"core.orchestrator_v9.{fn_name}", return_value=[{"vuln": "xss"}]):
        wrapper(cfg, result, tmp_path)
    field = getattr(result, result_field)
    assert len(field) == 1


# ─── AI wrappers ────────────────────────────────────────────────────────────

def test_w_ai_consensus_handles_dict_return(tmp_path):
    from core.orchestrator_v9 import _w_ai_consensus
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.run_consensus", return_value={"risk": "high"}):
        _w_ai_consensus(cfg, result, tmp_path)
    assert result.ai_consensus == {"risk": "high"}


def test_w_attack_paths_handles_list_return(tmp_path):
    from core.orchestrator_v9 import _w_attack_paths
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.generate_attack_paths", return_value=[]):
        _w_attack_paths(cfg, result, tmp_path)
    assert len(result.attack_chains) == 0


def test_w_ai_remediate_handles_list_return(tmp_path):
    from core.orchestrator_v9 import _w_ai_remediate
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.generate_remediations", return_value=[{"fix": "patch"}]):
        _w_ai_remediate(cfg, result, tmp_path)
    assert len(result.remediations) == 1


# ─── Sarif + report file path ───────────────────────────────────────────────

def test_w_sarif_export_invokes_export_sarif(tmp_path):
    from core.orchestrator_v9 import _w_sarif_export
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.export_sarif") as mock_export:
        _w_sarif_export(cfg, result, tmp_path)
        mock_export.assert_called_once_with(result, tmp_path)


# ─── DevOps wrapper — combines terraform + jenkins ──────────────────────────

def test_w_devops_calls_both_terraform_and_jenkins(tmp_path):
    from core.orchestrator_v9 import _w_devops
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.terraform_state_scan", return_value=[{"issue": "tf"}]) as mock_tf:
        with patch("core.orchestrator_v9.jenkins_scan", return_value=[{"issue": "jk"}]) as mock_jk:
            _w_devops(cfg, result, tmp_path)
            mock_tf.assert_called_once()
            mock_jk.assert_called_once()
    assert len(result.devops_findings) == 2


# ─── CVE lookup wrapper — iterates hosts ────────────────────────────────────

def test_w_cve_lookup_iterates_hosts(tmp_path):
    from core.orchestrator_v9 import _w_cve_lookup
    cfg = _cfg()
    result = _result()
    result.hosts = [
        HostResult(ip="1.2.3.4", hostnames=["example.com"],
                   ports=[PortInfo(port=22, protocol="tcp", state="open", service="ssh")]),
    ]
    set_active_config(cfg)
    with patch("core.orchestrator_v9.lookup_cves_for_host_result") as mock_cve:
        _w_cve_lookup(cfg, result, tmp_path)
        mock_cve.assert_called_once()


def test_w_cve_lookup_handles_empty_hosts(tmp_path):
    """No hosts → no CVE lookups. Must not raise."""
    from core.orchestrator_v9 import _w_cve_lookup
    cfg = _cfg()
    result = _result()
    set_active_config(cfg)
    with patch("core.orchestrator_v9.lookup_cves_for_host_result") as mock_cve:
        _w_cve_lookup(cfg, result, tmp_path)
        mock_cve.assert_not_called()


# ─── Full registration smoke test ───────────────────────────────────────────

def test_register_all_phases_with_full_suite_profile():
    """FULL_SUITE profile enables every phase; _register_all_phases must not
    raise TypeError for any of them."""
    import reconninja
    from core.orchestrator_v9 import _register_all_phases
    from core.phase_scheduler import PhaseScheduler
    from utils.models import ScopePolicy
    cfg = ScanConfig(target="example.com", profile=ScanProfile.FULL_SUITE)
    reconninja._apply_profile(cfg)
    result = _result()
    scheduler = PhaseScheduler(max_workers=2)
    scope = ScopePolicy()
    _register_all_phases(scheduler, cfg, result, Path("/tmp"), scope)
    assert len(scheduler.task_ids()) > 5
