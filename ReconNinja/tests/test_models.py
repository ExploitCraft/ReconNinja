"""
tests/test_models.py — ReconNinja v5.0.0
Exhaustive tests for utils/models.py

v5.0.0 additions:
  - TestScanConfigDefaults: run_cve_lookup, ai_provider, ai_key, ai_model, nvd_key
  - TestScanConfigCustom:   new AI/CVE fields construction & to_dict round-trip
  - TestScanConfigToDict:   new fields present in serialized dict
"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.models import (
    ScanProfile, Phase, NmapOptions, ScanConfig,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
    SEVERITY_PORTS, WEB_PORTS, VALID_TIMINGS,
)


# ═══════════════════════════════════════════════
# ScanProfile
# ═══════════════════════════════════════════════
class TestScanProfile:
    def test_all_eight_exist(self):
        vals = [p.value for p in ScanProfile]
        for v in ["fast","standard","thorough","stealth","custom","full_suite","web_only","port_only"]:
            assert v in vals

    def test_from_string_fast(self):        assert ScanProfile("fast")       == ScanProfile.FAST
    def test_from_string_standard(self):    assert ScanProfile("standard")   == ScanProfile.STANDARD
    def test_from_string_thorough(self):    assert ScanProfile("thorough")   == ScanProfile.THOROUGH
    def test_from_string_stealth(self):     assert ScanProfile("stealth")    == ScanProfile.STEALTH
    def test_from_string_custom(self):      assert ScanProfile("custom")     == ScanProfile.CUSTOM
    def test_from_string_full_suite(self):  assert ScanProfile("full_suite") == ScanProfile.FULL_SUITE
    def test_from_string_web_only(self):    assert ScanProfile("web_only")   == ScanProfile.WEB_ONLY
    def test_from_string_port_only(self):   assert ScanProfile("port_only")  == ScanProfile.PORT_ONLY
    def test_invalid_raises(self):
        with pytest.raises(ValueError): ScanProfile("hacker_mode")
    def test_values_unique(self):
        vals = [p.value for p in ScanProfile]
        assert len(vals) == len(set(vals))
    def test_count_is_eight(self):
        assert len(list(ScanProfile)) == 8


# ═══════════════════════════════════════════════
# Phase
# ═══════════════════════════════════════════════
class TestPhase:
    def test_all_phases_exist(self):
        vals = [p.value for p in Phase]
        for v in ["passive","port","service","web","directory","tech","vuln","screenshot","report"]:
            assert v in vals

    def test_from_string_port(self):       assert Phase("port")       == Phase.PORT
    def test_from_string_report(self):     assert Phase("report")     == Phase.REPORT
    def test_from_string_passive(self):    assert Phase("passive")    == Phase.PASSIVE
    def test_from_string_vuln(self):       assert Phase("vuln")       == Phase.VULN
    def test_invalid_raises(self):
        with pytest.raises(ValueError): Phase("not_a_phase")
    def test_count_is_nine(self):
        assert len(list(Phase)) == 9


# ═══════════════════════════════════════════════
# NmapOptions
# ═══════════════════════════════════════════════
class TestNmapOptionsDefaults:
    def setup_method(self): self.o = NmapOptions()

    def test_all_ports_false(self):         assert self.o.all_ports         is False
    def test_top_ports_1000(self):          assert self.o.top_ports         == 1000
    def test_scripts_true(self):            assert self.o.scripts           is True
    def test_version_detection_true(self):  assert self.o.version_detection is True
    def test_os_detection_false(self):      assert self.o.os_detection      is False
    def test_aggressive_false(self):        assert self.o.aggressive        is False
    def test_stealth_false(self):           assert self.o.stealth           is False
    def test_timing_T4(self):               assert self.o.timing            == "T4"
    def test_extra_flags_empty(self):       assert self.o.extra_flags       == []
    def test_script_args_none(self):        assert self.o.script_args       is None


class TestNmapOptionsValidation:
    def test_invalid_timing_raises(self):
        with pytest.raises(ValueError): NmapOptions(timing="T9")
    def test_timing_string_raises(self):
        with pytest.raises(ValueError): NmapOptions(timing="fast")
    def test_empty_timing_raises(self):
        with pytest.raises(ValueError): NmapOptions(timing="")
    def test_negative_top_ports_raises(self):
        with pytest.raises(ValueError): NmapOptions(top_ports=-1)
    def test_negative_large_raises(self):
        with pytest.raises(ValueError): NmapOptions(top_ports=-100)
    def test_all_valid_timings_accepted(self):
        for t in ["T1","T2","T3","T4","T5"]:
            assert NmapOptions(timing=t).timing == t
    def test_zero_top_ports_allowed(self):
        assert NmapOptions(top_ports=0).top_ports == 0


class TestNmapOptionsArgs:
    def test_normal_sT(self):           assert "-sT" in NmapOptions().as_nmap_args()
    def test_normal_sC(self):           assert "-sC" in NmapOptions(scripts=True).as_nmap_args()
    def test_normal_sV(self):           assert "-sV" in NmapOptions(version_detection=True).as_nmap_args()
    def test_no_sC_when_off(self):      assert "-sC" not in NmapOptions(scripts=False).as_nmap_args()
    def test_no_sV_when_off(self):      assert "-sV" not in NmapOptions(version_detection=False).as_nmap_args()
    def test_O_when_on(self):           assert "-O"  in NmapOptions(os_detection=True).as_nmap_args()
    def test_no_O_by_default(self):     assert "-O"  not in NmapOptions().as_nmap_args()
    def test_stealth_sS(self):          assert "-sS" in NmapOptions(stealth=True, timing="T2").as_nmap_args()
    def test_stealth_no_sT(self):       assert "-sT" not in NmapOptions(stealth=True, timing="T2").as_nmap_args()
    def test_stealth_no_sC(self):       assert "-sC" not in NmapOptions(stealth=True, timing="T2").as_nmap_args()
    def test_stealth_no_A(self):        assert "-A"  not in NmapOptions(stealth=True, timing="T2").as_nmap_args()
    def test_aggressive_A(self):        assert "-A"  in NmapOptions(aggressive=True).as_nmap_args()
    def test_aggressive_no_sT(self):    assert "-sT" not in NmapOptions(aggressive=True).as_nmap_args()
    def test_aggressive_no_sS(self):    assert "-sS" not in NmapOptions(aggressive=True).as_nmap_args()
    def test_no_sT_and_sS_normal(self):
        a = NmapOptions().as_nmap_args()
        assert not ("-sT" in a and "-sS" in a)
    def test_all_ports_flag(self):      assert "-p-" in NmapOptions(all_ports=True).as_nmap_args()
    def test_no_top_ports_when_all(self): assert "--top-ports" not in NmapOptions(all_ports=True).as_nmap_args()
    def test_top_ports_in_args(self):
        a = NmapOptions(top_ports=500).as_nmap_args()
        assert "--top-ports" in a and "500" in a
    def test_timing_T4_default(self):   assert "-T4" in NmapOptions().as_nmap_args()
    def test_timing_T1(self):           assert "-T1" in NmapOptions(timing="T1").as_nmap_args()
    def test_extra_flags_included(self):
        a = NmapOptions(extra_flags=["--open","-v"]).as_nmap_args()
        assert "--open" in a and "-v" in a
    def test_script_args_in_output(self):
        a = NmapOptions(script_args="vulners.mincvss=5").as_nmap_args()
        assert any("script-args" in f for f in a)
    def test_returns_list(self):        assert isinstance(NmapOptions().as_nmap_args(), list)
    def test_all_items_are_strings(self):
        for item in NmapOptions().as_nmap_args():
            assert isinstance(item, str)


# ═══════════════════════════════════════════════
# ScanConfig
# ═══════════════════════════════════════════════
class TestScanConfigDefaults:
    def setup_method(self): self.c = ScanConfig(target="10.0.0.1")

    def test_target(self):               assert self.c.target             == "10.0.0.1"
    def test_profile_standard(self):     assert self.c.profile            == ScanProfile.STANDARD
    def test_nmap_opts_instance(self):   assert isinstance(self.c.nmap_opts, NmapOptions)
    def test_run_subdomains_false(self):  assert self.c.run_subdomains     is False
    def test_run_rustscan_false(self):    assert self.c.run_rustscan       is False
    def test_run_feroxbuster_false(self): assert self.c.run_feroxbuster    is False
    def test_run_masscan_false(self):     assert self.c.run_masscan        is False
    def test_run_aquatone_false(self):    assert self.c.run_aquatone       is False
    def test_run_whatweb_false(self):     assert self.c.run_whatweb        is False
    def test_run_nikto_false(self):       assert self.c.run_nikto          is False
    def test_run_nuclei_false(self):      assert self.c.run_nuclei         is False
    def test_run_httpx_false(self):       assert self.c.run_httpx          is False
    def test_run_ai_analysis_false(self): assert self.c.run_ai_analysis    is False
    # ── v5.0.0 new fields ────────────────────────────────────────────────────
    def test_run_cve_lookup_false(self):  assert self.c.run_cve_lookup     is False
    def test_ai_provider_groq(self):      assert self.c.ai_provider        == "groq"
    def test_ai_key_empty(self):          assert self.c.ai_key             == ""
    def test_ai_model_empty(self):        assert self.c.ai_model           == ""
    def test_nvd_key_empty(self):         assert self.c.nvd_key            == ""
    # ── tuning defaults ───────────────────────────────────────────────────────
    def test_masscan_rate_5000(self):      assert self.c.masscan_rate       == 5000
    def test_threads_20(self):             assert self.c.threads            == 20
    def test_wordlist_medium(self):        assert self.c.wordlist_size      == "medium"
    def test_output_dir_reports(self):     assert self.c.output_dir         == "reports"
    def test_async_concurrency_1000(self): assert self.c.async_concurrency  == 1000
    def test_async_timeout_1_5(self):      assert self.c.async_timeout      == 1.5


class TestScanConfigToDict:
    def test_returns_dict(self):
        assert isinstance(ScanConfig(target="x").to_dict(), dict)
    def test_target_preserved(self):
        assert ScanConfig(target="10.0.0.1").to_dict()["target"] == "10.0.0.1"
    def test_profile_is_string(self):
        assert ScanConfig(target="x").to_dict()["profile"] == "standard"
    def test_profile_not_enum(self):
        d = ScanConfig(target="x").to_dict()
        assert not hasattr(d["profile"], "value")
    def test_all_feature_flags_in_dict(self):
        d = ScanConfig(target="x").to_dict()
        for k in ["run_subdomains","run_rustscan","run_nuclei","run_ai_analysis"]:
            assert k in d
    # ── v5.0.0: new fields present in to_dict() output ───────────────────────
    def test_run_cve_lookup_in_dict(self):
        assert "run_cve_lookup" in ScanConfig(target="x").to_dict()
    def test_ai_provider_in_dict(self):
        assert "ai_provider" in ScanConfig(target="x").to_dict()
    def test_ai_key_in_dict(self):
        assert "ai_key" in ScanConfig(target="x").to_dict()
    def test_ai_model_in_dict(self):
        assert "ai_model" in ScanConfig(target="x").to_dict()
    def test_nvd_key_in_dict(self):
        assert "nvd_key" in ScanConfig(target="x").to_dict()
    def test_custom_values_in_dict(self):
        d = ScanConfig(target="x", threads=50, masscan_rate=9000).to_dict()
        assert d["threads"] == 50
        assert d["masscan_rate"] == 9000
    def test_ai_provider_value_in_dict(self):
        d = ScanConfig(target="x", ai_provider="gemini").to_dict()
        assert d["ai_provider"] == "gemini"


class TestScanConfigCustom:
    def test_profile_thorough(self):
        assert ScanConfig(target="x", profile=ScanProfile.THOROUGH).profile == ScanProfile.THOROUGH
    def test_flags_enabled(self):
        c = ScanConfig(target="x", run_rustscan=True, run_nuclei=True, run_ai_analysis=True)
        assert c.run_rustscan    is True
        assert c.run_nuclei      is True
        assert c.run_ai_analysis is True
    # ── v5.0.0: new field construction ───────────────────────────────────────
    def test_run_cve_lookup_enabled(self):
        assert ScanConfig(target="x", run_cve_lookup=True).run_cve_lookup is True
    def test_ai_provider_set(self):
        assert ScanConfig(target="x", ai_provider="ollama").ai_provider == "ollama"
    def test_ai_key_set(self):
        assert ScanConfig(target="x", ai_key="gsk_abc123").ai_key == "gsk_abc123"
    def test_ai_model_set(self):
        assert ScanConfig(target="x", ai_model="llama3-8b").ai_model == "llama3-8b"
    def test_nvd_key_set(self):
        assert ScanConfig(target="x", nvd_key="nvd_xyz").nvd_key == "nvd_xyz"
    def test_all_new_fields_together(self):
        c = ScanConfig(
            target="x", run_cve_lookup=True,
            ai_provider="gemini", ai_key="AIza_secret",
            ai_model="gemini-pro", nvd_key="nvd_secret"
        )
        assert c.run_cve_lookup is True
        assert c.ai_provider    == "gemini"
        assert c.ai_key         == "AIza_secret"
        assert c.ai_model       == "gemini-pro"
        assert c.nvd_key        == "nvd_secret"
    def test_new_fields_in_to_dict(self):
        c = ScanConfig(target="x", run_cve_lookup=True, ai_provider="ollama", nvd_key="k")
        d = c.to_dict()
        assert d["run_cve_lookup"] is True
        assert d["ai_provider"]    == "ollama"
        assert d["nvd_key"]        == "k"


# ═══════════════════════════════════════════════
# PortInfo
# ═══════════════════════════════════════════════
class TestPortInfoDefaults:
    def setup_method(self): self.p = PortInfo(port=8080, protocol="tcp", state="open")

    def test_service_empty(self):   assert self.p.service    == ""
    def test_product_empty(self):   assert self.p.product    == ""
    def test_version_empty(self):   assert self.p.version    == ""
    def test_extra_info_empty(self):assert self.p.extra_info == ""
    def test_scripts_empty(self):   assert self.p.scripts    == {}


class TestPortInfoSeverity:
    def test_ssh_critical(self):    assert PortInfo(port=22,  protocol="tcp", state="open").severity == "critical"
    def test_ftp_critical(self):    assert PortInfo(port=21,  protocol="tcp", state="open").severity == "critical"
    def test_telnet_critical(self): assert PortInfo(port=23,  protocol="tcp", state="open").severity == "critical"
    def test_smtp_critical(self):   assert PortInfo(port=25,  protocol="tcp", state="open").severity == "critical"
    def test_smb_critical(self):    assert PortInfo(port=445, protocol="tcp", state="open").severity == "critical"
    def test_ldap_critical(self):   assert PortInfo(port=389, protocol="tcp", state="open").severity == "critical"
    def test_dns_critical(self):    assert PortInfo(port=53,  protocol="tcp", state="open").severity == "critical"
    def test_http_high(self):       assert PortInfo(port=80,   protocol="tcp", state="open").severity == "high"
    def test_https_high(self):      assert PortInfo(port=443,  protocol="tcp", state="open").severity == "high"
    def test_mysql_high(self):      assert PortInfo(port=3306, protocol="tcp", state="open").severity == "high"
    def test_rdp_high(self):        assert PortInfo(port=3389, protocol="tcp", state="open").severity == "high"
    def test_redis_high(self):      assert PortInfo(port=6379, protocol="tcp", state="open").severity == "high"
    def test_mongo_high(self):      assert PortInfo(port=27017,protocol="tcp", state="open").severity == "high"
    def test_8000_medium(self):     assert PortInfo(port=8000, protocol="tcp", state="open").severity == "medium"
    def test_elastic_medium(self):  assert PortInfo(port=9200, protocol="tcp", state="open").severity == "medium"
    def test_unknown_info(self):    assert PortInfo(port=54321,protocol="tcp", state="open").severity == "info"


class TestPortInfoIsWeb:
    def test_80_is_web(self):       assert PortInfo(port=80,   protocol="tcp", state="open").is_web is True
    def test_443_is_web(self):      assert PortInfo(port=443,  protocol="tcp", state="open").is_web is True
    def test_8080_is_web(self):     assert PortInfo(port=8080, protocol="tcp", state="open").is_web is True
    def test_8443_is_web(self):     assert PortInfo(port=8443, protocol="tcp", state="open").is_web is True
    def test_all_web_ports(self):
        for p in WEB_PORTS:
            assert PortInfo(port=p, protocol="tcp", state="open").is_web is True
    def test_22_not_web(self):      assert PortInfo(port=22,  protocol="tcp", state="open").is_web is False
    def test_3306_not_web(self):    assert PortInfo(port=3306,protocol="tcp", state="open").is_web is False


class TestPortInfoDisplayState:
    def test_open_contains_open(self):
        assert "open" in PortInfo(port=80, protocol="tcp", state="open").display_state
    def test_has_markup_brackets(self):
        ds = PortInfo(port=80, protocol="tcp", state="open").display_state
        assert "[" in ds and "]" in ds
    def test_returns_string(self):
        assert isinstance(PortInfo(port=80, protocol="tcp", state="open").display_state, str)


# ═══════════════════════════════════════════════
# HostResult
# ═══════════════════════════════════════════════
class TestHostResultDefaults:
    def setup_method(self): self.h = HostResult(ip="10.0.0.1")

    def test_mac_empty(self):             assert self.h.mac              == ""
    def test_hostnames_empty(self):       assert self.h.hostnames        == []
    def test_ports_empty(self):           assert self.h.ports            == []
    def test_open_ports_empty(self):      assert self.h.open_ports       == []
    def test_web_ports_empty(self):       assert self.h.web_ports        == []


class TestHostResultProperties:
    def _host(self):
        return HostResult(ip="192.168.1.1", ports=[
            PortInfo(port=22,   protocol="tcp", state="open"),
            PortInfo(port=80,   protocol="tcp", state="open"),
            PortInfo(port=443,  protocol="tcp", state="closed"),
            PortInfo(port=8080, protocol="tcp", state="open"),
            PortInfo(port=3306, protocol="tcp", state="open"),
        ])

    def test_open_ports_count(self):        assert len(self._host().open_ports) == 4
    def test_open_ports_only_open(self):
        for p in self._host().open_ports:   assert p.state == "open"
    def test_closed_excluded(self):
        ports = [p.port for p in self._host().open_ports]
        assert 443 not in ports
    def test_web_ports_includes_80_8080(self):
        ports = [p.port for p in self._host().web_ports]
        assert 80 in ports and 8080 in ports
    def test_web_ports_excludes_ssh(self):
        assert 22 not in [p.port for p in self._host().web_ports]


# ═══════════════════════════════════════════════
# WebFinding / VulnFinding / ReconResult
# ═══════════════════════════════════════════════
class TestWebFinding:
    def test_defaults(self):
        wf = WebFinding(url="http://x.com")
        assert wf.status_code == 0 and wf.title == "" and wf.technologies == []
    def test_technologies_independent(self):
        wf1 = WebFinding(url="a")
        wf2 = WebFinding(url="b")
        wf1.technologies.append("PHP")
        assert wf2.technologies == []


class TestVulnFinding:
    def test_cve_default_empty(self):
        assert VulnFinding(tool="t", severity="low", title="x", target="x").cve == ""
    def test_nvd_tool(self):
        v = VulnFinding(tool="nvd", severity="high", title="CVE (CVSS 7.5)",
                        target="192.168.1.1:80", cve="CVE-2021-41773")
        assert v.tool == "nvd" and v.cve == "CVE-2021-41773"


class TestReconResultDefaults:
    def setup_method(self): self.r = ReconResult(target="x.com", start_time="t")

    def test_end_time_empty(self):         assert self.r.end_time         == ""
    def test_subdomains_empty(self):       assert self.r.subdomains       == []
    def test_hosts_empty(self):            assert self.r.hosts            == []
    def test_nuclei_findings_empty(self):  assert self.r.nuclei_findings  == []
    def test_errors_empty(self):           assert self.r.errors           == []
    def test_phases_completed_empty(self): assert self.r.phases_completed == []

    def test_lists_independent_between_instances(self):
        r1 = ReconResult(target="x", start_time="t")
        r2 = ReconResult(target="y", start_time="t")
        r1.subdomains.append("sub.x.com")
        assert r2.subdomains == []


# ═══════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════
class TestConstants:
    def test_severity_keys(self):
        assert set(SEVERITY_PORTS.keys()) == {"critical","high","medium"}
    def test_critical_ssh(self):    assert 22   in SEVERITY_PORTS["critical"]
    def test_critical_smb(self):    assert 445  in SEVERITY_PORTS["critical"]
    def test_high_http(self):       assert 80   in SEVERITY_PORTS["high"]
    def test_high_mysql(self):      assert 3306 in SEVERITY_PORTS["high"]
    def test_medium_8000(self):     assert 8000 in SEVERITY_PORTS["medium"]
    def test_no_port_in_two_severities(self):
        all_ports = []
        for ports in SEVERITY_PORTS.values():
            all_ports.extend(ports)
        assert len(all_ports) == len(set(all_ports))
    def test_web_ports_has_common(self):
        for p in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]:
            assert p in WEB_PORTS
    def test_valid_timings_exact(self):
        assert VALID_TIMINGS == {"T1","T2","T3","T4","T5"}
