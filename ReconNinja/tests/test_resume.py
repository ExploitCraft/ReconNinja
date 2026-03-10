"""
tests/test_resume.py — ReconNinja v5.0.0
Tests for core/resume.py — save/load/find state.

v5.0.0 additions:
  - TestConfigDeserialization: verifies run_cve_lookup, ai_provider, ai_key,
    ai_model, nvd_key survive the to_dict() → _dict_to_config() round-trip
  - TestSaveLoadState: verifies all new fields restored from state.json
  - TestNewFieldsRoundTrip: dedicated full end-to-end round-trip class
"""
import pytest
import sys
import json
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.resume import (
    save_state, load_state, find_latest_state,
    _sanitize, _result_to_dict, _dict_to_result, _dict_to_config,
    STATE_FILE,
)
from utils.models import (
    ScanConfig, ScanProfile, NmapOptions,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_result(target="example.com"):
    return ReconResult(
        target=target,
        start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com","mail.example.com"],
        hosts=[HostResult(ip="192.168.1.1", ports=[
            PortInfo(port=22, protocol="tcp", state="open",
                     service="ssh", product="OpenSSH", version="8.9p1"),
            PortInfo(port=80, protocol="tcp", state="open",
                     service="http", product="Apache", version="2.4.52"),
        ])],
        web_findings=[WebFinding(url="http://example.com", status_code=200,
                                  title="Home", technologies=["Apache","PHP"])],
        nuclei_findings=[
            VulnFinding(tool="nuclei", severity="high", title="RCE",
                        target="http://example.com", cve="CVE-2021-41773"),
        ],
        errors=["nmap timeout on port 9999"],
        phases_completed=["subdomains","ports","web","vuln"],
    )

def make_config(target="example.com", **kwargs):
    defaults = dict(
        target=target,
        profile=ScanProfile.FULL_SUITE,
        nmap_opts=NmapOptions(timing="T4", scripts=True, version_detection=True),
        run_subdomains=True, run_rustscan=True, run_nuclei=True,
        threads=20, masscan_rate=5000,
    )
    defaults.update(kwargs)
    return ScanConfig(**defaults)


# ═══════════════════════════════════════════════
# _sanitize
# ═══════════════════════════════════════════════
class TestSanitize:
    def test_normal_string_unchanged(self):  assert _sanitize("example.com") == "example.com"
    def test_spaces_replaced(self):          assert " "  not in _sanitize("hello world")
    def test_slashes_replaced(self):         assert "/"  not in _sanitize("path/to/file")
    def test_colon_replaced(self):           assert ":"  not in _sanitize("http://x.com")
    def test_angle_brackets_replaced(self):  assert "<"  not in _sanitize("<tag>")
    def test_pipe_replaced(self):            assert "|"  not in _sanitize("a|b")
    def test_asterisk_replaced(self):        assert "*"  not in _sanitize("a*b")
    def test_returns_string(self):           assert isinstance(_sanitize("test"), str)
    def test_ip_unchanged(self):             assert _sanitize("192.168.1.1") == "192.168.1.1"


# ═══════════════════════════════════════════════
# _result_to_dict / _dict_to_result
# ═══════════════════════════════════════════════
class TestResultSerialization:
    def test_result_to_dict_returns_dict(self):
        assert isinstance(_result_to_dict(make_result()), dict)
    def test_round_trip_target(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.target == "example.com"
    def test_round_trip_subdomains(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.subdomains == make_result().subdomains
    def test_round_trip_hosts_count(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert len(r2.hosts) == 1
    def test_round_trip_host_ip(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.hosts[0].ip == "192.168.1.1"
    def test_round_trip_port_number(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        ports = [p.port for p in r2.hosts[0].ports]
        assert 22 in ports and 80 in ports
    def test_round_trip_port_product(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        port = next(p for p in r2.hosts[0].ports if p.port == 80)
        assert port.product == "Apache"
    def test_round_trip_web_findings(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.web_findings[0].url == "http://example.com"
    def test_round_trip_nuclei_findings(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.nuclei_findings[0].cve == "CVE-2021-41773"
    def test_round_trip_phases_completed(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.phases_completed == make_result().phases_completed
    def test_round_trip_errors(self):
        r2 = _dict_to_result(_result_to_dict(make_result()))
        assert r2.errors == make_result().errors
    def test_dict_to_result_missing_optional_fields(self):
        r = _dict_to_result({"target":"x.com","start_time":"t"})
        assert r.target == "x.com" and r.hosts == []


# ═══════════════════════════════════════════════
# _dict_to_config
# ═══════════════════════════════════════════════
class TestConfigDeserialization:
    def test_round_trip_target(self):
        cfg2 = _dict_to_config(make_config().to_dict())
        assert cfg2.target == "example.com"
    def test_round_trip_profile(self):
        cfg2 = _dict_to_config(make_config().to_dict())
        assert cfg2.profile == ScanProfile.FULL_SUITE
    def test_round_trip_run_subdomains(self):
        cfg2 = _dict_to_config(make_config().to_dict())
        assert cfg2.run_subdomains is True
    def test_round_trip_threads(self):
        cfg2 = _dict_to_config(make_config().to_dict())
        assert cfg2.threads == 20
    def test_round_trip_nmap_timing(self):
        cfg2 = _dict_to_config(make_config().to_dict())
        assert cfg2.nmap_opts.timing == "T4"
    def test_all_profiles_deserialize(self):
        for p in ScanProfile:
            cfg2 = _dict_to_config(ScanConfig(target="x", profile=p).to_dict())
            assert cfg2.profile == p
    # ── v5.0.0: new fields must survive round-trip ────────────────────────────
    def test_round_trip_run_cve_lookup_true(self):
        cfg = make_config(run_cve_lookup=True)
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.run_cve_lookup is True
    def test_round_trip_run_cve_lookup_false(self):
        cfg = make_config(run_cve_lookup=False)
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.run_cve_lookup is False
    def test_round_trip_ai_provider(self):
        cfg = make_config(ai_provider="gemini")
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.ai_provider == "gemini"
    def test_round_trip_ai_key(self):
        cfg = make_config(ai_key="gsk_supersecret")
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.ai_key == "gsk_supersecret"
    def test_round_trip_ai_model(self):
        cfg = make_config(ai_model="llama3-8b-8192")
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.ai_model == "llama3-8b-8192"
    def test_round_trip_nvd_key(self):
        cfg = make_config(nvd_key="nvd_apikey_xyz")
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.nvd_key == "nvd_apikey_xyz"
    def test_round_trip_all_new_fields_together(self):
        cfg = make_config(
            run_cve_lookup=True, ai_provider="openai",
            ai_key="sk-secret", ai_model="gpt-4o-mini", nvd_key="nvd123"
        )
        cfg2 = _dict_to_config(cfg.to_dict())
        assert cfg2.run_cve_lookup is True
        assert cfg2.ai_provider    == "openai"
        assert cfg2.ai_key         == "sk-secret"
        assert cfg2.ai_model       == "gpt-4o-mini"
        assert cfg2.nvd_key        == "nvd123"
    def test_missing_new_fields_get_defaults(self):
        """Old state.json files without new fields should still load cleanly."""
        d = {
            "target": "old.com",
            "profile": "standard",
            "nmap_opts": {},
        }
        cfg2 = _dict_to_config(d)
        assert cfg2.run_cve_lookup is False
        assert cfg2.ai_provider    == "groq"
        assert cfg2.ai_key         == ""
        assert cfg2.ai_model       == ""
        assert cfg2.nvd_key        == ""


# ═══════════════════════════════════════════════
# save_state / load_state
# ═══════════════════════════════════════════════
class TestSaveLoadState:
    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            assert (out / STATE_FILE).exists()

    def test_save_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert isinstance(data, dict)

    def test_save_contains_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            data = json.loads((out / STATE_FILE).read_text())
            assert "version" in data

    def test_load_returns_tuple(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            loaded = load_state(out / STATE_FILE)
            assert isinstance(loaded, tuple) and len(loaded) == 3

    def test_load_recovers_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result("mysite.com"), make_config("mysite.com"), out)
            result, cfg, folder = load_state(out / STATE_FILE)
            assert result.target == "mysite.com"
            assert cfg.target    == "mysite.com"

    def test_load_recovers_subdomains(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "www.example.com" in result.subdomains

    def test_load_recovers_phases_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "subdomains" in result.phases_completed

    def test_load_recovers_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert result.hosts[0].ip == "192.168.1.1"

    def test_load_recovers_vuln_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert result.nuclei_findings[0].cve == "CVE-2021-41773"

    def test_load_missing_file_returns_none(self):
        assert load_state(Path("/nonexistent/path/state.json")) is None

    def test_load_corrupt_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / STATE_FILE
            bad.write_text("NOT VALID JSON {{{{")
            assert load_state(bad) is None

    def test_overwrite_state_preserves_new_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = make_result()
            save_state(r, make_config(), out)
            r.phases_completed.append("ai_analysis")
            save_state(r, make_config(), out)
            result, _, _ = load_state(out / STATE_FILE)
            assert "ai_analysis" in result.phases_completed

    # ── v5.0.0: new config fields survive save → load ─────────────────────────
    def test_load_recovers_run_cve_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(run_cve_lookup=True), out)
            _, cfg, _ = load_state(out / STATE_FILE)
            assert cfg.run_cve_lookup is True

    def test_load_recovers_ai_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(ai_provider="gemini"), out)
            _, cfg, _ = load_state(out / STATE_FILE)
            assert cfg.ai_provider == "gemini"

    def test_load_recovers_ai_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(ai_key="gsk_test_key"), out)
            _, cfg, _ = load_state(out / STATE_FILE)
            assert cfg.ai_key == "gsk_test_key"

    def test_load_recovers_ai_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(ai_model="mixtral-8x7b"), out)
            _, cfg, _ = load_state(out / STATE_FILE)
            assert cfg.ai_model == "mixtral-8x7b"

    def test_load_recovers_nvd_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_state(make_result(), make_config(nvd_key="nvd_real_key"), out)
            _, cfg, _ = load_state(out / STATE_FILE)
            assert cfg.nvd_key == "nvd_real_key"

    def test_load_recovers_all_new_fields_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            cfg_in = make_config(
                run_cve_lookup=True, ai_provider="ollama",
                ai_key="sk-ollama", ai_model="llama3", nvd_key="nvd999"
            )
            save_state(make_result(), cfg_in, out)
            _, cfg_out, _ = load_state(out / STATE_FILE)
            assert cfg_out.run_cve_lookup is True
            assert cfg_out.ai_provider    == "ollama"
            assert cfg_out.ai_key         == "sk-ollama"
            assert cfg_out.ai_model       == "llama3"
            assert cfg_out.nvd_key        == "nvd999"


# ═══════════════════════════════════════════════
# find_latest_state
# ═══════════════════════════════════════════════
class TestFindLatestState:
    def test_returns_none_when_no_reports_dir(self):
        assert find_latest_state("example.com", Path("/nonexistent/path")) is None

    def test_returns_none_when_no_matching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            (reports / "other_target").mkdir()
            assert find_latest_state("example.com", reports) is None

    def test_returns_path_when_state_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports   = Path(tmp)
            target_dir = reports / "example.com" / "20240115_120000"
            target_dir.mkdir(parents=True)
            save_state(make_result(), make_config(), target_dir)
            result = find_latest_state("example.com", reports)
            assert result is not None and isinstance(result, Path)

    def test_returns_none_when_target_dir_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports   = Path(tmp)
            (reports / "example.com" / "20240115_120000").mkdir(parents=True)
            assert find_latest_state("example.com", reports) is None
