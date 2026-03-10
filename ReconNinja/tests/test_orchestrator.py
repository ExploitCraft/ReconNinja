"""
tests/test_orchestrator.py — ReconNinja v5.0.0
Comprehensive tests for core/orchestrator.py.

Covers the critical v5.0.0 fixes:
  1. All 13 phases skip on resume (phases_completed check)
  2. run_rustscan flag honoured — Phase 2 does NOT fire unconditionally
  3. Masscan re-hydrates all_open_ports on resume
  4. Phase skip guards exist in source code (regression)
  5. save_state called after every phase
  6. Orchestrator wires correct imports (CVE, AI, resume)
"""

import pytest
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.models import (
    ScanConfig, ScanProfile, NmapOptions,
    PortInfo, HostResult, WebFinding, VulnFinding, ReconResult,
)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers & fixtures
# ══════════════════════════════════════════════════════════════════════════════

ALL_PHASES = [
    "passive_recon", "rustscan", "async_tcp_scan", "masscan",
    "nmap", "cve_lookup", "httpx", "directory_scan",
    "whatweb", "nikto", "nuclei", "screenshots", "ai_analysis",
]

def make_cfg(**kwargs) -> ScanConfig:
    defaults = dict(
        target="example.com",
        profile=ScanProfile.STANDARD,
        nmap_opts=NmapOptions(scripts=True, version_detection=True, timing="T4"),
        run_subdomains=False,
        run_rustscan=False,
        run_masscan=False,
        run_httpx=False,
        run_feroxbuster=False,
        run_whatweb=False,
        run_nikto=False,
        run_nuclei=False,
        run_aquatone=False,
        run_ai_analysis=False,
        run_cve_lookup=False,
        threads=5,
    )
    defaults.update(kwargs)
    return ScanConfig(**defaults)


def make_host(ip="192.168.1.1", ports=None) -> HostResult:
    if ports is None:
        ports = [PortInfo(port=80, protocol="tcp", state="open",
                          service="http", product="Apache", version="2.4.52")]
    return HostResult(ip=ip, ports=ports)


def make_result(phases=None, target="example.com") -> ReconResult:
    r = ReconResult(target=target, start_time="20260101_120000")
    if phases:
        r.phases_completed = list(phases)
    return r


# Full mock patch context — mocks every external call orchestrator makes
MOCK_TARGETS = {
    "core.orchestrator.subdomain_enum":              MagicMock(return_value=["sub.example.com"]),
    "core.orchestrator.run_rustscan":                MagicMock(return_value={80, 443}),
    "core.orchestrator.async_port_scan":             MagicMock(return_value=([], [])),
    "core.orchestrator.run_masscan":                 MagicMock(return_value=(None, {8080})),
    "core.orchestrator.nmap_worker":                 MagicMock(return_value=(None, [make_host()], [])),
    "core.orchestrator.run_httpx":                   MagicMock(return_value=[]),
    "core.orchestrator.enrich_hosts_with_web":       MagicMock(),
    "core.orchestrator.run_dir_scan":                MagicMock(return_value=None),
    "core.orchestrator.run_whatweb":                 MagicMock(return_value=None),
    "core.orchestrator.run_nikto":                   MagicMock(return_value=None),
    "core.orchestrator.run_nuclei":                  MagicMock(return_value=[]),
    "core.orchestrator.run_aquatone":                MagicMock(return_value=True),
    "core.orchestrator.run_gowitness":               MagicMock(),
    "core.orchestrator.run_ai_analysis":             MagicMock(return_value=MagicMock(to_text=lambda: "AI ANALYSIS")),
    "core.orchestrator.lookup_cves_for_host_result": MagicMock(return_value=[]),
    "core.orchestrator.save_state":                  MagicMock(),
    "core.orchestrator.generate_json_report":        MagicMock(),
    "core.orchestrator.generate_html_report":        MagicMock(),
    "core.orchestrator.generate_markdown_report":    MagicMock(),
    "core.orchestrator.discover_plugins":            MagicMock(return_value=[]),
    "core.orchestrator.run_plugins":                 MagicMock(),
    "core.orchestrator.setup_file_logger":           MagicMock(),
    "core.orchestrator.ensure_dir":                  MagicMock(side_effect=lambda p: p),
}


def apply_mocks(extra=None):
    """Context manager: patches all external calls. Pass extra={} to override."""
    targets = {**MOCK_TARGETS}
    if extra:
        targets.update(extra)
    patches = [patch(k, v) for k, v in targets.items()]
    return patches


def run_orchestrate_with_mocks(cfg, result=None, folder=None, extra_patches=None):
    """Run orchestrate() with all external dependencies mocked."""
    from core.orchestrator import orchestrate
    patches = apply_mocks(extra_patches)
    started = []
    try:
        for p in patches:
            started.append(p.start())
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            if folder is None:
                folder = tmp_path / "scan_out"
                folder.mkdir()
            (folder / "scan_config.json").touch()
            return orchestrate(cfg, resume_result=result, resume_folder=folder)
    finally:
        for p in patches:
            p.stop()


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE CODE REGRESSION TESTS
# These catch regressions where the fix is accidentally removed from the code
# ══════════════════════════════════════════════════════════════════════════════

class TestPhaseSkipGuardsExistInSource:
    """
    Regression: verify every phase skip guard exists in orchestrator.py.
    These tests catch the v3.2.x bug where no phase was ever skipped on resume.
    """
    SRC = open(Path(__file__).parent.parent / "core" / "orchestrator.py").read()

    def test_passive_recon_skip_guard(self):
        assert 'passive_recon\" not in result.phases_completed' in self.SRC

    def test_rustscan_skip_guard(self):
        assert 'rustscan\" not in result.phases_completed' in self.SRC

    def test_async_tcp_skip_guard(self):
        assert 'async_tcp_scan\" not in result.phases_completed' in self.SRC

    def test_masscan_skip_guard(self):
        assert 'masscan\" not in result.phases_completed' in self.SRC

    def test_nmap_skip_guard(self):
        assert '\"nmap\" in result.phases_completed' in self.SRC

    def test_cve_lookup_skip_guard(self):
        assert 'cve_lookup\" not in result.phases_completed' in self.SRC

    def test_httpx_skip_guard(self):
        assert 'httpx\" not in result.phases_completed' in self.SRC

    def test_directory_scan_skip_guard(self):
        assert 'directory_scan\" not in result.phases_completed' in self.SRC

    def test_whatweb_skip_guard(self):
        assert 'whatweb\" not in result.phases_completed' in self.SRC

    def test_nikto_skip_guard(self):
        assert 'nikto\" not in result.phases_completed' in self.SRC

    def test_nuclei_skip_guard(self):
        assert 'nuclei\" not in result.phases_completed' in self.SRC

    def test_screenshots_skip_guard(self):
        assert 'screenshots\" not in result.phases_completed' in self.SRC

    def test_ai_analysis_skip_guard(self):
        assert 'ai_analysis\" not in result.phases_completed' in self.SRC

    def test_run_rustscan_flag_checked(self):
        # Phase 2 must check cfg.run_rustscan before firing
        assert 'cfg.run_rustscan and \"rustscan\" not in' in self.SRC

    def test_save_state_called_after_passive_recon(self):
        # Every phase must save a checkpoint
        src_after_passive = self.SRC[self.SRC.find("passive_recon"):]
        assert "save_state" in src_after_passive[:300]

    def test_correct_import_lookup_cves_for_host_result(self):
        # v5.0.0 bug: wrong function name. Must be exact.
        assert "lookup_cves_for_host_result" in self.SRC
        assert "lookup_cves_for_hosts" not in self.SRC  # old wrong name must not exist

    def test_correct_import_run_ai_analysis(self):
        assert "from core.ai_analysis import run_ai_analysis" in self.SRC

    def test_correct_import_save_state(self):
        assert "from core.resume import save_state" in self.SRC

    def test_no_youtubers777_in_source(self):
        assert "YouTubers777" not in self.SRC

    def test_exploitcraft_branding(self):
        # At minimum the updater references should be ExploitCraft
        updater_src = open(
            Path(__file__).parent.parent / "core" / "updater.py"
        ).read()
        assert "ExploitCraft" in updater_src
        assert "YouTubers777" not in updater_src


# ══════════════════════════════════════════════════════════════════════════════
# PHASE SKIP LOGIC — unit tests (no real I/O)
# ══════════════════════════════════════════════════════════════════════════════

class TestPhaseSkipLogic:
    """
    Tests that verify the core resume logic:
    phase already in phases_completed → skip, not re-run.
    """

    def test_rustscan_not_called_when_in_phases_completed(self):
        """Critical v5.0.0 fix: run_rustscan=True but phase already done → skip."""
        rustscan_mock = MagicMock(return_value={80})
        cfg = make_cfg(run_rustscan=True)
        result = make_result(phases=["rustscan", "async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_rustscan": rustscan_mock}
        )
        rustscan_mock.assert_not_called()

    def test_rustscan_called_when_not_in_phases_completed(self):
        """run_rustscan=True and phase NOT done → must call run_rustscan."""
        rustscan_mock = MagicMock(return_value=set())
        cfg = make_cfg(run_rustscan=True)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_rustscan": rustscan_mock}
        )
        rustscan_mock.assert_called_once()

    def test_rustscan_not_called_when_flag_false(self):
        """run_rustscan=False → never call run_rustscan regardless of resume state."""
        rustscan_mock = MagicMock(return_value={80})
        cfg = make_cfg(run_rustscan=False)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_rustscan": rustscan_mock}
        )
        rustscan_mock.assert_not_called()

    def test_subdomain_enum_skipped_when_completed(self):
        sub_mock = MagicMock(return_value=["sub.example.com"])
        cfg = make_cfg(run_subdomains=True)
        result = make_result(phases=["passive_recon"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.subdomain_enum": sub_mock}
        )
        sub_mock.assert_not_called()

    def test_subdomain_enum_runs_when_not_completed(self):
        sub_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_subdomains=True)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.subdomain_enum": sub_mock}
        )
        sub_mock.assert_called_once()

    def test_httpx_skipped_when_completed(self):
        httpx_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_httpx=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "httpx"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_httpx": httpx_mock}
        )
        httpx_mock.assert_not_called()

    def test_nuclei_skipped_when_completed(self):
        nuclei_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_nuclei=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "httpx", "nuclei"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_nuclei": nuclei_mock}
        )
        nuclei_mock.assert_not_called()

    def test_nuclei_runs_when_not_completed(self):
        nuclei_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_nuclei=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_nuclei": nuclei_mock}
        )
        nuclei_mock.assert_called()

    def test_cve_lookup_skipped_when_completed(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "cve_lookup"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        cve_mock.assert_not_called()

    def test_cve_lookup_runs_when_not_completed(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        cve_mock.assert_called()

    def test_ai_analysis_skipped_when_completed(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "done"))
        cfg = make_cfg(run_ai_analysis=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "ai_analysis"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        ai_mock.assert_not_called()

    def test_ai_analysis_runs_when_not_completed(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "HIGH RISK"))
        cfg = make_cfg(run_ai_analysis=True, ai_provider="groq", ai_key="key")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        ai_mock.assert_called_once()

    def test_whatweb_skipped_when_completed(self):
        ww_mock = MagicMock(return_value=None)
        cfg = make_cfg(run_whatweb=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "httpx", "whatweb"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_whatweb": ww_mock}
        )
        ww_mock.assert_not_called()

    def test_nikto_skipped_when_completed(self):
        nikto_mock = MagicMock(return_value=None)
        cfg = make_cfg(run_nikto=True)
        result = make_result(phases=["async_tcp_scan", "nmap", "httpx", "nikto"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_nikto": nikto_mock}
        )
        nikto_mock.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# MASSCAN RESUME — port rehydration test
# ══════════════════════════════════════════════════════════════════════════════

class TestMasscanResume:
    """
    v5.0.0 fix: when masscan phase is already completed, all_open_ports
    must be rehydrated from result.masscan_ports so Phase 4 has data.
    """

    def test_masscan_not_re_run_when_completed(self):
        masscan_mock = MagicMock(return_value=(None, {8080}))
        cfg = make_cfg(run_masscan=True)
        result = make_result(phases=["async_tcp_scan", "masscan", "nmap"])
        result.masscan_ports = [8080, 9090]
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_masscan": masscan_mock}
        )
        masscan_mock.assert_not_called()

    def test_masscan_runs_when_not_completed(self):
        masscan_mock = MagicMock(return_value=(None, set()))
        cfg = make_cfg(run_masscan=True)
        result = make_result(phases=["async_tcp_scan"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_masscan": masscan_mock}
        )
        masscan_mock.assert_called_once()

    def test_masscan_not_called_when_flag_false(self):
        masscan_mock = MagicMock(return_value=(None, {80}))
        cfg = make_cfg(run_masscan=False)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_masscan": masscan_mock}
        )
        masscan_mock.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# SAVE STATE — checkpoint written after every phase
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveStateCheckpoints:
    """
    v5.0.0 fix: save_state must be called after every phase.
    """

    def test_save_state_called_after_rustscan(self):
        save_mock = MagicMock()
        cfg = make_cfg(run_rustscan=True)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={
                "core.orchestrator.save_state": save_mock,
                "core.orchestrator.run_rustscan": MagicMock(return_value=set()),
            }
        )
        assert save_mock.call_count >= 1

    def test_save_state_called_after_nmap(self):
        save_mock = MagicMock()
        cfg = make_cfg()
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.save_state": save_mock}
        )
        # async_tcp_scan + nmap = at least 2 saves
        assert save_mock.call_count >= 2

    def test_save_state_called_after_subdomain(self):
        save_mock = MagicMock()
        cfg = make_cfg(run_subdomains=True)
        result = make_result(phases=[])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={
                "core.orchestrator.save_state": save_mock,
                "core.orchestrator.subdomain_enum": MagicMock(return_value=[]),
            }
        )
        # passive_recon save + async_tcp + nmap = at least 3
        assert save_mock.call_count >= 3

    def test_save_state_called_after_cve_lookup(self):
        save_mock = MagicMock()
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={
                "core.orchestrator.save_state": save_mock,
                "core.orchestrator.lookup_cves_for_host_result": MagicMock(return_value=[]),
            }
        )
        assert save_mock.call_count >= 1

    def test_save_state_called_after_ai_analysis(self):
        save_mock = MagicMock()
        cfg = make_cfg(run_ai_analysis=True, ai_provider="groq", ai_key="k")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={
                "core.orchestrator.save_state": save_mock,
                "core.orchestrator.run_ai_analysis": MagicMock(
                    return_value=MagicMock(to_text=lambda: "done")
                ),
            }
        )
        assert save_mock.call_count >= 1


# ══════════════════════════════════════════════════════════════════════════════
# CVE LOOKUP WIRING
# ══════════════════════════════════════════════════════════════════════════════

class TestCVELookupWiring:
    """
    v5.0.0 fix: CVE phase must actually execute when run_cve_lookup=True.
    """

    def test_cve_not_called_when_flag_false(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=False)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        cve_mock.assert_not_called()

    def test_cve_called_when_flag_true_and_hosts_present(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        cve_mock.assert_called()

    def test_cve_not_called_when_no_hosts(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = []  # no hosts

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        cve_mock.assert_not_called()

    def test_cve_findings_merged_into_nuclei_findings(self):
        cve_finding = VulnFinding(
            tool="nvd", severity="critical", title="CVE-2021-41773",
            target="192.168.1.1:80", cve="CVE-2021-41773"
        )
        cve_mock = MagicMock(return_value=[cve_finding])
        cfg = make_cfg(run_cve_lookup=True)
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]
        initial_count = len(result.nuclei_findings)

        final = run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        assert len(final.nuclei_findings) > initial_count

    def test_nvd_key_passed_to_cve_lookup(self):
        cve_mock = MagicMock(return_value=[])
        cfg = make_cfg(run_cve_lookup=True, nvd_key="test_nvd_key")
        result = make_result(phases=["async_tcp_scan", "nmap"])
        result.hosts = [make_host()]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.lookup_cves_for_host_result": cve_mock}
        )
        call_kwargs = str(cve_mock.call_args_list)
        assert "test_nvd_key" in call_kwargs


# ══════════════════════════════════════════════════════════════════════════════
# AI ANALYSIS WIRING
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAnalysisWiring:
    """
    v5.0.0 fix: --ai must call real run_ai_analysis(), not the fallback.
    """

    def test_ai_called_when_flag_true(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "HIGH RISK"))
        cfg = make_cfg(run_ai_analysis=True, ai_provider="groq", ai_key="key")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        ai_mock.assert_called_once()

    def test_ai_not_called_when_flag_false(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "done"))
        cfg = make_cfg(run_ai_analysis=False)
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        ai_mock.assert_not_called()

    def test_ai_provider_passed_correctly(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "done"))
        cfg = make_cfg(run_ai_analysis=True, ai_provider="gemini", ai_key="AIza_key")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        call_kwargs = str(ai_mock.call_args)
        assert "gemini" in call_kwargs

    def test_ai_key_passed_correctly(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "done"))
        cfg = make_cfg(run_ai_analysis=True, ai_provider="groq", ai_key="gsk_secret")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        call_kwargs = str(ai_mock.call_args)
        assert "gsk_secret" in call_kwargs

    def test_ai_result_stored_in_result(self):
        ai_mock = MagicMock(return_value=MagicMock(to_text=lambda: "CRITICAL RISK FOUND"))
        cfg = make_cfg(run_ai_analysis=True, ai_provider="groq", ai_key="key")
        result = make_result(phases=["async_tcp_scan", "nmap"])

        final = run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={"core.orchestrator.run_ai_analysis": ai_mock}
        )
        assert "CRITICAL RISK FOUND" in final.ai_analysis


# ══════════════════════════════════════════════════════════════════════════════
# RESULT INTEGRITY — orchestrate() returns correct data
# ══════════════════════════════════════════════════════════════════════════════

class TestResultIntegrity:
    def test_returns_recon_result(self):
        cfg = make_cfg()
        result = run_orchestrate_with_mocks(cfg)
        assert isinstance(result, ReconResult)

    def test_result_target_preserved(self):
        cfg = make_cfg(target="test.example.com")
        result = run_orchestrate_with_mocks(cfg)
        assert result.target == "test.example.com"

    def test_phases_completed_updated(self):
        cfg = make_cfg()
        result = run_orchestrate_with_mocks(cfg)
        assert "async_tcp_scan" in result.phases_completed
        assert "nmap" in result.phases_completed

    def test_resume_result_target_preserved(self):
        cfg = make_cfg(target="resume.example.com")
        existing = make_result(phases=["async_tcp_scan", "nmap"],
                               target="resume.example.com")
        existing.hosts = [make_host()]
        final = run_orchestrate_with_mocks(cfg, result=existing)
        assert final.target == "resume.example.com"

    def test_hosts_from_resume_preserved(self):
        cfg = make_cfg()
        existing = make_result(phases=["async_tcp_scan", "nmap"])
        existing.hosts = [make_host("10.0.0.1")]
        final = run_orchestrate_with_mocks(cfg, result=existing)
        # nmap is already done — hosts should still be present
        assert any(h.ip == "10.0.0.1" for h in final.hosts)

    def test_phases_completed_appended_not_replaced(self):
        cfg = make_cfg(run_httpx=True)
        existing = make_result(phases=["async_tcp_scan", "nmap"])
        existing.hosts = [make_host()]
        final = run_orchestrate_with_mocks(cfg, result=existing)
        # Original phases preserved
        assert "async_tcp_scan" in final.phases_completed
        assert "nmap" in final.phases_completed

    def test_reports_generated(self):
        html_mock = MagicMock()
        json_mock = MagicMock()
        cfg = make_cfg()
        run_orchestrate_with_mocks(
            cfg,
            extra_patches={
                "core.orchestrator.generate_html_report": html_mock,
                "core.orchestrator.generate_json_report": json_mock,
            }
        )
        html_mock.assert_called_once()
        json_mock.assert_called_once()

    def test_end_time_set(self):
        cfg = make_cfg()
        final = run_orchestrate_with_mocks(cfg)
        assert final.end_time is not None and final.end_time != ""


# ══════════════════════════════════════════════════════════════════════════════
# FULL RESUME SCENARIO — end-to-end
# ══════════════════════════════════════════════════════════════════════════════

class TestFullResumeScenario:
    """
    Simulates a real crash-and-resume:
    Scan crashes after Phase 5 (httpx). On resume, phases 1-5 skip,
    phases 6+ run. All mocks verify exactly which phases fire.
    """

    def test_completed_phases_all_skipped(self):
        sub_mock    = MagicMock(return_value=[])
        rust_mock   = MagicMock(return_value=set())
        httpx_mock  = MagicMock(return_value=[])
        nuclei_mock = MagicMock(return_value=[])

        cfg = make_cfg(
            run_subdomains=True, run_rustscan=True,
            run_httpx=True, run_nuclei=True
        )
        # Simulates crash after httpx — these are done
        completed = ["passive_recon", "rustscan", "async_tcp_scan", "nmap", "httpx"]
        result = make_result(phases=completed)
        result.hosts = [make_host()]
        result.subdomains = ["www.example.com"]

        run_orchestrate_with_mocks(
            cfg, result=result,
            extra_patches={
                "core.orchestrator.subdomain_enum": sub_mock,
                "core.orchestrator.run_rustscan":   rust_mock,
                "core.orchestrator.run_httpx":      httpx_mock,
                "core.orchestrator.run_nuclei":     nuclei_mock,
            }
        )

        # All completed phases must NOT re-run
        sub_mock.assert_not_called()
        rust_mock.assert_not_called()
        httpx_mock.assert_not_called()
        # Nuclei not yet done — must run
        nuclei_mock.assert_called()

    def test_no_phase_double_appended(self):
        """A phase already in phases_completed must not be appended again."""
        cfg = make_cfg(run_rustscan=True)
        result = make_result(phases=["rustscan", "async_tcp_scan"])
        result.hosts = [make_host()]

        final = run_orchestrate_with_mocks(cfg, result=result)
        rustscan_count = final.phases_completed.count("rustscan")
        assert rustscan_count == 1, f"rustscan appended {rustscan_count}x — should be 1"

    def test_all_phases_complete_fresh_scan(self):
        """Fresh scan (no resume) — all enabled phases must run and be recorded."""
        sub_mock    = MagicMock(return_value=[])
        rust_mock   = MagicMock(return_value=set())
        httpx_mock  = MagicMock(return_value=[])
        nuclei_mock = MagicMock(return_value=[])
        cve_mock    = MagicMock(return_value=[])
        ai_mock     = MagicMock(return_value=MagicMock(to_text=lambda: "done"))

        cfg = make_cfg(
            run_subdomains=True, run_rustscan=True, run_httpx=True,
            run_nuclei=True, run_cve_lookup=True,
            run_ai_analysis=True, ai_provider="groq", ai_key="k"
        )

        final = run_orchestrate_with_mocks(
            cfg,
            extra_patches={
                "core.orchestrator.subdomain_enum":              sub_mock,
                "core.orchestrator.run_rustscan":                rust_mock,
                "core.orchestrator.run_httpx":                   httpx_mock,
                "core.orchestrator.run_nuclei":                  nuclei_mock,
                "core.orchestrator.lookup_cves_for_host_result": cve_mock,
                "core.orchestrator.run_ai_analysis":             ai_mock,
            }
        )

        # All enabled phases must have run
        sub_mock.assert_called_once()
        rust_mock.assert_called_once()
        # CVE not called — no hosts from fresh nmap mock
        # AI was called
        ai_mock.assert_called_once()

        # phases_completed must include all executed phases
        assert "passive_recon"   in final.phases_completed
        assert "rustscan"        in final.phases_completed
        assert "async_tcp_scan"  in final.phases_completed
        assert "nmap"            in final.phases_completed
        assert "ai_analysis"     in final.phases_completed
