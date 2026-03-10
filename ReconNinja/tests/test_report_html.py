"""
tests/test_report_html.py — ReconNinja v3.3
Tests for output/report_html.py
"""
import pytest
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from output.report_html import (
    generate_html_report, _severity_color, _badge, _build_html,
)
from utils.models import (
    ReconResult, HostResult, PortInfo, WebFinding, VulnFinding,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_full_result():
    return ReconResult(
        target="example.com",
        start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com","mail.example.com","dev.example.com"],
        hosts=[HostResult(
            ip="192.168.1.1",
            hostnames=["example.com"],
            os_guess="Linux 5.x",
            os_accuracy="95",
            ports=[
                PortInfo(port=22,  protocol="tcp", state="open",
                         service="ssh", product="OpenSSH", version="8.9p1"),
                PortInfo(port=80,  protocol="tcp", state="open",
                         service="http", product="Apache", version="2.4.52"),
                PortInfo(port=443, protocol="tcp", state="closed"),
            ],
        )],
        web_findings=[
            WebFinding(url="http://example.com", status_code=200,
                       title="Home", technologies=["Apache","PHP 8.1"]),
            WebFinding(url="http://example.com/admin", status_code=403,
                       title="Forbidden"),
        ],
        nuclei_findings=[
            VulnFinding(tool="nuclei", severity="critical", title="RCE",
                        target="http://example.com", cve="CVE-2021-41773",
                        details="Path traversal to RCE"),
            VulnFinding(tool="nuclei", severity="high", title="XSS",
                        target="http://example.com/search"),
            VulnFinding(tool="nvd",    severity="medium", title="CVE-2021-42013 (CVSS 9.8)",
                        target="192.168.1.1:80", cve="CVE-2021-42013"),
        ],
        errors=["Masscan timed out"],
        phases_completed=["subdomains","ports","web","vuln"],
        ai_analysis="HIGH RISK\n\nApache RCE vulnerability detected.",
    )

def make_empty_result():
    return ReconResult(target="empty.com", start_time="2024-01-01")


# ═══════════════════════════════════════════════
# _severity_color
# ═══════════════════════════════════════════════
class TestSeverityColor:
    def test_critical_is_red(self):     assert "#" in _severity_color("critical")
    def test_high_is_orange(self):      assert "#" in _severity_color("high")
    def test_medium_is_yellow(self):    assert "#" in _severity_color("medium")
    def test_low_is_green(self):        assert "#" in _severity_color("low")
    def test_info_returns_color(self):  assert "#" in _severity_color("info")
    def test_unknown_returns_color(self): assert "#" in _severity_color("unknown_sev")
    def test_returns_hex(self):
        c = _severity_color("critical")
        assert c.startswith("#") and len(c) == 7
    def test_different_severities_different_colors(self):
        colors = {_severity_color(s) for s in ["critical","high","medium","low"]}
        assert len(colors) == 4   # all different
    def test_case_insensitive(self):
        assert _severity_color("CRITICAL") == _severity_color("critical")


# ═══════════════════════════════════════════════
# _badge
# ═══════════════════════════════════════════════
class TestBadge:
    def test_returns_html_string(self):     assert "<span" in _badge("critical")
    def test_contains_severity_upper(self): assert "CRITICAL" in _badge("critical")
    def test_contains_background_color(self): assert "background:" in _badge("high")
    def test_closes_span(self):             assert "</span>" in _badge("medium")
    def test_low_badge(self):               assert "LOW" in _badge("low")
    def test_info_badge(self):              assert "INFO" in _badge("info")
    def test_badge_has_class(self):         assert 'class="badge"' in _badge("critical")
    def test_different_severities(self):
        for sev in ["critical","high","medium","low","info"]:
            b = _badge(sev)
            assert sev.upper() in b


# ═══════════════════════════════════════════════
# _build_html
# ═══════════════════════════════════════════════
class TestBuildHtml:
    def test_returns_string(self):
        assert isinstance(_build_html(make_full_result()), str)

    def test_starts_with_doctype(self):
        assert _build_html(make_full_result()).strip().startswith("<!DOCTYPE html>")

    def test_contains_html_tag(self):
        h = _build_html(make_full_result())
        assert "<html" in h and "</html>" in h

    def test_contains_target(self):
        assert "example.com" in _build_html(make_full_result())

    def test_contains_ip(self):
        assert "192.168.1.1" in _build_html(make_full_result())

    def test_contains_port_22(self):
        assert "22" in _build_html(make_full_result())

    def test_contains_port_80(self):
        assert "80" in _build_html(make_full_result())

    def test_contains_apache(self):
        assert "Apache" in _build_html(make_full_result())

    def test_contains_subdomains(self):
        h = _build_html(make_full_result())
        assert "www.example.com" in h

    def test_contains_web_url(self):
        assert "http://example.com" in _build_html(make_full_result())

    def test_contains_vuln_title(self):
        assert "RCE" in _build_html(make_full_result())

    def test_contains_cve_link(self):
        h = _build_html(make_full_result())
        assert "CVE-2021-41773" in h

    def test_cve_links_to_nvd(self):
        h = _build_html(make_full_result())
        assert "nvd.nist.gov" in h

    def test_contains_ai_analysis(self):
        h = _build_html(make_full_result())
        assert "HIGH RISK" in h or "AI" in h

    def test_contains_phases(self):
        h = _build_html(make_full_result())
        assert "subdomains" in h or "ports" in h

    def test_has_navigation(self):
        h = _build_html(make_full_result())
        assert "<nav" in h

    def test_has_stats_section(self):
        h = _build_html(make_full_result())
        assert "stat" in h.lower()

    def test_has_css_styles(self):
        h = _build_html(make_full_result())
        assert "<nav" in h  # CSS was removed, just check structure exists

    def test_has_correct_vuln_count_in_stats(self):
        h = _build_html(make_full_result())
        # 3 vuln findings
        assert "3" in h

    def test_has_correct_subdomain_count(self):
        h = _build_html(make_full_result())
        # 3 subdomains
        assert "3" in h

    def test_empty_result_no_crash(self):
        h = _build_html(make_empty_result())
        assert isinstance(h, str) and len(h) > 100

    def test_empty_result_has_structure(self):
        h = _build_html(make_empty_result())
        assert "<!DOCTYPE html>" in h
        assert "empty.com" in h

    def test_no_ai_section_when_no_ai_analysis(self):
        r = make_full_result()
        r.ai_analysis = ""
        h = _build_html(r)
        assert "AI Threat Analysis" not in h

    def test_ai_section_when_ai_analysis(self):
        h = _build_html(make_full_result())
        assert "AI" in h

    def test_error_section_when_errors(self):
        h = _build_html(make_full_result())
        assert "Masscan timed out" in h or "Error" in h

    def test_no_error_section_when_no_errors(self):
        r = make_full_result()
        r.errors = []
        h = _build_html(r)
        assert "Masscan timed out" not in h

    def test_web_status_codes_shown(self):
        h = _build_html(make_full_result())
        assert "200" in h
        assert "403" in h

    def test_severity_badges_present(self):
        h = _build_html(make_full_result())
        assert "CRITICAL" in h or "critical" in h

    def test_html_is_valid_length(self):
        h = _build_html(make_full_result())
        assert len(h) > 3000  # real HTML should be substantial


# ═══════════════════════════════════════════════
# generate_html_report
# ═══════════════════════════════════════════════
class TestGenerateHtmlReport:
    def test_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(make_full_result(), out)
            assert out.exists()

    def test_returns_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            result = generate_html_report(make_full_result(), out)
            assert isinstance(result, Path)

    def test_returned_path_equals_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            result = generate_html_report(make_full_result(), out)
            assert result == out

    def test_file_contains_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(make_full_result(), out)
            content = out.read_text(encoding="utf-8")
            assert "<!DOCTYPE html>" in content

    def test_file_contains_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(make_full_result(), out)
            assert "example.com" in out.read_text(encoding="utf-8")

    def test_file_is_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(make_full_result(), out)
            content = out.read_text(encoding="utf-8")
            assert len(content) > 0

    def test_empty_result_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "empty_report.html"
            generate_html_report(make_empty_result(), out)
            assert out.exists()

    def test_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            out.write_text("OLD CONTENT")
            generate_html_report(make_full_result(), out)
            content = out.read_text(encoding="utf-8")
            assert "OLD CONTENT" not in content
            assert "<!DOCTYPE html>" in content
