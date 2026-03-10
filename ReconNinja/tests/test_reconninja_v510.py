"""
tests/test_reconninja_v510.py — ReconNinja v5.1.0 Blueprint Feature Tests

Tests all v5.1.0 features using mock APIs:
  - Data model changes (ScanConfig, ReconResult, PortInfo)
  - core/censys_lookup.py
  - core/hunter_lookup.py
  - core/diff.py
  - output/reports.py — CSV, SARIF, templates, severity summary
  - Smart port deduplication
  - Plugin VulnFinding return values
  - New CLI flags
  - Phase 13 (diff) wiring
  - Confidence filtering
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import unittest

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_result(**kwargs):
    from utils.models import ReconResult
    defaults = dict(target="example.com", start_time="2026-01-01T00:00:00")
    defaults.update(kwargs)
    return ReconResult(**defaults)

def _make_host(ip="1.2.3.4", ports=None):
    from utils.models import HostResult, PortInfo
    h = HostResult(ip=ip)
    if ports:
        h.ports = ports
    return h

def _make_port(port=80, state="open", service="http", severity_port=80,
               confidence=95, source="nmap"):
    from utils.models import PortInfo
    return PortInfo(
        port=port, protocol="tcp", state=state, service=service,
        confidence=confidence, source=source,
    )

def _make_vuln(severity="high", title="Test Vuln", target="1.2.3.4", cve="CVE-2024-0001"):
    from utils.models import VulnFinding
    return VulnFinding(tool="nuclei", severity=severity, title=title,
                       target=target, cve=cve)

def _make_config(**kwargs):
    from utils.models import ScanConfig
    defaults = dict(target="example.com")
    defaults.update(kwargs)
    return ScanConfig(**defaults)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 1 — Data Model Changes
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanConfigV51Fields(unittest.TestCase):
    """ScanConfig must have all v5.1.0 fields with correct defaults."""

    def setUp(self):
        self.cfg = _make_config()

    def test_run_censys_default_false(self):
        assert self.cfg.run_censys is False

    def test_run_hunter_default_false(self):
        assert self.cfg.run_hunter is False

    def test_censys_key_default_empty(self):
        assert self.cfg.censys_key == ""

    def test_hunter_key_default_empty(self):
        assert self.cfg.hunter_key == ""

    def test_diff_file_default_none(self):
        assert self.cfg.diff_file is None

    def test_report_template_default_none(self):
        assert self.cfg.report_template is None

    def test_nmap_scripts_default_none(self):
        assert self.cfg.nmap_scripts is None

    def test_confidence_min_default_zero(self):
        assert self.cfg.confidence_min == 0

    def test_censys_key_can_be_set(self):
        cfg = _make_config(censys_key="abc:xyz")
        assert cfg.censys_key == "abc:xyz"

    def test_hunter_key_can_be_set(self):
        cfg = _make_config(hunter_key="hunter123")
        assert cfg.hunter_key == "hunter123"

    def test_diff_file_accepts_path(self):
        cfg = _make_config(diff_file=Path("/tmp/state.json"))
        assert cfg.diff_file == Path("/tmp/state.json")

    def test_nmap_scripts_accepts_string(self):
        cfg = _make_config(nmap_scripts="vuln,http-title")
        assert cfg.nmap_scripts == "vuln,http-title"

    def test_confidence_min_accepts_int(self):
        cfg = _make_config(confidence_min=70)
        assert cfg.confidence_min == 70

    def test_to_dict_includes_v51_fields(self):
        cfg = _make_config(run_censys=True, censys_key="a:b", confidence_min=50)
        d = cfg.to_dict()
        assert d["run_censys"] is True
        assert d["censys_key"] == "a:b"
        assert d["confidence_min"] == 50


class TestReconResultV51Fields(unittest.TestCase):
    """ReconResult must have all v5.1.0 fields with correct defaults."""

    def setUp(self):
        self.r = _make_result()

    def test_censys_results_default_empty_list(self):
        assert self.r.censys_results == []

    def test_hunter_results_default_empty_list(self):
        assert self.r.hunter_results == []

    def test_diff_summary_default_none(self):
        assert self.r.diff_summary is None

    def test_censys_results_appendable(self):
        self.r.censys_results.append({"ip": "1.2.3.4", "org": "TestCo"})
        assert len(self.r.censys_results) == 1
        assert self.r.censys_results[0]["ip"] == "1.2.3.4"

    def test_hunter_results_appendable(self):
        self.r.hunter_results.append({"domain": "example.com", "total": 5})
        assert len(self.r.hunter_results) == 1

    def test_diff_summary_settable(self):
        self.r.diff_summary = {"summary": "2 new ports"}
        assert self.r.diff_summary["summary"] == "2 new ports"

    def test_v50_fields_still_present(self):
        # Ensure backwards compatibility
        assert hasattr(self.r, "shodan_results")
        assert hasattr(self.r, "vt_results")
        assert hasattr(self.r, "ssl_results")


class TestPortInfoV51Fields(unittest.TestCase):
    """PortInfo must have confidence and source fields."""

    def test_confidence_default_100(self):
        p = _make_port()
        assert p.confidence == 95  # we set 95 in helper; default is 100
        from utils.models import PortInfo
        p2 = PortInfo(port=80, protocol="tcp", state="open")
        assert p2.confidence == 100

    def test_source_default_empty(self):
        from utils.models import PortInfo
        p = PortInfo(port=80, protocol="tcp", state="open")
        assert p.source == ""

    def test_confidence_accepts_range(self):
        for c in [0, 50, 85, 100]:
            p = _make_port(confidence=c)
            assert p.confidence == c

    def test_source_accepts_scanner_names(self):
        for src in ["rustscan", "async", "masscan", "nmap"]:
            p = _make_port(source=src)
            assert p.source == src

    def test_source_can_be_combined(self):
        p = _make_port(source="rustscan,nmap")
        assert "rustscan" in p.source
        assert "nmap" in p.source


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2 — core/censys_lookup.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestCensysLookupModule(unittest.TestCase):
    """Test Censys lookup with mocked CensysHosts."""

    def _mock_host_view(self, ip="1.2.3.4"):
        return {
            "ip": ip,
            "autonomous_system": {"description": "TestISP", "asn": 12345},
            "location": {"country_code": "US"},
            "labels": ["cloud"],
            "services": [
                {"port": 80, "transport_protocol": "TCP",
                 "service_name": "HTTP", "banner": "nginx"},
            ],
        }

    def _patch_censys(self, ip="1.2.3.4"):
        import core.censys_lookup as mod
        mock_hosts_instance = MagicMock()
        mock_hosts_instance.view.return_value = self._mock_host_view(ip)
        mock_cls = MagicMock(return_value=mock_hosts_instance)
        mod.CensysHosts = mock_cls
        mod._CENSYS_AVAILABLE = True
        return mock_hosts_instance

    def test_returns_dict_with_ip(self):
        from core.censys_lookup import censys_host_lookup
        self._patch_censys()
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert r["ip"] == "1.2.3.4"

    def test_returns_org(self):
        from core.censys_lookup import censys_host_lookup
        self._patch_censys()
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert r["org"] == "TestISP"

    def test_returns_asn(self):
        from core.censys_lookup import censys_host_lookup
        self._patch_censys()
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert r["asn"] == 12345

    def test_services_extracted(self):
        from core.censys_lookup import censys_host_lookup
        self._patch_censys()
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert len(r["services"]) == 1
        assert r["services"][0]["port"] == 80

    def test_out_of_scope_false_for_normal_host(self):
        from core.censys_lookup import censys_host_lookup
        self._patch_censys()
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert r["out_of_scope"] is False

    def test_cloudflare_org_marked_out_of_scope(self):
        from core.censys_lookup import censys_host_lookup, _is_cdn_waf
        raw = {
            "autonomous_system": {"description": "Cloudflare Inc", "asn": 13335},
            "location": {"country_code": "US"}, "labels": [], "services": [],
        }
        assert _is_cdn_waf(raw) is True

    def test_cdn_label_marked_out_of_scope(self):
        from core.censys_lookup import _is_cdn_waf
        raw = {
            "autonomous_system": {"description": "SomeISP", "asn": 999},
            "location": {}, "labels": ["cdn", "cloud"], "services": [],
        }
        assert _is_cdn_waf(raw) is True

    def test_censys_unavailable_returns_error(self):
        from core.censys_lookup import censys_host_lookup
        import core.censys_lookup as mod
        orig = mod._CENSYS_AVAILABLE
        mod._CENSYS_AVAILABLE = False
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        mod._CENSYS_AVAILABLE = orig
        assert "error" in r
        assert r["ip"] == "1.2.3.4"

    def test_api_exception_returns_error(self):
        from core.censys_lookup import censys_host_lookup
        import core.censys_lookup as mod
        mock_hosts_instance = MagicMock()
        mock_hosts_instance.view.side_effect = Exception("network error")
        mod.CensysHosts = MagicMock(return_value=mock_hosts_instance)
        mod._CENSYS_AVAILABLE = True
        r = censys_host_lookup("1.2.3.4", "id", "secret")
        assert "error" in r

    def test_bulk_lookup_returns_list(self):
        from core.censys_lookup import censys_bulk_lookup
        self._patch_censys()
        results = censys_bulk_lookup(["1.2.3.4", "5.6.7.8"], "id", "secret")
        assert isinstance(results, list)
        assert len(results) == 2

    def test_bulk_lookup_cidr_expands(self):
        from core.censys_lookup import censys_bulk_lookup
        self._patch_censys()
        # /30 has 2 host addresses
        results = censys_bulk_lookup(["192.168.0.0/30"], "id", "secret")
        assert len(results) == 2

    def test_bulk_lookup_respects_max_ips(self):
        from core.censys_lookup import censys_bulk_lookup
        self._patch_censys()
        ips = [f"10.0.0.{i}" for i in range(1, 25)]
        results = censys_bulk_lookup(ips, "id", "secret", max_ips=5)
        assert len(results) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3 — core/hunter_lookup.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestHunterLookupModule(unittest.TestCase):
    """Test Hunter.io lookup with mocked HTTP responses."""

    def _mock_response(self, domain="example.com", total=3):
        payload = {
            "data": {
                "organization": "Example Corp",
                "domain": domain,
                "total": total,
                "pattern": "{first}@{domain}",
                "emails": [
                    {
                        "value": f"alice@{domain}",
                        "type": "personal",
                        "confidence": 90,
                        "first_name": "Alice",
                        "last_name": "Smith",
                        "position": "CTO",
                        "sources": [{"uri": f"https://{domain}/team"}],
                    },
                    {
                        "value": f"bob@{domain}",
                        "type": "personal",
                        "confidence": 40,
                        "first_name": "Bob",
                        "last_name": "Jones",
                        "position": "Dev",
                        "sources": [],
                    },
                ],
            }
        }
        return json.dumps(payload).encode()

    def _patch_urlopen(self, domain="example.com", total=3):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = self._mock_response(domain, total)
        return patch("urllib.request.urlopen", return_value=mock_resp)

    def test_returns_domain(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen():
            r = hunter_domain_search("example.com", "key123")
        assert r["domain"] == "example.com"

    def test_returns_organization(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen():
            r = hunter_domain_search("example.com", "key123")
        assert r["organization"] == "Example Corp"

    def test_returns_total(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen(total=5):
            r = hunter_domain_search("example.com", "key123")
        assert r["total"] == 5

    def test_emails_list_returned(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen():
            r = hunter_domain_search("example.com", "key123")
        assert isinstance(r["emails"], list)
        assert len(r["emails"]) == 2

    def test_email_fields_present(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen():
            r = hunter_domain_search("example.com", "key123")
        e = r["emails"][0]
        assert "value" in e
        assert "confidence" in e
        assert "first_name" in e
        assert "position" in e

    def test_email_value_correct(self):
        from core.hunter_lookup import hunter_domain_search
        with self._patch_urlopen():
            r = hunter_domain_search("example.com", "key123")
        assert r["emails"][0]["value"] == "alice@example.com"

    def test_http_error_returns_error_dict(self):
        from core.hunter_lookup import hunter_domain_search
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=401, msg="Unauthorized", hdrs=None, fp=None
        )):
            r = hunter_domain_search("example.com", "badkey")
        assert "error" in r
        assert r["domain"] == "example.com"

    def test_network_error_returns_error_dict(self):
        from core.hunter_lookup import hunter_domain_search
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            r = hunter_domain_search("example.com", "key")
        assert "error" in r

    def test_filter_by_confidence_removes_low(self):
        from core.hunter_lookup import filter_by_confidence
        result = {
            "emails": [
                {"value": "alice@x.com", "confidence": 90},
                {"value": "bob@x.com",   "confidence": 40},
                {"value": "carol@x.com", "confidence": 70},
            ]
        }
        filtered = filter_by_confidence(result, min_confidence=70)
        assert len(filtered["emails"]) == 2
        values = [e["value"] for e in filtered["emails"]]
        assert "alice@x.com" in values
        assert "carol@x.com" in values
        assert "bob@x.com" not in values

    def test_filter_by_confidence_tracks_filtered_count(self):
        from core.hunter_lookup import filter_by_confidence
        result = {"emails": [{"confidence": 80}, {"confidence": 30}]}
        out = filter_by_confidence(result, min_confidence=50)
        assert out["filtered_count"] == 1

    def test_filter_zero_keeps_all(self):
        from core.hunter_lookup import filter_by_confidence
        result = {"emails": [{"confidence": 0}, {"confidence": 100}]}
        out = filter_by_confidence(result, min_confidence=0)
        assert len(out["emails"]) == 2

    def test_filter_100_keeps_only_full_confidence(self):
        from core.hunter_lookup import filter_by_confidence
        result = {"emails": [{"confidence": 99}, {"confidence": 100}]}
        out = filter_by_confidence(result, min_confidence=100)
        assert len(out["emails"]) == 1
        assert out["emails"][0]["confidence"] == 100


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4 — core/diff.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestDiffEngine(unittest.TestCase):
    """Test scan diff logic."""

    def _state(self, target="example.com", ports=None, subs=None, vulns=None):
        s: dict = {
            "target": target,
            "start_time": "2026-01-01",
            "hosts": [],
            "subdomains": subs or [],
            "nuclei_findings": [],
        }
        if ports:
            host = {"ip": "1.2.3.4", "ports": [
                {"port": p, "state": "open", "protocol": "tcp"} for p in ports
            ]}
            s["hosts"] = [host]
        if vulns:
            for v in vulns:
                s["nuclei_findings"].append({
                    "severity": v[0], "title": v[1], "target": v[2]
                })
        return s

    def test_no_changes_summary(self):
        from core.diff import diff_states
        s = self._state(ports=[80, 443])
        d = diff_states(s, s)
        assert "No changes" in d["summary"]

    def test_new_open_port_detected(self):
        from core.diff import diff_states
        old = self._state(ports=[80])
        new = self._state(ports=[80, 8080])
        d = diff_states(old, new)
        assert "1.2.3.4:8080" in d["ports"]["new_open"]

    def test_closed_port_detected(self):
        from core.diff import diff_states
        old = self._state(ports=[80, 22])
        new = self._state(ports=[80])
        d = diff_states(old, new)
        assert "1.2.3.4:22" in d["ports"]["closed"]

    def test_unchanged_count_correct(self):
        from core.diff import diff_states
        old = self._state(ports=[80, 443, 22])
        new = self._state(ports=[80, 443, 8080])
        d = diff_states(old, new)
        assert d["ports"]["unchanged"] == 2

    def test_new_subdomain_detected(self):
        from core.diff import diff_states
        old = self._state(subs=["www.example.com"])
        new = self._state(subs=["www.example.com", "api.example.com"])
        d = diff_states(old, new)
        assert "api.example.com" in d["subdomains"]["added"]

    def test_removed_subdomain_detected(self):
        from core.diff import diff_states
        old = self._state(subs=["www.example.com", "old.example.com"])
        new = self._state(subs=["www.example.com"])
        d = diff_states(old, new)
        assert "old.example.com" in d["subdomains"]["removed"]

    def test_new_vuln_detected(self):
        from core.diff import diff_states
        old = self._state()
        new = self._state(vulns=[("high", "XSS", "1.2.3.4")])
        d = diff_states(old, new)
        assert len(d["vulns"]["new"]) == 1
        assert "XSS" in d["vulns"]["new"][0]

    def test_resolved_vuln_detected(self):
        from core.diff import diff_states
        old = self._state(vulns=[("high", "XSS", "1.2.3.4")])
        new = self._state()
        d = diff_states(old, new)
        assert len(d["vulns"]["resolved"]) == 1

    def test_summary_contains_new_port_count(self):
        from core.diff import diff_states
        old = self._state(ports=[80])
        new = self._state(ports=[80, 22, 8080])
        d = diff_states(old, new)
        assert "2 new open port" in d["summary"]

    def test_empty_states_no_changes(self):
        from core.diff import diff_states
        d = diff_states({}, {})
        assert d["ports"]["new_open"] == []
        assert d["subdomains"]["added"] == []

    def test_run_diff_missing_file(self):
        from core.diff import run_diff
        result = run_diff(Path("/nonexistent/state.json"), {})
        assert "error" in result

    def test_run_diff_loads_and_compares(self):
        from core.diff import run_diff
        old_state = self._state(ports=[80])
        new_state = self._state(ports=[80, 443])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(old_state, f)
            tmppath = Path(f.name)
        try:
            d = run_diff(tmppath, new_state)
            assert "1.2.3.4:443" in d["ports"]["new_open"]
        finally:
            tmppath.unlink()

    def test_render_diff_markdown_contains_new_port(self):
        from core.diff import diff_states, render_diff_markdown
        old = self._state(ports=[80])
        new = self._state(ports=[80, 8080])
        d = diff_states(old, new)
        md = render_diff_markdown(d)
        assert "8080" in md
        assert "NEW" in md

    def test_render_diff_markdown_error_case(self):
        from core.diff import render_diff_markdown
        md = render_diff_markdown({"error": "File not found"})
        assert "Error" in md

    def test_render_diff_markdown_resolved_vuln(self):
        from core.diff import diff_states, render_diff_markdown
        old = self._state(vulns=[("high", "SQLi", "1.2.3.4")])
        new = self._state()
        d = diff_states(old, new)
        md = render_diff_markdown(d)
        assert "resolved" in md.lower() or "SQLi" in md


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5 — output/reports.py CSV export
# ═══════════════════════════════════════════════════════════════════════════════

class TestCSVReport(unittest.TestCase):
    """Test CSV report generation."""

    def _make_full_result(self):
        from utils.models import ReconResult, HostResult, PortInfo, VulnFinding
        r = ReconResult(target="example.com", start_time="2026-01-01")
        h = HostResult(ip="1.2.3.4")
        h.ports = [
            PortInfo(port=80, protocol="tcp", state="open", service="http",
                     confidence=95, source="nmap"),
            PortInfo(port=443, protocol="tcp", state="open", service="https",
                     confidence=90, source="nmap"),
        ]
        r.hosts = [h]
        r.nuclei_findings = [
            VulnFinding(tool="nuclei", severity="high",
                        title="XSS", target="1.2.3.4", cve="CVE-2024-1234")
        ]
        return r

    def test_csv_file_created(self):
        from output.reports import generate_csv_report
        r = self._make_full_result()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            p = Path(f.name)
        try:
            generate_csv_report(r, p)
            assert p.exists()
        finally:
            p.unlink()

    def test_csv_has_header(self):
        from output.reports import generate_csv_report
        r = self._make_full_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.csv"
            generate_csv_report(r, p)
            content = p.read_text()
        assert "type" in content
        assert "port" in content
        assert "severity" in content

    def test_csv_contains_port_rows(self):
        from output.reports import generate_csv_report
        r = self._make_full_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.csv"
            generate_csv_report(r, p)
            rows = list(csv.DictReader(p.open()))
        port_rows = [row for row in rows if row["type"] == "port"]
        assert len(port_rows) == 2

    def test_csv_port_row_fields(self):
        from output.reports import generate_csv_report
        r = self._make_full_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.csv"
            generate_csv_report(r, p)
            rows = list(csv.DictReader(p.open()))
        port_row = next(row for row in rows if row["type"] == "port" and row["port"] == "80")
        assert port_row["service"] == "http"
        assert port_row["ip"] == "1.2.3.4"
        assert port_row["confidence"] == "95"
        assert port_row["source"] == "nmap"

    def test_csv_contains_vuln_row(self):
        from output.reports import generate_csv_report
        r = self._make_full_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.csv"
            generate_csv_report(r, p)
            rows = list(csv.DictReader(p.open()))
        vuln_rows = [row for row in rows if row["type"] == "vuln"]
        assert len(vuln_rows) == 1
        assert vuln_rows[0]["severity"] == "high"
        assert vuln_rows[0]["cve"] == "CVE-2024-1234"

    def test_csv_empty_result_has_placeholder(self):
        from output.reports import generate_csv_report
        r = _make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.csv"
            generate_csv_report(r, p)
            rows = list(csv.DictReader(p.open()))
        assert len(rows) == 1
        assert rows[0]["detail"] == "no findings"


# ═══════════════════════════════════════════════════════════════════════════════
# Section 6 — output/reports.py SARIF export
# ═══════════════════════════════════════════════════════════════════════════════

class TestSARIFReport(unittest.TestCase):
    """Test SARIF report generation."""

    def _make_result_with_vulns(self):
        from utils.models import ReconResult, VulnFinding
        r = ReconResult(target="example.com", start_time="2026-01-01")
        r.nuclei_findings = [
            VulnFinding(tool="nuclei", severity="critical",
                        title="RCE", target="1.2.3.4", cve="CVE-2024-0001"),
            VulnFinding(tool="nuclei", severity="medium",
                        title="XSS", target="1.2.3.4:8080"),
        ]
        return r

    def test_sarif_file_created(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            assert p.exists()

    def test_sarif_is_valid_json(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        assert "version" in data
        assert data["version"] == "2.1.0"

    def test_sarif_has_runs(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        assert len(data["runs"]) == 1

    def test_sarif_driver_name(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ReconNinja"

    def test_sarif_results_count(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        assert len(data["runs"][0]["results"]) == 2

    def test_sarif_critical_maps_to_error(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        results = data["runs"][0]["results"]
        critical_results = [r for r in results if "CVE-2024-0001" in r.get("ruleId", "")]
        assert critical_results[0]["level"] == "error"

    def test_sarif_medium_maps_to_warning(self):
        from output.reports import generate_sarif_report
        r = self._make_result_with_vulns()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        results = data["runs"][0]["results"]
        medium_results = [r for r in results if r.get("level") == "warning"]
        assert len(medium_results) == 1

    def test_sarif_empty_findings_valid(self):
        from output.reports import generate_sarif_report
        r = _make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.sarif"
            generate_sarif_report(r, p)
            data = json.loads(p.read_text())
        assert data["runs"][0]["results"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Section 7 — Severity Summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeveritySummary(unittest.TestCase):
    """Test build_severity_summary."""

    def test_all_zero_by_default(self):
        from output.reports import build_severity_summary
        r = _make_result()
        s = build_severity_summary(r)
        assert "CRIT:0" in s
        assert "HIGH:0" in s

    def test_counts_vuln_findings(self):
        from output.reports import build_severity_summary
        from utils.models import VulnFinding
        r = _make_result()
        r.nuclei_findings = [
            VulnFinding(tool="nuclei", severity="critical", title="RCE", target="t"),
            VulnFinding(tool="nuclei", severity="high",     title="XSS", target="t"),
            VulnFinding(tool="nuclei", severity="high",     title="SQLi", target="t"),
        ]
        s = build_severity_summary(r)
        assert "CRIT:1" in s
        assert "HIGH:2" in s

    def test_format_correct(self):
        from output.reports import build_severity_summary
        r = _make_result()
        s = build_severity_summary(r)
        assert "MED:" in s
        assert "LOW:" in s
        assert "INFO:" in s

    def test_counts_critical_ports(self):
        from output.reports import build_severity_summary
        r = _make_result()
        # Port 22 is "critical" in SEVERITY_PORTS
        from utils.models import HostResult, PortInfo
        h = HostResult(ip="1.2.3.4")
        h.ports = [PortInfo(port=22, protocol="tcp", state="open")]
        r.hosts = [h]
        s = build_severity_summary(r)
        # Port 22 severity = critical
        crit_val = int(s.split("CRIT:")[1].split()[0])
        assert crit_val >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Section 8 — Smart Port Deduplication
# ═══════════════════════════════════════════════════════════════════════════════

class TestSmartPortDedup(unittest.TestCase):
    """Test deduplicate_ports in core/ports.py."""

    def _p(self, port, service="", product="", version="", confidence=70, source="async"):
        from utils.models import PortInfo
        return PortInfo(port=port, protocol="tcp", state="open",
                        service=service, product=product, version=version,
                        confidence=confidence, source=source)

    def test_dedup_unique_ports_kept(self):
        from core.ports import deduplicate_ports
        ports = [self._p(80), self._p(443), self._p(22)]
        result = deduplicate_ports(ports)
        assert len(result) == 3

    def test_dedup_duplicate_port_merged(self):
        from core.ports import deduplicate_ports
        ports = [self._p(80), self._p(80)]
        result = deduplicate_ports(ports)
        assert len(result) == 1

    def test_dedup_higher_confidence_wins(self):
        from core.ports import deduplicate_ports
        low  = self._p(80, service="",    confidence=50, source="async")
        high = self._p(80, service="http", confidence=95, source="nmap")
        result = deduplicate_ports([low, high])
        assert result[0].service == "http"
        assert result[0].confidence == 95

    def test_dedup_service_filled_from_lower_confidence(self):
        from core.ports import deduplicate_ports
        winner  = self._p(80, service="",    confidence=95, source="nmap")
        helper  = self._p(80, service="http", confidence=70, source="async")
        result  = deduplicate_ports([winner, helper])
        assert result[0].service == "http"

    def test_dedup_source_merged(self):
        from core.ports import deduplicate_ports
        a = self._p(80, source="rustscan", confidence=80)
        b = self._p(80, source="nmap",     confidence=95)
        result = deduplicate_ports([a, b])
        assert "rustscan" in result[0].source
        assert "nmap" in result[0].source

    def test_dedup_result_sorted_by_port(self):
        from core.ports import deduplicate_ports
        ports = [self._p(8080), self._p(80), self._p(443)]
        result = deduplicate_ports(ports)
        port_nums = [p.port for p in result]
        assert port_nums == sorted(port_nums)

    def test_dedup_empty_list(self):
        from core.ports import deduplicate_ports
        assert deduplicate_ports([]) == []

    def test_dedup_single_port_unchanged(self):
        from core.ports import deduplicate_ports
        p = self._p(80, service="http", confidence=90, source="nmap")
        result = deduplicate_ports([p])
        assert len(result) == 1
        assert result[0].port == 80


# ═══════════════════════════════════════════════════════════════════════════════
# Section 9 — Plugin VulnFinding return values
# ═══════════════════════════════════════════════════════════════════════════════

class TestPluginVulnFindingReturn(unittest.TestCase):
    """Test that plugins can return VulnFinding lists."""

    def test_plugin_returning_vuln_findings_appended(self):
        from plugins import run_plugins
        from utils.models import VulnFinding, ReconResult, ScanConfig
        from pathlib import Path

        finding = VulnFinding(tool="myplugin", severity="high",
                              title="Found it", target="x.com")

        def good_plugin(target, out_folder, result, config):
            return [finding]

        plugins = [("myplugin", good_plugin)]
        result = ReconResult(target="x.com", start_time="now")
        config = ScanConfig(target="x.com")
        run_plugins(plugins, "x.com", Path("/tmp"), result, config)
        assert finding in result.nuclei_findings

    def test_plugin_returning_none_no_error(self):
        from plugins import run_plugins
        from utils.models import ReconResult, ScanConfig

        def none_plugin(target, out_folder, result, config):
            return None

        plugins = [("none_plugin", none_plugin)]
        result = ReconResult(target="x.com", start_time="now")
        config = ScanConfig(target="x.com")
        # Should not raise
        run_plugins(plugins, "x.com", Path("/tmp"), result, config)
        assert result.nuclei_findings == []

    def test_plugin_returning_empty_list_no_change(self):
        from plugins import run_plugins
        from utils.models import ReconResult, ScanConfig

        def empty_plugin(target, out_folder, result, config):
            return []

        plugins = [("empty_plugin", empty_plugin)]
        result = ReconResult(target="x.com", start_time="now")
        config = ScanConfig(target="x.com")
        run_plugins(plugins, "x.com", Path("/tmp"), result, config)
        assert result.nuclei_findings == []

    def test_plugin_returning_mixed_list_only_vulnfindings_appended(self):
        from plugins import run_plugins
        from utils.models import VulnFinding, ReconResult, ScanConfig

        vf = VulnFinding(tool="p", severity="low", title="T", target="t")

        def mixed_plugin(target, out_folder, result, config):
            return [vf, "not a vulnfinding", 42]

        plugins = [("mixed", mixed_plugin)]
        result = ReconResult(target="x.com", start_time="now")
        config = ScanConfig(target="x.com")
        run_plugins(plugins, "x.com", Path("/tmp"), result, config)
        assert vf in result.nuclei_findings
        assert len(result.nuclei_findings) == 1

    def test_multiple_plugins_all_findings_collected(self):
        from plugins import run_plugins
        from utils.models import VulnFinding, ReconResult, ScanConfig

        vf1 = VulnFinding(tool="p1", severity="high", title="A", target="t")
        vf2 = VulnFinding(tool="p2", severity="low",  title="B", target="t")

        plugins = [
            ("p1", lambda t, o, r, c: [vf1]),
            ("p2", lambda t, o, r, c: [vf2]),
        ]
        result = ReconResult(target="x.com", start_time="now")
        config = ScanConfig(target="x.com")
        run_plugins(plugins, "x.com", Path("/tmp"), result, config)
        assert vf1 in result.nuclei_findings
        assert vf2 in result.nuclei_findings


# ═══════════════════════════════════════════════════════════════════════════════
# Section 10 — CLI Flags
# ═══════════════════════════════════════════════════════════════════════════════

class TestNewCLIFlags(unittest.TestCase):
    """Test new v5.1.0 CLI flags are accepted."""

    def _parse(self, args_str):
        import sys
        from unittest.mock import patch
        # We just need parse_args to not exit
        sys.argv = ["reconninja.py"] + args_str.split()
        # Import parse_args
        import importlib
        import reconninja
        importlib.reload(reconninja)
        return reconninja.parse_args()

    def test_diff_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--diff", "/tmp/state.json"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.diff == "/tmp/state.json"

    def test_censys_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--censys"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.censys is True

    def test_censys_key_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--censys-key", "abc:xyz"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.censys_key == "abc:xyz"

    def test_hunter_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--hunter"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.hunter is True

    def test_hunter_key_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--hunter-key", "h123"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.hunter_key == "h123"

    def test_nmap_scripts_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--nmap-scripts", "vuln"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.nmap_scripts == "vuln"

    def test_confidence_min_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--confidence-min", "70"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.confidence_min == 70

    def test_output_format_csv_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--output-format", "csv"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.output_format == "csv"

    def test_output_format_sarif_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--output-format", "sarif"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.output_format == "sarif"

    def test_report_template_flag_accepted(self):
        import sys
        old = sys.argv[:]
        sys.argv = ["reconninja.py", "-t", "example.com", "--report-template", "/tmp/t.html"]
        import reconninja
        args = reconninja.parse_args()
        sys.argv = old
        assert args.report_template == "/tmp/t.html"


# ═══════════════════════════════════════════════════════════════════════════════
# Section 11 — Version
# ═══════════════════════════════════════════════════════════════════════════════

class TestVersion510(unittest.TestCase):
    def test_reconninja_version(self):
        import reconninja
        assert reconninja.VERSION == "5.1.0"

    def test_reports_version(self):
        from output.reports import VERSION
        assert VERSION == "5.1.0"

    def test_pyproject_version(self):
        import tomllib
        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["version"] == "5.1.0"

    def test_resume_version(self):
        """state.json written by save_state must carry version 5.1.0"""
        from utils.models import ReconResult, ScanConfig
        from core.resume import save_state
        import json
        r = ReconResult(target="x.com", start_time="t")
        c = ScanConfig(target="x.com")
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            save_state(r, c, folder)
            state = json.loads((folder / "state.json").read_text())
        assert state["version"] == "5.1.0"


if __name__ == "__main__":
    unittest.main()
