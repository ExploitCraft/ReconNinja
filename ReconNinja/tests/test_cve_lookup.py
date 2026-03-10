"""
tests/test_cve_lookup.py — ReconNinja v5.0.0
Tests for core/cve_lookup.py — pure logic only, no real HTTP calls.

v5.0.0 additions:
  - TestRateLimit: verifies delay >= 6.0s (NVD limit: 5 req/30s)
  - TestLookupCvesForHostResult: verifies correct function name exists
    (v5.0.0 orchestrator referenced non-existent lookup_cves_for_hosts)
"""
import pytest
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cve_lookup import (
    CVEResult, _build_search_term, lookup_cves_for_ports,
    lookup_cves_for_host_result, _nvd_search, _CACHE,
)
from utils.models import PortInfo, HostResult, VulnFinding


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_port(port=80, service="http", product="Apache", version="2.4.52", state="open"):
    return PortInfo(port=port, protocol="tcp", state=state,
                    service=service, product=product, version=version)

def make_cve(cve_id="CVE-2021-41773", score=7.5, severity="HIGH"):
    return CVEResult(cve_id=cve_id, description="Path traversal",
                     severity=severity, cvss_score=score,
                     published="2021-10-05", references=["https://nvd.nist.gov"])

def make_nvd_response(cves: list) -> bytes:
    vulns = []
    for c in cves:
        vulns.append({
            "cve": {
                "id": c["id"],
                "descriptions": [{"lang":"en","value": c.get("desc","Test CVE")}],
                "published": c.get("published","2024-01-01T00:00:00.000"),
                "references": [{"url": u} for u in c.get("refs",[])],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": c.get("score", 5.0),
                            "baseSeverity": c.get("severity","MEDIUM"),
                        }
                    }]
                }
            }
        })
    return json.dumps({"vulnerabilities": vulns, "totalResults": len(vulns)}).encode()


# ═══════════════════════════════════════════════
# CVEResult dataclass
# ═══════════════════════════════════════════════
class TestCVEResult:
    def test_construction(self):
        c = make_cve()
        assert c.cve_id == "CVE-2021-41773" and c.cvss_score == 7.5

    def test_references_default_empty(self):
        c = CVEResult(cve_id="CVE-X", description="d", severity="LOW",
                      cvss_score=2.0, published="2024-01-01")
        assert c.references == []

    def test_to_vuln_finding(self):
        vf = make_cve().to_vuln_finding("192.168.1.1:80")
        assert isinstance(vf, VulnFinding)
        assert vf.cve == "CVE-2021-41773" and vf.tool == "nvd" and "7.5" in vf.title

    def test_to_vuln_finding_severity_lowercased(self):
        assert make_cve(severity="HIGH").to_vuln_finding("x:80").severity == "high"

    def test_to_vuln_finding_critical(self):
        assert make_cve(severity="CRITICAL", score=9.8).to_vuln_finding("x:443").severity == "critical"

    def test_to_vuln_finding_description_truncated(self):
        c = CVEResult(cve_id="CVE-X", description="A"*500, severity="LOW",
                      cvss_score=2.0, published="2024-01-01")
        assert len(c.to_vuln_finding("x:80").details) <= 300

    def test_to_vuln_finding_custom_tool(self):
        assert make_cve().to_vuln_finding("x:80", tool="nvd_custom").tool == "nvd_custom"


# ═══════════════════════════════════════════════
# _build_search_term
# ═══════════════════════════════════════════════
class TestBuildSearchTerm:
    def test_product_and_version(self):
        assert _build_search_term(make_port(product="Apache", version="2.4.52")) == "Apache 2.4.52"

    def test_product_only(self):
        assert _build_search_term(make_port(product="OpenSSH", version="")) == "OpenSSH"

    def test_version_only_uses_service(self):
        assert _build_search_term(make_port(product="", service="http", version="2.4.52")) == "http 2.4.52"

    def test_service_only(self):
        assert _build_search_term(make_port(product="", service="ssh", version="")) == "ssh"

    def test_no_info_returns_none(self):
        assert _build_search_term(make_port(product="", service="", version="")) is None

    def test_product_takes_priority_over_service(self):
        result = _build_search_term(make_port(product="nginx", service="http", version="1.18.0"))
        assert "nginx" in result and "1.18.0" in result

    def test_spaces_trimmed(self):
        result = _build_search_term(make_port(product="Apache", version="2.4.52"))
        assert not result.startswith(" ") and not result.endswith(" ")


# ═══════════════════════════════════════════════
# Rate Limit — v5.0.0 fix
# ═══════════════════════════════════════════════
class TestRateLimit:
    """
    NVD free tier: 5 requests per 30 seconds = minimum 6.0s between requests.
    v5.0.0 used delay=0.7s (42 req/30s) — caused 403 after 5th request.
    v5.0.0 fix: delay=6.5s with buffer.
    """
    def test_default_delay_at_least_6_seconds(self):
        import inspect
        src = inspect.getsource(lookup_cves_for_ports)
        import re
        m = re.search(r'delay\s*:\s*float\s*=\s*([\d.]+)', src)
        assert m is not None, "Could not find delay parameter default"
        delay = float(m.group(1))
        assert delay >= 6.0, (
            f"delay={delay}s is too fast for NVD rate limit (5 req/30s = 6s minimum). "
            f"Will get 403 errors. Must be >= 6.0s."
        )

    def test_delay_not_absurdly_high(self):
        """Sanity check: delay shouldn't be more than 30s (one req per 30s is too slow)."""
        import inspect, re
        src = inspect.getsource(lookup_cves_for_ports)
        m = re.search(r'delay\s*:\s*float\s*=\s*([\d.]+)', src)
        if m:
            delay = float(m.group(1))
            assert delay <= 30.0, f"delay={delay}s is unreasonably high"

    def test_delay_with_api_key_could_be_faster(self):
        """
        With NVD API key: 50 req/30s = 0.6s minimum.
        This test documents the known limitation: we use a single delay value.
        Future improvement: pass api_key and use 0.7s when key is present.
        """
        # For now just verify the function accepts an api_key param
        import inspect
        sig = inspect.signature(lookup_cves_for_ports)
        assert "api_key" in sig.parameters, "lookup_cves_for_ports must accept api_key parameter"


# ═══════════════════════════════════════════════
# _nvd_search (mocked HTTP)
# ═══════════════════════════════════════════════
class TestNvdSearch:
    def setup_method(self):
        _CACHE.clear()

    def _mock_urlopen(self, response_data: bytes):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.read      = MagicMock(return_value=response_data)
        return mock_resp

    def test_returns_list(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("Apache 2.4.49")
        assert isinstance(results, list)

    def test_parses_cve_id(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("Apache 2.4.49")
        assert results[0].cve_id == "CVE-2021-41773"

    def test_parses_score(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("Apache 2.4.49")
        assert results[0].cvss_score == 7.5

    def test_sorted_by_score_descending(self):
        data = make_nvd_response([
            {"id":"CVE-LOW","score":2.0,"severity":"LOW"},
            {"id":"CVE-CRIT","score":9.8,"severity":"CRITICAL"},
            {"id":"CVE-MED","score":5.5,"severity":"MEDIUM"},
        ])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("test sorting")
        scores = [r.cvss_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_response_returns_empty_list(self):
        data = json.dumps({"vulnerabilities":[],"totalResults":0}).encode()
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("nonexistent_xyz_123")
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            assert _nvd_search("Apache 2.4.52") == []

    def test_caching_second_call_no_http(self):
        data = make_nvd_response([{"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"}])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)) as m:
            _nvd_search("Apache cached")
            _nvd_search("Apache cached")
            assert m.call_count == 1

    def test_multiple_cves_returned(self):
        data = make_nvd_response([
            {"id":"CVE-2021-41773","score":7.5,"severity":"HIGH"},
            {"id":"CVE-2021-42013","score":9.8,"severity":"CRITICAL"},
        ])
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            results = _nvd_search("Apache 2.4.49")
        assert len(results) == 2


# ═══════════════════════════════════════════════
# lookup_cves_for_ports (mocked)
# ═══════════════════════════════════════════════
class TestLookupCvesForPorts:
    def setup_method(self):
        _CACHE.clear()

    def test_returns_list(self):
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            assert isinstance(lookup_cves_for_ports([make_port()], "example.com"), list)

    def test_no_results_when_no_product(self):
        p = make_port(product="", service="", version="")
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            result = lookup_cves_for_ports([p], "example.com")
        m.assert_not_called()
        assert result == []

    def test_returns_vuln_findings(self):
        with patch("core.cve_lookup._nvd_search", return_value=[make_cve()]):
            result = lookup_cves_for_ports([make_port()], "example.com")
        assert all(isinstance(r, VulnFinding) for r in result)

    def test_target_includes_port(self):
        with patch("core.cve_lookup._nvd_search", return_value=[make_cve()]):
            result = lookup_cves_for_ports([make_port(port=8080)], "10.0.0.1")
        assert "8080" in result[0].target

    def test_deduplication_same_product(self):
        p1 = make_port(port=80,  product="Apache", version="2.4.52")
        p2 = make_port(port=443, product="Apache", version="2.4.52")
        with patch("core.cve_lookup._nvd_search", return_value=[make_cve()]) as m:
            lookup_cves_for_ports([p1, p2], "example.com", delay=0)
        assert m.call_count == 1

    def test_different_products_queried_separately(self):
        p1 = make_port(port=80,   product="Apache", version="2.4")
        p2 = make_port(port=3306, product="MySQL",  version="8.0")
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            lookup_cves_for_ports([p1, p2], "example.com", delay=0)
        assert m.call_count == 2

    def test_sorted_critical_first(self):
        crit = make_cve("CVE-CRIT", score=9.8, severity="CRITICAL")
        low  = make_cve("CVE-LOW",  score=2.0, severity="LOW")
        p1 = make_port(port=80,   product="Apache", version="2.4")
        p2 = make_port(port=8080, product="nginx",  version="1.18")
        with patch("core.cve_lookup._nvd_search", side_effect=[[crit], [low]]):
            result = lookup_cves_for_ports([p1, p2], "x.com", delay=0)
        severities = [r.severity for r in result]
        assert severities.index("critical") < severities.index("low")

    def test_empty_ports_list(self):
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            assert lookup_cves_for_ports([], "example.com") == []


# ═══════════════════════════════════════════════
# lookup_cves_for_host_result
# ═══════════════════════════════════════════════
class TestLookupCvesForHostResult:
    """
    v5.0.0: orchestrator previously imported non-existent lookup_cves_for_hosts.
    These tests verify lookup_cves_for_host_result exists and works correctly.
    """
    def setup_method(self):
        _CACHE.clear()

    def test_function_exists_and_is_callable(self):
        """Regression: v5.0.0 orchestrator called lookup_cves_for_hosts (wrong name)."""
        from core.cve_lookup import lookup_cves_for_host_result
        assert callable(lookup_cves_for_host_result)

    def test_wrong_function_name_does_not_exist(self):
        """Confirm the old broken name is gone."""
        import core.cve_lookup as m
        assert not hasattr(m, "lookup_cves_for_hosts"), (
            "lookup_cves_for_hosts should not exist — orchestrator must use "
            "lookup_cves_for_host_result instead"
        )

    def test_returns_list(self):
        host = HostResult(ip="10.0.0.1", ports=[make_port()])
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            assert isinstance(lookup_cves_for_host_result(host, "10.0.0.1"), list)

    def test_only_open_ports_queried(self):
        open_p   = make_port(port=80,  product="Apache", version="2.4", state="open")
        closed_p = make_port(port=443, product="nginx",  version="1.18", state="closed")
        host = HostResult(ip="10.0.0.1", ports=[open_p, closed_p])
        with patch("core.cve_lookup._nvd_search", return_value=[]) as m:
            lookup_cves_for_host_result(host, "10.0.0.1")
        for call in m.call_args_list:
            assert "nginx" not in str(call)

    def test_empty_host_returns_empty(self):
        with patch("core.cve_lookup._nvd_search", return_value=[]):
            assert lookup_cves_for_host_result(HostResult(ip="10.0.0.1"), "10.0.0.1") == []

    def test_returns_vuln_findings(self):
        host = HostResult(ip="10.0.0.1", ports=[make_port()])
        with patch("core.cve_lookup._nvd_search", return_value=[make_cve()]):
            result = lookup_cves_for_host_result(host, "10.0.0.1")
        assert all(isinstance(r, VulnFinding) for r in result)
