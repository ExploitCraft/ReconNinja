"""
tests/test_v4_modules.py — ReconNinja v5.0.0
Tests for the 5 v5 intelligence modules:
  - core/shodan_lookup.py
  - core/virustotal.py
  - core/whois_lookup.py
  - core/wayback.py
  - core/ssl_scan.py
"""

import sys
import json
import ssl
import socket
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


# ══════════════════════════════════════════════════════════════════════════════
# SHODAN LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

class TestShodanLookup:
    def test_empty_key_returns_empty(self):
        from core.shodan_lookup import shodan_host_lookup
        result = shodan_host_lookup("1.2.3.4", "")
        assert result == {}

    def test_empty_key_bulk_returns_empty(self):
        from core.shodan_lookup import shodan_bulk_lookup
        result = shodan_bulk_lookup(["1.2.3.4"], "")
        assert result == []

    def test_empty_ips_bulk_returns_empty(self):
        from core.shodan_lookup import shodan_bulk_lookup
        result = shodan_bulk_lookup([], "validkey")
        assert result == []

    def test_host_lookup_returns_dict_on_success(self):
        from core.shodan_lookup import shodan_host_lookup
        mock_data = {
            "org": "ACME Corp", "isp": "ACME ISP",
            "country_name": "US", "city": "New York",
            "hostnames": ["example.com"], "domains": ["example.com"],
            "tags": [], "vulns": {"CVE-2021-1234": {}},
            "ports": [80, 443],
            "data": [{"port": 80, "transport": "tcp", "product": "nginx",
                      "version": "1.18", "cpe": [], "data": "HTTP/1.1"}],
        }
        with patch("core.shodan_lookup._fetch", return_value=mock_data):
            result = shodan_host_lookup("1.2.3.4", "testkey")
        assert result["org"]   == "ACME Corp"
        assert result["ip"]    == "1.2.3.4"
        assert "CVE-2021-1234" in result["vulns"]
        assert 80 in result["open_ports"]
        assert len(result["services"]) == 1

    def test_404_returns_empty(self):
        from core.shodan_lookup import shodan_host_lookup
        import urllib.error
        with patch("core.shodan_lookup._fetch", return_value={}):
            result = shodan_host_lookup("1.2.3.4", "testkey")
        assert result == {}

    def test_network_error_returns_empty(self):
        from core.shodan_lookup import shodan_host_lookup
        with patch("core.shodan_lookup._fetch", side_effect=Exception("timeout")):
            result = shodan_host_lookup("1.2.3.4", "testkey")
        assert result == {}

    def test_resolve_no_key_returns_none(self):
        from core.shodan_lookup import shodan_resolve
        assert shodan_resolve("example.com", "") is None

    def test_bulk_lookup_calls_host_lookup_per_ip(self):
        from core.shodan_lookup import shodan_bulk_lookup
        mock_result = {"ip": "1.2.3.4", "org": "Test"}
        with patch("core.shodan_lookup.shodan_host_lookup", return_value=mock_result) as m:
            results = shodan_bulk_lookup(["1.2.3.4", "5.6.7.8"], "key")
        assert m.call_count == 2
        assert len(results) == 2


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════════════════

class TestVirusTotal:
    def test_empty_key_domain_returns_empty(self):
        from core.virustotal import vt_domain_lookup
        assert vt_domain_lookup("example.com", "") == {}

    def test_empty_key_ip_returns_empty(self):
        from core.virustotal import vt_ip_lookup
        assert vt_ip_lookup("1.2.3.4", "") == {}

    def test_empty_targets_bulk_returns_empty(self):
        from core.virustotal import vt_bulk_lookup
        assert vt_bulk_lookup([], "key") == []

    def test_domain_lookup_parses_stats(self):
        from core.virustotal import vt_domain_lookup
        mock_resp = {
            "data": {
                "attributes": {
                    "reputation": -10,
                    "last_analysis_stats": {
                        "malicious": 5, "suspicious": 2,
                        "harmless": 60, "undetected": 10,
                    },
                    "categories": {"test": "malware"},
                    "registrar": "Bad Registrar",
                    "creation_date": 1000000,
                    "tags": ["malware"],
                    "whois": "some whois data",
                }
            }
        }
        with patch("core.virustotal._fetch_vt", return_value=mock_resp):
            result = vt_domain_lookup("evil.com", "vtkey")
        assert result["malicious"]  == 5
        assert result["reputation"] == -10
        assert result["domain"]     == "evil.com"

    def test_ip_lookup_parses_asn(self):
        from core.virustotal import vt_ip_lookup
        mock_resp = {
            "data": {
                "attributes": {
                    "asn": 12345, "as_owner": "ACME",
                    "country": "US", "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "harmless": 70, "undetected": 5,
                    },
                    "tags": [], "network": "1.2.3.0/24",
                }
            }
        }
        with patch("core.virustotal._fetch_vt", return_value=mock_resp):
            result = vt_ip_lookup("1.2.3.4", "vtkey")
        assert result["asn"]      == 12345
        assert result["as_owner"] == "ACME"
        assert result["malicious"] == 0

    def test_empty_response_returns_empty(self):
        from core.virustotal import vt_domain_lookup
        with patch("core.virustotal._fetch_vt", return_value={}):
            assert vt_domain_lookup("x.com", "key") == {}

    def test_rate_limit_response_returns_empty(self):
        from core.virustotal import vt_domain_lookup
        import urllib.error
        err = urllib.error.HTTPError("url", 429, "Too Many Requests", {}, None)
        with patch("core.virustotal._fetch_vt", side_effect=err):
            result = vt_domain_lookup("x.com", "key")
        assert result == {}

    def test_parse_stats_zero_malicious(self):
        from core.virustotal import _parse_stats
        stats = _parse_stats({"malicious": 0, "suspicious": 0, "harmless": 100, "undetected": 0})
        assert stats["malicious"] == 0

    def test_parse_stats_high_malicious(self):
        from core.virustotal import _parse_stats
        stats = _parse_stats({"malicious": 50, "suspicious": 5, "harmless": 5, "undetected": 0})
        assert stats["malicious"] == 50

    def test_parse_stats_missing_keys_defaults_zero(self):
        from core.virustotal import _parse_stats
        stats = _parse_stats({})
        assert stats["malicious"]  == 0
        assert stats["suspicious"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

class TestWhoisLookup:
    SAMPLE_WHOIS = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Updated Date: 2023-08-14T07:01:34Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientDeleteProhibited
Registrant Organization: ACME Corp
Registrant Country: US
Tech Email: admin@example.com
"""

    def test_returns_dict(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert isinstance(result, dict)

    def test_target_preserved(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert result["target"] == "example.com"

    def test_registrar_extracted(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert "Registrar" in result["registrar"] or "registrar" in result["registrar"].lower()

    def test_expiry_extracted(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert "2025" in result["expires"] or result["expires"] != ""

    def test_nameservers_extracted(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert len(result["name_servers"]) >= 1

    def test_emails_extracted(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert any("example.com" in e for e in result["emails"])

    def test_country_extracted(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=self.SAMPLE_WHOIS):
            result = whois_lookup("example.com")
        assert result["country"] in ("US", "")

    def test_no_data_returns_error_dict(self):
        from core.whois_lookup import whois_lookup
        with patch("core.whois_lookup._whois_cli", return_value=""):
            with patch("core.whois_lookup._whois_python", return_value=""):
                result = whois_lookup("nodatahost.invalid")
        assert "error" in result

    def test_raw_truncated_to_3000(self):
        from core.whois_lookup import whois_lookup
        long_raw = "X" * 5000
        with patch("core.whois_lookup._whois_cli", return_value=long_raw):
            result = whois_lookup("example.com")
        assert len(result["raw"]) <= 3000


# ══════════════════════════════════════════════════════════════════════════════
# WAYBACK MACHINE
# ══════════════════════════════════════════════════════════════════════════════

class TestWayback:
    SAMPLE_CDX = [
        ["original", "statuscode", "mimetype", "timestamp"],
        ["https://example.com/admin/login.php", "200", "text/html", "20200101120000"],
        ["https://example.com/config.json", "200", "application/json", "20210501080000"],
        ["https://example.com/backup.sql", "200", "text/plain", "20190801000000"],
        ["https://example.com/about.html", "200", "text/html", "20220601000000"],
        ["https://example.com/api/users", "200", "application/json", "20230101000000"],
    ]

    def _mock_fetch(self, data):
        import json as _json
        mock_resp = MagicMock()
        mock_resp.read.return_value = _json.dumps(data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_returns_dict(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        assert isinstance(result, dict)

    def test_domain_preserved(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        assert result["domain"] == "example.com"

    def test_total_count_correct(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        assert result["total"] == 5  # 5 data rows (header excluded)

    def test_interesting_urls_detected(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        # admin, config.json, backup.sql, api should be flagged
        assert len(result["interesting"]) >= 3

    def test_php_extension_flagged(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        reasons = [i["reason"] for i in result["interesting"]]
        assert any(".php" in r for r in reasons)

    def test_sql_extension_flagged(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        reasons = [i["reason"] for i in result["interesting"]]
        assert any(".sql" in r for r in reasons)

    def test_empty_response_returns_empty(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch([])):
            result = wayback_lookup("example.com")
        assert result == {}

    def test_http_error_returns_empty(self):
        from core.wayback import wayback_lookup
        import urllib.error
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError("url", 503, "unavail", {}, None)):
            result = wayback_lookup("example.com")
        assert result == {}

    def test_network_error_returns_empty(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = wayback_lookup("example.com")
        assert result == {}

    def test_header_row_excluded_from_urls(self):
        from core.wayback import wayback_lookup
        with patch("urllib.request.urlopen", return_value=self._mock_fetch(self.SAMPLE_CDX)):
            result = wayback_lookup("example.com")
        # header row ["original","statuscode",...] must not be in urls
        assert "original" not in result["urls"]


# ══════════════════════════════════════════════════════════════════════════════
# SSL SCAN
# ══════════════════════════════════════════════════════════════════════════════

class TestSSLScan:
    def _make_cert(self, days_left=90, self_signed=False, cn="example.com"):
        import datetime
        now   = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        after = now + datetime.timedelta(days=days_left)
        fmt   = "%b %d %H:%M:%S %Y %Z"
        subj  = ((("commonName", cn),),)
        issuer= subj if self_signed else ((("commonName", "DigiCert Inc"),),)
        return {
            "subject":        subj,
            "issuer":         issuer,
            "subjectAltName": [("DNS", cn), ("DNS", f"www.{cn}")],
            "notBefore":      now.strftime("%b %d %H:%M:%S %Y") + " GMT",
            "notAfter":       after.strftime("%b %d %H:%M:%S %Y") + " GMT",
        }

    def test_returns_dict(self):
        from core.ssl_scan import ssl_scan
        with patch("core.ssl_scan._get_cert", return_value=None):
            result = ssl_scan("example.com")
        assert isinstance(result, dict)
        assert result["host"] == "example.com"

    def test_no_ssl_returns_empty_certs(self):
        from core.ssl_scan import ssl_scan
        with patch("core.ssl_scan._get_cert", return_value=None):
            result = ssl_scan("nossl.example.com")
        assert result["certs"] == []
        assert result["issues"] == []

    def test_valid_cert_no_issues(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=180),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("example.com", ports=[443])
        assert len(result["certs"]) == 1
        assert result["certs"][0]["expired"] == False
        # No critical issues for a valid cert
        critical = [i for i in result["issues"] if i["severity"] == "critical"]
        assert len(critical) == 0

    def test_expired_cert_flagged(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=-10),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("expired.example.com", ports=[443])
        assert result["certs"][0]["expired"] == True
        severities = [i["severity"] for i in result["issues"]]
        assert "critical" in severities

    def test_expiring_soon_flagged(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=7),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("soon.example.com", ports=[443])
        assert len(result["issues"]) >= 1

    def test_self_signed_flagged(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=90, self_signed=True),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("self.example.com", ports=[443])
        assert result["certs"][0]["self_signed"] == True
        details = " ".join(i["detail"] for i in result["issues"])
        assert "Self-signed" in details or "self-signed" in details.lower()

    def test_old_tls_protocol_flagged(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=90),
            "cipher":  ("AES128-SHA", "TLSv1", 128),
            "version": "TLSv1",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("oldtls.example.com", ports=[443])
        details = " ".join(i["detail"] for i in result["issues"])
        assert "TLSv1" in details

    def test_weak_cipher_rc4_flagged(self):
        from core.ssl_scan import _check_weak_cipher
        issues = _check_weak_cipher("RC4-MD5")
        assert any("RC4" in i for i in issues)

    def test_weak_cipher_des_flagged(self):
        from core.ssl_scan import _check_weak_cipher
        issues = _check_weak_cipher("DES-CBC-SHA")
        assert any("DES" in i for i in issues)

    def test_strong_cipher_no_issues(self):
        from core.ssl_scan import _check_weak_cipher
        issues = _check_weak_cipher("TLS_AES_256_GCM_SHA384")
        assert issues == []

    def test_san_extracted(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=90),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        with patch("core.ssl_scan._get_cert", return_value=mock_data):
            result = ssl_scan("example.com", ports=[443])
        san = result["certs"][0]["san"]
        assert "example.com" in san

    def test_multiple_ports_scanned(self):
        from core.ssl_scan import ssl_scan
        mock_data = {
            "cert":    self._make_cert(days_left=90),
            "cipher":  ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "version": "TLSv1.3",
        }
        call_count = [0]
        def mock_get_cert(host, port, timeout=10):
            call_count[0] += 1
            return mock_data

        with patch("core.ssl_scan._get_cert", side_effect=mock_get_cert):
            ssl_scan("example.com", ports=[443, 8443])
        assert call_count[0] == 2


# ══════════════════════════════════════════════════════════════════════════════
# RESUME — state save/load round-trip for intelligence fields
# ══════════════════════════════════════════════════════════════════════════════

class TestResumeV4Fields:
    """
    Bug fixed in v5.0.0: _dict_to_result and _dict_to_config both dropped all intelligence fields.
    After resume, intelligence results were wiped and flags were all False.
    These tests verify the fix.
    """

    def _make_full_result(self):
        from utils.models import ReconResult
        r = ReconResult(target="example.com", start_time="20260307_120000")
        r.shodan_results  = [{"ip": "1.2.3.4", "org": "ACME"}]
        r.vt_results      = [{"domain": "example.com", "malicious": 0}]
        r.whois_results   = [{"target": "example.com", "registrar": "Namecheap"}]
        r.wayback_results = [{"domain": "example.com", "total": 42}]
        r.ssl_results     = [{"host": "example.com", "certs": [], "issues": []}]
        r.phases_completed = ["passive_recon", "whois", "wayback", "ssl"]
        return r

    def _make_v4_cfg(self):
        from utils.models import ScanConfig
        return ScanConfig(
            target          = "example.com",
            run_shodan      = True,
            run_virustotal  = True,
            run_whois       = True,
            run_wayback     = True,
            run_ssl         = True,
            shodan_key      = "shodan_abc",
            vt_key          = "vt_xyz",
            output_format   = "html",
            exclude_phases  = ["passive", "vuln"],
            global_timeout  = 60,
            rate_limit      = 1.5,
        )

    def test_result_v4_fields_survive_round_trip(self):
        import json, tempfile
        from pathlib import Path
        from core.resume import save_state, load_state
        r   = self._make_full_result()
        cfg = self._make_v4_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            save_state(r, cfg, folder)
            loaded = load_state(folder / "state.json")
        assert loaded is not None
        result2, _, _ = loaded
        assert result2.shodan_results  == r.shodan_results
        assert result2.vt_results      == r.vt_results
        assert result2.whois_results   == r.whois_results
        assert result2.wayback_results == r.wayback_results
        assert result2.ssl_results     == r.ssl_results

    def test_config_v4_flags_survive_round_trip(self):
        import tempfile
        from pathlib import Path
        from core.resume import save_state, load_state
        r   = self._make_full_result()
        cfg = self._make_v4_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            save_state(r, cfg, folder)
            loaded = load_state(folder / "state.json")
        assert loaded is not None
        _, cfg2, _ = loaded
        assert cfg2.run_shodan     == True
        assert cfg2.run_virustotal == True
        assert cfg2.run_whois      == True
        assert cfg2.run_wayback    == True
        assert cfg2.run_ssl        == True
        assert cfg2.shodan_key     == "shodan_abc"
        assert cfg2.vt_key         == "vt_xyz"
        assert cfg2.output_format  == "html"
        assert cfg2.global_timeout == 60
        assert cfg2.rate_limit     == 1.5
        assert "passive" in cfg2.exclude_phases

    def test_state_version_is_v5(self):
        import json, tempfile
        from pathlib import Path
        from core.resume import save_state
        r   = self._make_full_result()
        cfg = self._make_v4_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            save_state(r, cfg, folder)
            state = json.loads((folder / "state.json").read_text())
        assert state["version"] == "5.2.2"

    def test_v4_results_empty_list_survives_round_trip(self):
        import tempfile
        from pathlib import Path
        from utils.models import ReconResult
        from core.resume import save_state, load_state
        r   = ReconResult(target="x.com", start_time="t")
        cfg = self._make_v4_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            save_state(r, cfg, folder)
            loaded = load_state(folder / "state.json")
        assert loaded is not None
        result2, _, _ = loaded
        assert result2.shodan_results  == []
        assert result2.wayback_results == []


# ══════════════════════════════════════════════════════════════════════════════
# REPORTS — JSON report includes intelligence fields
# ══════════════════════════════════════════════════════════════════════════════

class TestReportsV4:
    def _make_result(self):
        from utils.models import ReconResult
        r = ReconResult(target="example.com", start_time="20260307_120000")
        r.shodan_results  = [{"ip": "1.2.3.4", "org": "TestOrg", "vulns": ["CVE-2021-1234"]}]
        r.vt_results      = [{"domain": "example.com", "malicious": 0, "suspicious": 1}]
        r.whois_results   = [{"target": "example.com", "registrar": "Namecheap", "expires": "2027-01-01",
                               "registered": "2010-01-01", "updated": "2024-01-01",
                               "registrant": "ACME", "country": "US",
                               "name_servers": ["ns1.namecheap.com"], "emails": ["admin@example.com"]}]
        r.wayback_results = [{"domain": "example.com", "total": 5, "interesting": [], "urls": []}]
        r.ssl_results     = [{"host": "example.com", "certs": [], "issues": []}]
        return r

    def test_json_report_has_shodan_results(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert "shodan_results" in data
        assert data["shodan_results"][0]["org"] == "TestOrg"

    def test_json_report_has_vt_results(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert "vt_results" in data
        assert data["vt_results"][0]["domain"] == "example.com"

    def test_json_report_has_whois_results(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert "whois_results" in data
        assert data["whois_results"][0]["registrar"] == "Namecheap"

    def test_json_report_has_wayback_results(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert "wayback_results" in data

    def test_json_report_has_ssl_results(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert "ssl_results" in data

    def test_json_version_is_v5(self):
        import json, tempfile
        from pathlib import Path
        from output.reports import generate_json_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            generate_json_report(r, p)
            data = json.loads(p.read_text())
        assert data["meta"]["version"] == "5.2.2"

    def test_html_report_contains_whois_section(self):
        import tempfile
        from pathlib import Path
        from output.reports import generate_html_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.html"
            generate_html_report(r, p)
            html = p.read_text()
        assert "WHOIS" in html
        assert "Namecheap" in html

    def test_html_report_v4_header(self):
        import tempfile
        from pathlib import Path
        from output.reports import generate_html_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.html"
            generate_html_report(r, p)
            html = p.read_text()
        assert "v5.2.2" in html
        assert "RECON NINJA v5" in html

    def test_md_report_contains_whois_section(self):
        import tempfile
        from pathlib import Path
        from output.reports import generate_markdown_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.md"
            generate_markdown_report(r, p)
            md = p.read_text()
        assert "## WHOIS" in md
        assert "Namecheap" in md

    def test_md_report_contains_wayback_section(self):
        import tempfile
        from pathlib import Path
        from output.reports import generate_markdown_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.md"
            generate_markdown_report(r, p)
            md = p.read_text()
        assert "## Wayback Machine" in md

    def test_md_report_v4_header(self):
        import tempfile
        from pathlib import Path
        from output.reports import generate_markdown_report
        r = self._make_result()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.md"
            generate_markdown_report(r, p)
            md = p.read_text()
        assert "v5.2.2" in md
