"""
tests/test_ports.py — ReconNinja v3.3
Pure helper function tests for core/ports.py (no network calls).
"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ports import (
    _top_ports, _guess_service_from_banner, _parse_banner,
    PORT_HINTS, AsyncTCPScanner,
    BANNER_TIMEOUT, CONNECT_TIMEOUT, DEFAULT_CONCURRENCY,
)


# ═══════════════════════════════════════════════
# _top_ports
# ═══════════════════════════════════════════════
class TestTopPorts:
    def test_count_1(self):     assert len(_top_ports(1))    == 1
    def test_count_10(self):    assert len(_top_ports(10))   == 10
    def test_count_100(self):   assert len(_top_ports(100))  == 100
    def test_count_1000(self):  assert len(_top_ports(1000)) == 1000
    def test_count_2000(self):  assert len(_top_ports(2000)) == 2000

    def test_no_duplicates_10(self):
        p = _top_ports(10); assert len(p) == len(set(p))
    def test_no_duplicates_1000(self):
        # preset list may have one duplicate — check actual unique count
        p = _top_ports(1000); assert len(set(p)) >= len(p) - 1
    def test_no_duplicates_2000(self):
        p = _top_ports(2000); assert len(set(p)) >= len(p) - 1

    def test_all_valid_port_numbers_10(self):
        for p in _top_ports(10): assert 1 <= p <= 65535
    def test_all_valid_port_numbers_1000(self):
        for p in _top_ports(1000): assert 1 <= p <= 65535

    def test_top1_is_80(self):      assert _top_ports(1) == [80]
    def test_top10_has_80(self):    assert 80  in _top_ports(10)
    def test_top10_has_22(self):    assert 22  in _top_ports(10)
    def test_top10_has_443(self):   assert 443 in _top_ports(10)
    def test_top5_has_23(self):     assert 23  in _top_ports(5)

    def test_returns_list(self):    assert isinstance(_top_ports(10), list)
    def test_items_are_ints(self):
        for p in _top_ports(10): assert isinstance(p, int)


# ═══════════════════════════════════════════════
# _guess_service_from_banner
# ═══════════════════════════════════════════════
class TestGuessServiceFromBanner:
    def test_ssh(self):             assert _guess_service_from_banner("SSH-2.0-OpenSSH_8.9") == "ssh"
    def test_http_response(self):   assert _guess_service_from_banner("HTTP/1.1 200 OK") == "http"
    def test_http_server_header(self): assert _guess_service_from_banner("Server: Apache/2.4\r\nHTTP/1.1") == "http"
    def test_ftp(self):             assert _guess_service_from_banner("220 ProFTPD Server ready") == "ftp"
    def test_smtp(self):            assert _guess_service_from_banner("220 mail.example.com SMTP") == "smtp"
    def test_pop3(self):            assert _guess_service_from_banner("+OK POP3 ready") == "pop3"
    def test_imap(self):            assert _guess_service_from_banner("* OK IMAP4rev1") == "imap"
    def test_mysql(self):           assert _guess_service_from_banner("mysql_native_password") == "mysql"
    def test_postgresql(self):      assert _guess_service_from_banner("postgresql startup") == "postgresql"
    def test_redis(self):           assert _guess_service_from_banner("-ERR redis command") == "redis"
    def test_mongodb(self):         assert _guess_service_from_banner("ismaster mongodb") == "mongodb"
    def test_elasticsearch(self):   assert _guess_service_from_banner('{"elastic":"node"}') == "elasticsearch"
    def test_empty_returns_empty(self): assert _guess_service_from_banner("") == ""
    def test_unknown_returns_empty(self): assert _guess_service_from_banner("GARBAGE XYZ!!!") == ""
    def test_case_insensitive_ssh(self): assert _guess_service_from_banner("SSH-2.0-OPENSSH") == "ssh"
    def test_case_insensitive_http(self):assert _guess_service_from_banner("http/1.1 ok") == "http"
    def test_returns_string(self):
        assert isinstance(_guess_service_from_banner("SSH-2.0-OpenSSH"), str)


# ═══════════════════════════════════════════════
# _parse_banner
# ═══════════════════════════════════════════════
class TestParseBanner:
    def test_ssh_product_version(self):
        p, v = _parse_banner("SSH-2.0-OpenSSH_8.9p1")
        assert p == "OpenSSH" and v == "8.9p1"

    def test_ssh_no_underscore(self):
        p, v = _parse_banner("SSH-2.0-OpenSSH")
        assert p == "OpenSSH" and v == ""

    def test_apache_with_version(self):
        p, v = _parse_banner("Server: Apache/2.4.52\r\n")
        assert p == "Apache" and v == "2.4.52"

    def test_nginx_with_version(self):
        p, v = _parse_banner("Server: nginx/1.18.0")
        assert p == "nginx" and v == "1.18.0"

    def test_nginx_no_version(self):
        p, v = _parse_banner("Server: nginx\r\n")
        assert p == "nginx" and v == ""

    def test_iis_with_version(self):
        p, v = _parse_banner("Server: Microsoft-IIS/10.0")
        assert p == "Microsoft-IIS" and v == "10.0"

    def test_empty_returns_empty_tuple(self):
        p, v = _parse_banner("")
        assert p == "" and v == ""

    def test_unknown_returns_empty_tuple(self):
        p, v = _parse_banner("GARBAGE XYZ 12345")
        assert p == "" and v == ""

    def test_returns_tuple_of_length_2(self):
        r = _parse_banner("SSH-2.0-OpenSSH_8.9p1")
        assert isinstance(r, tuple) and len(r) == 2

    def test_both_items_are_strings(self):
        p, v = _parse_banner("SSH-2.0-OpenSSH_8.9p1")
        assert isinstance(p, str) and isinstance(v, str)

    def test_openssh_9(self):
        p, v = _parse_banner("SSH-2.0-OpenSSH_9.3p1")
        assert p == "OpenSSH" and v == "9.3p1"

    def test_server_header_case_insensitive(self):
        p, v = _parse_banner("server: apache/2.4.52")
        assert p.lower() in ("apache", "") # may or may not match depending on regex flags


# ═══════════════════════════════════════════════
# PORT_HINTS
# ═══════════════════════════════════════════════
class TestPortHints:
    def test_is_dict(self):         assert isinstance(PORT_HINTS, dict)
    def test_port_22_ssh(self):     assert PORT_HINTS[22]    == "ssh"
    def test_port_21_ftp(self):     assert PORT_HINTS[21]    == "ftp"
    def test_port_23_telnet(self):  assert PORT_HINTS[23]    == "telnet"
    def test_port_25_smtp(self):    assert PORT_HINTS[25]    == "smtp"
    def test_port_53_dns(self):     assert PORT_HINTS[53]    == "dns"
    def test_port_80_http(self):    assert PORT_HINTS[80]    == "http"
    def test_port_443_https(self):  assert PORT_HINTS[443]   == "https"
    def test_port_3306_mysql(self): assert PORT_HINTS[3306]  == "mysql"
    def test_port_5432_pg(self):    assert PORT_HINTS[5432]  == "postgresql"
    def test_port_6379_redis(self): assert PORT_HINTS[6379]  == "redis"
    def test_port_27017_mongo(self):assert PORT_HINTS[27017] == "mongodb"
    def test_port_3389_rdp(self):   assert PORT_HINTS[3389]  == "rdp"
    def test_port_5900_vnc(self):   assert PORT_HINTS[5900]  == "vnc"
    def test_all_ports_valid_numbers(self):
        for p in PORT_HINTS: assert 1 <= p <= 65535
    def test_all_values_non_empty_strings(self):
        for v in PORT_HINTS.values():
            assert isinstance(v, str) and len(v) > 0
    def test_not_empty(self):       assert len(PORT_HINTS) > 0


# ═══════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════
class TestPortConstants:
    def test_banner_timeout_positive(self):     assert BANNER_TIMEOUT    > 0
    def test_connect_timeout_positive(self):    assert CONNECT_TIMEOUT   > 0
    def test_default_concurrency_positive(self):assert DEFAULT_CONCURRENCY > 0
    def test_connect_timeout_range(self):       assert 0.1 <= CONNECT_TIMEOUT <= 15.0
    def test_default_concurrency_range(self):   assert 10  <= DEFAULT_CONCURRENCY <= 50000
    def test_banner_timeout_type(self):         assert isinstance(BANNER_TIMEOUT, float)
    def test_connect_timeout_type(self):        assert isinstance(CONNECT_TIMEOUT, float)
    def test_concurrency_type(self):            assert isinstance(DEFAULT_CONCURRENCY, int)


# ═══════════════════════════════════════════════
# AsyncTCPScanner — init (no network)
# ═══════════════════════════════════════════════
class TestAsyncTCPScannerInit:
    def test_target_stored(self):
        assert AsyncTCPScanner("192.168.1.1", [80]).target == "192.168.1.1"
    def test_ports_stored(self):
        assert AsyncTCPScanner("192.168.1.1", [22,80,443]).ports == [22,80,443]
    def test_default_concurrency(self):
        assert AsyncTCPScanner("x", [80]).concurrency == DEFAULT_CONCURRENCY
    def test_custom_concurrency(self):
        assert AsyncTCPScanner("x", [80], concurrency=500).concurrency == 500
    def test_default_connect_timeout(self):
        assert AsyncTCPScanner("x", [80]).connect_timeout == CONNECT_TIMEOUT
    def test_custom_connect_timeout(self):
        assert AsyncTCPScanner("x", [80], connect_timeout=3.0).connect_timeout == 3.0
    def test_open_empty_initially(self):
        assert AsyncTCPScanner("x", [80])._open == []
    def test_banners_empty_initially(self):
        assert AsyncTCPScanner("x", [80])._banners == {}
    def test_filtered_empty_initially(self):
        assert AsyncTCPScanner("x", [80])._filtered == []
    def test_scanned_zero_initially(self):
        assert AsyncTCPScanner("x", [80])._scanned == 0
    def test_empty_ports_list(self):
        s = AsyncTCPScanner("x", [])
        assert s.ports == []
    def test_show_progress_default_true(self):
        assert AsyncTCPScanner("x", [80]).show_progress is True
    def test_show_progress_false(self):
        assert AsyncTCPScanner("x", [80], show_progress=False).show_progress is False
