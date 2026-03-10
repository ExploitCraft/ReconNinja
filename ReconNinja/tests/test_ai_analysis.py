"""
tests/test_ai_analysis.py — ReconNinja v3.3
Tests for core/ai_analysis.py — no real API calls.
"""
import pytest
import sys
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ai_analysis import (
    AIAnalysis, PROVIDERS, _build_prompt, _extract_text,
    run_ai_analysis, list_providers,
)
from utils.models import (
    ReconResult, HostResult, PortInfo, WebFinding, VulnFinding,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_result(target="example.com"):
    return ReconResult(
        target=target, start_time="2024-01-15 12:00:00",
        end_time="2024-01-15 13:00:00",
        subdomains=["www.example.com","mail.example.com"],
        hosts=[HostResult(ip="192.168.1.1", ports=[
            PortInfo(port=22,  protocol="tcp", state="open", service="ssh",
                     product="OpenSSH", version="8.9p1"),
            PortInfo(port=80,  protocol="tcp", state="open", service="http",
                     product="Apache", version="2.4.52"),
            PortInfo(port=443, protocol="tcp", state="open"),
        ])],
        web_findings=[WebFinding(url="http://example.com", status_code=200,
                                  title="Home", technologies=["Apache","PHP 8.1"])],
        nuclei_findings=[
            VulnFinding(tool="nuclei", severity="critical", title="RCE",
                        target="http://example.com", cve="CVE-2021-41773"),
            VulnFinding(tool="nuclei", severity="high",     title="XSS",
                        target="http://example.com/search"),
        ],
        nikto_findings=["Outdated Apache version detected"],
    )

def good_ai_json():
    return json.dumps({
        "risk_level":        "HIGH",
        "summary":           "Target has critical RCE via Apache CVE-2021-41773.",
        "critical_findings": ["Apache 2.4.52 RCE CVE-2021-41773"],
        "attack_vectors":    ["Path traversal to RCE on port 80"],
        "recommendations":   ["Upgrade Apache immediately","Disable directory listing"],
        "next_steps":        ["Exploit CVE-2021-41773","Check phpMyAdmin"],
    })


# ═══════════════════════════════════════════════
# PROVIDERS registry
# ═══════════════════════════════════════════════
class TestProviders:
    def test_four_providers(self):      assert len(PROVIDERS) == 4
    def test_groq_exists(self):         assert "groq"   in PROVIDERS
    def test_ollama_exists(self):       assert "ollama" in PROVIDERS
    def test_gemini_exists(self):       assert "gemini" in PROVIDERS
    def test_openai_exists(self):       assert "openai" in PROVIDERS

    def test_groq_has_url(self):        assert "url"     in PROVIDERS["groq"]
    def test_groq_has_model(self):      assert "model"   in PROVIDERS["groq"]
    def test_groq_has_env_key(self):    assert "env_key" in PROVIDERS["groq"]
    def test_groq_auth_bearer(self):    assert PROVIDERS["groq"]["auth"] == "bearer"
    def test_groq_format_openai(self):  assert PROVIDERS["groq"]["format"] == "openai"
    def test_groq_model_llama3(self):   assert "llama3" in PROVIDERS["groq"]["model"]
    def test_groq_env_key_name(self):   assert PROVIDERS["groq"]["env_key"] == "GROQ_API_KEY"
    def test_groq_url_contains_groq(self): assert "groq.com" in PROVIDERS["groq"]["url"]

    def test_ollama_auth_none(self):    assert PROVIDERS["ollama"]["auth"] == "none"
    def test_ollama_no_env_key(self):   assert PROVIDERS["ollama"]["env_key"] is None
    def test_ollama_local_url(self):    assert "localhost" in PROVIDERS["ollama"]["url"]
    def test_ollama_format_ollama(self):assert PROVIDERS["ollama"]["format"] == "ollama"

    def test_gemini_auth_query(self):   assert PROVIDERS["gemini"]["auth"] == "query"
    def test_gemini_env_key(self):      assert PROVIDERS["gemini"]["env_key"] == "GEMINI_API_KEY"
    def test_gemini_format(self):       assert PROVIDERS["gemini"]["format"] == "gemini"

    def test_openai_auth_bearer(self):  assert PROVIDERS["openai"]["auth"] == "bearer"
    def test_openai_model_mini(self):   assert "mini" in PROVIDERS["openai"]["model"]
    def test_openai_format_openai(self):assert PROVIDERS["openai"]["format"] == "openai"
    def test_openai_env_key(self):      assert PROVIDERS["openai"]["env_key"] == "OPENAI_API_KEY"


# ═══════════════════════════════════════════════
# AIAnalysis dataclass
# ═══════════════════════════════════════════════
class TestAIAnalysis:
    def _make(self, **kwargs):
        defaults = dict(provider="groq", model="llama3-70b-8192",
                        risk_level="HIGH", summary="Test summary",
                        critical_findings=["finding1"],
                        attack_vectors=["attack1"],
                        recommendations=["rec1"],
                        next_steps=["step1"],
                        raw_response='{"risk_level":"HIGH"}')
        defaults.update(kwargs)
        return AIAnalysis(**defaults)

    def test_construction(self):
        a = self._make()
        assert a.provider  == "groq"
        assert a.risk_level == "HIGH"

    def test_error_default_empty(self):
        assert self._make().error == ""

    def test_to_text_contains_provider(self):
        assert "groq" in self._make().to_text()

    def test_to_text_contains_risk(self):
        assert "HIGH" in self._make().to_text()

    def test_to_text_contains_summary(self):
        assert "Test summary" in self._make().to_text()

    def test_to_text_contains_critical_findings(self):
        assert "finding1" in self._make().to_text()

    def test_to_text_contains_attack_vectors(self):
        assert "attack1" in self._make().to_text()

    def test_to_text_contains_recommendations(self):
        assert "rec1" in self._make().to_text()

    def test_to_text_contains_next_steps(self):
        assert "step1" in self._make().to_text()

    def test_to_text_returns_string(self):
        assert isinstance(self._make().to_text(), str)

    def test_to_text_empty_lists(self):
        a = self._make(critical_findings=[], attack_vectors=[], recommendations=[], next_steps=[])
        text = a.to_text()
        assert isinstance(text, str)


# ═══════════════════════════════════════════════
# _build_prompt
# ═══════════════════════════════════════════════
class TestBuildPrompt:
    def test_returns_string(self):
        assert isinstance(_build_prompt(make_result()), str)

    def test_contains_target(self):
        assert "example.com" in _build_prompt(make_result())

    def test_contains_port_info(self):
        p = _build_prompt(make_result())
        assert "22" in p or "80" in p

    def test_contains_open_ports_section(self):
        p = _build_prompt(make_result())
        assert "OPEN PORTS" in p or "open" in p.lower()

    def test_contains_subdomains(self):
        p = _build_prompt(make_result())
        assert "www.example.com" in p or "SUBDOMAIN" in p

    def test_contains_vuln_findings(self):
        p = _build_prompt(make_result())
        assert "CVE-2021-41773" in p or "VULNERABILITY" in p or "RCE" in p

    def test_contains_web_findings(self):
        p = _build_prompt(make_result())
        assert "http://example.com" in p or "WEB" in p

    def test_contains_json_instruction(self):
        p = _build_prompt(make_result())
        assert "JSON" in p or "json" in p

    def test_contains_risk_level_instruction(self):
        p = _build_prompt(make_result())
        assert "risk_level" in p

    def test_caps_subdomains_at_20(self):
        r = make_result()
        r.subdomains = [f"sub{i}.example.com" for i in range(50)]
        p = _build_prompt(r)
        # Should not dump all 50 subdomains
        assert p.count(".example.com") <= 25  # 20 + some margin

    def test_empty_result_doesnt_crash(self):
        r = ReconResult(target="x.com", start_time="t")
        p = _build_prompt(r)
        assert isinstance(p, str) and len(p) > 0

    def test_nikto_findings_included(self):
        r = make_result()
        p = _build_prompt(r)
        assert "Outdated Apache" in p or "NIKTO" in p


# ═══════════════════════════════════════════════
# _extract_text
# ═══════════════════════════════════════════════
class TestExtractText:
    def test_openai_format(self):
        raw = {"choices":[{"message":{"content":"hello"}}]}
        assert _extract_text(raw, "openai") == "hello"

    def test_ollama_format(self):
        raw = {"message":{"content":"hello"}}
        assert _extract_text(raw, "ollama") == "hello"

    def test_gemini_format(self):
        raw = {"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}
        assert _extract_text(raw, "gemini") == "hello"

    def test_unknown_format_returns_str(self):
        result = _extract_text({"key":"val"}, "unknown")
        assert isinstance(result, str)


# ═══════════════════════════════════════════════
# run_ai_analysis (mocked)
# ═══════════════════════════════════════════════
class TestRunAiAnalysis:
    def _mock_post(self, text: str, fmt: str = "openai"):
        if fmt == "openai":
            return {"choices":[{"message":{"content": text}}]}
        if fmt == "ollama":
            return {"message":{"content": text}}
        if fmt == "gemini":
            return {"candidates":[{"content":{"parts":[{"text": text}]}}]}

    def test_unknown_provider_returns_error(self):
        r = run_ai_analysis(make_result(), provider="unknown_provider")
        assert r.risk_level == "ERROR"
        assert r.error != ""

    def test_missing_key_returns_error(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GROQ_API_KEY", None)
            r = run_ai_analysis(make_result(), provider="groq", api_key=None)
        assert r.risk_level == "ERROR"
        assert "key" in r.error.lower() or "key" in r.summary.lower() or r.error != ""

    def test_ollama_no_key_needed(self):
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(good_ai_json(), "ollama")):
            r = run_ai_analysis(make_result(), provider="ollama")
        assert r.risk_level == "HIGH"

    def test_successful_groq_call(self):
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(good_ai_json(), "openai")):
            r = run_ai_analysis(make_result(), provider="groq", api_key="gsk_test")
        assert r.risk_level    == "HIGH"
        assert r.summary       != ""
        assert r.provider      != ""
        assert isinstance(r.critical_findings, list)
        assert isinstance(r.recommendations,   list)

    def test_successful_gemini_call(self):
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(good_ai_json(), "gemini")):
            r = run_ai_analysis(make_result(), provider="gemini", api_key="AIza_test")
        assert r.risk_level == "HIGH"

    def test_json_wrapped_in_markdown(self):
        wrapped = f"```json\n{good_ai_json()}\n```"
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(wrapped, "openai")):
            r = run_ai_analysis(make_result(), provider="groq", api_key="test")
        assert r.risk_level == "HIGH"

    def test_invalid_json_response_still_returns(self):
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post("Not JSON at all, just prose.", "openai")):
            r = run_ai_analysis(make_result(), provider="groq", api_key="test")
        assert isinstance(r, AIAnalysis)
        assert r.risk_level in ("UNKNOWN","ERROR","HIGH","MEDIUM","LOW","CRITICAL","INFO")

    def test_http_error_returns_error_analysis(self):
        import urllib.error
        with patch("core.ai_analysis._post_json",
                   side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None)):
            r = run_ai_analysis(make_result(), provider="groq", api_key="bad_key")
        assert r.risk_level == "ERROR"

    def test_network_error_returns_error_analysis(self):
        with patch("core.ai_analysis._post_json", side_effect=Exception("Connection refused")):
            r = run_ai_analysis(make_result(), provider="groq", api_key="test")
        assert r.risk_level == "ERROR"

    def test_env_key_used_when_no_api_key_arg(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "env_key_value"}):
            with patch("core.ai_analysis._post_json",
                       return_value=self._mock_post(good_ai_json())) as mock:
                run_ai_analysis(make_result(), provider="groq")
        mock.assert_called_once()

    def test_explicit_key_overrides_env(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "env_key"}):
            with patch("core.ai_analysis._post_json",
                       return_value=self._mock_post(good_ai_json())) as mock:
                run_ai_analysis(make_result(), provider="groq", api_key="explicit_key")
        call_args = str(mock.call_args)
        assert "explicit_key" in call_args

    def test_custom_model_used(self):
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(good_ai_json())) as mock:
            r = run_ai_analysis(make_result(), provider="groq",
                                api_key="key", model="llama3-8b-8192")
        assert r.model == "llama3-8b-8192"

    def test_raw_response_stored(self):
        payload = good_ai_json()
        with patch("core.ai_analysis._post_json",
                   return_value=self._mock_post(payload)):
            r = run_ai_analysis(make_result(), provider="groq", api_key="key")
        assert r.raw_response != ""


# ═══════════════════════════════════════════════
# list_providers
# ═══════════════════════════════════════════════
class TestListProviders:
    def test_returns_string(self):  assert isinstance(list_providers(), str)
    def test_contains_groq(self):   assert "groq"   in list_providers()
    def test_contains_ollama(self): assert "ollama" in list_providers()
    def test_contains_gemini(self): assert "gemini" in list_providers()
    def test_contains_openai(self): assert "openai" in list_providers()
    def test_contains_flag_hint(self): assert "--ai-provider" in list_providers()
