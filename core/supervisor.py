"""
ReconNinja v9 — SupervisorAgent
LLM-driven orchestration layer.

The supervisor reads intermediate ReconResult state after each phase and decides:
  - Which phases to run next (adaptive routing)
  - Whether a finding warrants immediate follow-up (e.g. port 389 → trigger ldap_enum)
  - When to raise an approval gate for the operator
  - When to stop (budget exhausted, diminishing returns)

Supports: groq, openai, ollama, gemini — same providers as v8 ai_config.
Falls back to rule-based routing if no LLM key / provider configured.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from typing import Any, Callable

from utils.logger import log, safe_print
from utils.models import ReconResult, ScanConfig


# ─── Rule-based trigger map (used as fallback and to seed the LLM prompt) ─────

PORT_TRIGGERS: dict[int, list[str]] = {
    389:   ["ldap_enum"],
    636:   ["ldap_enum"],
    445:   ["smb_scan"],
    88:    ["ad_recon"],
    3306:  ["db_exposure"],
    5432:  ["db_exposure"],
    27017: ["db_exposure"],
    6379:  ["db_exposure"],
    9200:  ["db_exposure"],
    2375:  ["container_deep"],
    2376:  ["container_deep"],
    10250: ["container_deep"],
    2379:  ["container_deep"],
    8080:  ["httpx", "api_fuzz"],
    443:   ["httpx", "ssl"],
    80:    ["httpx"],
    11434: ["llm_recon"],   # Ollama default port
    6333:  ["llm_recon"],   # Qdrant
    8000:  ["llm_recon"],   # Chroma
    502:   ["iot_scan"],    # Modbus
    47808: ["iot_scan"],    # BACnet
    44818: ["iot_scan"],    # EtherNet/IP
}

FINDING_TRIGGERS: dict[str, list[str]] = {
    "kerberos":         ["ad_recon"],
    "active directory": ["ad_recon"],
    "s3":               ["cloud_deep"],
    "azure":            ["cloud_deep"],
    "gcp":              ["cloud_deep"],
    "jwt":              ["jwt_scan"],
    "graphql":          ["graphql"],
    "cors":             ["cors"],
    "dockerfile":       ["container_deep"],
    "kubernetes":       ["container_deep"],
    ".git":             ["github_osint"],
    "oauth":            ["oauth_scan"],
    "openapi":          ["api_fuzz"],
}


# ─── SupervisorAgent ──────────────────────────────────────────────────────────

class SupervisorAgent:
    """
    Adaptive scan orchestrator.

    In agent_mode, after each phase the supervisor:
      1. Inspects new findings via rule-based triggers (fast, free)
      2. Optionally consults the LLM for deeper reasoning (budget-controlled)
      3. Returns a list of phase_ids to enqueue next

    With classic_mode=True, the supervisor is a no-op (v8 sequential behaviour).
    """

    def __init__(self, cfg: ScanConfig) -> None:
        self._cfg = cfg
        self._calls_made = 0
        self._lock = threading.Lock()
        self._approval_event: threading.Event | None = None
        if cfg.require_approval:
            self._approval_event = threading.Event()
        self._llm_available = bool(cfg.ai_config.get("key") or cfg.ai_provider == "ollama")

    # ── Public API ────────────────────────────────────────────────────────────

    def decide_next_phases(
        self,
        completed_phase: str,
        result: ReconResult,
        already_queued: set[str],
    ) -> list[str]:
        """
        Called after `completed_phase` finishes.
        Returns list of new phase_ids to enqueue (not already queued).
        """
        if self._cfg.classic_mode:
            return []

        candidates: set[str] = set()

        # Rule-based: port triggers
        for host in result.hosts:
            for port in host.open_ports:
                for phase in PORT_TRIGGERS.get(port.port, []):
                    candidates.add(phase)

        # Rule-based: finding keyword triggers
        all_text = self._extract_finding_text(result).lower()
        for keyword, phases in FINDING_TRIGGERS.items():
            if keyword in all_text:
                candidates.update(phases)

        # LLM reasoning (budget-controlled)
        if self._llm_available and self._calls_made < self._cfg.agent_budget:
            llm_candidates = self._consult_llm(completed_phase, result, candidates)
            candidates.update(llm_candidates)

        new_phases = [p for p in candidates if p not in already_queued]

        if new_phases and self._cfg.require_approval:
            new_phases = self._gate_approval(new_phases)

        return new_phases

    def summarise_plan(self, result: ReconResult) -> str:
        """Return a short text summary of what the supervisor plans to run."""
        open_ports = [p.port for h in result.hosts for p in h.open_ports]
        triggered = set()
        for port in open_ports:
            triggered.update(PORT_TRIGGERS.get(port, []))
        if triggered:
            return f"[supervisor] Rule-based triggers from open ports: {', '.join(sorted(triggered))}"
        return "[supervisor] No additional phases triggered by current findings."

    # ── LLM consultation ──────────────────────────────────────────────────────

    def _consult_llm(
        self,
        completed_phase: str,
        result: ReconResult,
        rule_candidates: set[str],
    ) -> list[str]:
        """Ask the configured LLM which additional phases to run."""
        with self._lock:
            if self._calls_made >= self._cfg.agent_budget:
                return []
            self._calls_made += 1

        prompt = self._build_prompt(completed_phase, result, rule_candidates)
        response_text = self._call_llm(prompt)
        return self._parse_llm_response(response_text)

    def _build_prompt(self, completed_phase: str, result: ReconResult, rule_candidates: set[str]) -> str:
        open_ports = [p.port for h in result.hosts for p in h.open_ports]
        subdomains = result.subdomains[:20]
        findings_summary = self._extract_finding_text(result)[:1500]
        available_phases = [
            "ad_recon", "cloud_deep", "llm_recon", "iot_scan", "container_deep",
            "wireless_osint", "darkweb_osint", "cors", "jwt_scan", "graphql",
            "api_fuzz", "oauth_scan", "web_vulns", "db_exposure", "devops_scan",
            "ldap_enum", "smtp_enum", "snmp_scan", "nuclei", "shodan", "censys",
        ]
        return f"""You are the ReconNinja v9 supervisor agent for an authorized penetration test.

Completed phase: {completed_phase}
Target: {result.target}
Open ports discovered: {open_ports}
Subdomains: {subdomains}
Current findings summary (truncated):
{findings_summary}

Rule-based triggers already identified: {sorted(rule_candidates)}

Available phases to run: {available_phases}

Based on the findings so far, which additional phases (if any) should be run next?
Consider attack surface breadth and severity of findings.
Reply ONLY with a JSON array of phase_id strings. Example: ["ad_recon", "cloud_deep"]
If no additional phases are needed, reply: []"""

    def _call_llm(self, prompt: str) -> str:
        cfg = self._cfg.ai_config
        provider = cfg.get("provider", self._cfg.ai_provider)
        key = cfg.get("key", self._cfg.ai_key)
        model = cfg.get("model", self._cfg.ai_model)

        try:
            if provider == "ollama":
                return self._call_ollama(prompt, model or "qwen3:8b")
            elif provider == "groq":
                return self._call_groq(prompt, key, model or "llama3-8b-8192")
            elif provider == "openai":
                return self._call_openai(prompt, key, model or "gpt-4o-mini")
            elif provider in ("gemini", "google"):
                return self._call_gemini(prompt, key, model or "gemini-1.5-flash")
        except Exception as e:
            log.warning(f"[supervisor] LLM call failed: {e}")
        return "[]"

    def _call_ollama(self, prompt: str, model: str) -> str:
        import requests
        resp = requests.post(
            f"{self._cfg.local_llm_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=60,
        )
        return resp.json().get("response", "[]")

    def _call_groq(self, prompt: str, key: str, model: str) -> str:
        import requests
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 200, "temperature": 0.1},
            timeout=30,
        )
        return resp.json()["choices"][0]["message"]["content"]

    def _call_openai(self, prompt: str, key: str, model: str) -> str:
        import requests
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 200, "temperature": 0.1},
            timeout=30,
        )
        return resp.json()["choices"][0]["message"]["content"]

    def _call_gemini(self, prompt: str, key: str, model: str) -> str:
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    def _parse_llm_response(self, text: str) -> list[str]:
        text = text.strip()
        # Extract JSON array from response
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            phases = json.loads(text[start:end + 1])
            return [p for p in phases if isinstance(p, str)]
        except json.JSONDecodeError:
            return []

    # ── Approval gate ─────────────────────────────────────────────────────────

    def _gate_approval(self, phases: list[str]) -> list[str]:
        """Pause and ask the operator to approve the next phases."""
        safe_print(f"\n[warning]⚠  Supervisor wants to run: {phases}[/]")
        safe_print("[info]Press ENTER to approve, or type phase names to skip (comma-separated):[/]")
        try:
            response = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return []
        if not response:
            return phases
        skip = {s.strip() for s in response.split(",")}
        return [p for p in phases if p not in skip]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_finding_text(result: ReconResult) -> str:
        parts = []
        for vf in result.nuclei_findings[:30]:
            parts.append(f"{vf.severity}: {vf.title} @ {vf.target}")
        for host in result.hosts[:10]:
            for port in host.open_ports[:20]:
                parts.append(f"{host.ip}:{port.port} {port.service} {port.product}")
        parts.extend(result.subdomains[:20])
        return "\n".join(parts)

    @property
    def calls_made(self) -> int:
        return self._calls_made

    @property
    def budget_remaining(self) -> int:
        return max(0, self._cfg.agent_budget - self._calls_made)
