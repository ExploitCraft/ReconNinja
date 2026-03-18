"""
core/ai_analysis.py
ReconNinja v3.3 — Groq AI Analysis Module (Optional)

Usage:
  python3 reconninja.py -t target.com --ai --ai-key YOUR_GROQ_KEY
  python3 reconninja.py -t target.com --ai --ai-key YOUR_GROQ_KEY --ai-provider groq

  Or set env var (keeps key out of shell history):
  export GROQ_API_KEY="gsk_xxxx"
  python3 reconninja.py -t target.com --ai

  Other providers:
  --ai-provider ollama    (local, free, no key needed)
  --ai-provider gemini    --ai-key YOUR_GEMINI_KEY
  --ai-provider openai    --ai-key YOUR_OPENAI_KEY
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass

from utils.logger import safe_print
from utils.models import ReconResult


# ── Provider registry ─────────────────────────────────────────────────────────

PROVIDERS: dict[str, dict] = {
    "groq": {
        "name":    "Groq (llama3-70b-8192) — FREE",
        "url":     "https://api.groq.com/openai/v1/chat/completions",
        "model":   "llama3-70b-8192",
        "env_key": "GROQ_API_KEY",
        "auth":    "bearer",           # Authorization: Bearer <key>
        "format":  "openai",
    },
    "ollama": {
        "name":    "Ollama (local, completely free)",
        "url":     "http://localhost:11434/api/chat",
        "model":   "llama3",
        "env_key": None,
        "auth":    "none",
        "format":  "ollama",
    },
    "gemini": {
        "name":    "Google Gemini Flash — FREE tier",
        "url":     "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
        "model":   "gemini-1.5-flash",
        "env_key": "GEMINI_API_KEY",
        "auth":    "query",            # ?key=<key> in URL
        "format":  "gemini",
    },
    "openai": {
        "name":    "OpenAI (gpt-4o-mini, cheap)",
        "url":     "https://api.openai.com/v1/chat/completions",
        "model":   "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "auth":    "bearer",
        "format":  "openai",
    },
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AIAnalysis:
    provider:          str
    model:             str
    risk_level:        str
    summary:           str
    critical_findings: list[str]
    attack_vectors:    list[str]
    recommendations:   list[str]
    next_steps:        list[str]
    raw_response:      str
    error:             str = ""

    def to_text(self) -> str:
        lines = [
            "=== ReconNinja AI Analysis (Groq/LLM) ===",
            f"Provider : {self.provider}",
            f"Model    : {self.model}",
            f"Risk     : {self.risk_level}",
            "",
            f"Summary:\n  {self.summary}",
            "",
        ]
        if self.critical_findings:
            lines.append("Critical Findings:")
            for f in self.critical_findings:
                lines.append(f"  ⚠  {f}")
            lines.append("")
        if self.attack_vectors:
            lines.append("Attack Vectors:")
            for v in self.attack_vectors:
                lines.append(f"  → {v}")
            lines.append("")
        if self.recommendations:
            lines.append("Recommendations (priority order):")
            for i, r in enumerate(self.recommendations, 1):
                lines.append(f"  {i}. {r}")
            lines.append("")
        if self.next_steps:
            lines.append("Suggested Next Steps:")
            for s in self.next_steps:
                lines.append(f"  • {s}")
        return "\n".join(lines)


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(result: ReconResult) -> str:
    lines: list[str] = [
        f"TARGET: {result.target}",
        f"SCAN TIME: {result.start_time} → {result.end_time or 'N/A'}",
        "",
    ]

    if result.hosts:
        lines.append("=== OPEN PORTS & SERVICES ===")
        for host in result.hosts:
            hn = ", ".join(host.hostnames) or host.ip
            os_str = f"  OS: {host.os_guess}" if host.os_guess else ""
            lines.append(f"Host: {hn}{os_str}")
            for p in host.open_ports:
                svc = " ".join(filter(None, [p.service, p.product, p.version]))
                lines.append(f"  {p.port}/{p.protocol}  {p.state}  {svc or '?'}")
        lines.append("")

    if result.subdomains:
        lines.append(f"=== SUBDOMAINS ({len(result.subdomains)}) ===")
        for s in result.subdomains[:20]:
            lines.append(f"  {s}")
        if len(result.subdomains) > 20:
            lines.append(f"  ... and {len(result.subdomains)-20} more")
        lines.append("")

    if result.web_findings:
        lines.append(f"=== WEB SERVICES ({len(result.web_findings)}) ===")
        for wf in result.web_findings[:10]:
            tech = ", ".join(wf.technologies) if wf.technologies else "unknown"
            lines.append(f"  [{wf.status_code}] {wf.url}  |  {wf.title or '?'}  |  {tech}")
        lines.append("")

    if result.nuclei_findings:
        lines.append(f"=== VULNERABILITY FINDINGS ({len(result.nuclei_findings)}) ===")
        sevorder = ["critical","high","medium","low","info"]
        for vf in sorted(result.nuclei_findings,
                         key=lambda x: sevorder.index(x.severity) if x.severity in sevorder else 99):
            cve = f" [{vf.cve}]" if vf.cve else ""
            lines.append(f"  [{vf.severity.upper()}]{cve} {vf.title} — {vf.target}")
        lines.append("")

    if result.nikto_findings:
        lines.append("=== NIKTO FINDINGS ===")
        for nf in result.nikto_findings[:10]:
            lines.append(f"  {nf}")
        lines.append("")

    scan_data = "\n".join(lines)

    return f"""You are an expert penetration tester and security analyst.
Analyse the following recon scan results and provide a structured security assessment.

{scan_data}

Respond ONLY with a valid JSON object using exactly this structure (no markdown, no backticks):
{{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence plain English overview of the security posture",
  "critical_findings": ["most dangerous finding 1", "finding 2"],
  "attack_vectors": ["specific attack path 1", "attack path 2"],
  "recommendations": ["highest priority fix 1", "fix 2", "fix 3"],
  "next_steps": ["suggested next recon or exploit step 1", "step 2"]
}}

Be specific. Reference actual ports, services, versions, and CVEs found."""


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _post_json(url: str, payload: dict, headers: dict, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _extract_text(raw: dict, fmt: str) -> str:
    if fmt == "openai":
        return raw["choices"][0]["message"]["content"]
    if fmt == "ollama":
        return raw["message"]["content"]
    if fmt == "gemini":
        return raw["candidates"][0]["content"]["parts"][0]["text"]
    return str(raw)


# ── Main entry point ──────────────────────────────────────────────────────────

def run_ai_analysis(
    result:   ReconResult,
    provider: str = "groq",
    api_key:  str | None = None,
    model:    str | None = None,
    timeout:  int = 60,
) -> AIAnalysis:
    """
    Run AI analysis on scan results.

    Args:
        result:   completed ReconResult from orchestrator
        provider: "groq" | "ollama" | "gemini" | "openai"
        api_key:  API key (or None to read from env var)
        model:    override default model for this provider
        timeout:  HTTP timeout in seconds
    """

    if provider not in PROVIDERS:
        return AIAnalysis(
            provider=provider, model="?", risk_level="ERROR",
            summary=f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}",
            critical_findings=[], attack_vectors=[],
            recommendations=[], next_steps=[], raw_response="",
            error=f"Unknown provider: {provider}",
        )

    prov   = PROVIDERS[provider]
    mdl    = model or prov["model"]
    fmt    = prov["format"]
    url    = prov["url"]
    auth   = prov["auth"]

    # Resolve API key
    key = api_key or (os.environ.get(prov["env_key"]) if prov["env_key"] else None)
    if auth != "none" and not key:
        env_hint = prov.get("env_key", "N/A")
        return AIAnalysis(
            provider=prov["name"], model=mdl, risk_level="ERROR",
            summary=f"No API key provided for {provider}.",
            critical_findings=[],
            attack_vectors=[],
            recommendations=[
                f"Pass --ai-key YOUR_KEY or set env var: export {env_hint}=YOUR_KEY"
            ],
            next_steps=[], raw_response="",
            error="Missing API key",
        )

    safe_print(f"[info]🤖 AI Analysis — {prov['name']} ({mdl})[/]")

    prompt = _build_prompt(result)

    # Build request
    headers = {"Content-Type": "application/json"}

    if auth == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    elif auth == "query":
        url = f"{url}?key={key}"

    # Build payload per format
    if fmt == "openai":
        payload = {
            "model": mdl,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1500,
        }
    elif fmt == "ollama":
        payload = {
            "model": mdl,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    elif fmt == "gemini":
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1500},
        }
    else:
        payload = {}

    # Call API
    try:
        raw_resp = _post_json(url, payload, headers, timeout)
        text = _extract_text(raw_resp, fmt)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        err  = f"HTTP {e.code}: {body}"
        safe_print(f"[danger]AI API error: {err}[/]")
        return AIAnalysis(
            provider=prov["name"], model=mdl, risk_level="ERROR",
            summary=f"API call failed: {err}",
            critical_findings=[], attack_vectors=[],
            recommendations=[], next_steps=[], raw_response="",
            error=err,
        )
    except Exception as e:
        err = str(e)
        safe_print(f"[danger]AI error: {err}[/]")
        return AIAnalysis(
            provider=prov["name"], model=mdl, risk_level="ERROR",
            summary=f"Unexpected error: {err}",
            critical_findings=[], attack_vectors=[],
            recommendations=[], next_steps=[], raw_response="",
            error=err,
        )

    # Parse JSON from model response
    try:
        clean = text.strip()
        # Strip markdown code fences if model wraps in ```json ... ```
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        parsed = json.loads(clean.strip())

        return AIAnalysis(
            provider          = prov["name"],
            model             = mdl,
            risk_level        = parsed.get("risk_level", "UNKNOWN"),
            summary           = parsed.get("summary", ""),
            critical_findings = parsed.get("critical_findings", []),
            attack_vectors    = parsed.get("attack_vectors", []),
            recommendations   = parsed.get("recommendations", []),
            next_steps        = parsed.get("next_steps", []),
            raw_response      = text,
        )
    except json.JSONDecodeError:
        # Model returned prose instead of JSON — use raw text as summary
        return AIAnalysis(
            provider=prov["name"], model=mdl, risk_level="UNKNOWN",
            summary=text[:500],
            critical_findings=[], attack_vectors=[],
            recommendations=[], next_steps=[], raw_response=text,
            error="Could not parse JSON from model response",
        )


def list_providers() -> str:
    lines = ["Available AI providers:"]
    for key, p in PROVIDERS.items():
        free = " [FREE]" if p.get("free") else ""
        env  = f"  env: {p['env_key']}" if p["env_key"] else "  no key needed"
        lines.append(f"  --ai-provider {key:<10} {p['name']}{free}")
        lines.append(f"               {env}")
    return "\n".join(lines)
