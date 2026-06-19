"""
ReconNinja v9 — LLM/AI Surface Recon  (--llm-recon)
Discovers exposed AI endpoints: Ollama, LocalAI, OpenWebUI, vector DBs,
MCP servers, agent frameworks, AI gateway fingerprinting.
"""
from __future__ import annotations

from pathlib import Path
import requests

from utils.logger import log, safe_print
from utils.models import LLMSurface, ReconResult, ScanConfig, HostResult


def llm_recon_scan(target: str, result: ReconResult, cfg: ScanConfig, out_folder: Path) -> list[LLMSurface]:
    surfaces: list[LLMSurface] = []
    safe_print("[module]🤖  LLM/AI Surface Recon...[/]")

    # Ports and endpoints to probe
    checks = [
        # (port, path, surface_type, description)
        (11434, "/api/tags",         "ollama",          "Ollama API — unauthenticated model list"),
        (11434, "/api/version",      "ollama",          "Ollama version endpoint"),
        (8080,  "/",                 "openwebui",        "Possible OpenWebUI instance"),
        (3000,  "/api/config",       "openwebui",        "OpenWebUI config endpoint"),
        (1234,  "/v1/models",        "lm_studio",        "LM Studio OpenAI-compat API"),
        (8000,  "/api/v1/collections","vectordb",        "Chroma vector DB collections"),
        (6333,  "/collections",      "vectordb",        "Qdrant vector DB collections"),
        (8080,  "/v1/schema",        "vectordb",        "Weaviate schema endpoint"),
        (8765,  "/",                 "mcp",             "Possible MCP server"),
        (4000,  "/v1/models",        "ai_gateway",      "LiteLLM proxy models endpoint"),
        (8080,  "/api/tags",         "ollama",          "Ollama on alt port 8080"),
    ]

    hosts_to_probe = [target] + [h.ip for h in result.hosts[:10]]

    for host in hosts_to_probe:
        for port, path, stype, desc in checks:
            url = f"http://{host}:{port}{path}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=False)
                if resp.status_code in (200, 401, 403):
                    auth_bypass = resp.status_code == 200 and stype in ("ollama", "vectordb", "mcp")
                    sev = "critical" if auth_bypass else "high"
                    surfaces.append(LLMSurface(
                        surface_type=stype,
                        url=url,
                        severity=sev,
                        detail=desc + (f" — unauthenticated access confirmed" if auth_bypass else ""),
                        auth_bypass=auth_bypass,
                    ))
            except Exception:
                pass

    # Prompt injection surface discovery in web findings
    for wf in result.web_findings:
        for pattern in ["/api/chat", "/v1/completions", "/v1/chat/completions",
                        "/ask", "/query", "/generate", "/api/generate"]:
            if pattern in wf.url:
                surfaces.append(LLMSurface(
                    surface_type="prompt_injection",
                    url=wf.url,
                    severity="medium",
                    detail=f"Potential AI inference endpoint detected: {wf.url}",
                ))

    result.llm_surfaces.extend(surfaces)
    safe_print(f"[success]  ✔ LLM recon: {len(surfaces)} surfaces found[/]")
    return surfaces
