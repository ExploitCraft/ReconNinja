"""
core/ai_enhanced.py — ReconNinja v8.0.0
Enhanced AI Analysis — multi-model consensus, attack path generation,
and per-finding remediation with CVSSv3 scoring.

Extends the existing ai_analysis.py with three new capabilities:
  1. --ai-consensus  : run 2+ AI providers, merge & flag disagreements
  2. --attack-paths  : chain findings into kill-chain narratives
  3. --ai-remediate  : per-finding fix suggestions + CVSSv3 score
"""
from __future__ import annotations
import json, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from utils.logger import safe_print
from utils.models import ReconResult

# ── CVSS v3.1 base score calculator (simplified AV:N/AC:L vectors) ────────────

CVSS_SEVERITY_MAP = {
    "critical": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "high":     {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "medium":   {"AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "low":      {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
}

CVSS_BASE_SCORES = {
    "critical": 9.8, "high": 8.1, "medium": 5.3, "low": 2.1,
}

def _cvss_vector(severity: str) -> str:
    v = CVSS_SEVERITY_MAP.get(severity, CVSS_SEVERITY_MAP["medium"])
    return (f"CVSS:3.1/AV:{v['AV']}/AC:{v['AC']}/PR:{v['PR']}/UI:{v['UI']}"
            f"/S:{v['S']}/C:{v['C']}/I:{v['I']}/A:{v['A']}")


@dataclass
class AttackPath:
    title: str
    steps: list[str]
    severity: str
    prerequisites: list[str] = field(default_factory=list)
    mitre_ttps: list[str] = field(default_factory=list)


@dataclass
class RemediationAdvice:
    finding_title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    short_fix: str
    detailed_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    effort: str = "medium"   # low / medium / high


@dataclass
class AIEnhancedResult:
    target: str
    consensus_summary: str = ""
    model_responses: dict[str, str] = field(default_factory=dict)
    disagreements: list[str] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    remediations: list[RemediationAdvice] = field(default_factory=list)


# ── provider helpers ───────────────────────────────────────────────────────────

def _call_groq(prompt: str, api_key: str, model: str = "llama3-70b-8192",
               max_tokens: int = 1500) -> str:
    try:
        import groq
        client = groq.Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        return f"[Groq error: {e}]"


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini",
                 max_tokens: int = 1500) -> str:
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        return f"[OpenAI error: {e}]"


def _call_gemini(prompt: str, api_key: str, max_tokens: int = 1500) -> str:
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        resp = model.generate_content(
            prompt,
            generation_config={"max_output_tokens": max_tokens, "temperature": 0.2},
        )
        return resp.text or ""
    except Exception as e:
        return f"[Gemini error: {e}]"


def _call_ollama(prompt: str, model: str = "llama3", max_tokens: int = 1500) -> str:
    try:
        import urllib.request, json as _json
        payload = _json.dumps({"model": model, "prompt": prompt,
                               "stream": False, "options": {"num_predict": max_tokens}}).encode()
        req = urllib.request.Request("http://localhost:11434/api/generate",
                                     data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=60) as r:
            data = _json.loads(r.read().decode())
            return data.get("response", "")
    except Exception as e:
        return f"[Ollama error: {e}]"


# ── consensus ─────────────────────────────────────────────────────────────────

def run_consensus(result: ReconResult, ai_config: dict, out_folder: Path) -> AIEnhancedResult:
    """
    Run the same analysis prompt across multiple AI providers,
    then synthesize a consensus summary and flag disagreements.
    """
    ai_result = AIEnhancedResult(target=result.target)
    findings_summary = _build_findings_summary(result)

    prompt = f"""You are a senior penetration tester reviewing a recon report.
Target: {result.target}

FINDINGS:
{findings_summary}

Provide:
1. A 3-sentence executive summary of the risk posture
2. The top 3 most critical issues to address immediately
3. Overall risk rating (Critical/High/Medium/Low) with one-line justification

Be concise and specific. No generic advice."""

    providers_run = []

    if api_key := ai_config.get("groq_api_key"):
        safe_print("  [dim]AI Consensus: querying Groq...[/]")
        response = _call_groq(prompt, api_key)
        ai_result.model_responses["groq"] = response
        providers_run.append("groq")

    if api_key := ai_config.get("openai_api_key"):
        safe_print("  [dim]AI Consensus: querying OpenAI...[/]")
        response = _call_openai(prompt, api_key)
        ai_result.model_responses["openai"] = response
        providers_run.append("openai")

    if api_key := ai_config.get("gemini_api_key"):
        safe_print("  [dim]AI Consensus: querying Gemini...[/]")
        response = _call_gemini(prompt, api_key)
        ai_result.model_responses["gemini"] = response
        providers_run.append("gemini")

    if ai_config.get("use_ollama"):
        safe_print("  [dim]AI Consensus: querying Ollama...[/]")
        response = _call_ollama(prompt, ai_config.get("ollama_model", "llama3"))
        ai_result.model_responses["ollama"] = response
        providers_run.append("ollama")

    if not providers_run:
        safe_print("  [dim]AI Consensus: no AI providers configured[/]")
        return ai_result

    # Build consensus: if multiple providers, find common themes
    if len(providers_run) > 1:
        all_text = "\n---\n".join(ai_result.model_responses.values())
        consensus_prompt = f"""You received these security assessments from {len(providers_run)} AI models:

{all_text}

1. Identify points ALL models AGREE on (consensus findings)
2. Identify any CONTRADICTIONS or DISAGREEMENTS between the models
3. Write a 4-sentence final consensus summary

Format:
CONSENSUS:
<summary>

DISAGREEMENTS:
<list or "None">"""

        # Use whichever provider is available for synthesis
        if "groq" in providers_run:
            synthesis = _call_groq(consensus_prompt, ai_config["groq_api_key"], max_tokens=800)
        elif "openai" in providers_run:
            synthesis = _call_openai(consensus_prompt, ai_config["openai_api_key"], max_tokens=800)
        else:
            synthesis = all_text[:500]

        ai_result.consensus_summary = synthesis
        # Extract disagreements
        if "DISAGREEMENTS:" in synthesis:
            disag_section = synthesis.split("DISAGREEMENTS:")[-1].strip()
            if disag_section.lower() not in ("none", "none.", ""):
                ai_result.disagreements = [disag_section[:500]]
    else:
        ai_result.consensus_summary = list(ai_result.model_responses.values())[0]

    # Save
    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# AI Consensus Analysis — {result.target}\n\n",
             f"Providers: {', '.join(providers_run)}\n\n",
             "## Consensus Summary\n", ai_result.consensus_summary, "\n\n"]
    if ai_result.disagreements:
        lines.append("## Model Disagreements\n")
        for d in ai_result.disagreements:
            lines.append(f"  {d}\n")
    lines.append("\n## Individual Model Responses\n")
    for provider, resp in ai_result.model_responses.items():
        lines.append(f"\n### {provider.capitalize()}\n{resp}\n")
    (out_folder / "ai_consensus.txt").write_text("".join(lines), encoding="utf-8")

    safe_print(f"  [success]✓ AI Consensus: {len(providers_run)} models queried[/]")
    return ai_result


# ── attack path generator ─────────────────────────────────────────────────────

def generate_attack_paths(result: ReconResult, ai_config: dict,
                          out_folder: Path) -> list[AttackPath]:
    """Chain findings into MITRE ATT&CK kill-chain attack path narratives."""
    findings_summary = _build_findings_summary(result)
    prompt = f"""You are a red team operator. Given these reconnaissance findings for {result.target}:

{findings_summary}

Generate up to 3 realistic attack paths an attacker could follow.
For each path output EXACTLY this format:

ATTACK PATH: <short title>
SEVERITY: critical|high|medium
PREREQUISITES: <comma-separated list>
MITRE TTPs: <T1234, T5678, ...>
STEPS:
1. <step>
2. <step>
3. <step>
---"""

    response = ""
    if api_key := ai_config.get("groq_api_key"):
        response = _call_groq(prompt, api_key, max_tokens=1200)
    elif api_key := ai_config.get("openai_api_key"):
        response = _call_openai(prompt, api_key, max_tokens=1200)
    elif api_key := ai_config.get("gemini_api_key"):
        response = _call_gemini(prompt, api_key, max_tokens=1200)
    elif ai_config.get("use_ollama"):
        response = _call_ollama(prompt, ai_config.get("ollama_model", "llama3"))

    paths = []
    if not response or response.startswith("["):
        return paths

    # Parse structured response
    for block in response.split("---"):
        block = block.strip()
        if not block or "ATTACK PATH:" not in block:
            continue
        ap = AttackPath(title="", steps=[], severity="high")
        for line in block.splitlines():
            if line.startswith("ATTACK PATH:"):
                ap.title = line.split(":", 1)[1].strip()
            elif line.startswith("SEVERITY:"):
                ap.severity = line.split(":", 1)[1].strip().lower()
            elif line.startswith("PREREQUISITES:"):
                ap.prerequisites = [p.strip() for p in line.split(":", 1)[1].split(",")]
            elif line.startswith("MITRE TTPs:"):
                ap.mitre_ttps = [t.strip() for t in line.split(":", 1)[1].split(",")]
            elif line and line[0].isdigit() and ". " in line:
                ap.steps.append(line.split(". ", 1)[1].strip())
        if ap.title and ap.steps:
            paths.append(ap)

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# Attack Paths — {result.target}\n\n"]
    for i, ap in enumerate(paths, 1):
        lines.append(f"## Path {i}: {ap.title}\n")
        lines.append(f"Severity: {ap.severity.upper()}\n")
        if ap.mitre_ttps:
            lines.append(f"MITRE TTPs: {', '.join(ap.mitre_ttps)}\n")
        if ap.prerequisites:
            lines.append(f"Prerequisites: {', '.join(ap.prerequisites)}\n")
        lines.append("Steps:\n")
        for j, step in enumerate(ap.steps, 1):
            lines.append(f"  {j}. {step}\n")
        lines.append("\n")
    (out_folder / "attack_paths.txt").write_text("".join(lines), encoding="utf-8")

    safe_print(f"  [success]✓ Attack Paths: {len(paths)} generated[/]")
    return paths


# ── remediation engine ────────────────────────────────────────────────────────

def generate_remediations(result: ReconResult, ai_config: dict,
                          out_folder: Path) -> list[RemediationAdvice]:
    """Generate per-finding remediation steps with CVSSv3 scoring."""
    remediations = []
    # Collect all findings across result
    findings = _collect_all_findings(result)

    if not findings:
        return remediations

    # Batch up to 10 findings per AI call
    batch = findings[:10]
    findings_text = "\n".join(
        f"- [{f.get('severity','medium').upper()}] {f.get('title', f.get('issue', 'Unknown'))}: "
        f"{f.get('detail', f.get('description',''))[:150]}"
        for f in batch
    )

    prompt = f"""For each security finding below, provide remediation advice.
For each finding output EXACTLY:

FINDING: <title>
FIX: <one sentence fix>
STEPS: <step1> | <step2> | <step3>
EFFORT: low|medium|high
REFS: <CVE or URL if applicable, else none>
---

Findings:
{findings_text}"""

    response = ""
    if api_key := ai_config.get("groq_api_key"):
        response = _call_groq(prompt, api_key, max_tokens=2000)
    elif api_key := ai_config.get("openai_api_key"):
        response = _call_openai(prompt, api_key, max_tokens=2000)
    elif api_key := ai_config.get("gemini_api_key"):
        response = _call_gemini(prompt, api_key, max_tokens=2000)
    elif ai_config.get("use_ollama"):
        response = _call_ollama(prompt, ai_config.get("ollama_model", "llama3"), max_tokens=2000)

    if response and not response.startswith("["):
        for block in response.split("---"):
            block = block.strip()
            if "FINDING:" not in block:
                continue
            ra = RemediationAdvice(
                finding_title="", severity="medium",
                cvss_score=5.3, cvss_vector="",
                short_fix="",
            )
            for line in block.splitlines():
                if line.startswith("FINDING:"):
                    ra.finding_title = line.split(":", 1)[1].strip()
                elif line.startswith("FIX:"):
                    ra.short_fix = line.split(":", 1)[1].strip()
                elif line.startswith("STEPS:"):
                    ra.detailed_steps = [s.strip() for s in line.split(":", 1)[1].split("|")]
                elif line.startswith("EFFORT:"):
                    ra.effort = line.split(":", 1)[1].strip().lower()
                elif line.startswith("REFS:"):
                    refs = line.split(":", 1)[1].strip()
                    if refs.lower() != "none":
                        ra.references = [refs]
            if ra.finding_title and ra.short_fix:
                # Match severity from original findings
                for f in batch:
                    title = f.get("title", f.get("issue", ""))
                    if ra.finding_title.lower() in title.lower() or title.lower() in ra.finding_title.lower():
                        ra.severity = f.get("severity", "medium")
                        break
                ra.cvss_score = CVSS_BASE_SCORES.get(ra.severity, 5.3)
                ra.cvss_vector = _cvss_vector(ra.severity)
                remediations.append(ra)

    # Always generate CVSS scores even without AI
    if not remediations:
        for f in batch:
            sev = f.get("severity", "medium")
            remediations.append(RemediationAdvice(
                finding_title=f.get("title", f.get("issue", "Finding")),
                severity=sev,
                cvss_score=CVSS_BASE_SCORES.get(sev, 5.3),
                cvss_vector=_cvss_vector(sev),
                short_fix="Review and remediate per vendor guidance.",
                detailed_steps=["Review finding", "Apply patch or configuration fix",
                                 "Re-test to confirm remediation"],
            ))

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# AI Remediation Report — {result.target}\n\n"]
    for r in remediations:
        lines.append(f"## {r.finding_title}\n")
        lines.append(f"Severity: {r.severity.upper()}  CVSS: {r.cvss_score}\n")
        lines.append(f"Vector:   {r.cvss_vector}\n")
        lines.append(f"Fix:      {r.short_fix}\n")
        if r.detailed_steps:
            lines.append("Steps:\n")
            for step in r.detailed_steps:
                lines.append(f"  - {step}\n")
        lines.append(f"Effort:   {r.effort}\n")
        if r.references:
            lines.append(f"Refs:     {', '.join(r.references)}\n")
        lines.append("\n")
    (out_folder / "ai_remediation.txt").write_text("".join(lines), encoding="utf-8")

    safe_print(f"  [success]✓ AI Remediation: {len(remediations)} finding remediations generated[/]")
    return remediations


# ── internal helpers ──────────────────────────────────────────────────────────

def _build_findings_summary(result: ReconResult) -> str:
    lines = []
    if result.vuln_findings:
        lines.append(f"Vulnerabilities ({len(result.vuln_findings)}):")
        for vf in result.vuln_findings[:15]:
            lines.append(f"  [{vf.severity.upper()}] {vf.title}: {vf.details[:100]}")
    if result.open_ports:
        port_list = [f"{p.port}/{p.protocol}" for p in result.open_ports[:20]]
        lines.append(f"Open ports: {', '.join(port_list)}")
    if result.subdomains:
        lines.append(f"Subdomains ({len(result.subdomains)}): {', '.join(list(result.subdomains)[:10])}")
    return "\n".join(lines) if lines else "No findings collected yet."


def _collect_all_findings(result: ReconResult) -> list[dict]:
    findings = []
    for vf in result.vuln_findings:
        findings.append({
            "title": vf.title,
            "severity": vf.severity,
            "detail": vf.details,
        })
    # Add port-based findings
    for port in result.open_ports:
        if port.severity in ("critical", "high"):
            findings.append({
                "title": f"Open {port.service} port {port.port}",
                "severity": port.severity,
                "detail": port.banner[:100] if port.banner else "",
            })
    return findings
