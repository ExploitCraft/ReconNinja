"""
ReconNinja v9 — Agentic Correlation Pipeline
CorrelationAgent → HypothesisAgent → ReportAgent

CorrelationAgent:  reads ReconResult + ReconGraph, groups findings by host/service/severity
HypothesisAgent:   queries LLM to generate AttackChain objects with MITRE TTPs
ReportAgent:       assembles executive summary, narrative, and remediation plan

All three agents gracefully degrade to rule-based logic when no LLM is configured.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any

import requests

from utils.logger import log, safe_print
from utils.models import AttackChain, ReconResult, ScanConfig, VulnFinding


# ─── MITRE TTP keyword map ────────────────────────────────────────────────────

MITRE_KEYWORDS: dict[str, list[str]] = {
    "T1190": ["web vuln", "rce", "sql injection", "command injection", "xss", "exposed api"],
    "T1133": ["vpn", "rdp", "ssh", "remote access", "exposed service"],
    "T1110": ["brute force", "password spray", "credential stuffing"],
    "T1078": ["default credentials", "weak password", "valid accounts"],
    "T1213": ["s3", "bucket", "blob", "gcs", "exposed storage"],
    "T1552": ["secret", "key", "token", "api key", "credentials in"],
    "T1136": ["new user", "account creation", "privilege escalation"],
    "T1562": ["firewall disabled", "waf bypass", "security disabled"],
    "T1071": ["c2", "command and control", "beacon"],
    "T1059": ["remote code", "shell", "command execution"],
    "T1558": ["kerberoast", "as-rep", "kerberos"],
    "T1484": ["acl abuse", "gpo", "delegation"],
    "T1610": ["docker", "container escape", "kubelet"],
    "T1537": ["cloud storage", "azure blob", "gcs exfil"],
}


def _map_ttps(text: str) -> list[str]:
    """Return MITRE TTP IDs whose keywords appear in text."""
    text = text.lower()
    ttps = []
    for ttp_id, keywords in MITRE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            ttps.append(ttp_id)
    return ttps


# ─── CorrelationAgent ─────────────────────────────────────────────────────────

class CorrelationAgent:
    """Groups findings by host and attack surface into correlated clusters."""

    def correlate(self, result: ReconResult) -> dict[str, list[VulnFinding]]:
        """
        Returns dict: host_ip → [VulnFinding].
        Also identifies cross-host patterns (e.g. same CVE on multiple hosts).
        """
        clusters: dict[str, list[VulnFinding]] = {}

        for vf in result.nuclei_findings:
            host = self._extract_host(vf.target)
            clusters.setdefault(host, []).append(vf)

        return clusters

    def find_patterns(self, clusters: dict[str, list[VulnFinding]]) -> list[dict]:
        """Cross-host: same CVE, same severity group, lateral movement potential."""
        patterns: list[dict] = []
        cve_hosts: dict[str, list[str]] = {}
        for host, findings in clusters.items():
            for vf in findings:
                if vf.cve:
                    cve_hosts.setdefault(vf.cve, []).append(host)

        for cve, hosts in cve_hosts.items():
            if len(hosts) > 1:
                patterns.append({
                    "type": "widespread_cve",
                    "cve": cve,
                    "hosts": hosts,
                    "risk": "Vulnerability present on multiple hosts — high lateral movement potential.",
                })

        return patterns

    @staticmethod
    def _extract_host(target: str) -> str:
        target = target.replace("https://", "").replace("http://", "")
        return target.split("/")[0].split(":")[0]


# ─── HypothesisAgent ──────────────────────────────────────────────────────────

class HypothesisAgent:
    """Generates AttackChain hypotheses from correlated findings."""

    def __init__(self, cfg: ScanConfig) -> None:
        self._cfg = cfg

    def generate_chains(
        self,
        result: ReconResult,
        clusters: dict[str, list[VulnFinding]],
        patterns: list[dict],
    ) -> list[AttackChain]:
        chains: list[AttackChain] = []

        # Rule-based chains (always run, no LLM needed)
        chains += self._rule_based_chains(result, clusters, patterns)

        # LLM-enhanced chains
        if self._cfg.ai_key or self._cfg.ai_provider == "ollama":
            try:
                chains += self._llm_chains(result, clusters)
            except Exception as e:
                log.warning(f"[hypothesis] LLM chain generation failed: {e}")

        # Deduplicate by title
        seen_titles: set[str] = set()
        unique: list[AttackChain] = []
        for chain in chains:
            if chain.title not in seen_titles:
                seen_titles.add(chain.title)
                unique.append(chain)

        return unique

    def _rule_based_chains(
        self,
        result: ReconResult,
        clusters: dict[str, list[VulnFinding]],
        patterns: list[dict],
    ) -> list[AttackChain]:
        chains: list[AttackChain] = []
        chain_id = 1

        # AD + kerberoast → lateral movement
        has_kerberoast = any(f.category == "kerberoast" for f in result.ad_findings)
        has_rdp = any(
            p.port == 3389
            for h in result.hosts
            for p in h.open_ports
        )
        if has_kerberoast and has_rdp:
            chains.append(AttackChain(
                chain_id=f"CHAIN-{chain_id:03d}",
                title="Kerberoasting → Credential Cracking → RDP Lateral Movement",
                steps=[
                    "1. Enumerate Kerberoastable SPNs via GetUserSPNs",
                    "2. Request TGS tickets for service accounts",
                    "3. Crack service account hashes offline (hashcat)",
                    "4. Use recovered credentials to authenticate via RDP (port 3389)",
                    "5. Establish persistence and enumerate further",
                ],
                probability=0.78,
                severity="critical",
                prerequisites=["Domain credentials or network access", "Kerberoastable SPN accounts exist"],
                mitre_ttps=["T1558.003", "T1110.002", "T1021.001"],
                remediation="Use gMSA for service accounts; enable MFA on RDP; "
                            "monitor for abnormal TGS requests (event ID 4769).",
                source_finding_ids=["ad_recon:kerberoast"],
            ))
            chain_id += 1

        # Unauthenticated container API + pod exec
        container_crits = [f for f in result.container_findings if f.severity == "critical"]
        if container_crits:
            chains.append(AttackChain(
                chain_id=f"CHAIN-{chain_id:03d}",
                title="Unauthenticated Container API → Cluster Takeover",
                steps=[
                    "1. Access unauthenticated Docker socket or kubelet API",
                    "2. List running pods / containers",
                    "3. Exec into privileged container or mount host filesystem",
                    "4. Escape to host OS via privileged container",
                    "5. Access cloud metadata service for IAM credentials",
                ],
                probability=0.88,
                severity="critical",
                prerequisites=["Network access to internal segment"],
                mitre_ttps=["T1610", "T1611", "T1552.007"],
                remediation="Bind Docker socket to Unix socket only; enable kubelet auth; "
                            "restrict anonymous API access.",
            ))
            chain_id += 1

        # Public cloud bucket → data exfiltration
        public_buckets = [
            f for f in result.cloud_deep_findings
            if f.public and f.service in ("s3", "blob", "gcs")
        ]
        if public_buckets:
            chains.append(AttackChain(
                chain_id=f"CHAIN-{chain_id:03d}",
                title="Public Cloud Storage → Sensitive Data Exfiltration",
                steps=[
                    f"1. Access publicly listed {public_buckets[0].provider.upper()} "
                    f"{public_buckets[0].service} bucket: {public_buckets[0].resource}",
                    "2. Enumerate and download files (credentials, backups, PII)",
                    "3. Discover hardcoded keys in stored files",
                    "4. Use discovered keys to escalate cloud access",
                ],
                probability=0.72,
                severity="critical",
                mitre_ttps=["T1213", "T1552", "T1537"],
                remediation="Apply bucket policies: Block Public Access; "
                            "enable S3 Object Ownership and ACL restrictions; audit IAM.",
            ))
            chain_id += 1

        # Widespread CVE patterns
        for pattern in patterns:
            if pattern["type"] == "widespread_cve" and len(pattern["hosts"]) >= 3:
                chains.append(AttackChain(
                    chain_id=f"CHAIN-{chain_id:03d}",
                    title=f"Mass Exploitation of {pattern['cve']} ({len(pattern['hosts'])} hosts)",
                    steps=[
                        f"1. {pattern['cve']} confirmed on: {', '.join(pattern['hosts'][:5])}",
                        "2. Mass exploit using automated tooling",
                        "3. Deploy RAT / backdoor for persistence",
                        "4. Lateral movement across affected subnet",
                    ],
                    probability=0.65,
                    severity="critical",
                    mitre_ttps=["T1190", "T1059"],
                    remediation=f"Immediately patch {pattern['cve']} across all affected hosts. "
                                "Isolate hosts until patched.",
                ))
                chain_id += 1

        return chains

    def _llm_chains(
        self,
        result: ReconResult,
        clusters: dict[str, list[VulnFinding]],
    ) -> list[AttackChain]:
        """Ask the LLM to generate additional AttackChain objects."""
        summary = self._build_summary(result, clusters)
        prompt = f"""You are a senior penetration tester writing an attack chain report.
Given these findings, identify the 2-3 most dangerous attack chains:

{summary}

Reply ONLY with a valid JSON array of attack chain objects. Each object must have:
- title (string)
- steps (array of strings)
- probability (float 0.0-1.0)
- severity (critical|high|medium|low)
- mitre_ttps (array of TTP IDs like T1190)
- remediation (string)

Example:
[{{"title": "...", "steps": ["1. ...", "2. ..."], "probability": 0.75, "severity": "critical", "mitre_ttps": ["T1190"], "remediation": "..."}}]"""

        response = self._call_llm(prompt)
        return self._parse_chains(response)

    def _build_summary(self, result: ReconResult, clusters: dict[str, list[VulnFinding]]) -> str:
        lines = [f"Target: {result.target}"]
        lines.append(f"Open ports: {[p.port for h in result.hosts for p in h.open_ports][:30]}")
        lines.append(f"Subdomains: {result.subdomains[:10]}")
        lines.append(f"AD findings: {len(result.ad_findings)}")
        lines.append(f"Cloud findings: {len(result.cloud_deep_findings)} "
                     f"(public: {sum(1 for f in result.cloud_deep_findings if f.public)})")
        lines.append(f"Container findings: {len(result.container_findings)}")
        for host, findings in list(clusters.items())[:5]:
            crits = [f.title for f in findings if f.severity in ("critical", "high")][:3]
            if crits:
                lines.append(f"Host {host}: {crits}")
        return "\n".join(lines)

    def _call_llm(self, prompt: str) -> str:
        cfg = self._cfg
        try:
            if cfg.ai_provider == "ollama":
                resp = requests.post(
                    f"{cfg.local_llm_url}/api/generate",
                    json={"model": cfg.ai_model or "qwen3:8b", "prompt": prompt, "stream": False},
                    timeout=90,
                )
                return resp.json().get("response", "[]")
            elif cfg.ai_provider == "groq":
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {cfg.ai_key}"},
                    json={"model": cfg.ai_model or "llama3-8b-8192",
                          "messages": [{"role": "user", "content": prompt}],
                          "max_tokens": 2000, "temperature": 0.2},
                    timeout=60,
                )
                return resp.json()["choices"][0]["message"]["content"]
            elif cfg.ai_provider == "openai":
                resp = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {cfg.ai_key}"},
                    json={"model": cfg.ai_model or "gpt-4o",
                          "messages": [{"role": "user", "content": prompt}],
                          "max_tokens": 2000, "temperature": 0.2},
                    timeout=60,
                )
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            log.warning(f"[hypothesis] LLM call failed: {e}")
        return "[]"

    def _parse_chains(self, text: str) -> list[AttackChain]:
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            raw = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
        chains = []
        for i, obj in enumerate(raw):
            if not isinstance(obj, dict):
                continue
            chains.append(AttackChain(
                chain_id=f"CHAIN-LLM-{i+1:03d}",
                title=obj.get("title", "Unnamed chain"),
                steps=obj.get("steps", []),
                probability=float(obj.get("probability", 0.5)),
                severity=obj.get("severity", "high"),
                mitre_ttps=obj.get("mitre_ttps", []),
                remediation=obj.get("remediation", ""),
            ))
        return chains


# ─── ReportAgent ──────────────────────────────────────────────────────────────

class ReportAgent:
    """Produces structured report sections from AttackChains + ReconResult."""

    def __init__(self, cfg: ScanConfig) -> None:
        self._cfg = cfg

    def executive_summary(self, result: ReconResult) -> str:
        total_findings = (
            len(result.nuclei_findings) + len(result.ad_findings) +
            len(result.cloud_deep_findings) + len(result.container_findings) +
            len(result.iot_findings)
        )
        crits = (
            sum(1 for f in result.nuclei_findings if f.severity == "critical") +
            sum(1 for f in result.ad_findings if f.severity == "critical") +
            sum(1 for f in result.cloud_deep_findings if f.severity == "critical")
        )
        chains = result.attack_chains
        top_chain = chains[0] if chains else None

        parts = [
            f"Security assessment of {result.target} identified {total_findings} findings "
            f"({crits} critical) across {len(result.hosts)} hosts.",
        ]
        if top_chain:
            parts.append(
                f"The highest-risk attack chain identified is: '{top_chain.title}' "
                f"(confidence: {int(top_chain.probability * 100)}%, severity: {top_chain.severity})."
            )
        if result.ad_findings:
            parts.append(
                f"Active Directory assessment revealed {len(result.ad_findings)} issues, "
                f"including {sum(1 for f in result.ad_findings if f.category == 'kerberoast')} "
                f"Kerberoastable accounts."
            )
        if result.cloud_deep_findings:
            public = sum(1 for f in result.cloud_deep_findings if f.public)
            parts.append(f"Cloud assessment found {public} publicly exposed storage resources.")
        return " ".join(parts)

    def remediation_plan(self, result: ReconResult) -> list[dict]:
        plan = []
        # Attack chains (P0)
        for chain in result.attack_chains:
            if chain.severity == "critical" and chain.remediation:
                plan.append({
                    "priority": "P0 — Immediate",
                    "title": chain.title,
                    "action": chain.remediation,
                    "mitre": chain.mitre_ttps,
                })
        # High findings
        for vf in result.nuclei_findings:
            if vf.severity in ("critical", "high") and vf.cve:
                plan.append({
                    "priority": "P1 — Within 7 Days",
                    "title": f"Patch {vf.cve}: {vf.title}",
                    "action": f"Apply vendor patch for {vf.cve}. REI: {vf.rei}",
                    "epss": vf.epss_score,
                })
        return plan[:50]

    def compliance_gaps(self, result: ReconResult, framework: str) -> list[dict]:
        """Map findings to compliance control failures."""
        gaps = []
        framework = framework.lower()
        if "pci" in framework:
            if any(p.port == 23 for h in result.hosts for p in h.open_ports):
                gaps.append({"control": "PCI DSS 8.2", "gap": "Telnet (port 23) exposed — insecure protocol",
                             "severity": "critical"})
            if not result.ssl_results:
                gaps.append({"control": "PCI DSS 4.2", "gap": "TLS/SSL not verified", "severity": "high"})
        if "iso" in framework:
            if result.ad_findings:
                gaps.append({"control": "ISO 27001:2022 A.5.18",
                             "gap": f"{len(result.ad_findings)} AD access control issues", "severity": "high"})
        if "nist" in framework:
            if result.nuclei_findings:
                gaps.append({"control": "NIST CSF ID.RA-1",
                             "gap": f"{len(result.nuclei_findings)} vulnerabilities identified",
                             "severity": "medium"})
        return gaps


# ─── Full correlation pipeline entry point ────────────────────────────────────

def run_correlation_pipeline(
    result: ReconResult,
    cfg: ScanConfig,
) -> tuple[list[AttackChain], str, list[dict]]:
    """
    Run full CorrelationAgent → HypothesisAgent → ReportAgent pipeline.
    Returns (attack_chains, executive_summary, remediation_plan).
    """
    safe_print("[module]🔗  Running agentic correlation pipeline...[/]")

    corr = CorrelationAgent()
    clusters = corr.correlate(result)
    patterns = corr.find_patterns(clusters)
    safe_print(f"[info]  → {len(clusters)} host clusters, {len(patterns)} cross-host patterns[/]")

    hyp = HypothesisAgent(cfg)
    chains = hyp.generate_chains(result, clusters, patterns)
    result.attack_chains = chains
    safe_print(f"[success]  ✔ {len(chains)} attack chains generated[/]")

    rep = ReportAgent(cfg)
    summary = rep.executive_summary(result)
    plan = rep.remediation_plan(result)
    result.remediations = plan

    return chains, summary, plan
