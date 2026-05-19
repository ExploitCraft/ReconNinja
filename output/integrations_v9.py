"""
ReconNinja v9 — New Output Integrations
DefectDojo push, Notion database export, Obsidian vault export.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests

from utils.logger import log, safe_print
from utils.models import ReconResult, ScanConfig


# ─── DefectDojo ───────────────────────────────────────────────────────────────

def push_to_defectdojo(result: ReconResult, cfg: ScanConfig) -> None:
    """Push findings to DefectDojo via REST API."""
    if not cfg.defectdojo_url or not cfg.defectdojo_key:
        log.warning("[defectdojo] URL or API key not set — skipping")
        return

    safe_print("[module]📤  Pushing to DefectDojo...[/]")
    base = cfg.defectdojo_url.rstrip("/")
    headers = {
        "Authorization": f"Token {cfg.defectdojo_key}",
        "Content-Type": "application/json",
    }

    # Find or create product
    product_id = _dojo_get_or_create_product(base, headers, cfg.defectdojo_product or result.target)
    if not product_id:
        log.warning("[defectdojo] Could not resolve product — aborting push")
        return

    # Create engagement
    engagement_id = _dojo_create_engagement(base, headers, product_id, result)
    if not engagement_id:
        return

    # Push findings
    pushed = 0
    for vf in result.nuclei_findings:
        payload = {
            "test":              engagement_id,
            "title":             vf.title,
            "severity":          vf.severity.capitalize(),
            "description":       vf.details or vf.title,
            "url":               vf.target,
            "cve":               vf.cve or None,
            "cvssv3_score":      vf.cvss_v4 or None,
            "active":            True,
            "verified":          False,
            "numerical_severity": _dojo_severity_num(vf.severity),
        }
        try:
            resp = requests.post(f"{base}/api/v2/findings/", json=payload, headers=headers, timeout=15)
            if resp.status_code in (200, 201):
                pushed += 1
        except Exception as e:
            log.warning(f"[defectdojo] Finding push error: {e}")

    safe_print(f"[success]  ✔ DefectDojo: {pushed} findings pushed[/]")


def _dojo_get_or_create_product(base: str, headers: dict, product_name: str) -> int | None:
    try:
        resp = requests.get(f"{base}/api/v2/products/", params={"name": product_name},
                            headers=headers, timeout=10)
        results = resp.json().get("results", [])
        if results:
            return results[0]["id"]
        # Create
        resp = requests.post(f"{base}/api/v2/products/",
                             json={"name": product_name, "prod_type": 1},
                             headers=headers, timeout=10)
        return resp.json().get("id")
    except Exception as e:
        log.warning(f"[defectdojo] Product lookup error: {e}")
        return None


def _dojo_create_engagement(base: str, headers: dict, product_id: int, result: ReconResult) -> int | None:
    try:
        from utils.helpers import timestamp
        resp = requests.post(
            f"{base}/api/v2/engagements/",
            json={
                "product":          product_id,
                "name":             f"ReconNinja v9 — {result.target}",
                "engagement_type":  "CI/CD",
                "status":           "Completed",
                "target_start":     result.start_time[:10],
                "target_end":       (result.end_time or result.start_time)[:10],
            },
            headers=headers, timeout=10,
        )
        return resp.json().get("id")
    except Exception as e:
        log.warning(f"[defectdojo] Engagement create error: {e}")
        return None


def _dojo_severity_num(severity: str) -> str:
    return {"critical": "S0", "high": "S1", "medium": "S2", "low": "S3", "info": "S4"}.get(severity, "S4")


# ─── Notion export ────────────────────────────────────────────────────────────

def export_to_notion(result: ReconResult, cfg: ScanConfig) -> None:
    """Export findings to a Notion database."""
    if not cfg.notion_token or not cfg.notion_db_id:
        log.warning("[notion] Token or database ID not set — skipping")
        return

    safe_print("[module]📓  Exporting to Notion...[/]")
    headers = {
        "Authorization":  f"Bearer {cfg.notion_token}",
        "Content-Type":   "application/json",
        "Notion-Version": "2022-06-28",
    }
    pushed = 0
    for vf in result.nuclei_findings[:100]:
        payload = {
            "parent": {"database_id": cfg.notion_db_id},
            "properties": {
                "Title":    {"title": [{"text": {"content": vf.title[:100]}}]},
                "Severity": {"select": {"name": vf.severity.capitalize()}},
                "Target":   {"rich_text": [{"text": {"content": vf.target[:100]}}]},
                "CVE":      {"rich_text": [{"text": {"content": vf.cve or ""}}]},
                "EPSS":     {"number": vf.epss_score},
                "REI":      {"number": vf.rei},
            },
        }
        try:
            resp = requests.post("https://api.notion.com/v1/pages",
                                 json=payload, headers=headers, timeout=15)
            if resp.status_code in (200, 201):
                pushed += 1
        except Exception as e:
            log.warning(f"[notion] Push error: {e}")

    safe_print(f"[success]  ✔ Notion: {pushed} pages created[/]")


# ─── Obsidian export ──────────────────────────────────────────────────────────

def export_to_obsidian(result: ReconResult, cfg: ScanConfig, out_folder: Path) -> None:
    """Export report and findings as Markdown files into an Obsidian vault directory."""
    vault = Path(cfg.obsidian_vault_path)
    recon_dir = vault / "ReconNinja" / result.target.replace("/", "_")
    recon_dir.mkdir(parents=True, exist_ok=True)

    safe_print("[module]🗒  Exporting to Obsidian vault...[/]")

    # Main scan note
    main_note = _build_obsidian_main(result)
    (recon_dir / "README.md").write_text(main_note, encoding="utf-8")

    # Individual finding notes
    findings_dir = recon_dir / "findings"
    findings_dir.mkdir(exist_ok=True)
    for i, vf in enumerate(result.nuclei_findings[:200]):
        fname = f"{vf.severity.upper()}_{i+1:03d}_{vf.cve or 'no-cve'}.md"
        note = _build_obsidian_finding(vf)
        (findings_dir / fname).write_text(note, encoding="utf-8")

    # Attack chains
    if result.attack_chains:
        chains_dir = recon_dir / "attack_chains"
        chains_dir.mkdir(exist_ok=True)
        for chain in result.attack_chains:
            fname = f"{chain.chain_id}_{chain.title[:40].replace(' ', '_')}.md"
            note = _build_obsidian_chain(chain)
            (chains_dir / fname).write_text(note, encoding="utf-8")

    safe_print(f"[success]  ✔ Obsidian vault: {recon_dir}[/]")


def _build_obsidian_main(result: ReconResult) -> str:
    return f"""# ReconNinja Scan — {result.target}

**Started:** {result.start_time}
**Completed:** {result.end_time}

## Summary
- Subdomains: {len(result.subdomains)}
- Hosts: {len(result.hosts)}
- Open Ports: {sum(len(h.open_ports) for h in result.hosts)}
- Nuclei Findings: {len(result.nuclei_findings)}
- Attack Chains: {len(result.attack_chains)}
- AD Findings: {len(result.ad_findings)}
- Cloud Findings: {len(result.cloud_deep_findings)}

## AI Analysis
{result.ai_analysis or '_Not run_'}

## Attack Chains
{chr(10).join(f'- [[attack_chains/{c.chain_id}_{c.title[:40].replace(" ", "_")}|{c.title}]] ({c.severity})' for c in result.attack_chains)}

## Findings Index
{chr(10).join(f'- [[findings/{vf.severity.upper()}_{i+1:03d}_{vf.cve or "no-cve"}|{vf.title}]]' for i, vf in enumerate(result.nuclei_findings[:50]))}
"""


def _build_obsidian_finding(vf) -> str:
    from dataclasses import asdict
    return f"""# {vf.title}

**Severity:** {vf.severity}
**Target:** {vf.target}
**CVE:** {vf.cve or 'N/A'}
**EPSS:** {vf.epss_score:.4f}
**REI:** {vf.rei}
**CVSSv4:** {vf.cvss_v4 or 'N/A'}

## Details
{vf.details or '_No details_'}

## Tags
#severity/{vf.severity} #tool/{vf.tool}
"""


def _build_obsidian_chain(chain) -> str:
    steps_md = "\n".join(f"{s}" for s in chain.steps)
    ttps_md = ", ".join(chain.mitre_ttps)
    return f"""# {chain.title}

**Chain ID:** {chain.chain_id}
**Severity:** {chain.severity}
**Probability:** {int(chain.probability * 100)}%
**MITRE TTPs:** {ttps_md}

## Steps
{steps_md}

## Remediation
{chain.remediation or '_None specified_'}

## Tags
#attack_chain #severity/{chain.severity}
"""
