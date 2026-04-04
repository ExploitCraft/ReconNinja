"""
core/email_security.py — ReconNinja v7.0.0
Email Security: SPF, DKIM, DMARC record validation and spoofability scoring.

Checks:
  - SPF record presence, policy strength (-all vs ~all vs ?all)
  - DMARC record presence, policy (none/quarantine/reject), pct
  - MX record presence and reverse-DNS
  - DKIM selector probing (common selectors)
  - Spoofability score (0-100, higher = easier to spoof)

No external tools or API keys required — pure dnspython or socket fallback.
"""

from __future__ import annotations

import socket
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir, run_cmd, tool_exists
from utils.logger import safe_print, log


# ── Common DKIM selectors to probe ────────────────────────────────────────────
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2", "selector1", "selector2",
    "s1", "s2", "smtp", "mimecast", "proofpoint", "sendgrid", "mailchimp",
    "amazonses", "mandrill", "postmark", "sparkpost",
]


@dataclass
class EmailSecurityResult:
    domain:          str
    spf_record:      str   = ""
    spf_policy:      str   = ""   # pass/softfail/fail/neutral/none
    spf_issues:      list[str] = field(default_factory=list)
    dmarc_record:    str   = ""
    dmarc_policy:    str   = ""   # none/quarantine/reject
    dmarc_pct:       int   = 100
    dmarc_issues:    list[str] = field(default_factory=list)
    mx_records:      list[str] = field(default_factory=list)
    dkim_selectors:  list[str] = field(default_factory=list)  # found selectors
    spoofability:    int   = 0    # 0-100 (100 = trivially spoofable)
    spoofability_label: str = ""
    summary:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain":             self.domain,
            "spf_record":         self.spf_record,
            "spf_policy":         self.spf_policy,
            "spf_issues":         self.spf_issues,
            "dmarc_record":       self.dmarc_record,
            "dmarc_policy":       self.dmarc_policy,
            "dmarc_pct":          self.dmarc_pct,
            "dmarc_issues":       self.dmarc_issues,
            "mx_records":         self.mx_records,
            "dkim_selectors":     self.dkim_selectors,
            "spoofability":       self.spoofability,
            "spoofability_label": self.spoofability_label,
            "summary":            self.summary,
        }


# ── DNS TXT lookup ────────────────────────────────────────────────────────────

def _txt_records(name: str) -> list[str]:
    """Resolve TXT records for a name using dnspython or dig fallback."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT")
        return ["".join(r.strings[i].decode() for i in range(len(r.strings))) for r in answers]
    except ImportError:
        pass
    except Exception:
        pass

    # dig fallback
    try:
        rc, out, _ = run_cmd(["dig", "+short", "TXT", name], timeout=10)
        if rc == 0 and out:
            records = []
            for line in out.strip().splitlines():
                line = line.strip().strip('"')
                if line:
                    records.append(line)
            return records
    except Exception:
        pass

    return []


def _mx_records(domain: str) -> list[str]:
    """Resolve MX records."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in answers]
    except ImportError:
        pass
    except Exception:
        pass
    try:
        rc, out, _ = run_cmd(["dig", "+short", "MX", domain], timeout=10)
        if rc == 0 and out:
            return [line.split()[-1].rstrip(".") for line in out.strip().splitlines() if line.strip()]
    except Exception:
        pass
    return []


# ── SPF analysis ──────────────────────────────────────────────────────────────

def _analyse_spf(records: list[str]) -> tuple[str, str, list[str]]:
    """Returns (spf_record, policy_label, issues)."""
    spf = next((r for r in records if r.lower().startswith("v=spf1")), "")
    if not spf:
        return "", "none", ["No SPF record found — domain is trivially spoofable"]

    issues: list[str] = []
    policy = "fail"  # default assumption

    if "-all" in spf:
        policy = "fail"
    elif "~all" in spf:
        policy = "softfail"
        issues.append("SPF uses ~all (softfail) — some MTAs treat as pass; use -all for hard reject")
    elif "?all" in spf:
        policy = "neutral"
        issues.append("SPF uses ?all (neutral) — effectively no protection")
    elif "+all" in spf:
        policy = "pass_all"
        issues.append("CRITICAL: SPF uses +all — allows ANY server to send as this domain!")
    else:
        policy = "no_all"
        issues.append("SPF record has no 'all' mechanism — incomplete policy")

    # Check for too many DNS lookups (>10 causes perm error)
    lookup_mechs = re.findall(r"\b(include:|a:|mx:|ptr:|exists:)", spf)
    if len(lookup_mechs) > 8:
        issues.append(f"SPF has {len(lookup_mechs)} DNS-lookup mechanisms — may exceed 10-lookup limit")

    return spf, policy, issues


# ── DMARC analysis ────────────────────────────────────────────────────────────

def _analyse_dmarc(domain: str) -> tuple[str, str, int, list[str]]:
    """Returns (dmarc_record, policy, pct, issues)."""
    records = _txt_records(f"_dmarc.{domain}")
    dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), "")
    if not dmarc:
        return "", "none", 0, ["No DMARC record found — phishing/spoofing not mitigated"]

    issues: list[str] = []

    # Policy
    p_match = re.search(r"\bp=(\w+)", dmarc, re.I)
    policy = p_match.group(1).lower() if p_match else "none"
    if policy == "none":
        issues.append("DMARC policy=none — monitoring only, no protection against spoofing")
    elif policy == "quarantine":
        issues.append("DMARC policy=quarantine — spoofed mail goes to spam (better than none, not ideal)")

    # Percentage
    pct_match = re.search(r"\bpct=(\d+)", dmarc, re.I)
    pct = int(pct_match.group(1)) if pct_match else 100
    if pct < 100:
        issues.append(f"DMARC pct={pct} — only {pct}% of mail checked; gradually ramp to 100")

    # RUA reporting
    if "rua=" not in dmarc.lower():
        issues.append("DMARC has no rua= reporting URI — no visibility into spoofing attempts")

    return dmarc, policy, pct, issues


# ── DKIM selector probing ─────────────────────────────────────────────────────

def _probe_dkim_selectors(domain: str, selectors: list[str]) -> list[str]:
    """Returns list of selectors that have valid DKIM TXT records."""
    found = []
    for sel in selectors:
        records = _txt_records(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            found.append(sel)
    return found


# ── Spoofability score ────────────────────────────────────────────────────────

def _spoofability(spf_policy: str, dmarc_policy: str, dmarc_pct: int) -> tuple[int, str]:
    score = 0

    # SPF contribution (0-40)
    spf_scores = {"none": 40, "no_all": 35, "neutral": 30, "softfail": 15, "fail": 0, "pass_all": 40}
    score += spf_scores.get(spf_policy, 20)

    # DMARC contribution (0-60)
    if dmarc_policy == "none":
        score += 45
    elif dmarc_policy == "quarantine":
        score += 20 + int((100 - dmarc_pct) * 0.20)
    elif dmarc_policy == "reject":
        score += 0 + int((100 - dmarc_pct) * 0.10)
    else:  # no dmarc
        score += 60

    score = min(100, score)

    if score >= 75:
        label = "CRITICAL — trivially spoofable"
    elif score >= 50:
        label = "HIGH — easy to spoof"
    elif score >= 25:
        label = "MEDIUM — partial protection"
    else:
        label = "LOW — well protected"

    return score, label


# ── Public API ────────────────────────────────────────────────────────────────

def email_security_scan(domain: str, out_folder: Path) -> EmailSecurityResult:
    """
    Run full email security check on a domain.
    Checks SPF, DMARC, MX, DKIM selectors and computes spoofability score.
    """
    ensure_dir(out_folder)
    safe_print(f"[info]▶ Email Security — scanning {domain}[/]")

    result = EmailSecurityResult(domain=domain)

    # SPF
    spf_txt = _txt_records(domain)
    result.spf_record, result.spf_policy, result.spf_issues = _analyse_spf(spf_txt)

    # DMARC
    result.dmarc_record, result.dmarc_policy, result.dmarc_pct, result.dmarc_issues = _analyse_dmarc(domain)

    # MX
    result.mx_records = _mx_records(domain)
    if not result.mx_records:
        result.spf_issues.append("No MX records found — domain may not accept email")

    # DKIM selectors
    result.dkim_selectors = _probe_dkim_selectors(domain, DKIM_SELECTORS[:10])

    # Spoofability score
    result.spoofability, result.spoofability_label = _spoofability(
        result.spf_policy, result.dmarc_policy, result.dmarc_pct
    )

    # Summary
    if result.spf_record:
        result.summary.append(f"SPF: {result.spf_policy} ({result.spf_record[:60]}...)")
    else:
        result.summary.append("SPF: MISSING")
    if result.dmarc_record:
        result.summary.append(f"DMARC: policy={result.dmarc_policy} pct={result.dmarc_pct}")
    else:
        result.summary.append("DMARC: MISSING")
    result.summary.append(f"MX: {len(result.mx_records)} record(s)")
    result.summary.append(f"DKIM selectors found: {result.dkim_selectors or 'none probed'}")
    result.summary.append(f"Spoofability: {result.spoofability}/100 — {result.spoofability_label}")

    # Print summary
    sev = "danger" if result.spoofability >= 75 else "warning" if result.spoofability >= 50 else "success"
    safe_print(f"  [{sev}]Email spoofability: {result.spoofability}/100 — {result.spoofability_label}[/]")
    for issue in result.spf_issues + result.dmarc_issues:
        safe_print(f"  [warning]  ⚠  {issue}[/]")

    # Save report
    out_file = out_folder / "email_security.txt"
    lines = [f"# Email Security Report — {domain}", ""]
    for s in result.summary:
        lines.append(f"  {s}")
    lines.append("")
    for issue in result.spf_issues + result.dmarc_issues:
        lines.append(f"[ISSUE] {issue}")
    out_file.write_text("\n".join(lines))

    safe_print(f"[success]✔ Email Security scan complete → {out_file}[/]")
    return result
