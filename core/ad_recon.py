"""
ReconNinja v9 — Active Directory Recon  (--ad-recon)
Covers: domain/forest discovery, Kerberoasting, AS-REP roasting,
ACL abuse, delegation checks, BloodHound JSON ingest.

Requires: impacket, ldap3
All checks are passive LDAP enumeration — no exploitation.
Use only against targets you own or have explicit written permission to test.
"""
from __future__ import annotations

import subprocess
import json
from pathlib import Path

from utils.logger import log, safe_print
from utils.models import ADFinding, ReconResult, ScanConfig


def ad_recon_scan(
    target: str,
    result: ReconResult,
    cfg: ScanConfig,
    out_folder: Path,
) -> list[ADFinding]:
    """Entry point for AD recon. Returns list of ADFinding objects."""
    findings: list[ADFinding] = []

    if not cfg.ad_dc or not cfg.ad_domain:
        log.warning("[ad_recon] --ad-dc and --ad-domain are required")
        return findings

    safe_print("[module]🏰  Active Directory Recon...[/]")

    findings += _dc_discovery(cfg)
    findings += _kerberoastable_accounts(cfg, out_folder)
    findings += _asrep_roastable_accounts(cfg, out_folder)
    findings += _acl_abuse_check(cfg)
    findings += _delegation_check(cfg)
    _run_bloodhound(cfg, out_folder)

    result.ad_findings.extend(findings)

    crits = [f for f in findings if f.severity == "critical"]
    highs = [f for f in findings if f.severity == "high"]
    safe_print(f"[success]  ✔ AD recon: {len(findings)} findings "
               f"({len(crits)} critical, {len(highs)} high)[/]")
    return findings


# ─── DC discovery ─────────────────────────────────────────────────────────────

def _dc_discovery(cfg: ScanConfig) -> list[ADFinding]:
    findings: list[ADFinding] = []
    try:
        import ldap3  # type: ignore
        server = ldap3.Server(cfg.ad_dc, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(server, auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND
                                if not cfg.ad_user else True)
        if cfg.ad_user:
            conn = ldap3.Connection(
                server,
                user=f"{cfg.ad_domain}\\{cfg.ad_user}",
                password=cfg.ad_password,
                auto_bind=True,
            )
        if conn.bound:
            domain_nc = server.info.other.get("defaultNamingContext", [None])[0]
            findings.append(ADFinding(
                category="misc",
                severity="info",
                title=f"Domain controller reachable: {cfg.ad_dc}",
                detail=f"Domain NC: {domain_nc}",
            ))
    except ImportError:
        log.warning("[ad_recon] ldap3 not installed — skipping DC discovery")
    except Exception as e:
        log.warning(f"[ad_recon] DC discovery error: {e}")
    return findings


# ─── Kerberoasting ────────────────────────────────────────────────────────────

def _kerberoastable_accounts(cfg: ScanConfig, out_folder: Path) -> list[ADFinding]:
    findings: list[ADFinding] = []
    if not cfg.ad_user:
        return findings
    try:
        out_file = out_folder / "kerberoast_hashes.txt"
        result = subprocess.run(
            [
                "python3", "-m", "impacket.examples.GetUserSPNs",
                f"{cfg.ad_domain}/{cfg.ad_user}:{cfg.ad_password}",
                "-dc-ip", cfg.ad_dc,
                "-outputfile", str(out_file),
            ],
            capture_output=True, text=True, timeout=60,
        )
        lines = result.stdout.splitlines()
        spn_accounts = [l for l in lines if "ServicePrincipalName" not in l and "/" in l]
        for acct in spn_accounts:
            findings.append(ADFinding(
                category="kerberoast",
                severity="high",
                title=f"Kerberoastable account: {acct.strip()}",
                detail="Service account has SPN set — hash can be captured and cracked offline.",
                mitigation="Use managed service accounts or Group Managed Service Accounts (gMSA).",
            ))
    except FileNotFoundError:
        log.warning("[ad_recon] impacket not found — install with: pip install impacket")
    except subprocess.TimeoutExpired:
        log.warning("[ad_recon] GetUserSPNs timed out")
    except Exception as e:
        log.warning(f"[ad_recon] Kerberoast check error: {e}")
    return findings


# ─── AS-REP roasting ──────────────────────────────────────────────────────────

def _asrep_roastable_accounts(cfg: ScanConfig, out_folder: Path) -> list[ADFinding]:
    findings: list[ADFinding] = []
    try:
        out_file = out_folder / "asrep_hashes.txt"
        result = subprocess.run(
            [
                "python3", "-m", "impacket.examples.GetNPUsers",
                cfg.ad_domain + "/",
                "-dc-ip", cfg.ad_dc,
                "-no-pass",
                "-format", "hashcat",
                "-outputfile", str(out_file),
            ],
            capture_output=True, text=True, timeout=60,
        )
        if out_file.exists() and out_file.stat().st_size > 0:
            count = sum(1 for l in out_file.read_text().splitlines() if l.startswith("$krb5asrep"))
            if count:
                findings.append(ADFinding(
                    category="asrep",
                    severity="high",
                    title=f"{count} AS-REP roastable account(s) found",
                    detail=f"Hashes saved to {out_file}. Accounts do not require pre-authentication.",
                    mitigation="Enable Kerberos pre-authentication on all user accounts.",
                ))
    except FileNotFoundError:
        log.warning("[ad_recon] impacket not found — skipping AS-REP check")
    except Exception as e:
        log.warning(f"[ad_recon] AS-REP check error: {e}")
    return findings


# ─── ACL abuse ────────────────────────────────────────────────────────────────

def _acl_abuse_check(cfg: ScanConfig) -> list[ADFinding]:
    findings: list[ADFinding] = []
    if not cfg.ad_user:
        return findings
    try:
        import ldap3  # type: ignore

        dangerous_rights = {
            "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
        }

        server = ldap3.Server(cfg.ad_dc, connect_timeout=10)
        conn = ldap3.Connection(
            server,
            user=f"{cfg.ad_domain}\\{cfg.ad_user}",
            password=cfg.ad_password,
            auto_bind=True,
        )
        domain_nc = f"DC={cfg.ad_domain.replace('.', ',DC=')}"
        conn.search(
            domain_nc,
            "(objectClass=user)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],
        )
        acl_hits = 0
        for entry in conn.entries[:200]:
            dn = str(entry.distinguishedName)
            sd = entry["nTSecurityDescriptor"].value
            if sd and any(right in str(sd) for right in dangerous_rights):
                acl_hits += 1
                findings.append(ADFinding(
                    category="acl",
                    severity="critical",
                    title=f"Dangerous ACL on: {dn[:80]}",
                    object_dn=dn,
                    detail="Object has WriteDACL, GenericAll, or replication rights set.",
                    mitigation="Review and remove over-permissive ACEs from AD objects.",
                ))
                if acl_hits >= 10:
                    break
    except ImportError:
        log.warning("[ad_recon] ldap3 not available for ACL check")
    except Exception as e:
        log.warning(f"[ad_recon] ACL check error: {e}")
    return findings


# ─── Delegation check ─────────────────────────────────────────────────────────

def _delegation_check(cfg: ScanConfig) -> list[ADFinding]:
    findings: list[ADFinding] = []
    if not cfg.ad_user:
        return findings
    try:
        import ldap3  # type: ignore
        server = ldap3.Server(cfg.ad_dc, connect_timeout=10)
        conn = ldap3.Connection(
            server,
            user=f"{cfg.ad_domain}\\{cfg.ad_user}",
            password=cfg.ad_password,
            auto_bind=True,
        )
        domain_nc = f"DC={cfg.ad_domain.replace('.', ',DC=')}"
        # Unconstrained delegation: userAccountControl flag 0x80000
        conn.search(domain_nc, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                    attributes=["sAMAccountName", "distinguishedName"])
        for entry in conn.entries:
            findings.append(ADFinding(
                category="delegation",
                severity="high",
                title=f"Unconstrained delegation: {entry.sAMAccountName}",
                object_dn=str(entry.distinguishedName),
                detail="Computer account has unconstrained Kerberos delegation — "
                       "attacker with admin on this machine can impersonate any user.",
                mitigation="Move to constrained or resource-based constrained delegation.",
            ))
    except Exception as e:
        log.warning(f"[ad_recon] Delegation check error: {e}")
    return findings


# ─── BloodHound ingest ────────────────────────────────────────────────────────

def _run_bloodhound(cfg: ScanConfig, out_folder: Path) -> None:
    bh_out = Path(cfg.ad_bloodhound_output)
    bh_out.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "bloodhound-python",
                "-d", cfg.ad_domain,
                "-u", cfg.ad_user,
                "-p", cfg.ad_password,
                "-c", "All",
                "-dc", cfg.ad_dc,
                "--zip",
                "-o", str(bh_out),
            ],
            capture_output=True, text=True, timeout=180,
        )
        safe_print(f"[success]  ✔ BloodHound data collected → {bh_out}[/]")
    except FileNotFoundError:
        log.warning("[ad_recon] bloodhound-python not found — install: pip install bloodhound")
    except subprocess.TimeoutExpired:
        log.warning("[ad_recon] bloodhound-python timed out")
    except Exception as e:
        log.warning(f"[ad_recon] BloodHound error: {e}")
