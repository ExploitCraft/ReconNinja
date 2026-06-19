"""
ReconNinja v9 — Wireless OSINT  (--wireless-osint)
Passive only — no active transmission. Wigle.net API, WPS/Shodan, rogue AP detection.
"""
from __future__ import annotations
import re
from pathlib import Path
import requests
from utils.logger import log, safe_print
from utils.models import WirelessFinding, DarkWebFinding, ReconResult, ScanConfig


def wireless_osint_scan(target: str, result: ReconResult, cfg: ScanConfig, out_folder: Path) -> list[WirelessFinding]:
    findings: list[WirelessFinding] = []
    safe_print("[module]📡  Wireless OSINT (passive)...[/]")

    org_name = target.split(".")[0] if "." in target else target

    if cfg.wigle_api_token:
        findings += _wigle_query(org_name, cfg.wigle_api_token)
        findings += _detect_rogue_aps(org_name, findings)
    else:
        safe_print("[dim]  ⚠ --wigle-token not set — wireless OSINT skipped[/]")

    result.wireless_findings.extend(findings)
    safe_print(f"[success]  ✔ Wireless OSINT: {len(findings)} SSIDs found[/]")
    return findings


def _wigle_query(org_name: str, token: str) -> list[WirelessFinding]:
    findings: list[WirelessFinding] = []
    try:
        import base64
        resp = requests.get(
            "https://api.wigle.net/api/v2/network/search",
            params={"ssid": org_name, "resultsPerPage": 50},
            headers={"Authorization": f"Basic {token}"},
            timeout=15,
        )
        data = resp.json()
        for net in data.get("results", []):
            findings.append(WirelessFinding(
                ssid=net.get("ssid", ""),
                bssid=net.get("netid", ""),
                lat=net.get("trilat", 0.0),
                lng=net.get("trilong", 0.0),
                source="wigle",
            ))
    except Exception as e:
        log.warning(f"[wireless_osint] Wigle query error: {e}")
    return findings


def _detect_rogue_aps(org_name: str, known: list[WirelessFinding]) -> list[WirelessFinding]:
    """Flag SSIDs that are typosquats of the org name."""
    rogues: list[WirelessFinding] = []
    org_lower = org_name.lower()
    variants = {
        org_lower + "-free",
        org_lower + "_wifi",
        org_lower + "-guest",
        org_lower + "2",
        org_lower.replace("o", "0"),
    }
    known_ssids = {f.ssid.lower() for f in known}
    for ssid in known_ssids:
        if ssid in variants or (ssid != org_lower and org_lower in ssid):
            rogues.append(WirelessFinding(
                ssid=ssid, source="wigle", is_rogue=True,
                detail=f"Possible rogue AP — SSID '{ssid}' resembles '{org_name}'.",
            ))
    return rogues


# ─── Dark Web OSINT ───────────────────────────────────────────────────────────

"""
ReconNinja v9 — Dark Web / Threat Intel OSINT  (--darkweb-osint)
Ransomwatch tracker, Telegram public channels, paste expansion.
Read-only, no Tor required, clearnet proxies only.
"""


def darkweb_osint_scan(target: str, result: ReconResult, cfg: ScanConfig, out_folder: Path) -> list[DarkWebFinding]:
    findings: list[DarkWebFinding] = []
    safe_print("[module]🕸  Dark Web / Threat Intel OSINT...[/]")

    findings += _ransomwatch_check(target)
    findings += _telegram_check(target, cfg)

    result.darkweb_findings.extend(findings)
    safe_print(f"[success]  ✔ Dark web OSINT: {len(findings)} mentions found[/]")
    return findings


def _ransomwatch_check(target: str) -> list[DarkWebFinding]:
    findings: list[DarkWebFinding] = []
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
            timeout=20,
        )
        posts = resp.json()
        domain = target.split("//")[-1].split("/")[0]
        for post in posts:
            if domain.lower() in str(post).lower():
                findings.append(DarkWebFinding(
                    source="ransomwatch",
                    mention=f"Target mentioned on ransomware leak site: {post.get('group_name', 'unknown')}",
                    url=post.get("url", ""),
                    date=post.get("discovered", ""),
                    severity="critical",
                ))
    except Exception as e:
        log.warning(f"[darkweb_osint] Ransomwatch check error: {e}")
    return findings


def _telegram_check(target: str, cfg: ScanConfig) -> list[DarkWebFinding]:
    if not cfg.telegram_token:
        return []
    findings: list[DarkWebFinding] = []
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{cfg.telegram_token}/getUpdates",
            timeout=10,
        )
        # Public channel search via Telegram API is limited without a bot in the channel
        # This checks recent bot updates for any mentions
        domain = target.split("//")[-1].split("/")[0]
        updates = resp.json().get("result", [])
        for update in updates:
            text = str(update.get("message", {}).get("text", ""))
            if domain.lower() in text.lower():
                findings.append(DarkWebFinding(
                    source="telegram",
                    mention=f"Target domain mentioned in Telegram: ...{text[:100]}...",
                    severity="high",
                ))
    except Exception as e:
        log.warning(f"[darkweb_osint] Telegram check error: {e}")
    return findings
