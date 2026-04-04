"""
core/greynoise.py — ReconNinja v7.0.0
GreyNoise IP context — filters internet noise vs targeted scans.

Tags each discovered IP as:
  - noise (mass internet scanner, safe to de-prioritize)
  - riot (known safe service like Google, Cloudflare)
  - unknown (targeted / worth investigating)

Free Community API: up to 500 IPs/day, no registration required.
Paid API key gives enriched context.
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log

GN_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
GN_CONTEXT_URL   = "https://api.greynoise.io/v2/noise/context/{ip}"


@dataclass
class GreyNoiseResult:
    ip:          str
    noise:       bool   = False   # True = mass internet scanner
    riot:        bool   = False   # True = known benign (Google, CF)
    name:        str    = ""      # company/service name if riot
    category:    str    = ""      # business/isp/education/...
    intention:   str    = ""      # malicious/benign/unknown
    last_seen:   str    = ""
    tags:        list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip":        self.ip,
            "noise":     self.noise,
            "riot":      self.riot,
            "name":      self.name,
            "category":  self.category,
            "intention": self.intention,
            "last_seen": self.last_seen,
            "tags":      self.tags,
        }

    @property
    def label(self) -> str:
        if self.riot:
            return f"RIOT ({self.name})"
        if self.noise:
            return f"NOISE ({self.intention})"
        return "UNKNOWN (investigate)"


def _gn_fetch(url: str, api_key: Optional[str] = None, timeout: int = 10) -> Optional[dict]:
    headers = {"User-Agent": "ReconNinja/7.0.0", "Accept": "application/json"}
    if api_key:
        headers["key"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"noise": False, "riot": False, "message": "not found"}
        if e.code == 429:
            safe_print("[dim]GreyNoise rate limit — waiting 2s[/]")
            time.sleep(2)
        return None
    except Exception as e:
        log.debug(f"GreyNoise fetch error: {e}")
        return None


def greynoise_lookup(
    ips: list[str],
    out_folder: Path,
    api_key: Optional[str] = None,
    delay: float = 0.3,
) -> list[GreyNoiseResult]:
    """
    Tag IPs as internet noise, known-benign RIOT, or unknown/targeted.

    Args:
        ips:       list of IPs to check
        out_folder: output directory
        api_key:   GreyNoise API key (optional, community tier works without)
        delay:     seconds between requests

    Returns:
        list of GreyNoiseResult
    """
    ensure_dir(out_folder)
    results: list[GreyNoiseResult] = []
    safe_print(f"[info]▶ GreyNoise — tagging {len(ips)} IP(s)[/]")

    for ip in ips[:100]:  # cap at 100 per scan
        url  = GN_COMMUNITY_URL.format(ip=ip)
        data = _gn_fetch(url, api_key)

        if data is None:
            results.append(GreyNoiseResult(ip=ip))
            continue

        r = GreyNoiseResult(
            ip        = ip,
            noise     = data.get("noise", False),
            riot      = data.get("riot", False),
            name      = data.get("name", ""),
            last_seen = data.get("last_seen", ""),
        )
        results.append(r)

        if r.riot:
            safe_print(f"  [dim]  {ip} → RIOT ({r.name})[/]")
        elif r.noise:
            safe_print(f"  [dim]  {ip} → NOISE (mass scanner)[/]")
        else:
            safe_print(f"  [warning]  {ip} → UNKNOWN (investigate)[/]")

        time.sleep(delay)

    noise_count   = sum(1 for r in results if r.noise)
    riot_count    = sum(1 for r in results if r.riot)
    unknown_count = sum(1 for r in results if not r.noise and not r.riot)

    safe_print(
        f"[success]✔ GreyNoise: {noise_count} noise, "
        f"{riot_count} RIOT, {unknown_count} unknown[/]"
    )

    out_file = out_folder / "greynoise.txt"
    lines = [f"# GreyNoise Results\n"]
    for r in results:
        lines.append(f"{r.ip}: {r.label}")
    out_file.write_text("\n".join(lines))
    return results
