"""
ReconNinja v3 — Web Recon
httpx live detection, WhatWeb fingerprinting, Nikto, directory brute-force.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from utils.helpers import run_cmd, tool_exists, get_wordlist, ensure_dir, BUILTIN_DIRS
from utils.logger import safe_print, log
from utils.models import WebFinding, HostResult, WEB_PORTS


# ─── httpx ────────────────────────────────────────────────────────────────────

def run_httpx(targets: list[str], out_folder: Path) -> list[WebFinding]:
    """
    Probe targets for live web services using httpx.
    Falls back to manual HTTP check if httpx unavailable.
    """
    ensure_dir(out_folder)
    findings: list[WebFinding] = []

    if not tool_exists("httpx"):
        safe_print("[dim]httpx not found — skipping live web detection[/]")
        return findings

    # Write targets to temp file
    targets_file = out_folder / "httpx_targets.txt"
    urls: list[str] = []
    for t in targets:
        if not t.startswith("http"):
            urls += [f"http://{t}", f"https://{t}"]
        else:
            urls.append(t)
    targets_file.write_text("\n".join(urls))

    out_file  = out_folder / "httpx_results.json"
    cmd = [
        "httpx",
        "-l", str(targets_file),
        "-json",
        "-o", str(out_file),
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-server",
        "-silent",
        "-follow-redirects",
        "-threads", "50",
        "-timeout", "10",
    ]
    safe_print(f"[info]▶ httpx — probing {len(targets)} target(s)[/]")
    run_cmd(cmd, timeout=300)

    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(WebFinding(
                    url           = data.get("url", ""),
                    status_code   = data.get("status-code", data.get("status_code", 0)),
                    title         = data.get("title", ""),
                    technologies  = data.get("technologies", data.get("tech", [])),
                    server        = data.get("webserver", data.get("server", "")),
                    content_length= int(data.get("content-length", data.get("content_length", 0)) or 0),
                ))
            except (json.JSONDecodeError, ValueError) as e:
                log.debug(f"httpx parse error: {e} — line: {line[:80]}")

        safe_print(f"[success]✔ httpx: {len(findings)} live web services[/]")

    return findings


def enrich_hosts_with_web(
    hosts: list[HostResult], web_findings: list[WebFinding]
) -> None:
    """Attach discovered web URLs back to their HostResult."""
    url_map: dict[str, list[str]] = {}
    for wf in web_findings:
        parsed = urlparse(wf.url)
        host = parsed.hostname or ""
        url_map.setdefault(host, []).append(wf.url)

    for host in hosts:
        # Match by IP or hostnames
        keys = [host.ip] + host.hostnames + (
            [host.source_subdomain] if host.source_subdomain else []
        )
        for key in keys:
            if key in url_map:
                host.web_urls = list(set(host.web_urls + url_map[key]))


# ─── WhatWeb ──────────────────────────────────────────────────────────────────

def run_whatweb(target_url: str, out_folder: Path) -> Optional[Path]:
    ensure_dir(out_folder)
    if not tool_exists("whatweb"):
        safe_print("[dim]whatweb not found — skipping[/]")
        return None
    out_file = out_folder / "whatweb.txt"
    run_cmd(
        ["whatweb", "--color=never", "--log-verbose", str(out_file), target_url],
        timeout=120,
    )
    if out_file.exists():
        safe_print(f"[success]✔ whatweb → {out_file}[/]")
        return out_file
    return None


# ─── Nikto ────────────────────────────────────────────────────────────────────

def run_nikto(target_url: str, out_folder: Path) -> Optional[Path]:
    ensure_dir(out_folder)
    if not tool_exists("nikto"):
        safe_print("[dim]nikto not found — skipping[/]")
        return None
    out_file = out_folder / "nikto.txt"
    run_cmd(
        [
            "nikto", "-h", target_url,
            "-output", str(out_file), "-Format", "txt", "-nointeractive",
        ],
        timeout=600,
    )
    if out_file.exists():
        safe_print(f"[success]✔ Nikto → {out_file}[/]")
        return out_file
    return None


# ─── Directory brute force ────────────────────────────────────────────────────

def run_dir_scan(
    target_url: str, out_folder: Path, wordlist_size: str = "small"
) -> Optional[Path]:
    ensure_dir(out_folder)
    out_file = out_folder / "dirscan.txt"
    wl = get_wordlist("dir", wordlist_size)

    # feroxbuster preferred
    if tool_exists("feroxbuster"):
        cmd = [
            "feroxbuster",
            "-u", target_url,
            "--no-recursion", "-q",
            "-t", "50",
            "-o", str(out_file),
        ]
        if wl:
            cmd += ["-w", str(wl)]
        safe_print(f"[info]▶ feroxbuster → {target_url}[/]")
        run_cmd(cmd, timeout=600)
        if out_file.exists() and out_file.stat().st_size > 0:
            safe_print(f"[success]✔ feroxbuster → {out_file}[/]")
            return out_file

    # ffuf fallback
    if tool_exists("ffuf") and wl:
        ffuf_out = out_folder / "ffuf_dir.csv"
        cmd = [
            "ffuf", "-w", str(wl),
            "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "50",
            "-o", str(ffuf_out), "-of", "csv",
            "-timeout", "10", "-silent",
        ]
        safe_print(f"[info]▶ ffuf dir-scan → {target_url}[/]")
        run_cmd(cmd, timeout=600)
        if ffuf_out.exists():
            findings = []
            with ffuf_out.open(errors="ignore") as f:
                for row in csv.reader(f):
                    if row:
                        findings.append(row[0])
            out_file.write_text("\n".join(findings))
            safe_print(f"[success]✔ ffuf dir-scan → {out_file}[/]")
            return out_file

    # dirsearch fallback
    if tool_exists("dirsearch"):
        cmd = [
            "dirsearch",
            "-u", target_url,
            "-o", str(out_file),
            "--format", "plain",
            "-q",
        ]
        if wl:
            cmd += ["-w", str(wl)]
        safe_print(f"[info]▶ dirsearch → {target_url}[/]")
        run_cmd(cmd, timeout=600)
        if out_file.exists() and out_file.stat().st_size > 0:
            safe_print(f"[success]✔ dirsearch → {out_file}[/]")
            return out_file

    safe_print("[warning]No dir-scan tool available (feroxbuster/ffuf/dirsearch)[/]")
    return None
