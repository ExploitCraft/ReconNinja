"""
ReconNinja v3 — Subdomain Enumeration
Passive + active subdomain discovery with live DNS verification.
"""

from __future__ import annotations

import csv
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from utils.helpers import (
    run_cmd, tool_exists, detect_seclists, get_wordlist,
    resolve_host, ensure_dir, BUILTIN_SUBS
)
from utils.logger import safe_print, log


# ─── Tool wrappers ─────────────────────────────────────────────────────────────

def _subfinder(target: str, out_file: Path) -> bool:
    if not tool_exists("subfinder"):
        return False
    rc, _, _ = run_cmd(
        ["subfinder", "-d", target, "-silent", "-all", "-o", str(out_file)]
    )
    return rc == 0 and out_file.exists() and out_file.stat().st_size > 0


def _amass(target: str, out_file: Path) -> bool:
    if not tool_exists("amass"):
        return False
    rc, _, _ = run_cmd(
        ["amass", "enum", "-passive", "-d", target, "-o", str(out_file)],
        timeout=300,
    )
    return rc == 0 and out_file.exists() and out_file.stat().st_size > 0


def _assetfinder(target: str, out_file: Path) -> bool:
    if not tool_exists("assetfinder"):
        return False
    rc, out, _ = run_cmd(["assetfinder", "--subs-only", target])
    if rc == 0 and out:
        out_file.write_text(out)
        return True
    return False


def _crtsh(target: str, out_file: Path) -> bool:
    """
    Query crt.sh certificate transparency logs (no external tool required).
    """
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/3.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        found: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(f".{target}") or line == target:
                    found.add(line)
        if found:
            out_file.write_text("\n".join(sorted(found)))
            return True
    except Exception as e:
        log.debug(f"crt.sh error: {e}")
    return False


def _ffuf_subdomain(target: str, wordlist: Path, out_file: Path, threads: int = 50) -> bool:
    if not tool_exists("ffuf"):
        return False
    csv_tmp = out_file.with_suffix(".csv")
    cmd = [
        "ffuf", "-w", str(wordlist),
        "-u", f"https://FUZZ.{target}",
        "-mc", "200,204,301,302,307,401,403,405",
        "-t", str(threads),
        "-o", str(csv_tmp), "-of", "csv",
        "-timeout", "10", "-silent",
    ]
    run_cmd(cmd, timeout=600)
    if csv_tmp.exists():
        found: set[str] = set()
        with csv_tmp.open(errors="ignore") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                try:
                    from urllib.parse import urlparse
                    host = urlparse(row[0]).netloc
                    if host and (host.endswith("." + target) or host == target):
                        found.add(host)
                except Exception:
                    pass
        if found:
            out_file.write_text("\n".join(sorted(found)))
            return True
    return False


def _dns_brute(
    target: str, wordlist: Optional[Path], out_file: Path, custom_list: Optional[list[str]] = None
) -> bool:
    """DNS brute force — uses wordlist file or built-in list."""
    names = custom_list or []
    if wordlist and wordlist.exists() and not names:
        with wordlist.open(errors="ignore") as fh:
            names = [l.strip() for l in fh if l.strip()]

    found: set[str] = set()
    safe_print(f"[dim]DNS brute: testing {len(names):,} names...[/]")

    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(resolve_host, f"{n}.{target}"): f"{n}.{target}" for n in names}
        for fut in as_completed(futures):
            fqdn = futures[fut]
            try:
                if fut.result() is not None:
                    found.add(fqdn)
            except Exception:
                pass

    if found:
        out_file.write_text("\n".join(sorted(found)))
        return True
    return False


# ─── Orchestrator ──────────────────────────────────────────────────────────────

def subdomain_enum(
    target: str, out_folder: Path, wordlist_size: str = "medium"
) -> list[str]:
    """
    Full subdomain enumeration pipeline.
    Returns sorted list of live (DNS-verified) subdomains.
    """
    ensure_dir(out_folder)
    all_subs: set[str] = set()

    def _try(label: str, fn, *args) -> bool:
        tmp = out_folder / f"subs_{label}.txt"
        safe_print(f"[info]  → {label}...[/]")
        try:
            ok = fn(*args, tmp)
            if ok and tmp.exists():
                lines = {l.strip() for l in tmp.read_text().splitlines() if l.strip()}
                safe_print(f"[success]  ✔ {label}: {len(lines)} found[/]")
                all_subs.update(lines)
                return True
        except Exception as e:
            log.debug(f"{label} error: {e}")
        safe_print(f"[dim]  ✘ {label}: no results[/]")
        return False

    # Passive tools
    _try("subfinder",    _subfinder,   target)
    _try("amass",        _amass,       target)
    _try("assetfinder",  _assetfinder, target)
    _try("crt.sh",       _crtsh,       target)

    # Active brute if passive yielded nothing
    if not all_subs:
        wl = get_wordlist("sub", wordlist_size)
        if wl:
            if not _try("ffuf", _ffuf_subdomain, target, wl):
                _try("dns-brute", _dns_brute, target, wl)
        else:
            safe_print("[dim]No wordlist found — using built-in minimal list[/]")
            tmp_builtin = out_folder / "subs_builtin_brute.txt"
            _try("dns-brute-builtin", _dns_brute, target, None, BUILTIN_SUBS)

    # DNS verification (filter dead entries)
    if all_subs:
        safe_print(f"[info]Verifying {len(all_subs)} subdomains...[/]")
        live: set[str] = set()
        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = {ex.submit(resolve_host, s): s for s in all_subs}
            for fut in as_completed(futures):
                try:
                    if fut.result() is not None:
                        live.add(futures[fut])
                except Exception:
                    pass
        all_subs = live

    merged_file = out_folder / "subdomains_merged.txt"
    merged_file.write_text("\n".join(sorted(all_subs)))
    safe_print(f"[success]✔ {len(all_subs)} live subdomains → {merged_file}[/]")
    return sorted(all_subs)
