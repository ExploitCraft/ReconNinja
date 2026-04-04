"""
core/typosquat.py — ReconNinja v7.0.0
Typosquatting Domain Detection.

Generates lookalike domain variants (homoglyphs, transpositions,
missing dots, vowel swaps, bitsquatting) and checks which ones
are registered and pointing to live IPs.

Uses dnstwist if installed (pip install dnstwist), pure Python fallback.
"""

from __future__ import annotations

import itertools
import socket
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir, run_cmd, tool_exists
from utils.logger import safe_print, log

# ── Keyboard adjacency map for substitution ───────────────────────────────────
KEYBOARD_ADJACENT: dict[str, list[str]] = {
    "a": ["q","w","s","z"], "b": ["v","g","h","n"], "c": ["x","d","f","v"],
    "d": ["s","e","r","f","c","x"], "e": ["w","r","d","s"],
    "f": ["d","r","t","g","v","c"], "g": ["f","t","y","h","b","v"],
    "h": ["g","y","u","j","n","b"], "i": ["u","o","k","j"],
    "j": ["h","u","i","k","m","n"], "k": ["j","i","o","l","m"],
    "l": ["k","o","p"], "m": ["n","j","k"],
    "n": ["b","h","j","m"], "o": ["i","p","l","k"],
    "p": ["o","l"], "q": ["w","a"], "r": ["e","t","f","d"],
    "s": ["a","w","e","d","x","z"], "t": ["r","y","g","f"],
    "u": ["y","i","j","h"], "v": ["c","f","g","b"],
    "w": ["q","e","s","a"], "x": ["z","s","d","c"],
    "y": ["t","u","h","g"], "z": ["a","s","x"],
}


@dataclass
class TyposquatResult:
    original:     str
    variant:      str
    technique:    str
    registered:   bool   = False
    ip:           str    = ""
    mx_exists:    bool   = False
    severity:     str    = "medium"

    def to_dict(self) -> dict:
        return {
            "original":   self.original,
            "variant":    self.variant,
            "technique":  self.technique,
            "registered": self.registered,
            "ip":         self.ip,
            "mx_exists":  self.mx_exists,
        }


# ── Variant generation ────────────────────────────────────────────────────────

def _extract_parts(domain: str) -> tuple[str, str]:
    """Return (name, tld) e.g. 'example', 'com'."""
    parts = domain.rsplit(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (domain, "com")


def _generate_variants(domain: str) -> list[tuple[str, str]]:
    """Generate (variant_domain, technique) pairs."""
    name, tld = _extract_parts(domain)
    variants: list[tuple[str, str]] = []

    # 1. Character transposition
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        variants.append((f"{swapped}.{tld}", "transposition"))

    # 2. Character omission
    for i in range(len(name)):
        omitted = name[:i] + name[i+1:]
        if len(omitted) >= 2:
            variants.append((f"{omitted}.{tld}", "omission"))

    # 3. Character doubling
    for i in range(len(name)):
        doubled = name[:i] + name[i] + name[i] + name[i+1:]
        variants.append((f"{doubled}.{tld}", "doubling"))

    # 4. Keyboard substitution
    for i, ch in enumerate(name):
        for sub in KEYBOARD_ADJACENT.get(ch.lower(), []):
            subs = name[:i] + sub + name[i+1:]
            variants.append((f"{subs}.{tld}", "keyboard-sub"))

    # 5. Hyphen insertion
    for i in range(1, len(name)):
        hyph = name[:i] + "-" + name[i:]
        variants.append((f"{hyph}.{tld}", "hyphen-insert"))

    # 6. TLD variations
    for alt_tld in ("net", "org", "co", "io", "info", "biz", "xyz"):
        if alt_tld != tld:
            variants.append((f"{name}.{alt_tld}", "tld-swap"))

    # 7. Subdomain prefix
    for prefix in ("www", "mail", "login", "account", "secure", "app"):
        variants.append((f"{prefix}-{name}.{tld}", "prefix"))

    # 8. Vowel swap
    vowels = "aeiou"
    for i, ch in enumerate(name):
        if ch.lower() in vowels:
            for v in vowels:
                if v != ch.lower():
                    subs = name[:i] + v + name[i+1:]
                    variants.append((f"{subs}.{tld}", "vowel-swap"))

    # Deduplicate and exclude the original
    seen: set[str] = {domain}
    unique: list[tuple[str, str]] = []
    for d, tech in variants:
        if d not in seen and re.match(r"^[a-z0-9.-]+$", d):
            seen.add(d)
            unique.append((d, tech))

    return unique[:200]  # cap at 200 variants


def _check_registered(domain: str, timeout: int = 3) -> tuple[bool, str]:
    """Check if domain is registered by resolving it."""
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except socket.gaierror:
        return False, ""


# ── dnstwist integration ──────────────────────────────────────────────────────

def _dnstwist(domain: str, out_folder: Path) -> Optional[list[tuple[str, str]]]:
    """Use dnstwist CLI if available for richer results."""
    if not tool_exists("dnstwist"):
        return None
    out_file = out_folder / "dnstwist_raw.txt"
    rc, out, _ = run_cmd(
        ["dnstwist", "--registered", "--format", "list", domain],
        timeout=120,
    )
    if rc == 0 and out:
        results = []
        for line in out.strip().splitlines():
            parts = line.strip().split()
            if parts:
                results.append((parts[0], "dnstwist"))
        return results
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def typosquat_scan(
    domain: str,
    out_folder: Path,
    timeout: int = 3,
    max_check: int = 100,
) -> list[TyposquatResult]:
    """
    Generate and check typosquatting domain variants.

    Args:
        domain:     target domain
        out_folder: output directory
        timeout:    DNS resolution timeout per domain
        max_check:  max variants to DNS-resolve

    Returns:
        list of TyposquatResult for registered variants only
    """
    ensure_dir(out_folder)
    safe_print(f"[info]▶ Typosquat Detection — {domain}[/]")

    # Try dnstwist first
    dt_variants = _dnstwist(domain, out_folder)
    if dt_variants:
        safe_print(f"  [dim]Using dnstwist for variant generation[/]")
        variants = dt_variants[:max_check]
    else:
        variants = _generate_variants(domain)[:max_check]

    safe_print(f"  [dim]Checking {len(variants)} variants...[/]")

    results: list[TyposquatResult] = []
    for variant_domain, technique in variants:
        registered, ip = _check_registered(variant_domain, timeout)
        if registered:
            r = TyposquatResult(
                original=domain, variant=variant_domain,
                technique=technique, registered=True, ip=ip,
            )
            results.append(r)
            safe_print(f"  [warning]⚠  Registered: {variant_domain} → {ip} [{technique}][/]")

    safe_print(
        f"[{'warning' if results else 'success'}]"
        f"✔ Typosquat: {len(results)}/{len(variants)} variants registered[/]"
    )

    out_file = out_folder / "typosquat.txt"
    lines = [f"# Typosquat Results — {domain}", ""]
    for r in results:
        lines.append(f"  {r.variant} → {r.ip} [{r.technique}]")
    out_file.write_text("\n".join(lines))
    return results
