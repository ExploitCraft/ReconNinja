"""
ReconNinja v3 — Shared Utilities
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Generator, Optional


# ─── Filesystem ───────────────────────────────────────────────────────────────

def timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    return datetime.now().strftime(fmt)


def ensure_dir(path: Path | str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def sanitize_dirname(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)


# ─── Tool detection ───────────────────────────────────────────────────────────

SECLISTS_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/local/share/seclists",
    Path.home() / "seclists",
    "/opt/seclists",
]

WORDLISTS = {
    "sub": {
        "small":  "Discovery/DNS/subdomains-top1million-5000.txt",
        "medium": "Discovery/DNS/subdomains-top1million-110000.txt",
        "large":  "Discovery/DNS/subdomains-top1million.txt",
    },
    "dir": {
        "small":  "Discovery/Web-Content/common.txt",
        "medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "large":  "Discovery/Web-Content/directory-list-2.3-big.txt",
    },
}


@lru_cache(maxsize=1)
def detect_seclists() -> Optional[Path]:
    for candidate in SECLISTS_CANDIDATES:
        p = Path(candidate)
        if p.exists():
            return p
    return None


@lru_cache(maxsize=None)
def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def get_wordlist(category: str, size: str) -> Optional[Path]:
    seclists = detect_seclists()
    if not seclists:
        return None
    rel = WORDLISTS.get(category, {}).get(size)
    if not rel:
        return None
    candidate = seclists / rel
    if candidate.exists():
        return candidate
    # Fallback to small
    fallback = WORDLISTS.get(category, {}).get("small")
    if fallback:
        fb = seclists / fallback
        return fb if fb.exists() else None
    return None


# ─── Network helpers ──────────────────────────────────────────────────────────

def is_valid_target(target: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(target)
        return True
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(target))


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# ─── Process execution ────────────────────────────────────────────────────────

def run_cmd(
    cmd: list[str],
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    """Execute command → (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ.copy(),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except PermissionError as e:
        return 126, "", f"Permission denied: {e}"
    except Exception as e:
        return 1, "", str(e)


def stream_cmd(cmd: list[str]) -> Generator[str, None, None]:
    """Stream stdout line-by-line."""
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:  # type: ignore[union-attr]
            yield line.rstrip()
        proc.wait()
    except FileNotFoundError:
        yield f"[ERROR] Command not found: {cmd[0]}"
    except Exception as e:
        yield f"[ERROR] {e}"


# ─── Internal minimal wordlist fallback ───────────────────────────────────────

BUILTIN_SUBS = [
    "www","dev","test","stage","staging","api","mail","vpn","admin","beta",
    "ns1","ns2","ftp","ssh","portal","dashboard","auth","login","app","cdn",
    "mx","smtp","pop","imap","webmail","remote","cloud","shop","blog","docs",
    "status","monitor","grafana","jenkins","gitlab","github","jira","confluence",
    "git","svn","backup","db","database","mysql","redis","elastic","kafka",
    "rabbitmq","prometheus","kibana","sonar","ci","cd","build","deploy",
]

BUILTIN_DIRS = [
    "admin","login","dashboard","api","v1","v2","swagger","docs","uploads",
    "static","assets","images","css","js","fonts","media","files","backup",
    "config","settings","manage","console","panel","wp-admin","phpmyadmin",
    "robots.txt","sitemap.xml",".env","health","metrics","actuator","status",
]
