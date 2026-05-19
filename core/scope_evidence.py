"""
ReconNinja v9 — Scope Enforcement Engine
Validates every target/host/URL against the scope policy before any module touches it.
On strict mode, exits immediately if an out-of-scope target is attempted.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from utils.logger import log, safe_print
from utils.models import ScanConfig, ScopePolicy


# ─── Load scope policy ────────────────────────────────────────────────────────

def load_scope_policy(cfg: ScanConfig) -> ScopePolicy:
    """Build ScopePolicy from --scope-file YAML or inline --exclude-targets."""
    allowed: list[str] = []
    excluded: list[str] = list(cfg.exclude_targets or [])
    strict = cfg.scope_strict

    if cfg.scope_file:
        path = Path(cfg.scope_file)
        if path.exists():
            try:
                with path.open() as f:
                    data = yaml.safe_load(f)
                allowed  = data.get("allowed", [])
                excluded += data.get("excluded", [])
                strict    = data.get("strict", strict)
                safe_print(f"[info]  → Scope policy loaded: "
                           f"{len(allowed)} allowed, {len(excluded)} excluded[/]")
            except Exception as e:
                log.warning(f"[scope] Failed to load scope file: {e}")
        else:
            log.warning(f"[scope] Scope file not found: {path}")

    return ScopePolicy(allowed=allowed, excluded=excluded, strict=strict)


# ─── Pre-flight validation ────────────────────────────────────────────────────

def validate_preflight(target: str, policy: ScopePolicy, cfg: ScanConfig) -> bool:
    """
    Check the primary target against scope before any modules run.
    Returns True if in scope, False if OOS (strict mode: exits).
    """
    if not policy.in_scope(target):
        msg = f"[danger]⛔  Target '{target}' is OUT OF SCOPE per scope policy.[/]"
        safe_print(msg)
        if policy.strict:
            safe_print("[danger]Strict mode: aborting scan.[/]")
            sys.exit(1)
        return False
    safe_print(f"[success]  ✔ Target '{target}' in scope[/]")
    return True


def filter_in_scope(targets: list[str], policy: ScopePolicy) -> list[str]:
    """Filter a list of targets, logging any OOS entries."""
    in_scope = []
    for t in targets:
        if policy.in_scope(t):
            in_scope.append(t)
        else:
            log.info(f"[scope] Dropping OOS target: {t}")
    return in_scope


# ─── Evidence collection ──────────────────────────────────────────────────────

"""
ReconNinja v9 — Evidence Collection
Saves raw HTTP requests/responses and screenshots with SHA-256 integrity hashes.
Optional GPG signing for legal chain of custody.
"""

import subprocess
import time
from utils.models import EvidenceItem


def collect_http_evidence(
    finding_id: str,
    url: str,
    out_folder: Path,
    sign_key: str = "",
) -> EvidenceItem | None:
    """Capture raw HTTP request + response for a URL. Returns EvidenceItem."""
    try:
        import requests
        ts = int(time.time())
        req_file = out_folder / f"evidence_{finding_id}_{ts}.http"

        resp = requests.get(url, timeout=15, allow_redirects=False)
        # Build raw evidence blob
        raw = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {url.split('/')[2]}\r\n\r\n"
            f"--- RESPONSE {resp.status_code} ---\r\n"
            + resp.text[:10000]
        )
        req_file.write_text(raw, encoding="utf-8", errors="replace")

        sha = _sha256_file(req_file)
        _maybe_gpg_sign(req_file, sign_key)

        return EvidenceItem(
            finding_id=finding_id,
            type="http_request",
            filename=req_file.name,
            sha256=sha,
            description=f"HTTP capture for {url} — status {resp.status_code}",
        )
    except Exception as e:
        log.warning(f"[evidence] HTTP capture failed for {url}: {e}")
        return None


def collect_screenshot_evidence(
    finding_id: str,
    url: str,
    out_folder: Path,
    sign_key: str = "",
) -> EvidenceItem | None:
    """Take a screenshot using gowitness. Returns EvidenceItem."""
    out_file = out_folder / f"evidence_{finding_id}_screenshot.png"
    try:
        subprocess.run(
            ["gowitness", "single", "--url", url, "--screenshot-path", str(out_file)],
            capture_output=True, timeout=30,
        )
        if out_file.exists():
            sha = _sha256_file(out_file)
            _maybe_gpg_sign(out_file, sign_key)
            return EvidenceItem(
                finding_id=finding_id,
                type="screenshot",
                filename=out_file.name,
                sha256=sha,
                description=f"Screenshot of {url}",
            )
    except FileNotFoundError:
        log.warning("[evidence] gowitness not found — screenshot skipped")
    except Exception as e:
        log.warning(f"[evidence] Screenshot failed for {url}: {e}")
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _maybe_gpg_sign(path: Path, key: str) -> None:
    if not key:
        return
    try:
        subprocess.run(
            ["gpg", "--batch", "--yes", "-u", key, "--detach-sign", str(path)],
            capture_output=True, timeout=15,
        )
    except Exception as e:
        log.warning(f"[evidence] GPG sign failed: {e}")


def write_evidence_manifest(items: list[EvidenceItem], out_folder: Path) -> None:
    """Write a JSON manifest of all collected evidence items."""
    manifest = [
        {
            "finding_id": e.finding_id,
            "type": e.type,
            "filename": e.filename,
            "sha256": e.sha256,
            "description": e.description,
        }
        for e in items
    ]
    manifest_path = out_folder / "evidence_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    safe_print(f"[success]  ✔ Evidence manifest: {manifest_path}[/]")
