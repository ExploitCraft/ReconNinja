"""
ReconNinja v3 — Vulnerability Scanning & Screenshots
Nuclei templates + Aquatone visual recon.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from utils.helpers import run_cmd, tool_exists, ensure_dir
from utils.logger import safe_print, log
from utils.models import VulnFinding


# ─── Nuclei ───────────────────────────────────────────────────────────────────

def run_nuclei(target: str, out_folder: Path) -> list[VulnFinding]:
    """
    Run nuclei against a target.
    Returns list of structured VulnFinding objects.
    """
    if not tool_exists("nuclei"):
        safe_print("[dim]nuclei not found — skipping[/]")
        return []

    ensure_dir(out_folder)
    out_file = out_folder / "nuclei.txt"
    json_file = out_folder / "nuclei.json"

    cmd = [
        "nuclei",
        "-u", target,
        "-severity", "medium,high,critical",
        "-silent",
        "-o", str(out_file),
        "-json-export", str(json_file),
        "-nc",          # no color
        "-timeout", "10",
        "-rate-limit", "150",
    ]
    safe_print(f"[info]▶ Nuclei → {target}[/]")
    run_cmd(cmd, timeout=1800)

    findings: list[VulnFinding] = []

    # Parse JSON output for structured results
    if json_file.exists():
        import json
        for line in json_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append(VulnFinding(
                    tool     = "nuclei",
                    severity = info.get("severity", "info"),
                    title    = info.get("name", data.get("template-id", "")),
                    target   = data.get("host", target),
                    details  = data.get("matched-at", ""),
                    cve      = ", ".join(info.get("classification", {}).get("cve-id", [])),
                ))
            except Exception as e:
                log.debug(f"nuclei json parse error: {e}")

    # Fallback: plain text
    if not findings and out_file.exists() and out_file.stat().st_size > 0:
        for line in out_file.read_text().splitlines():
            if line.strip():
                findings.append(VulnFinding(
                    tool="nuclei", severity="info",
                    title=line.strip(), target=target,
                ))

    if findings:
        safe_print(f"[success]✔ Nuclei: {len(findings)} finding(s)[/]")
    else:
        safe_print("[dim]Nuclei: no findings[/]")

    return findings


# ─── Aquatone ─────────────────────────────────────────────────────────────────

def run_aquatone(hosts_file: Path, out_folder: Path) -> Optional[Path]:
    """
    Screenshot web services via Aquatone.
    Uses direct stdin pipe — no shell injection via path.
    """
    if not tool_exists("aquatone"):
        safe_print("[dim]aquatone not found — skipping screenshots[/]")
        return None

    aq_dir = out_folder / "aquatone"
    ensure_dir(aq_dir)

    try:
        with hosts_file.open("rb") as stdin_fh:
            proc = subprocess.run(
                ["aquatone", "-out", str(aq_dir), "-quiet"],
                stdin=stdin_fh,
                capture_output=True,
                timeout=600,
            )
        if proc.returncode == 0:
            safe_print(f"[success]✔ Aquatone screenshots → {aq_dir}[/]")
            return aq_dir
        safe_print(
            f"[warning]Aquatone failed (rc={proc.returncode}): "
            f"{proc.stderr.decode(errors='ignore')[:200]}[/]"
        )
    except subprocess.TimeoutExpired:
        safe_print("[warning]Aquatone timed out[/]")
    except Exception as e:
        safe_print(f"[warning]Aquatone error: {e}[/]")
    return None


# ─── gowitness (alternative to aquatone) ──────────────────────────────────────

def run_gowitness(hosts_file: Path, out_folder: Path) -> Optional[Path]:
    """Screenshot web services with gowitness (modern alternative to aquatone)."""
    if not tool_exists("gowitness"):
        return None

    gw_dir = out_folder / "gowitness"
    ensure_dir(gw_dir)

    cmd = [
        "gowitness",
        "file",
        "-f", str(hosts_file),
        "--screenshot-path", str(gw_dir),
        "--log-level", "error",
    ]
    safe_print("[info]▶ gowitness screenshots[/]")
    rc, _, _ = run_cmd(cmd, timeout=600)
    if rc == 0:
        safe_print(f"[success]✔ gowitness screenshots → {gw_dir}[/]")
        return gw_dir
    return None
