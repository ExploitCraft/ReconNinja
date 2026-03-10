"""
core/updater.py
ReconNinja v3.3 — Self-Update (--update)

Pulls the latest version from GitHub and reinstalls to ~/.reconninja/

Usage:
  ReconNinja --update
  python3 reconninja.py --update
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import urllib.request
import json
import tempfile
import zipfile
from pathlib import Path

from utils.logger import console


GITHUB_USER = "ExploitCraft"
GITHUB_REPO = "ReconNinja"
INSTALL_DIR = Path.home() / ".reconninja"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"


def _get_latest_release() -> tuple[str, str]:
    """
    Query GitHub API for the latest release.
    Returns (tag_name, zip_download_url).
    """
    req = urllib.request.Request(
        RELEASES_API,
        headers={"User-Agent": "ReconNinja-Updater/3.2"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())

    tag     = data["tag_name"]                      # e.g. v5.0.0
    zip_url = data["zipball_url"]                   # GitHub source zip

    # Prefer our attached release asset if it exists
    for asset in data.get("assets", []):
        if asset["name"].endswith(".zip"):
            zip_url = asset["browser_download_url"]
            break

    return tag, zip_url


def _download_zip(url: str, dest: Path) -> None:
    console.print(f"  Downloading from [cyan]{url}[/]...")
    urllib.request.urlretrieve(url, dest)


def _get_current_version() -> str:
    try:
        # Read VERSION from reconninja.py
        entry = INSTALL_DIR / "reconninja.py"
        if entry.exists():
            for line in entry.read_text().splitlines():
                if line.strip().startswith("VERSION"):
                    return line.split("=")[-1].strip().strip('"\'')
    except Exception:
        pass
    return "unknown"


def run_update(force: bool = False) -> bool:
    """
    Check for updates and install the latest version.
    Returns True if updated, False if already up to date.
    """
    console.print("\n[header]  ReconNinja Updater[/]")
    console.print(f"  Install dir: [cyan]{INSTALL_DIR}[/]")

    current = _get_current_version()
    console.print(f"  Current version: [yellow]{current}[/]")

    # ── Check latest release ──────────────────────────────────────────────────
    console.print("  Checking GitHub for latest release...")
    try:
        tag, zip_url = _get_latest_release()
    except Exception as e:
        console.print(f"[danger]  Failed to check for updates: {e}[/]")
        console.print("  Check your internet connection or visit:")
        console.print(f"  https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases")
        return False

    console.print(f"  Latest version:  [green]{tag}[/]")

    # ── Already up to date? ───────────────────────────────────────────────────
    current_clean = current.lstrip("v")
    latest_clean  = tag.lstrip("v")

    if current_clean == latest_clean and not force:
        console.print(f"\n[green]  ✔  Already up to date ({tag})[/]")
        return False

    # ── Download ──────────────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path  = Path(tmp)
        zip_path  = tmp_path / "reconninja_update.zip"
        extract   = tmp_path / "extracted"

        try:
            _download_zip(zip_url, zip_path)
            console.print(f"  Downloaded [cyan]{zip_path.stat().st_size // 1024}KB[/]")
        except Exception as e:
            console.print(f"[danger]  Download failed: {e}[/]")
            return False

        # ── Extract ───────────────────────────────────────────────────────────
        console.print("  Extracting...")
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extract)
        except zipfile.BadZipFile as e:
            console.print(f"[danger]  Bad zip file: {e}[/]")
            return False

        # Find the root folder inside the zip
        extracted_dirs = [d for d in extract.iterdir() if d.is_dir()]
        if not extracted_dirs:
            console.print("[danger]  Empty archive[/]")
            return False
        src_dir = extracted_dirs[0]

        # ── Backup existing install ───────────────────────────────────────────
        if INSTALL_DIR.exists():
            backup = INSTALL_DIR.parent / f".reconninja_backup_{current_clean}"
            console.print(f"  Backing up current install to [dim]{backup}[/]...")
            if backup.exists():
                shutil.rmtree(backup)
            shutil.copytree(INSTALL_DIR, backup)

        # ── Install new version ───────────────────────────────────────────────
        console.print(f"  Installing {tag} to [cyan]{INSTALL_DIR}[/]...")
        try:
            # Copy new files over existing install
            # Preserve reports/ and any user configs
            for item in src_dir.iterdir():
                dest = INSTALL_DIR / item.name
                if item.name in ("reports",):
                    continue   # never overwrite user reports
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

            # Make sure reconninja.py stays executable
            entry = INSTALL_DIR / "reconninja.py"
            if entry.exists():
                entry.chmod(0o755)

        except Exception as e:
            console.print(f"[danger]  Install failed: {e}[/]")
            console.print(f"  Your backup is at: {backup}")
            return False

    # ── Install pip deps ──────────────────────────────────────────────────────
    req_file = INSTALL_DIR / "requirements.txt"
    if req_file.exists():
        console.print("  Installing Python dependencies...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file),
                 "--break-system-packages", "-q"],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError:
            # Try without --break-system-packages
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file), "-q"],
                check=False,
            )

    # ── Done ──────────────────────────────────────────────────────────────────
    console.print(f"\n[green bold]  ✔  Updated to {tag} successfully![/]")
    console.print(f"  Run [cyan]ReconNinja --check-tools[/cyan] to verify everything works.\n")
    return True

def print_update_status():
    current = _get_current_version()
    try:
        latest, _ = _get_latest_release()
    except Exception as e:
        console.print(f"  [dim]Could not check for updates: {e}[/]")
        return
    print(f"  Installed : v{current}")
    print(f"  Latest    : v{latest}")
    if current != latest:
        print(f"  Run: ReconNinja --update")
    else:
        print("  Status    : Up to date")

