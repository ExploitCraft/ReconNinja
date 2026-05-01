"""
core/updater.py
ReconNinja v8.1.0 — Self-Update (--update / --force-update)

Update strategy (in order):
  1. git pull origin main  — if ~/.reconninja is a git repo (fastest, always latest)
  2. GitHub release zip    — fallback if git is not available or not a git repo

Usage:
  ReconNinja --update
  ReconNinja --force-update
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from utils.logger import console

# ── Constants ─────────────────────────────────────────────────────────────────
GITHUB_USER  = "ExploitCraft"
GITHUB_REPO  = "ReconNinja"
INSTALL_DIR  = Path.home() / ".reconninja"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
REPO_URL     = f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}.git"
BRANCH       = "main"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_current_version() -> str:
    """Read VERSION string from the installed reconninja.py."""
    try:
        entry = INSTALL_DIR / "reconninja.py"
        if entry.exists():
            for line in entry.read_text().splitlines():
                if line.strip().startswith("VERSION"):
                    return line.split("=")[-1].strip().strip('"\'')
    except Exception:
        pass
    return "unknown"


def _get_latest_release() -> tuple[str, str]:
    """
    Query GitHub API for the latest release.
    Returns (tag_name, zip_download_url).
    """
    req = urllib.request.Request(
        RELEASES_API,
        headers={"User-Agent": f"ReconNinja-Updater/8.1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())

    tag     = data["tag_name"]
    zip_url = data["zipball_url"]

    for asset in data.get("assets", []):
        if asset["name"].endswith(".zip"):
            zip_url = asset["browser_download_url"]
            break

    return tag, zip_url


def _git_available() -> bool:
    return shutil.which("git") is not None


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _run_git(*args: str, cwd: Path) -> tuple[bool, str]:
    """Run a git command. Returns (success, combined_output)."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "git command timed out"
    except Exception as e:
        return False, str(e)


def _install_pip_deps() -> None:
    """Install / upgrade Python dependencies from requirements.txt."""
    req_file = INSTALL_DIR / "requirements.txt"
    if not req_file.exists():
        return
    console.print("  Installing Python dependencies...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req_file),
             "--break-system-packages", "-q"],
            check=True, capture_output=True, timeout=300,
        )
        console.print("  [green]✔[/]  Dependencies up to date")
    except subprocess.CalledProcessError:
        # Try without --break-system-packages (some systems don't need it)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req_file), "-q"],
            check=False, timeout=300,
        )


# ── Strategy 1: git pull ──────────────────────────────────────────────────────

def _update_via_git(force: bool) -> bool:
    """
    Pull latest changes into ~/.reconninja using git.
    Returns True on success, False on failure.
    """
    console.print(f"  [cyan]Strategy:[/] git pull origin {BRANCH}")

    # Make sure remote is set correctly
    ok, out = _run_git("remote", "get-url", "origin", cwd=INSTALL_DIR)
    if ok:
        console.print(f"  Remote: [dim]{out}[/]")
    else:
        # No remote — add it
        console.print(f"  Adding remote origin → [dim]{REPO_URL}[/]")
        ok, out = _run_git("remote", "add", "origin", REPO_URL, cwd=INSTALL_DIR)
        if not ok:
            console.print(f"  [warning]Could not add remote: {out}[/]")

    # Fetch first so we can compare
    console.print("  Fetching from origin...")
    ok, out = _run_git("fetch", "origin", BRANCH, cwd=INSTALL_DIR)
    if not ok:
        console.print(f"  [danger]git fetch failed: {out}[/]")
        return False

    # Check if we're already up to date
    ok, local  = _run_git("rev-parse", "HEAD",             cwd=INSTALL_DIR)
    ok2, remote = _run_git("rev-parse", f"origin/{BRANCH}", cwd=INSTALL_DIR)

    if ok and ok2 and local == remote and not force:
        console.print(f"\n  [green]✔  Already up to date[/] [dim](HEAD {local[:8]})[/]")
        return True   # not an error — just nothing to do

    # Pull
    console.print(f"  Pulling origin/{BRANCH}...")
    ok, out = _run_git("pull", "origin", BRANCH, cwd=INSTALL_DIR)
    if not ok:
        console.print(f"  [danger]git pull failed:[/]\n  {out}")
        return False

    # Show what changed
    if out and "Already up to date" not in out:
        console.print(f"  [dim]{out}[/]")

    # Make reconninja.py executable
    entry = INSTALL_DIR / "reconninja.py"
    if entry.exists():
        entry.chmod(0o755)

    return True


def _clone_fresh() -> bool:
    """
    ~/.reconninja exists but is not a git repo.
    Clone the repo into a temp dir then copy files over.
    """
    console.print(f"  [dim]~/.reconninja is not a git repo — cloning fresh...[/]")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / "reconninja"
        ok, out = _run_git(
            "clone", "--depth", "1", "--branch", BRANCH, REPO_URL, str(tmp_path),
            cwd=Path(tmp),
        )
        if not ok:
            console.print(f"  [danger]git clone failed: {out}[/]")
            return False

        console.print("  Copying files to ~/.reconninja...")
        for item in tmp_path.iterdir():
            dest = INSTALL_DIR / item.name
            if item.name in ("reports",):
                continue  # never overwrite user reports
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

    entry = INSTALL_DIR / "reconninja.py"
    if entry.exists():
        entry.chmod(0o755)

    return True


# ── Strategy 2: zip download (fallback) ───────────────────────────────────────

def _update_via_zip(tag: str, zip_url: str, current_clean: str) -> bool:
    """
    Download the GitHub release zip and install it.
    Returns True on success.
    """
    console.print(f"  [cyan]Strategy:[/] GitHub release zip ({tag})")
    console.print(f"  Downloading from [dim]{zip_url}[/]...")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "reconninja_update.zip"
        extract  = tmp_path / "extracted"

        try:
            urllib.request.urlretrieve(zip_url, zip_path)
            console.print(f"  Downloaded [dim]{zip_path.stat().st_size // 1024} KB[/]")
        except Exception as e:
            console.print(f"  [danger]Download failed: {e}[/]")
            return False

        console.print("  Extracting...")
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extract)
        except zipfile.BadZipFile as e:
            console.print(f"  [danger]Bad zip: {e}[/]")
            return False

        extracted_dirs = [d for d in extract.iterdir() if d.is_dir()]
        if not extracted_dirs:
            console.print("  [danger]Empty archive[/]")
            return False
        src_dir = extracted_dirs[0]

        # Backup
        backup: Path | None = None
        if INSTALL_DIR.exists():
            backup = INSTALL_DIR.parent / f".reconninja_backup_{current_clean}"
            console.print(f"  Backing up to [dim]{backup}[/]...")
            if backup.exists():
                shutil.rmtree(backup)
            shutil.copytree(INSTALL_DIR, backup)

        # Install
        console.print(f"  Installing {tag} → [dim]{INSTALL_DIR}[/]...")
        try:
            for item in src_dir.iterdir():
                dest = INSTALL_DIR / item.name
                if item.name in ("reports",):
                    continue
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
            (INSTALL_DIR / "reconninja.py").chmod(0o755)
        except Exception as e:
            console.print(f"  [danger]Install failed: {e}[/]")
            if backup:
                console.print(f"  Backup preserved at: {backup}")
            return False

    return True


# ── Public entry point ─────────────────────────────────────────────────────────

def run_update(force: bool = False) -> bool:
    """
    Check for updates and install the latest version.

    Order of preference:
      1. git pull origin main   (if git available + ~/.reconninja is a git repo)
      2. git clone → copy       (if git available but not a git repo)
      3. GitHub release zip     (fallback — no git required)

    Returns True if updated/already-latest, False on error.
    """
    console.rule("[bold cyan]ReconNinja Updater[/]")
    console.print(f"  Install dir : [cyan]{INSTALL_DIR}[/]")

    current = _get_current_version()
    console.print(f"  Version     : [yellow]{current}[/]")

    if not INSTALL_DIR.exists():
        console.print(f"  [danger]~/.reconninja does not exist — run install.sh first[/]")
        return False

    updated = False

    # ── Path A: git ────────────────────────────────────────────────────────────
    if _git_available():
        if _is_git_repo(INSTALL_DIR):
            console.print("")
            updated = _update_via_git(force)
        else:
            console.print("")
            console.print("  [dim]~/.reconninja exists but has no .git — will clone and copy[/]")
            updated = _clone_fresh()

        if updated:
            _install_pip_deps()
            new_ver = _get_current_version()
            console.print("")
            console.rule("[bold green]✔  Update complete[/]")
            console.print(f"  [dim]{current}[/] → [green bold]{new_ver}[/]")
            console.print("  Run [cyan]ReconNinja --check-tools[/] to verify everything works.\n")
            return True
        else:
            console.print("  [warning]git update failed — trying release zip fallback...[/]")
    else:
        console.print("  [dim]git not found — using release zip[/]")

    # ── Path B: release zip fallback ───────────────────────────────────────────
    console.print("  Checking GitHub releases...")
    try:
        tag, zip_url = _get_latest_release()
    except Exception as e:
        console.print(f"  [danger]Cannot reach GitHub: {e}[/]")
        console.print(f"  Visit: https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases")
        return False

    console.print(f"  Latest release : [green]{tag}[/]")

    current_clean = current.lstrip("v")
    latest_clean  = tag.lstrip("v")

    if current_clean == latest_clean and not force:
        console.print(f"\n  [green]✔  Already up to date ({tag})[/]\n")
        return True

    updated = _update_via_zip(tag, zip_url, current_clean)
    if updated:
        _install_pip_deps()
        new_ver = _get_current_version()
        console.print("")
        console.rule("[bold green]✔  Update complete[/]")
        console.print(f"  [dim]{current}[/] → [green bold]{new_ver}[/]")
        console.print("  Run [cyan]ReconNinja --check-tools[/] to verify everything works.\n")
    else:
        console.print("\n  [danger]Update failed. Check errors above.[/]\n")

    return updated


def print_update_status() -> None:
    """Print current vs latest version (no install)."""
    current = _get_current_version()
    is_git  = _git_available() and _is_git_repo(INSTALL_DIR)

    console.print(f"  Installed : [yellow]{current}[/]")

    if is_git:
        ok, out = _run_git("log", "-1", "--format=%h %s", cwd=INSTALL_DIR)
        if ok:
            console.print(f"  Commit    : [dim]{out}[/]")

    try:
        latest, _ = _get_latest_release()
        console.print(f"  Latest    : [green]{latest}[/]")
        if current.lstrip("v") != latest.lstrip("v"):
            console.print("  [warning]Update available — run: ReconNinja --update[/]")
        else:
            console.print("  Status    : [green]Up to date[/]")
    except Exception as e:
        console.print(f"  [dim]Could not check GitHub: {e}[/]")
