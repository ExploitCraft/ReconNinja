"""
info — single source of truth for ReconNinja metadata.

Any file that needs the version should import from here:

    from info import __version__

To bump the version, edit only:  info/version
"""

from pathlib import Path

# Read the plain-text version file so this is the ONE place to change it.
__version__: str = (Path(__file__).parent / "version").read_text(encoding="utf-8").strip()
