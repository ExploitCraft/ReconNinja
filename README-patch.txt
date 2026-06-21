ReconNinja v10.5.2 — Patch
==========================

Fixes: CI test failure (CHANGELOG missing entry for v10.5.1) +
includes the v10.5.1 scan-results-show-nothing fix.

Files in this zip
-----------------

  version              → info/version               (bumped to 10.5.2)
  orchestrator_v9.py   → core/orchestrator_v9.py    (v10.5.1 scan fix)
  CHANGELOG.md         → CHANGELOG.md               (added 10.5.1 + 10.5.2 entries)
  README.md            → README.md                  (badge bumped)
  PKGBUILD             → aur/PKGBUILD               (pkgver=10.5.2)
  .SRCINFO             → aur/.SRCINFO
  install.sh           → install.sh

What changed
------------

v10.5.1 (scan fix):
  - _w_async_tcp: extract open ports from port_infos (not filtered_ports)
  - _w_async_tcp: create HostResult even when nmap isn't installed
  - _w_nmap: skip if no open ports; merge into existing HostResult

v10.5.2 (CI fix):
  - Added missing CHANGELOG entries for 10.5.1 and 10.5.2
  - Fixes test_changelog_has_entry failure

Tests: 616 passed, 1 skipped.

Apply
-----

    cp version            /path/to/ReconNinja/info/version
    cp orchestrator_v9.py /path/to/ReconNinja/core/orchestrator_v9.py
    cp CHANGELOG.md       /path/to/ReconNinja/CHANGELOG.md
    cp README.md          /path/to/ReconNinja/README.md
    cp PKGBUILD           /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO           /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh         /path/to/ReconNinja/install.sh
