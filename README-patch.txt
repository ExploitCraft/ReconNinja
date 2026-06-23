ReconNinja v10.6.0 — Patch
==========================

Fixes the critical TypeError that crashed every port-scan-only run.

Files in this zip
-----------------

  version                  → info/version                (bumped to 10.6.0)
  orchestrator_v9.py       → core/orchestrator_v9.py     (THE FIX)
  test_v10_6_wrappers.py   → tests/test_v10_6_wrappers.py (NEW — 56 audit tests)
  CHANGELOG.md             → CHANGELOG.md                (v10.6.0 entry)
  README.md                → README.md                   (badge bumped)
  PKGBUILD                 → aur/PKGBUILD                (refreshed per maintainer)
  .SRCINFO                 → aur/.SRCINFO
  install.sh               → install.sh

What was broken
---------------

When you ran menu option [04] Port Scan Only against 192.168.0.1, the
scan crashed with:

  ERROR  Phase 'rustscan' failed: can only concatenate list (not "set") to list
  File "core/orchestrator_v9.py", line 854, in _w_rustscan
    result.rustscan_ports = sorted(set(result.rustscan_ports + (ports or set())))

Root cause: run_rustscan() returns set[int], run_masscan() returns
(Path|None, set[int]). The wrappers did `list + set` which Python
forbids. This crashed every port-scan-only invocation.

The fix
-------

_w_rustscan and _w_masscan now use set-union:

  merged = set(result.rustscan_ports) | set(ports or [])
  result.rustscan_ports = sorted(merged)

Comprehensive audit
-------------------

I wrote tests/test_v10_6_wrappers.py — 56 new tests that mock every v8
module and invoke every _w_<phase> wrapper with controlled inputs.
Each test verifies the wrapper runs without raising and that the result
field is populated correctly.

Coverage:
  • Port-scan wrappers: rustscan (set/empty/merge), masscan (set/empty),
    async_tcp (creates HostResult), nmap (skips empty, merges existing)
  • Passive OSINT: whois, wayback, ssl, subdomains, github_osint,
    shodan (no-hosts fallback, with-hosts bulk, missing-key),
    virustotal (iterates subdomains + hosts)
  • 24 web-phase wrappers parametrized over list + dict returns
  • AI wrappers: ai_consensus, attack_paths, ai_remediate
  • Report wrappers: sarif_export, devops (terraform + jenkins)
  • CVE lookup: iterates hosts, handles empty
  • FULL_SUITE registration smoke test

All 56 pass. Full suite: 672 passed, 1 skipped.

PKGBUILD refresh
----------------

Incorporated your updated PKGBUILD structure (cleaner depends/optdepends
formatting). Re-added the zsh + fish completion blocks you omitted for
brevity, and added the new --tui/--menu/--no-tui/--version/--check-tools
/--update/--diff/--gui flags to the bash completion list.

Apply
-----

    cp version                /path/to/ReconNinja/info/version
    cp orchestrator_v9.py     /path/to/ReconNinja/core/orchestrator_v9.py
    cp test_v10_6_wrappers.py /path/to/ReconNinja/tests/test_v10_6_wrappers.py
    cp CHANGELOG.md           /path/to/ReconNinja/CHANGELOG.md
    cp README.md              /path/to/ReconNinja/README.md
    cp PKGBUILD               /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO               /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh             /path/to/ReconNinja/install.sh

Verify
------

    python reconninja.py --version        # → ReconNinja v10.6.0
    python reconninja.py                  # → menu → [04] Port Scan → 192.168.0.1
    # should now complete without TypeError
    python -m pytest tests/               # → 672 passed, 1 skipped
