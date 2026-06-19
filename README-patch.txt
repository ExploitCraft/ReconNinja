ReconNinja v10.1.1 — Patch Release
==================================

This zip contains ONLY the files modified between v10.1.0 and v10.1.1.
Drop them into your existing v10.1.0 checkout, overwriting the old files.

Files in this zip
-----------------

  version                  → info/version
  test_v10_release.py      → tests/test_v10_release.py
  CHANGELOG.md             → CHANGELOG.md
  README.md                → README.md
  PKGBUILD                 → aur/PKGBUILD
  .SRCINFO                 → aur/.SRCINFO
  install.sh               → install.sh

What changed in v10.1.1
-----------------------

CI resilience fix: tests/test_v10_release.py now gracefully skips the 10
tests that transitively `import requests` (via core.orchestrator_v9 →
core.subdomains etc.) when requests isn't installed. Previously these
raised ModuleNotFoundError at test-collection time, which crashed the
whole pytest run with 4 hard failures on CI environments that ran the
legacy v9.1.2 workflow (`pip install rich pytest flake8`).

Now:
  • With requests installed (normal case) → all 18 v10_release tests pass.
  • Without requests (minimal CI) → 8 tests pass, 10 skip with a clear
    "run pip install -r requirements.txt to enable" message, exit code 0.

The 8 unconditional tests cover:
  - save_state / load_state round-trip (both 2-arg and 3-arg forms)
  - schema_version field presence
  - v9 field round-trip (ad_findings, attack_chains, cloud_deep_findings)
  - v10 field round-trip (ai_consensus, aquatone_results)
  - --version / --check-tools / --diff / --update / --gui CLI flags exist
  - Version string starts with "10."

Verification
------------

    unzip ReconNinja-v10.1.1-patch.zip
    # Copy files into your v10.1.0 tree:
    cp version                /path/to/ReconNinja/info/version
    cp test_v10_release.py    /path/to/ReconNinja/tests/test_v10_release.py
    cp CHANGELOG.md           /path/to/ReconNinja/CHANGELOG.md
    cp README.md              /path/to/ReconNinja/README.md
    cp PKGBUILD               /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO               /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh             /path/to/ReconNinja/install.sh

    cd /path/to/ReconNinja
    python reconninja.py --version        # → ReconNinja v10.1.1
    python -m pytest tests/               # → 611 passed (with requests installed)
