ReconNinja v10.2.0 — Patch Release
==================================

This zip contains ONLY the files modified between v10.1.1 and v10.2.0.
Drop them into your existing v10.1.x checkout, overwriting the old files.

Files in this zip
-----------------

  version                  → info/version
  test_v10_release.py      → tests/test_v10_release.py
  CHANGELOG.md             → CHANGELOG.md
  README.md                → README.md
  PKGBUILD                 → aur/PKGBUILD
  .SRCINFO                 → aur/.SRCINFO
  install.sh               → install.sh

What changed in v10.2.0
-----------------------

CI resilience fix round 2: v10.1.1 only checked for `requests`, but
`core.orchestrator_v9` transitively imports 8 third-party packages:

    requests  →  core.subdomains, core.web, ...
    yaml      →  core.scope_evidence
    dns       →  core.dns_zone_transfer, core.dns_leak  (dnspython)
    bs4       →  core.js_extractor                       (beautifulsoup4)
    cryptography → core.jwt_scan
    ldap3     →  core.ldap_enum
    whois     →  core.whois_lookup                       (python-whois)
    ipwhois   →  core.asn_map

When CI had `requests` but not `pyyaml` (your exact failure), the same
`ModuleNotFoundError` crashed test collection — just for a different
missing dep.

Now tests/test_v10_release.py probes ALL 8 deps up-front and skips every
orchestrator-dependent test under a single `_requires_orchestrator_deps`
marker if ANY of them is missing. The skip message lists the exact
missing packages and the pip-install command needed:

    SKIPPED [1] tests/test_v10_release.py:77: missing transitive deps
    for core.orchestrator_v9: pyyaml — run `pip install -r
    requirements.txt` to enable

Verified scenarios
------------------

  • All 8 deps installed  →  18/18 v10_release tests pass (full suite: 611 passed)
  • Only `yaml` missing   →  8 pass, 10 skip cleanly, exit code 0  ← your CI case
  • All 8 deps missing    →  8 pass, 10 skip cleanly, exit code 0

The 8 unconditional tests cover:
  - save_state / load_state round-trip (both 2-arg and 3-arg forms)
  - schema_version field presence
  - v9 field round-trip (ad_findings, attack_chains, cloud_deep_findings)
  - v10 field round-trip (ai_consensus, aquatone_results)
  - --version / --check-tools / --diff / --update / --gui CLI flags exist
  - Version string starts with "10."

Apply
-----

    unzip ReconNinja-v10.2.0-patch.zip
    cp version                /path/to/ReconNinja/info/version
    cp test_v10_release.py    /path/to/ReconNinja/tests/test_v10_release.py
    cp CHANGELOG.md           /path/to/ReconNinja/CHANGELOG.md
    cp README.md              /path/to/ReconNinja/README.md
    cp PKGBUILD               /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO               /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh             /path/to/ReconNinja/install.sh

    cd /path/to/ReconNinja
    python reconninja.py --version        # → ReconNinja v10.2.0
    python -m pytest tests/               # → 611 passed (with deps installed)
                                         # → 8 passed, 10 skipped (without deps)
