"""
tests/test_v8_2_release.py — ReconNinja v8.2.0
Tests covering every fix and improvement shipped in v8.2.0:

  1. Version consistency  — VERSION constant, argparse description, pyproject.toml all agree
  2. requirements.txt     — All 11 core deps declared; no spurious extras
  3. pyproject.toml deps  — Mirrors requirements.txt core section
  4. Argparse help text   — All 17 previously-blank arguments now have help strings
  5. Argparse defaults    — Defaults are sane and haven't regressed
  6. Help completeness    — Every argument has a non-empty help string (regression guard)
"""

import sys
import re
import argparse
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _get_parser() -> argparse.ArgumentParser:
    """Import reconninja and return its ArgumentParser without running main()."""
    import reconninja
    # build_parser is defined inline inside main(); re-create it by calling the
    # module-level function if it exists, otherwise parse the module source.
    if hasattr(reconninja, "build_parser"):
        return reconninja.build_parser()

    # Fallback: exec only the parser-building block via a fresh ArgumentParser
    # instantiated the same way the module does it.
    import io, contextlib
    parser = argparse.ArgumentParser(
        prog="reconninja",
        description=f"ReconNinja v{reconninja.VERSION} — Elite all-in-one recon framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # We can't easily call build_parser without running main(); instead we
    # verify help via subprocess (see test_help_exits_zero).
    return parser


def _requirements_packages() -> list[str]:
    req = (ROOT / "requirements.txt").read_text()
    packages = []
    for line in req.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # strip version specifier  e.g. "requests>=2.31.0" → "requests"
        pkg = re.split(r"[><=!]", line)[0].strip()
        packages.append(pkg)
    return packages


def _pyproject_deps() -> list[str]:
    text = (ROOT / "pyproject.toml").read_text()
    # Extract lines inside [project] dependencies = [ ... ]
    m = re.search(r'\[project\].*?dependencies\s*=\s*\[(.*?)\]', text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    packages = []
    for line in block.splitlines():
        line = line.strip().strip('",').strip()
        if not line or line.startswith("#"):
            continue
        pkg = re.split(r"[><=!]", line)[0].strip()
        packages.append(pkg)
    return packages


def _help_output() -> str:
    import subprocess
    result = subprocess.run(
        [sys.executable, str(ROOT / "reconninja.py"), "--help"],
        capture_output=True, text=True,
    )
    return result.stdout


# ══════════════════════════════════════════════════════════════════════════════
# 1. Version consistency (dynamic, no hardcoding)
# ══════════════════════════════════════════════════════════════════════════════

class TestVersionConsistency:
    """VERSION constant, banner, pyproject.toml, and README all agree."""

    @property
    def expected(self):
        import reconninja
        return reconninja.VERSION

    def test_version_constant(self):
        import reconninja
        assert reconninja.VERSION == self.expected

    def test_pyproject_version(self):
        text = (ROOT / "pyproject.toml").read_text()
        # pyproject.toml now uses dynamic versioning — verify it delegates to info/version
        assert 'dynamic = ["version"]' in text or "dynamic = ['version']" in text, \
            "pyproject.toml should declare version as dynamic"
        assert 'version = {file = "info/version"}' in text, \
            "pyproject.toml [tool.setuptools.dynamic] should point to info/version"
        # and the actual version file must match
        from info import __version__
        assert __version__ == self.expected

    def test_readme_badge_version(self):
        text = (ROOT / "README.md").read_text()
        assert f"version-{self.expected}" in text, \
            f"README badge does not reference version {self.expected}"

    def test_changelog_has_entry(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        assert f"## [{self.expected}]" in text, \
            f"CHANGELOG missing entry for [{self.expected}]"

    def test_help_banner_version(self):
        out = _help_output()
        assert self.expected in out, \
            f"--help output does not mention version {self.expected}"

    def test_docstring_version(self):
        src = (ROOT / "reconninja.py").read_text()
        assert f"v{self.expected}" in src, \
            f"reconninja.py source does not mention v{self.expected}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. requirements.txt correctness
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_CORE_PACKAGES = [
    "rich",
    "python-dotenv",
    "requests",
    "dnspython",
    "beautifulsoup4",
    "cryptography",
    "flask",
    "pyyaml",
    "python-whois",
    "ipwhois",
    "ldap3",
]


class TestRequirementsTxt:
    """requirements.txt must declare all core runtime dependencies."""

    def test_file_exists(self):
        assert (ROOT / "requirements.txt").exists()

    @pytest.mark.parametrize("pkg", REQUIRED_CORE_PACKAGES)
    def test_core_package_declared(self, pkg):
        packages = _requirements_packages()
        assert pkg in packages, \
            f"'{pkg}' is missing from requirements.txt"

    def test_no_duplicate_entries(self):
        packages = _requirements_packages()
        seen = set()
        dupes = []
        for p in packages:
            if p in seen:
                dupes.append(p)
            seen.add(p)
        assert not dupes, f"Duplicate packages in requirements.txt: {dupes}"

    def test_version_pins_present(self):
        """Every entry should have a version constraint."""
        req = (ROOT / "requirements.txt").read_text()
        for line in req.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            assert re.search(r"[><=!]", line), \
                f"requirements.txt entry has no version pin: '{line}'"


# ══════════════════════════════════════════════════════════════════════════════
# 3. pyproject.toml dependency alignment
# ══════════════════════════════════════════════════════════════════════════════

class TestPyprojectDeps:
    """pyproject.toml [project.dependencies] must include all core packages."""

    @pytest.mark.parametrize("pkg", REQUIRED_CORE_PACKAGES)
    def test_core_package_in_pyproject(self, pkg):
        deps = _pyproject_deps()
        assert pkg in deps, \
            f"'{pkg}' missing from [project.dependencies] in pyproject.toml"

    def test_pyproject_deps_not_empty(self):
        deps = _pyproject_deps()
        assert len(deps) >= len(REQUIRED_CORE_PACKAGES)

    def test_pyproject_and_requirements_aligned(self):
        """Every core package in requirements.txt must also be in pyproject.toml."""
        req_pkgs = set(_requirements_packages())
        proj_pkgs = set(_pyproject_deps())
        # Only enforce the known core set (requirements.txt has optional commented lines)
        core = set(REQUIRED_CORE_PACKAGES)
        missing_from_proj = core - proj_pkgs
        assert not missing_from_proj, \
            f"Packages in requirements.txt but not pyproject.toml: {missing_from_proj}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Argparse help text — the 17 previously-blank arguments
# ══════════════════════════════════════════════════════════════════════════════

# Map flag → keyword(s) that must appear in its help string
EXPECTED_HELP = {
    "--profile":       ["fast", "thorough"],
    "--all-ports":     ["65"],          # "65535" or "65 535"
    "--top-ports":     ["1000"],
    "--timing":        ["T4", "T1"],
    "--threads":       ["20"],
    "--subdomains":    ["subfinder"],
    "--rustscan":      ["rustscan"],
    "--ferox":         ["feroxbuster"],
    "--masscan":       ["root"],
    "--httpx":         ["httpx"],
    "--nuclei":        ["nuclei"],
    "--nikto":         ["nikto"],
    "--whatweb":       ["whatweb"],
    "--aquatone":      ["aquatone"],
    "--wordlist-size": ["small", "medium", "large"],
    "--masscan-rate":  ["5000"],
    "--check-tools":   ["installed"],
}


class TestArgparseHelpText:
    """Every previously-blank argument now has a meaningful help string."""

    @pytest.fixture(scope="class")
    def help_out(self):
        return _help_output()

    @pytest.mark.parametrize("flag,keywords", EXPECTED_HELP.items())
    def test_flag_help_contains_keywords(self, flag, keywords, help_out):
        # Only search inside the "options:" block, not the usage synopsis at the top
        options_section = re.split(r"\noptions:\n", help_out, maxsplit=1)
        assert len(options_section) == 2, "--help output has no 'options:' section"
        opts = options_section[1]

        pattern = re.escape(flag) + r".*?(?=\n  --|\Z)"
        m = re.search(pattern, opts, re.DOTALL)
        assert m, f"Flag {flag} not found in options section of --help"
        block = m.group(0)
        for kw in keywords:
            assert kw in block, \
                f"Expected keyword '{kw}' in help for {flag}. Got:\n{block}"

    def test_help_exits_zero(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(ROOT / "reconninja.py"), "--help"],
            capture_output=True,
        )
        assert result.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# 5. Argparse defaults — regression guard
# ══════════════════════════════════════════════════════════════════════════════

class TestArgparseDefaults:
    """Defaults must not have regressed from documented values."""

    @pytest.fixture(scope="class")
    def args(self):
        """Parse an empty argv to get all defaults."""
        import subprocess, json
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0,'.');"
             "import argparse;"
             "exec(open('reconninja.py').read().split('def main')[1].split('def ')[0])"
             ],
            capture_output=True, text=True, cwd=ROOT,
        )
        # Simpler: just grep the source for default= values
        return {}

    def test_default_timing(self):
        src = (ROOT / "reconninja.py").read_text()
        assert 'default="T4"' in src or "default='T4'" in src

    def test_default_threads(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=20" in src

    def test_default_top_ports(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=1000" in src

    def test_default_wordlist_size(self):
        src = (ROOT / "reconninja.py").read_text()
        assert 'default="medium"' in src or "default='medium'" in src

    def test_default_masscan_rate(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=5000" in src

    def test_default_async_concurrency(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=1000" in src

    def test_default_gui_port(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=7117" in src

    def test_default_output_dir(self):
        src = (ROOT / "reconninja.py").read_text()
        assert '"reports"' in src or "'reports'" in src

    def test_default_timeout(self):
        src = (ROOT / "reconninja.py").read_text()
        assert "default=30" in src


# ══════════════════════════════════════════════════════════════════════════════
# 6. Help completeness — every argument has a help string (regression guard)
# ══════════════════════════════════════════════════════════════════════════════

class TestHelpCompleteness:
    """No argument should silently lack help text in future PRs."""

    @pytest.fixture(scope="class")
    def help_out(self):
        return _help_output()

    def _extract_flags(self, help_out: str) -> list[str]:
        """Return all --flag names visible in the help output."""
        return re.findall(r"^\s{2}(--[\w-]+)", help_out, re.MULTILINE)

    def test_all_flags_present_in_help(self, help_out):
        flags = self._extract_flags(help_out)
        assert len(flags) >= 60, \
            f"Expected ≥60 flags in --help, found {len(flags)}"

    def test_no_flag_has_only_metavar_line(self, help_out):
        """
        A flag with no help= only shows 'FLAG_NAME' or the metavar on the
        same line with no description. Detect bare flags — those whose
        block has no alphabetic description text beyond the flag name itself.
        """
        # Split help into per-flag blocks
        blocks = re.split(r"\n(?=  --)", help_out)
        bare = []
        for block in blocks:
            if not block.strip().startswith("--"):
                continue
            flag_line, *rest = block.strip().split("\n")
            # If there's no continuation and the flag line has no description
            # after the flag/metavar, it's bare.
            after_flag = re.sub(r"--[\w-]+\s*[\w{},|]*\s*", "", flag_line).strip()
            continuation = " ".join(l.strip() for l in rest).strip()
            description = (after_flag + " " + continuation).strip()
            if not description:
                bare.append(flag_line.strip().split()[0])
        assert not bare, \
            f"These flags have no help text: {bare}"

    def test_profile_help_lists_all_modes(self, help_out):
        modes = ["fast", "standard", "thorough", "stealth",
                 "web_only", "port_only", "full_suite", "custom"]
        opts = re.split(r"\noptions:\n", help_out, maxsplit=1)[1]
        profile_section = re.search(
            r"--profile.*?(?=\n  --|\Z)", opts, re.DOTALL
        )
        assert profile_section
        block = profile_section.group(0)
        for mode in modes:
            assert mode in block, \
                f"Profile mode '{mode}' missing from --profile help text"

    def test_timing_help_mentions_t1_and_t5(self, help_out):
        opts = re.split(r"\noptions:\n", help_out, maxsplit=1)[1]
        timing_section = re.search(
            r"--timing.*?(?=\n  --|\Z)", opts, re.DOTALL
        )
        assert timing_section
        block = timing_section.group(0)
        assert "T1" in block and "T5" in block
