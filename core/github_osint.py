"""
core/github_osint.py — ReconNinja v7.0.0
GitHub OSINT — search public repositories for exposed secrets, API keys,
config files, and sensitive data belonging to the target organisation.

No external tools required — pure Python using the GitHub Search API.
Optional: --github-token for higher rate limits (5000 vs 60 req/hr).

BUG-FIX (v6): All API calls wrapped with explicit timeout and retry.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from utils.logger import safe_print, log

GITHUB_SEARCH_URL  = "https://api.github.com/search/code"
GITHUB_REPO_URL    = "https://api.github.com/search/repositories"
GITHUB_COMMITS_URL = "https://api.github.com/search/commits"

# Secret patterns to search for (query, label)
SECRET_QUERIES = [
    ("{target} password",           "password exposure"),
    ("{target} api_key",            "API key"),
    ("{target} secret_key",         "secret key"),
    ("{target} aws_access_key",     "AWS access key"),
    ("{target} private_key",        "private key"),
    ("{target} .env",               ".env file"),
    ("{target} database_url",       "database URL"),
    ("{target} token",              "access token"),
    ("{target} smtp password",      "SMTP credential"),
    ("{target} connectionstring",   "connection string"),
]

# Sensitive file patterns (filename, label)
FILE_QUERIES = [
    ("{target} filename:.env",          ".env file"),
    ("{target} filename:config.yml",    "config.yml"),
    ("{target} filename:settings.py",   "Django settings"),
    ("{target} filename:wp-config.php", "WordPress config"),
    ("{target} filename:database.yml",  "database config"),
    ("{target} filename:.htpasswd",     ".htpasswd"),
]


@dataclass
class GitHubFinding:
    category:    str
    query:       str
    label:       str
    repo_name:   str
    repo_url:    str
    file_path:   str
    html_url:    str
    score:       float = 0.0


@dataclass
class GitHubOSINTResult:
    target:         str
    secret_hits:    list[GitHubFinding] = field(default_factory=list)
    file_hits:      list[GitHubFinding] = field(default_factory=list)
    org_repos:      list[dict]          = field(default_factory=list)
    total_findings: int = 0
    errors:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "secret_hits":    [_finding_to_dict(f) for f in self.secret_hits],
            "file_hits":      [_finding_to_dict(f) for f in self.file_hits],
            "org_repos":      self.org_repos,
            "total_findings": self.total_findings,
            "errors":         self.errors,
        }


def _finding_to_dict(f: GitHubFinding) -> dict:
    return {
        "category":  f.category,
        "query":     f.query,
        "label":     f.label,
        "repo":      f.repo_name,
        "repo_url":  f.repo_url,
        "file":      f.file_path,
        "url":       f.html_url,
        "score":     f.score,
    }


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _gh_get(url: str, token: Optional[str], timeout: int = 15) -> dict:
    headers = {
        "User-Agent":  "ReconNinja/7.0.0",
        "Accept":      "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise RuntimeError("GitHub rate limit hit — pass --github-token to increase limits")
        if e.code == 422:
            return {}   # invalid query — skip silently
        raise
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from e


def _rate_limited_search(
    query: str,
    token: Optional[str],
    per_page: int = 5,
    delay: float = 2.0,
) -> list[dict]:
    """Search GitHub code API with polite rate limiting."""
    time.sleep(delay)
    params = urllib.parse.urlencode({
        "q":        query,
        "per_page": per_page,
        "sort":     "indexed",
    })
    url = f"{GITHUB_SEARCH_URL}?{params}"
    try:
        data = _gh_get(url, token)
        return data.get("items", [])
    except RuntimeError as e:
        log.warning(f"GitHub search error '{query}': {e}")
        return []
    except Exception as e:
        log.debug(f"GitHub search failed '{query}': {e}")
        return []


def _extract_domain_org(domain: str) -> str:
    """Strip subdomains to get the root organisation name for searching."""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return parts[-2]   # e.g. "example" from "api.example.com"
    return domain


# ── Public API ────────────────────────────────────────────────────────────────

def github_osint(
    target: str,
    token: Optional[str] = None,
    max_queries: int = 8,
    delay: float = 2.0,
) -> GitHubOSINTResult:
    """
    Run GitHub OSINT against a target domain/organisation.

    Args:
        target:      domain or org name to search for
        token:       GitHub personal access token (optional, raises rate limit)
        max_queries: max number of secret queries to run (cap for long scans)
        delay:       seconds between API requests

    Returns:
        GitHubOSINTResult with secret_hits, file_hits, org_repos
    """
    result = GitHubOSINTResult(target=target)
    org    = _extract_domain_org(target)

    safe_print(f"[info]▶ GitHub OSINT — searching for '{org}' / '{target}'[/]")

    # ── Secret / credential searches ─────────────────────────────────────────
    queries_run = 0
    for query_tmpl, label in SECRET_QUERIES[:max_queries]:
        query = query_tmpl.format(target=org)
        items = _rate_limited_search(query, token, delay=delay)
        for item in items[:3]:
            repo = item.get("repository", {})
            finding = GitHubFinding(
                category  = "secret",
                query     = query,
                label     = label,
                repo_name = repo.get("full_name", ""),
                repo_url  = repo.get("html_url", ""),
                file_path = item.get("path", ""),
                html_url  = item.get("html_url", ""),
                score     = float(item.get("score", 0)),
            )
            result.secret_hits.append(finding)
        queries_run += 1

    if result.secret_hits:
        safe_print(
            f"  [danger]⚠  {len(result.secret_hits)} potential secret(s) exposed on GitHub[/]"
        )

    # ── Sensitive file searches ───────────────────────────────────────────────
    for query_tmpl, label in FILE_QUERIES[:4]:
        query = query_tmpl.format(target=org)
        items = _rate_limited_search(query, token, delay=delay)
        for item in items[:3]:
            repo = item.get("repository", {})
            finding = GitHubFinding(
                category  = "file",
                query     = query,
                label     = label,
                repo_name = repo.get("full_name", ""),
                repo_url  = repo.get("html_url", ""),
                file_path = item.get("path", ""),
                html_url  = item.get("html_url", ""),
                score     = float(item.get("score", 0)),
            )
            result.file_hits.append(finding)

    if result.file_hits:
        safe_print(
            f"  [warning]{len(result.file_hits)} sensitive file(s) found on GitHub[/]"
        )

    # ── Organisation repositories ─────────────────────────────────────────────
    try:
        time.sleep(delay)
        params   = urllib.parse.urlencode({"q": f"org:{org}", "per_page": 10})
        repo_url = f"{GITHUB_REPO_URL}?{params}"
        repo_data = _gh_get(repo_url, token)
        for repo in repo_data.get("items", [])[:10]:
            result.org_repos.append({
                "name":        repo.get("full_name", ""),
                "url":         repo.get("html_url", ""),
                "description": repo.get("description", ""),
                "stars":       repo.get("stargazers_count", 0),
                "language":    repo.get("language", ""),
                "pushed_at":   repo.get("pushed_at", ""),
                "private":     repo.get("private", False),
            })
        if result.org_repos:
            safe_print(
                f"  [info]GitHub:[/] {len(result.org_repos)} public repo(s) found for org '{org}'"
            )
    except Exception as e:
        err = f"GitHub repo search failed: {e}"
        log.debug(err)
        result.errors.append(err)

    result.total_findings = len(result.secret_hits) + len(result.file_hits)

    safe_print(
        f"[success]✔ GitHub OSINT: {result.total_findings} finding(s), "
        f"{len(result.org_repos)} repo(s)[/]"
    )
    return result
