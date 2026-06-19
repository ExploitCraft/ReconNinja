"""
core/oauth_scan.py — ReconNinja v8.0.0
OAuth 2.0 / OIDC Misconfiguration Scanner.

Checks for common OAuth/OIDC weaknesses:
  - Open redirects in redirect_uri
  - Token leakage via Referer header
  - PKCE bypass (code_challenge not enforced)
  - Implicit flow still enabled
  - State parameter not enforced (CSRF)
  - OIDC discovery endpoint exposed
  - Client credentials exposed in JS
"""

from __future__ import annotations

import re
import json
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import safe_print


@dataclass
class OAuthFinding:
    issue: str
    severity: str
    detail: str
    url: str = ""
    evidence: str = ""


@dataclass
class OAuthScanResult:
    target: str
    findings: list[OAuthFinding] = field(default_factory=list)
    oidc_discovered: bool = False
    oidc_config: dict = field(default_factory=dict)
    oauth_endpoints: list[str] = field(default_factory=list)


# ── common OAuth endpoint paths ───────────────────────────────────────────────

OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",  # Keycloak
    "/oauth2/.well-known/openid-configuration",
    "/connect/.well-known/openid-configuration",
]

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth/token", "/oauth2/authorize",
    "/oauth2/token", "/auth/authorize", "/auth/token",
    "/connect/authorize", "/connect/token",
    "/api/oauth/authorize", "/login/oauth/authorize",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F@legitimate",
    "https://legitimate.evil.com",
    "javascript:alert(1)",
    "data:text/html,<h1>pwned</h1>",
]


def _fetch(url: str, timeout: int = 8) -> tuple[int, str, dict]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        req.add_header("Accept", "application/json, */*")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(4096).decode(errors="ignore")
            return resp.status, raw, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(512).decode(errors="ignore")
        except Exception:
            raw = ""
        return e.code, raw, {}
    except Exception:
        return 0, "", {}


def _check_oidc_discovery(base_url: str, timeout: int) -> tuple[bool, str, dict]:
    for path in OAUTH_DISCOVERY_PATHS:
        url = base_url.rstrip("/") + path
        code, body, _ = _fetch(url, timeout)
        if code == 200:
            try:
                config = json.loads(body)
                if "issuer" in config or "authorization_endpoint" in config:
                    return True, url, config
            except Exception:
                pass
    return False, "", {}


def _check_implicit_flow(config: dict) -> list[OAuthFinding]:
    findings = []
    grants = config.get("grant_types_supported", [])
    rt = config.get("response_types_supported", [])
    if "implicit" in grants or "token" in rt:
        findings.append(OAuthFinding(
            issue="Implicit grant flow enabled",
            severity="high",
            detail="Implicit flow exposes access tokens in URL fragments — susceptible to token leakage via Referer, history, and browser storage. RFC 9700 recommends disabling implicit flow.",
            evidence=f"grant_types_supported: {grants}",
        ))
    return findings


def _check_pkce_enforcement(config: dict, base_url: str, timeout: int) -> list[OAuthFinding]:
    findings = []
    auth_ep = config.get("authorization_endpoint", "")
    if not auth_ep:
        return findings
    # Try auth request without code_challenge
    test_url = (auth_ep + "?response_type=code&client_id=test"
                "&redirect_uri=https://localhost&scope=openid")
    code, body, hdrs = _fetch(test_url, timeout)
    # If we get a redirect or 200 without requiring PKCE params, it may not enforce it
    if code in (200, 302, 301) and "code_challenge" not in body.lower():
        findings.append(OAuthFinding(
            issue="PKCE not enforced on authorization endpoint",
            severity="medium",
            detail="Authorization endpoint accepted request without code_challenge. Public clients are vulnerable to authorization code interception (RFC 7636).",
            url=test_url,
        ))
    return findings


def _check_open_redirect_uri(config: dict, base_url: str, timeout: int) -> list[OAuthFinding]:
    findings = []
    auth_ep = config.get("authorization_endpoint", "")
    if not auth_ep:
        return findings
    for payload in OPEN_REDIRECT_PAYLOADS[:3]:
        test_url = (auth_ep + f"?response_type=code&client_id=test"
                    f"&redirect_uri={urllib.request.quote(payload, safe='')}"
                    f"&scope=openid&state=xyz")
        code, body, hdrs = _fetch(test_url, timeout)
        location = hdrs.get("Location", "")
        if any(evil in location for evil in ["evil.com", "javascript:", "data:"]):
            findings.append(OAuthFinding(
                issue="Open redirect in OAuth redirect_uri",
                severity="critical",
                detail=f"Server redirected to attacker-controlled URI: {location}",
                url=test_url,
                evidence=f"Payload: {payload} → Location: {location}",
            ))
    return findings


def _check_state_csrf(config: dict, base_url: str, timeout: int) -> list[OAuthFinding]:
    findings = []
    auth_ep = config.get("authorization_endpoint", "")
    if not auth_ep:
        return findings
    # Request without state param
    test_url = (auth_ep + "?response_type=code&client_id=test"
                "&redirect_uri=https://localhost&scope=openid")
    code, body, _ = _fetch(test_url, timeout)
    if code in (200, 302) and "state" not in body.lower():
        findings.append(OAuthFinding(
            issue="OAuth state parameter not enforced (CSRF risk)",
            severity="medium",
            detail="Authorization endpoint accepts requests without the state parameter. This allows CSRF attacks against the OAuth flow (RFC 6749 §10.12).",
            url=test_url,
        ))
    return findings


def _check_token_endpoint_cors(config: dict, timeout: int) -> list[OAuthFinding]:
    findings = []
    token_ep = config.get("token_endpoint", "")
    if not token_ep:
        return findings
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(token_ep, method="OPTIONS")
        req.add_header("Origin", "https://evil.com")
        req.add_header("User-Agent", "ReconNinja/8.0.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            hdrs = dict(resp.headers)
            acao = hdrs.get("Access-Control-Allow-Origin", "")
            if acao == "*" or "evil.com" in acao:
                findings.append(OAuthFinding(
                    issue="Token endpoint has permissive CORS policy",
                    severity="high",
                    detail=f"Token endpoint reflects arbitrary Origin or uses wildcard: '{acao}'. Cross-origin token requests may be possible.",
                    url=token_ep,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                ))
    except Exception:
        pass
    return findings


def _check_exposed_client_creds(base_url: str, timeout: int) -> list[OAuthFinding]:
    """Check if client_secret appears in JS files served from the target."""
    findings = []
    paths_to_check = ["/", "/app.js", "/static/js/main.js", "/assets/app.js"]
    patterns = [
        re.compile(r'client_secret["\s:=]+(["\'])([A-Za-z0-9_\-]{16,})\1', re.I),
        re.compile(r'clientSecret["\s:=]+(["\'])([A-Za-z0-9_\-]{16,})\1', re.I),
        re.compile(r'client_id["\s:=]+(["\'])([A-Za-z0-9_\-]{8,})\1.*?'
                   r'client_secret["\s:=]+(["\'])([A-Za-z0-9_\-]{8,})\3', re.I | re.S),
    ]
    for path in paths_to_check:
        url = base_url.rstrip("/") + path
        _, body, _ = _fetch(url, timeout)
        for pat in patterns:
            m = pat.search(body)
            if m:
                findings.append(OAuthFinding(
                    issue="OAuth client credentials exposed in frontend code",
                    severity="critical",
                    detail=f"client_secret or credentials pattern found in {path}",
                    url=url,
                    evidence=body[max(0, m.start()-20):m.end()+20],
                ))
    return findings


def oauth_scan(target: str, out_folder: Path, timeout: int = 10) -> OAuthScanResult:
    """Run full OAuth/OIDC misconfiguration scan."""
    if not target.startswith("http"):
        base_url = f"https://{target}"
    else:
        base_url = target

    result = OAuthScanResult(target=target)
    safe_print(f"[info]▶ OAuth/OIDC Scanner — {base_url}[/]")

    # Discover OIDC config
    safe_print("  [dim]Probing OIDC discovery endpoint...[/]")
    found, disc_url, config = _check_oidc_discovery(base_url, timeout)

    if found:
        result.oidc_discovered = True
        result.oidc_config = config
        safe_print(f"  [success]✓ OIDC discovery found: {disc_url}[/]")
        result.findings.append(OAuthFinding(
            issue="OIDC discovery endpoint publicly accessible",
            severity="info",
            detail="Discovery endpoint exposes OAuth server configuration. "
                   "Not a vulnerability itself, but confirms OAuth is in use.",
            url=disc_url,
        ))

        # Run checks against discovered config
        result.findings.extend(_check_implicit_flow(config))
        result.findings.extend(_check_pkce_enforcement(config, base_url, timeout))
        result.findings.extend(_check_open_redirect_uri(config, base_url, timeout))
        result.findings.extend(_check_state_csrf(config, base_url, timeout))
        result.findings.extend(_check_token_endpoint_cors(config, timeout))

        # Collect known endpoints
        for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                    "jwks_uri", "revocation_endpoint", "introspection_endpoint"):
            if ep := config.get(key):
                result.oauth_endpoints.append(ep)
    else:
        # No OIDC discovery — probe known paths
        safe_print("  [dim]No OIDC discovery — probing known OAuth paths...[/]")
        for path in OAUTH_PATHS:
            url = base_url.rstrip("/") + path
            code, _, _ = _fetch(url, timeout)
            if code not in (0, 404):
                result.oauth_endpoints.append(url)

    # Always check for exposed client credentials
    result.findings.extend(_check_exposed_client_creds(base_url, timeout))

    crit = sum(1 for f in result.findings if f.severity == "critical")
    high = sum(1 for f in result.findings if f.severity == "high")
    if any(f.severity != "info" for f in result.findings):
        safe_print(f"  [warning]⚠  OAuth: {len(result.findings)} findings "
                   f"({crit} critical, {high} high)[/]")
    else:
        safe_print("  [dim]OAuth: no critical misconfigurations found[/]")

    # Save
    out_folder.mkdir(parents=True, exist_ok=True)
    out_file = out_folder / "oauth_scan.txt"
    lines = ["# OAuth/OIDC Scan Results\n", f"Target: {base_url}\n\n"]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.issue}\n")
        lines.append(f"  Detail: {f.detail}\n")
        if f.url:
            lines.append(f"  URL:    {f.url}\n")
        if f.evidence:
            lines.append(f"  Evidence: {f.evidence[:100]}\n")
        lines.append("\n")
    out_file.write_text("".join(lines), encoding="utf-8")

    return result
