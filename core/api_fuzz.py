"""
core/api_fuzz.py — ReconNinja v8.0.0
REST API Fuzzer — endpoint discovery, parameter tampering, auth bypass probes.

Discovers hidden API endpoints, tests for common misconfigurations,
checks for unauthenticated access, and probes for parameter-level issues.
No external tools required — pure Python asyncio.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import urllib.request
import urllib.error
import http.client
import ssl

from utils.logger import safe_print
from utils.helpers import make_request

# ── data models ──────────────────────────────────────────────────────────────

@dataclass
class APIFinding:
    url: str
    method: str
    issue: str
    severity: str          # critical / high / medium / low / info
    detail: str
    status_code: int = 0
    response_snippet: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class APIFuzzResult:
    target: str
    base_url: str
    endpoints_found: list[str] = field(default_factory=list)
    findings: list[APIFinding] = field(default_factory=list)
    swagger_found: bool = False
    swagger_url: str = ""
    graphql_found: bool = False
    total_probed: int = 0


# ── common endpoint wordlist ──────────────────────────────────────────────────

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api/docs",
    "/health", "/healthz", "/health/live", "/health/ready",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/info",
    "/.well-known/openid-configuration",
    "/admin", "/admin/api", "/internal/api",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/admin", "/api/config", "/api/settings",
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/keys", "/api/secrets",
    "/api/debug", "/api/test", "/api/ping",
]

# IDOR / parameter tampering payloads
IDOR_IDS = ["0", "1", "2", "99999", "-1", "null", "undefined",
            "../", "../../etc/passwd", "%00", "admin", "true"]

# Auth bypass headers
AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
]

# HTTP methods to test on discovered endpoints
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


# ── helpers ───────────────────────────────────────────────────────────────────

def _fetch(url: str, method: str = "GET", headers: dict | None = None,
           body: bytes | None = None, timeout: int = 8) -> tuple[int, str, dict]:
    """Return (status_code, body_snippet, response_headers)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "ReconNinja/8.0.0 API-Fuzzer")
        req.add_header("Accept", "application/json, */*")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(2048).decode(errors="ignore")
            return resp.status, raw, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(512).decode(errors="ignore")
        except Exception:
            raw = ""
        return e.code, raw, {}
    except Exception:
        return 0, "", {}


def _looks_like_api(body: str, headers: dict) -> bool:
    ct = headers.get("Content-Type", "")
    return ("json" in ct or "xml" in ct or
            body.strip().startswith("{") or body.strip().startswith("["))


# ── phase functions ────────────────────────────────────────────────────────────

def _discover_endpoints(base_url: str, timeout: int) -> list[str]:
    """Probe common API paths and return live ones."""
    found = []
    for path in COMMON_API_PATHS:
        url = base_url.rstrip("/") + path
        code, body, hdrs = _fetch(url, timeout=timeout)
        if code in (200, 201, 204, 301, 302, 401, 403):
            found.append(url)
    return found


def _check_swagger(base_url: str, timeout: int) -> tuple[bool, str, list[str]]:
    """Try to find and parse Swagger/OpenAPI spec — returns (found, url, endpoints)."""
    swagger_paths = [
        "/swagger.json", "/openapi.json", "/api-docs",
        "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    ]
    for path in swagger_paths:
        url = base_url.rstrip("/") + path
        code, body, hdrs = _fetch(url, timeout=timeout)
        if code == 200 and ('"swagger"' in body or '"openapi"' in body):
            # Extract paths from spec
            endpoints = []
            try:
                spec = json.loads(body)
                base = spec.get("basePath", "")
                for p in spec.get("paths", {}):
                    endpoints.append(base + p)
            except Exception:
                pass
            return True, url, endpoints
    return False, "", []


def _check_method_not_allowed(url: str, timeout: int) -> list[APIFinding]:
    """Test multiple HTTP methods — flag unexpected 2xx on dangerous methods."""
    findings = []
    dangerous = ["DELETE", "PUT", "PATCH"]
    for method in dangerous:
        code, body, hdrs = _fetch(url, method=method, timeout=timeout)
        if code in (200, 201, 204):
            findings.append(APIFinding(
                url=url, method=method,
                issue="Unexpected HTTP method accepted",
                severity="medium",
                detail=f"{method} returned {code} — resource may be modifiable without proper intent",
                status_code=code,
                response_snippet=body[:200],
            ))
    return findings


def _check_auth_bypass(base_url: str, timeout: int) -> list[APIFinding]:
    """Test header-based auth bypass on admin-looking endpoints."""
    findings = []
    targets = ["/admin", "/api/admin", "/actuator", "/internal"]
    for path in targets:
        url = base_url.rstrip("/") + path
        baseline_code, _, _ = _fetch(url, timeout=timeout)
        if baseline_code not in (401, 403):
            continue  # not protected, no bypass to test
        for bypass_hdrs in AUTH_BYPASS_HEADERS:
            code, body, hdrs = _fetch(url, headers=bypass_hdrs, timeout=timeout)
            if code in (200, 201, 204):
                hdr_str = ", ".join(f"{k}: {v}" for k, v in bypass_hdrs.items())
                findings.append(APIFinding(
                    url=url, method="GET",
                    issue="Auth bypass via header manipulation",
                    severity="critical",
                    detail=f"Adding '{hdr_str}' bypassed {baseline_code} and returned {code}",
                    status_code=code,
                    response_snippet=body[:300],
                    evidence={"bypass_header": bypass_hdrs},
                ))
                break
    return findings


def _check_idor(endpoints: list[str], timeout: int) -> list[APIFinding]:
    """Probe ID-like path segments for IDOR."""
    findings = []
    id_pattern = re.compile(r"/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
    for url in endpoints[:20]:  # cap to avoid flooding
        if not id_pattern.search(url):
            continue
        for payload in IDOR_IDS[:5]:
            test_url = id_pattern.sub(f"/{payload}", url, count=1)
            code, body, hdrs = _fetch(test_url, timeout=timeout)
            if code == 200 and _looks_like_api(body, hdrs):
                findings.append(APIFinding(
                    url=test_url, method="GET",
                    issue="Potential IDOR — object ID manipulation returned data",
                    severity="high",
                    detail=f"Replaced ID with '{payload}' in {url} → HTTP {code}",
                    status_code=code,
                    response_snippet=body[:250],
                ))
    return findings


def _check_mass_assignment(endpoints: list[str], timeout: int) -> list[APIFinding]:
    """POST/PUT with extra privilege fields and check if accepted."""
    findings = []
    payloads = [
        b'{"role":"admin","isAdmin":true}',
        b'{"admin":true,"privilege":"superuser"}',
        b'{"user":{"role":"admin"}}',
    ]
    headers_json = {"Content-Type": "application/json"}
    for url in endpoints[:15]:
        for method in ("POST", "PUT"):
            for payload in payloads:
                code, body, hdrs = _fetch(url, method=method,
                                          headers=headers_json,
                                          body=payload, timeout=timeout)
                if code in (200, 201) and _looks_like_api(body, hdrs):
                    if any(kw in body.lower() for kw in ["admin", "role", "privilege", "true"]):
                        findings.append(APIFinding(
                            url=url, method=method,
                            issue="Potential mass assignment vulnerability",
                            severity="high",
                            detail=f"Privilege field in payload accepted with HTTP {code}",
                            status_code=code,
                            response_snippet=body[:250],
                            evidence={"payload": payload.decode()},
                        ))
    return findings


def _check_exposed_debug(endpoints: list[str], timeout: int) -> list[APIFinding]:
    """Flag debug/info endpoints that expose internals."""
    findings = []
    sensitive_keys = ["password", "secret", "token", "key", "db_url", "database",
                      "connection_string", "aws_", "private"]
    for url in endpoints:
        code, body, hdrs = _fetch(url, timeout=timeout)
        if code != 200:
            continue
        lower = body.lower()
        hits = [k for k in sensitive_keys if k in lower]
        if hits:
            findings.append(APIFinding(
                url=url, method="GET",
                issue="Sensitive data exposed in API endpoint",
                severity="high",
                detail=f"Response contains potential secrets: {', '.join(hits)}",
                status_code=code,
                response_snippet=body[:300],
                evidence={"matched_keywords": hits},
            ))
    return findings


# ── main entry ────────────────────────────────────────────────────────────────

def api_fuzz_scan(target: str, out_folder: Path, timeout: int = 10) -> APIFuzzResult:
    """
    Main API fuzzing scan. Discovers endpoints, then probes for auth bypass,
    IDOR, mass assignment, method confusion, and exposed debug info.
    """
    # Build base URL
    if not target.startswith("http"):
        base_url = f"https://{target}"
    else:
        base_url = target

    result = APIFuzzResult(target=target, base_url=base_url)
    safe_print(f"[info]▶ API Fuzzer — {base_url}[/]")

    # Step 1 — Swagger/OpenAPI discovery
    safe_print("  [dim]Checking for OpenAPI/Swagger spec...[/]")
    swagger_found, swagger_url, spec_endpoints = _check_swagger(base_url, timeout)
    if swagger_found:
        result.swagger_found = True
        result.swagger_url = swagger_url
        result.endpoints_found.extend(
            base_url.rstrip("/") + ep for ep in spec_endpoints
        )
        safe_print(f"  [success]✓ Swagger/OpenAPI spec found: {swagger_url} "
                   f"({len(spec_endpoints)} paths)[/]")
        result.findings.append(APIFinding(
            url=swagger_url, method="GET",
            issue="API specification publicly accessible",
            severity="medium",
            detail="Swagger/OpenAPI spec is unauthenticated — exposes full API surface",
            status_code=200,
        ))

    # Step 2 — endpoint discovery
    safe_print("  [dim]Probing common API paths...[/]")
    discovered = _discover_endpoints(base_url, timeout)
    for ep in discovered:
        if ep not in result.endpoints_found:
            result.endpoints_found.append(ep)
    result.total_probed = len(COMMON_API_PATHS)
    safe_print(f"  [dim]{len(result.endpoints_found)} endpoints found[/]")

    # Step 3 — auth bypass
    safe_print("  [dim]Testing auth bypass headers...[/]")
    result.findings.extend(_check_auth_bypass(base_url, timeout))

    # Step 4 — IDOR probes
    if result.endpoints_found:
        safe_print("  [dim]Probing for IDOR...[/]")
        result.findings.extend(_check_idor(result.endpoints_found, timeout))

    # Step 5 — mass assignment
    safe_print("  [dim]Testing mass assignment...[/]")
    result.findings.extend(_check_mass_assignment(result.endpoints_found[:10], timeout))

    # Step 6 — method confusion on discovered endpoints
    for ep in result.endpoints_found[:10]:
        result.findings.extend(_check_method_not_allowed(ep, timeout))

    # Step 7 — exposed debug / sensitive keys
    safe_print("  [dim]Scanning for exposed sensitive data...[/]")
    result.findings.extend(_check_exposed_debug(result.endpoints_found, timeout))

    # Summary
    crit = sum(1 for f in result.findings if f.severity == "critical")
    high = sum(1 for f in result.findings if f.severity == "high")
    if result.findings:
        safe_print(f"  [warning]⚠  API Fuzz: {len(result.findings)} findings "
                   f"({crit} critical, {high} high)[/]")
    else:
        safe_print("  [dim]API Fuzz: no significant findings[/]")

    # Save report
    out_folder.mkdir(parents=True, exist_ok=True)
    out_file = out_folder / "api_fuzz.txt"
    lines = ["# API Fuzz Results\n"]
    lines.append(f"Target: {base_url}\n")
    lines.append(f"Endpoints discovered: {len(result.endpoints_found)}\n\n")
    for ep in result.endpoints_found:
        lines.append(f"  ENDPOINT  {ep}\n")
    lines.append("\n")
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.issue}\n")
        lines.append(f"  URL:    {f.url}\n")
        lines.append(f"  Method: {f.method}\n")
        lines.append(f"  Detail: {f.detail}\n")
        if f.response_snippet:
            lines.append(f"  Resp:   {f.response_snippet[:120]}\n")
        lines.append("\n")
    out_file.write_text("".join(lines), encoding="utf-8")

    return result
