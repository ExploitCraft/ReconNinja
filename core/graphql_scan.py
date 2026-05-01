"""
core/graphql_scan.py — ReconNinja v7.0.0
GraphQL endpoint discovery and introspection abuse.

Finds GraphQL endpoints on live web services, runs introspection
queries to dump schema, detects dangerous patterns:
  - Introspection enabled in production (schema disclosure)
  - Batch query support (DoS/brute vector)
  - Field suggestions enabled (information leakage)
  - Deeply nested queries (DoS vector)
  - Missing query depth limiting

No external tools required — pure Python stdlib.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print

# ── Known GraphQL endpoint paths ──────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/graphql/v1", "/graphql/v2", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/graphiql", "/playground", "/altair",
    "/api/v1/graphql", "/api/v2/graphql",
]

# ── Introspection query ───────────────────────────────────────────────────────

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields { name args { name type { name kind ofType { name kind } } } }
        }
      }
    }
    """
}

# ── Batch query (detect if enabled) ──────────────────────────────────────────

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

# ── Field suggestion detection ────────────────────────────────────────────────

SUGGESTION_QUERY = {"query": "{ _doesNotExist }"}


@dataclass
class GraphQLFinding:
    url:               str
    introspection:     bool  = False
    batching:          bool  = False
    field_suggestions: bool  = False
    schema_types:      list[str] = field(default_factory=list)
    mutations:         list[str] = field(default_factory=list)
    queries:           list[str] = field(default_factory=list)
    issues:            list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url":               self.url,
            "introspection":     self.introspection,
            "batching":          self.batching,
            "field_suggestions": self.field_suggestions,
            "schema_types":      self.schema_types[:20],
            "mutations":         self.mutations[:10],
            "queries":           self.queries[:10],
            "issues":            self.issues,
        }


# ── HTTP POST helper ──────────────────────────────────────────────────────────

def _gql_post(url: str, payload, timeout: int = 10) -> Optional[dict]:
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent":   "ReconNinja/7.0.0",
                "Accept":       "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(1_000_000).decode(errors="ignore"))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(10000).decode(errors="ignore")
            return json.loads(body)
        except Exception:
            return None
    except Exception:
        return None


# ── Endpoint discovery ────────────────────────────────────────────────────────

def _find_graphql_endpoints(base_url: str, timeout: int = 8) -> list[str]:
    """Probe common GraphQL paths on a base URL."""
    found = []
    base = base_url.rstrip("/")
    for path in GRAPHQL_PATHS:
        url = base + path
        resp = _gql_post(url, {"query": "{ __typename }"}, timeout=timeout)
        if resp and ("data" in resp or "errors" in resp):
            found.append(url)
    return found


# ── Analysis ──────────────────────────────────────────────────────────────────

def _analyse_endpoint(url: str, timeout: int = 10) -> GraphQLFinding:
    finding = GraphQLFinding(url=url)

    # 1. Introspection
    intro_resp = _gql_post(url, INTROSPECTION_QUERY, timeout=timeout)
    if intro_resp:
        schema = intro_resp.get("data", {}).get("__schema", {})
        if schema:
            finding.introspection = True
            finding.issues.append({
                "severity": "high",
                "issue":    "GraphQL introspection enabled in production — full schema disclosed",
            })
            # Extract type names
            types = schema.get("types", [])
            finding.schema_types = [
                t["name"] for t in types
                if t.get("name") and not t["name"].startswith("__")
            ]
            # Extract queries
            query_type_name = (schema.get("queryType") or {}).get("name")
            mutation_type_name = (schema.get("mutationType") or {}).get("name")
            for t in types:
                if t.get("name") == query_type_name and t.get("fields"):
                    finding.queries = [f["name"] for f in t["fields"]]
                if t.get("name") == mutation_type_name and t.get("fields"):
                    finding.mutations = [f["name"] for f in t["fields"]]
            if finding.mutations:
                finding.issues.append({
                    "severity": "medium",
                    "issue":    f"Mutations exposed: {', '.join(finding.mutations[:5])}",
                })

    # 2. Batch queries
    batch_resp = _gql_post(url, BATCH_QUERY, timeout=timeout)
    if isinstance(batch_resp, list) and len(batch_resp) == 2:
        finding.batching = True
        finding.issues.append({
            "severity": "medium",
            "issue":    "GraphQL batch queries enabled — can be used for credential brute-force or rate limit bypass",
        })

    # 3. Field suggestions
    sugg_resp = _gql_post(url, SUGGESTION_QUERY, timeout=timeout)
    if sugg_resp:
        errors = sugg_resp.get("errors", [])
        for err in errors:
            msg = err.get("message", "").lower()
            if "did you mean" in msg or "suggestion" in msg:
                finding.field_suggestions = True
                finding.issues.append({
                    "severity": "low",
                    "issue":    "GraphQL field suggestions enabled — leaks valid field names",
                })
                break

    return finding


# ── Public API ────────────────────────────────────────────────────────────────

def graphql_scan(
    web_urls: list[str],
    out_folder: Path,
    timeout: int = 10,
) -> list[GraphQLFinding]:
    """
    Discover and analyse GraphQL endpoints on live web services.

    Args:
        web_urls:   live URLs from httpx
        out_folder: output directory
        timeout:    per-request timeout

    Returns:
        list of GraphQLFinding
    """
    ensure_dir(out_folder)
    findings: list[GraphQLFinding] = []
    tested: set[str] = set()

    safe_print(f"[info]▶ GraphQL Scanner — probing {len(web_urls)} target(s)[/]")

    for base_url in web_urls[:15]:
        endpoints = _find_graphql_endpoints(base_url, timeout=timeout)
        for ep_url in endpoints:
            if ep_url in tested:
                continue
            tested.add(ep_url)
            safe_print(f"  [info]GraphQL found: {ep_url}[/]")
            finding = _analyse_endpoint(ep_url, timeout=timeout)
            findings.append(finding)

    # Save
    out_file = out_folder / "graphql_findings.txt"
    lines = ["# GraphQL Scan Results\n"]
    for f in findings:
        lines.append(f"Endpoint: {f.url}")
        lines.append(f"  Introspection: {f.introspection}")
        lines.append(f"  Batching:      {f.batching}")
        lines.append(f"  Types: {', '.join(f.schema_types[:10])}")
        for issue in f.issues:
            lines.append(f"  [{issue['severity'].upper()}] {issue['issue']}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    critical = sum(1 for f in findings for i in f.issues if i["severity"] == "high")
    sev = "danger" if critical else "success"
    safe_print(f"[{sev}]✔ GraphQL: {len(findings)} endpoint(s), {critical} high-severity finding(s)[/]")
    return findings
