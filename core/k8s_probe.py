"""
core/k8s_probe.py — ReconNinja v7.0.0
Kubernetes API Server exposure detection.

Detects:
  - Unauthenticated kubelet API (port 10250, 10255)
  - Unauthenticated kube-api server (port 6443, 8080)
  - Anonymous kubectl access (/api, /apis, /version)
  - etcd exposure (port 2379)
  - Kubernetes dashboard (port 30000-32767 range)
  - Docker API exposure (port 2375, 2376)

No external tools required — pure Python stdlib.
"""

from __future__ import annotations

import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print


@dataclass
class K8sFinding:
    host:     str
    port:     int
    service:  str
    url:      str
    severity: str
    detail:   str
    response: str = ""

    def to_dict(self) -> dict:
        return {
            "host":     self.host,
            "port":     self.port,
            "service":  self.service,
            "url":      self.url,
            "severity": self.severity,
            "detail":   self.detail,
        }


# ── Probe definitions ─────────────────────────────────────────────────────────

K8S_PROBES = [
    # (service, port, path, http_scheme, indicator_strings, severity)
    ("kube-api anon",  6443, "/api",      "https", ["v1", "groups"],              "critical"),
    ("kube-api http",  8080, "/api",      "http",  ["v1", "groups"],              "critical"),
    ("kube-api pods",  6443, "/api/v1/pods","https",["items","namespace"],        "critical"),
    ("kubelet read",  10255, "/pods",     "http",  ["items","namespace","spec"],  "critical"),
    ("kubelet exec",  10250, "/pods",     "https", ["items","namespace"],         "critical"),
    ("etcd",          2379,  "/version",  "http",  ["etcdserver","etcdcluster"],  "critical"),
    ("docker api",    2375,  "/version",  "http",  ["ApiVersion","Version"],      "critical"),
    ("k8s dashboard", 8001,  "/api/v1",   "http",  ["v1", "groups"],              "high"),
]


def _probe_k8s(host: str, port: int, path: str, scheme: str,
               indicators: list[str], timeout: int = 6) -> Optional[str]:
    """Returns response body if any indicator found, else None."""
    url = f"{scheme}://{host}:{port}{path}"
    try:
        # Skip SSL verification for self-signed certs
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=timeout) as r:
            body = r.read(8192).decode(errors="ignore")
            if not indicators or any(ind in body for ind in indicators):
                return body
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "__AUTH_REQUIRED__"
        return None
    except Exception:
        return None
    return None


def k8s_probe(
    target: str,
    open_ports: set[int],
    out_folder: Path,
    timeout: int = 6,
) -> list[K8sFinding]:
    """
    Detect exposed Kubernetes/Docker API surfaces.

    Args:
        target:     IP or hostname
        open_ports: ports found open by port scanner
        out_folder: output directory

    Returns:
        list of K8sFinding
    """
    ensure_dir(out_folder)
    findings: list[K8sFinding] = []
    k8s_ports = {6443, 8080, 8001, 10250, 10255, 2379, 2375, 2376}
    relevant  = k8s_ports & open_ports if open_ports else k8s_ports

    safe_print(f"[info]▶ Kubernetes/Docker Probe — {target} ({len(relevant)} port(s))[/]")

    for service, port, path, scheme, indicators, severity in K8S_PROBES:
        if open_ports and port not in open_ports:
            continue  # skip if port not found open
        url  = f"{scheme}://{target}:{port}{path}"
        body = _probe_k8s(target, port, path, scheme, indicators, timeout)

        if body and body != "__AUTH_REQUIRED__":
            findings.append(K8sFinding(
                host=target, port=port, service=service, url=url,
                severity=severity,
                detail=f"Unauthenticated {service} access at {url}",
                response=body[:200],
            ))
            safe_print(f"  [danger]⚠  {service.upper()}: {url} — UNAUTHENTICATED[/]")
        elif body == "__AUTH_REQUIRED__":
            # Still worth noting — service exists, just auth'd
            findings.append(K8sFinding(
                host=target, port=port, service=service, url=url,
                severity="medium",
                detail=f"{service} is accessible (authentication required)",
                response="",
            ))
            safe_print(f"  [warning]{service}: {url} — authentication required (exists)[/]")

    # Save
    out_file = out_folder / "k8s_findings.txt"
    lines = [f"# Kubernetes/Docker Probe — {target}", ""]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.service}: {f.url}")
        lines.append(f"  {f.detail}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    crit = sum(1 for f in findings if f.severity == "critical")
    safe_print(f"[{'danger' if crit else 'success'}]✔ K8s Probe: {len(findings)} finding(s), {crit} critical[/]")
    return findings
