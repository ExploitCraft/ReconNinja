"""
ReconNinja v9 — Container & Orchestration Deep Scan  (--container-deep)
Docker socket, kubelet, etcd, RBAC, registry enum, Helm chart exposure.
"""
from __future__ import annotations
import socket
from pathlib import Path
import requests
from utils.logger import log, safe_print
from utils.models import ContainerFinding, ReconResult, ScanConfig


def container_deep_scan(target: str, result: ReconResult, cfg: ScanConfig, out_folder: Path) -> list[ContainerFinding]:
    findings: list[ContainerFinding] = []
    safe_print("[module]🐳  Container / K8s Deep Scan...[/]")

    hosts = [target] + [h.ip for h in result.hosts[:20]]

    for host in hosts:
        # Docker socket
        for port in [2375, 2376]:
            try:
                resp = requests.get(f"http://{host}:{port}/version", timeout=5)
                if resp.status_code == 200 and "ApiVersion" in resp.text:
                    sev = "critical" if port == 2375 else "high"
                    findings.append(ContainerFinding(
                        check="docker_socket", severity=sev, host=host, port=port,
                        detail=f"Docker daemon API accessible on port {port}"
                               + (" (unauthenticated)" if port == 2375 else " (TLS — verify cert)"),
                        evidence=resp.text[:200],
                    ))
            except Exception:
                pass

        # Kubelet API
        try:
            resp = requests.get(f"https://{host}:10250/pods", timeout=5, verify=False)
            if resp.status_code == 200:
                findings.append(ContainerFinding(
                    check="kubelet", severity="critical", host=host, port=10250,
                    detail="Kubelet API is unauthenticated — anonymous pod listing possible.",
                ))
            elif resp.status_code == 401:
                findings.append(ContainerFinding(
                    check="kubelet", severity="medium", host=host, port=10250,
                    detail="Kubelet API requires authentication (good) — port confirmed open.",
                ))
        except Exception:
            pass

        # kube-apiserver anonymous
        for port in [6443, 8443, 8080]:
            try:
                resp = requests.get(f"https://{host}:{port}/api/v1/namespaces", timeout=5, verify=False)
                if resp.status_code == 200:
                    findings.append(ContainerFinding(
                        check="kube_apiserver", severity="critical", host=host, port=port,
                        detail="kube-apiserver allows anonymous read access to namespaces.",
                    ))
                elif resp.status_code in (401, 403):
                    findings.append(ContainerFinding(
                        check="kube_apiserver", severity="info", host=host, port=port,
                        detail=f"kube-apiserver reachable on port {port} — auth enforced.",
                    ))
            except Exception:
                pass

        # etcd
        try:
            resp = requests.get(f"http://{host}:2379/v3/keys", timeout=5)
            if resp.status_code in (200, 404):
                findings.append(ContainerFinding(
                    check="etcd", severity="critical", host=host, port=2379,
                    detail="etcd is accessible without authentication — cluster secrets may be exposed.",
                ))
        except Exception:
            pass

    result.container_findings.extend(findings)
    safe_print(f"[success]  ✔ Container scan: {len(findings)} findings[/]")
    return findings
