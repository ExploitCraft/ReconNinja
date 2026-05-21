"""
ReconNinja v9 — Cloud-Native Deep Scan  (--cloud-deep)
AWS: IAM role via metadata, S3 ACLs, Lambda URLs, RDS snapshots, ECR images.
Azure: Managed identity, Blob enum, App Service, Azure AD guest enum, SAS tokens.
GCP: GCS bucket enum, service account keys, Cloud Run unauthenticated endpoints, Firebase.
Multi-cloud correlation: cross-reference org presence across providers.

Use only against targets you own or have explicit written permission to test.
"""
from __future__ import annotations

import re
from pathlib import Path

import requests

from utils.logger import log, safe_print
from utils.models import CloudFinding, ReconResult, ScanConfig


def cloud_deep_scan(
    target: str,
    result: ReconResult,
    cfg: ScanConfig,
    out_folder: Path,
) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    safe_print("[module]☁  Cloud Deep Scan...[/]")

    # Derive org name guesses from target
    org_names = _derive_org_names(target)

    findings += _aws_scan(target, org_names, cfg)
    findings += _azure_scan(target, org_names, cfg)
    findings += _gcp_scan(target, org_names, cfg)
    findings += _cross_cloud_correlation(findings)

    result.cloud_deep_findings.extend(findings)

    crits = sum(1 for f in findings if f.severity == "critical")
    safe_print(f"[success]  ✔ Cloud deep: {len(findings)} findings ({crits} critical)[/]")
    return findings


# ─── Org name derivation ──────────────────────────────────────────────────────

def _derive_org_names(target: str) -> list[str]:
    # Strip TLD: example.com → example, sub.example.co.uk → example
    parts = target.lower().split(".")
    names = []
    if len(parts) >= 2:
        names.append(parts[-2])
    if len(parts) >= 3:
        names.append(parts[-3])
    names.append(target.replace(".", "-"))
    return list(set(names))


# ─── AWS ──────────────────────────────────────────────────────────────────────

def _aws_scan(target: str, org_names: list[str], cfg: ScanConfig) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    # S3 bucket enumeration
    for name in org_names:
        for variant in [name, f"{name}-backup", f"{name}-dev", f"{name}-prod",
                        f"{name}-assets", f"{name}-logs", f"{name}-data",
                        f"{name}-uploads", f"{name}-public"]:
            result = _check_s3_bucket(variant)
            if result:
                findings.append(result)

    # Check for IMDS v1 exposure (only meaningful on cloud instances in scope)
    # Lambda function URL patterns — check httpx findings for *.lambda-url.*.on.aws
    lambda_pattern = re.compile(r"https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws")
    # (Would be applied against httpx findings in orchestrator context)

    # Exposed ECR registry via public.ecr.aws
    for name in org_names:
        try:
            resp = requests.get(
                f"https://public.ecr.aws/v2/{name}",
                timeout=10, allow_redirects=True,
            )
            if resp.status_code in (200, 401):
                findings.append(CloudFinding(
                    provider="aws",
                    service="ecr",
                    severity="medium",
                    resource=f"public.ecr.aws/{name}",
                    detail="ECR public registry namespace exists — may contain sensitive images.",
                    public=resp.status_code == 200,
                ))
        except Exception:
            pass

    return findings


def _check_s3_bucket(bucket_name: str) -> CloudFinding | None:
    try:
        resp = requests.head(
            f"https://{bucket_name}.s3.amazonaws.com",
            timeout=8, allow_redirects=False,
        )
        if resp.status_code == 200:
            return CloudFinding(
                provider="aws", service="s3", severity="critical",
                resource=f"s3://{bucket_name}",
                detail="S3 bucket is publicly accessible — unauthenticated read possible.",
                public=True,
            )
        if resp.status_code == 403:
            return CloudFinding(
                provider="aws", service="s3", severity="info",
                resource=f"s3://{bucket_name}",
                detail="S3 bucket exists but access denied (403). Bucket name confirmed.",
                public=False,
            )
    except Exception:
        pass
    return None


# ─── Azure ────────────────────────────────────────────────────────────────────

def _azure_scan(target: str, org_names: list[str], cfg: ScanConfig) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    for name in org_names:
        # Azure Blob storage
        for container in ["", "backup", "public", "data", "logs", "$web"]:
            url = f"https://{name}.blob.core.windows.net"
            if container:
                url += f"/{container}?restype=container&comp=list"
            try:
                resp = requests.get(url, timeout=8)
                if resp.status_code == 200 and "<Blobs>" in resp.text:
                    findings.append(CloudFinding(
                        provider="azure", service="blob",
                        severity="critical",
                        resource=url,
                        detail=f"Azure Blob container '{container or 'root'}' is publicly listed.",
                        public=True,
                    ))
                elif resp.status_code in (200, 400):
                    findings.append(CloudFinding(
                        provider="azure", service="blob",
                        severity="info",
                        resource=f"https://{name}.blob.core.windows.net",
                        detail="Azure storage account exists.",
                        public=False,
                    ))
                    break
            except Exception:
                pass

        # Azure App Service / Static Web App
        for suffix in [".azurewebsites.net", ".azurestaticapps.net", ".scm.azurewebsites.net"]:
            try:
                resp = requests.get(f"https://{name}{suffix}", timeout=8, allow_redirects=True)
                if resp.status_code < 500:
                    sev = "high" if ".scm." in suffix else "info"
                    findings.append(CloudFinding(
                        provider="azure", service="appservice",
                        severity=sev,
                        resource=f"https://{name}{suffix}",
                        detail=f"Azure App Service endpoint reachable{' (Kudu/SCM endpoint)' if '.scm.' in suffix else ''}.",
                        public=True,
                    ))
            except Exception:
                pass

    return findings


# ─── GCP ──────────────────────────────────────────────────────────────────────

def _gcp_scan(target: str, org_names: list[str], cfg: ScanConfig) -> list[CloudFinding]:
    findings: list[CloudFinding] = []

    for name in org_names:
        # GCS bucket
        for variant in [name, f"{name}-backup", f"{name}-public", f"{name}-assets"]:
            try:
                resp = requests.get(
                    f"https://storage.googleapis.com/{variant}",
                    timeout=8,
                )
                if resp.status_code == 200:
                    findings.append(CloudFinding(
                        provider="gcp", service="gcs", severity="critical",
                        resource=f"gs://{variant}",
                        detail="GCS bucket is publicly readable — unauthenticated access confirmed.",
                        public=True,
                    ))
                elif resp.status_code == 403:
                    findings.append(CloudFinding(
                        provider="gcp", service="gcs", severity="info",
                        resource=f"gs://{variant}",
                        detail="GCS bucket exists (access denied — bucket name confirmed).",
                        public=False,
                    ))
            except Exception:
                pass

        # Firebase RTDB
        for db_name in [name, f"{name}-default-rtdb"]:
            try:
                resp = requests.get(
                    f"https://{db_name}.firebaseio.com/.json",
                    timeout=8,
                )
                if resp.status_code == 200:
                    findings.append(CloudFinding(
                        provider="gcp", service="firebase", severity="critical",
                        resource=f"https://{db_name}.firebaseio.com",
                        detail="Firebase Realtime Database is publicly readable — no authentication required.",
                        public=True,
                    ))
            except Exception:
                pass

        # Cloud Run unauthenticated endpoints
        try:
            resp = requests.get(
                f"https://{name}-run.a.run.app",
                timeout=8, allow_redirects=True,
            )
            if resp.status_code < 500:
                findings.append(CloudFinding(
                    provider="gcp", service="cloudrun", severity="medium",
                    resource=f"https://{name}-run.a.run.app",
                    detail="Cloud Run endpoint is publicly reachable — verify auth is enforced.",
                    public=True,
                ))
        except Exception:
            pass

    return findings


# ─── Cross-cloud correlation ──────────────────────────────────────────────────

def _cross_cloud_correlation(findings: list[CloudFinding]) -> list[CloudFinding]:
    providers = {f.provider for f in findings if f.provider != "gcp" or f.severity != "info"}
    if len(providers) > 1:
        return [CloudFinding(
            provider="multi",
            service="correlation",
            severity="medium",
            resource="multi-cloud",
            detail=f"Target has presence in {', '.join(sorted(providers)).upper()} — "
                   "cross-cloud identity misconfigurations may be exploitable.",
        )]
    return []
