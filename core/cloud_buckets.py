"""
core/cloud_buckets.py — ReconNinja v7.0.0
Cloud storage bucket enumeration — AWS S3, Azure Blob, GCS.

Given a target domain like "example.com" (root org = "example"), probes
common bucket naming conventions for public access.

No API keys required — pure HTTP probing via urllib.
"""

from __future__ import annotations

import concurrent.futures
import re
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


@dataclass
class BucketFinding:
    provider: str    # aws | azure | gcp
    url:      str
    name:     str
    status:   str    # public | authenticated | private | not_found | error
    content:  str    # snippet of public listing XML if accessible


# ── Bucket name generators ────────────────────────────────────────────────────

def _org_from_domain(domain: str) -> str:
    """Strip subdomains + TLD to get root org name."""
    parts = re.sub(r"https?://", "", domain).split("/")[0].split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _generate_names(org: str, domain: str) -> list[str]:
    """Generate bucket name candidates from target org."""
    base = re.sub(r"[^a-z0-9]", "-", org.lower()).strip("-")
    dom  = re.sub(r"[^a-z0-9]", "-", domain.lower().split(".")[0]).strip("-")
    candidates = {base, dom}
    for suffix in ("backup", "backups", "dev", "prod", "staging", "assets",
                   "static", "media", "files", "uploads", "data", "storage",
                   "logs", "archive", "images", "web", "cdn", "api", "internal"):
        candidates.add(f"{base}-{suffix}")
        candidates.add(f"{base}.{suffix}")
        candidates.add(f"{suffix}-{base}")
        candidates.add(f"{suffix}.{base}")
    return [c for c in sorted(candidates) if 3 <= len(c) <= 63][:60]


# ── Provider-specific probers ─────────────────────────────────────────────────

def _probe_s3(name: str, timeout: int = 8) -> BucketFinding:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2048).decode(errors="ignore")
            status = "public" if "<ListBucketResult" in body or "<Contents" in body else "authenticated"
            return BucketFinding("aws", url, name, status, body[:500])
    except urllib.error.HTTPError as e:
        status = {403: "authenticated", 404: "not_found"}.get(e.code, f"http_{e.code}")
        return BucketFinding("aws", url, name, status, "")
    except Exception:
        return BucketFinding("aws", url, name, "error", "")


def _probe_azure(name: str, timeout: int = 8) -> BucketFinding:
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2048).decode(errors="ignore")
            status = "public" if "<EnumerationResults" in body else "authenticated"
            return BucketFinding("azure", url, name, status, body[:500])
    except urllib.error.HTTPError as e:
        status = {403: "authenticated", 404: "not_found"}.get(e.code, f"http_{e.code}")
        return BucketFinding("azure", url, name, status, "")
    except Exception:
        return BucketFinding("azure", url, name, "error", "")


def _probe_gcs(name: str, timeout: int = 8) -> BucketFinding:
    url = f"https://storage.googleapis.com/{name}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2048).decode(errors="ignore")
            status = "public" if "<ListBucketResult" in body else "authenticated"
            return BucketFinding("gcp", url, name, status, body[:500])
    except urllib.error.HTTPError as e:
        status = {403: "authenticated", 404: "not_found"}.get(e.code, f"http_{e.code}")
        return BucketFinding("gcp", url, name, status, "")
    except Exception:
        return BucketFinding("gcp", url, name, "error", "")


# ── Public API ────────────────────────────────────────────────────────────────

def enumerate_buckets(
    target: str,
    out_folder: Path,
    concurrency: int = 20,
    timeout: int = 8,
) -> list[BucketFinding]:
    """
    Enumerate cloud storage buckets for a target domain.

    Checks AWS S3, Azure Blob, and Google Cloud Storage for:
      - Publicly accessible (listable) buckets
      - Authenticated-only buckets (exists but requires auth)

    Args:
        target:      target domain or org name
        out_folder:  output folder for results
        concurrency: parallel probes
        timeout:     per-request timeout

    Returns:
        list of BucketFinding — only non-404 results
    """
    ensure_dir(out_folder)
    org   = _org_from_domain(target)
    names = _generate_names(org, target)

    safe_print(
        f"[info]▶ Cloud Buckets — probing {len(names)} candidates "
        f"× 3 providers for '{org}'[/]"
    )

    jobs = (
        [(_probe_s3,    n, timeout) for n in names] +
        [(_probe_azure, n, timeout) for n in names] +
        [(_probe_gcs,   n, timeout) for n in names]
    )

    interesting: list[BucketFinding] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(fn, name, to): (fn, name) for fn, name, to in jobs}
        for fut in concurrent.futures.as_completed(futs):
            try:
                result = fut.result()
                if result.status not in ("not_found", "error"):
                    interesting.append(result)
            except Exception as e:
                log.debug(f"Bucket probe error: {e}")

    public  = [f for f in interesting if f.status == "public"]
    authed  = [f for f in interesting if f.status == "authenticated"]

    if public:
        safe_print(f"  [danger]⚠  {len(public)} PUBLIC bucket(s) found![/]")
        for f in public:
            safe_print(f"    [danger]→ [{f.provider.upper()}] {f.url}[/]")
    if authed:
        safe_print(f"  [warning]{len(authed)} authenticated (private) bucket(s) discovered[/]")

    # Save results
    out_file = out_folder / "buckets.txt"
    lines = ["# Cloud Bucket Enumeration Results\n"]
    for f in sorted(interesting, key=lambda x: x.status):
        lines.append(f"[{f.status.upper()}] [{f.provider.upper()}] {f.url}")
    out_file.write_text("\n".join(lines))

    safe_print(
        f"[success]✔ Cloud Buckets: {len(public)} public, "
        f"{len(authed)} authenticated[/]"
    )
    return interesting
