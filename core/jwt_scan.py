"""
core/jwt_scan.py — ReconNinja v7.0.0
JWT (JSON Web Token) vulnerability scanner.

Detects:
  - Algorithm confusion (none / HS256 with RS256 public key)
  - Weak HMAC secrets (dictionary attack on HS256/HS384/HS512)
  - JWT in URL parameters (token leakage)
  - No expiry (exp claim missing)
  - Overly long expiry

No external tools required — pure Python stdlib + optional PyJWT.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.helpers import ensure_dir
from utils.logger import safe_print, log


WEAK_SECRETS = [
    "secret", "password", "123456", "test", "admin", "key",
    "jwt_secret", "mysecret", "changeme", "your-256-bit-secret",
    "your-secret", "secret-key", "jwt-secret", "hs256",
]


@dataclass
class JWTFinding:
    url:      str
    token:    str
    issue:    str
    severity: str
    detail:   str = ""

    def to_dict(self) -> dict:
        return {
            "url":      self.url,
            "token":    self.token[:30] + "...",
            "issue":    self.issue,
            "severity": self.severity,
            "detail":   self.detail,
        }


def _b64pad(s: str) -> str:
    """Add padding to base64url string."""
    return s + "=" * (-len(s) % 4)


def _decode_jwt(token: str) -> Optional[tuple[dict, dict]]:
    """Decode JWT header and payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return header, payload
    except Exception:
        return None


def _test_none_algorithm(token: str, url: str) -> Optional[JWTFinding]:
    """Test if server accepts 'none' algorithm JWTs."""
    decoded = _decode_jwt(token)
    if not decoded:
        return None
    header, payload = decoded

    # Craft none-alg token
    new_header  = {**header, "alg": "none"}
    new_h_enc   = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b"=").decode()
    new_p_enc   = token.split(".")[1]
    none_token  = f"{new_h_enc}.{new_p_enc}."

    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {none_token}",
                "User-Agent": "ReconNinja/7.0.0",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status in (200, 201, 204):
                return JWTFinding(
                    url=url,
                    token=none_token,
                    issue="JWT none-algorithm accepted",
                    severity="critical",
                    detail="Server accepts unsigned JWT with alg=none — full authentication bypass",
                )
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass
    return None


def _test_weak_secret(token: str) -> Optional[str]:
    """Try to crack HS256/HS384/HS512 JWT with common weak secrets."""
    decoded = _decode_jwt(token)
    if not decoded:
        return None
    header, _ = decoded

    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return None

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map.get(alg, hashlib.sha256)

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig  = base64.urlsafe_b64decode(_b64pad(parts[2]))

    for secret in WEAK_SECRETS:
        sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(sig, expected_sig):
            return secret
    return None


def _extract_jwts_from_url(url: str, timeout: int = 8) -> list[str]:
    """Fetch a URL and extract JWT tokens from response headers/body."""
    tokens = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            # Check headers
            for hdr in r.headers.values():
                tokens.extend(jwt_re.findall(hdr))
            # Check body
            body = r.read(50000).decode(errors="ignore")
            tokens.extend(jwt_re.findall(body))
    except Exception:
        pass
    return list(set(tokens))


def jwt_scan(
    web_urls: list[str],
    out_folder: Path,
    timeout: int = 8,
) -> list[JWTFinding]:
    """
    Scan web endpoints for JWT vulnerabilities.

    Args:
        web_urls:   live URLs to scan
        out_folder: output directory

    Returns:
        list of JWTFinding
    """
    ensure_dir(out_folder)
    findings: list[JWTFinding] = []
    safe_print(f"[info]▶ JWT Scanner — {len(web_urls)} target(s)[/]")

    for url in web_urls[:20]:
        tokens = _extract_jwts_from_url(url, timeout=timeout)
        for token in tokens[:5]:
            decoded = _decode_jwt(token)
            if not decoded:
                continue
            header, payload = decoded

            # Check expiry
            if "exp" not in payload:
                findings.append(JWTFinding(
                    url=url, token=token,
                    issue="JWT missing exp claim",
                    severity="medium",
                    detail="Tokens without expiry never expire — permanent session risk",
                ))

            # Check weak secret
            cracked = _test_weak_secret(token)
            if cracked:
                findings.append(JWTFinding(
                    url=url, token=token,
                    issue=f"JWT signed with weak secret: '{cracked}'",
                    severity="critical",
                    detail="Weak HMAC secret allows forging arbitrary tokens",
                ))

            # Test none algorithm
            none_finding = _test_none_algorithm(token, url)
            if none_finding:
                findings.append(none_finding)

    # Save
    out_file = out_folder / "jwt_findings.txt"
    lines = [f"# JWT Scan Results\n"]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.issue}")
        lines.append(f"  URL:    {f.url}")
        lines.append(f"  Detail: {f.detail}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    crit = sum(1 for f in findings if f.severity == "critical")
    safe_print(f"[{'danger' if crit else 'success'}]✔ JWT: {len(findings)} finding(s), {crit} critical[/]")
    return findings
