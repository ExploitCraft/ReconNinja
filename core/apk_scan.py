"""
core/apk_scan.py — ReconNinja v8.0.0
APK Static Analysis — manifest permissions, hardcoded secrets,
embedded URLs, dangerous API usage. No emulator required.
Requires: aapt (Android SDK build-tools) for manifest extraction,
          or falls back to pure Python zip parsing.
"""
from __future__ import annotations
import re, zipfile, io, os
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print
from utils.helpers import run_cmd, tool_exists

@dataclass
class ApkFinding:
    category: str   # permission / secret / url / api / component
    severity: str
    detail: str
    file: str = ""
    snippet: str = ""

@dataclass
class ApkScanResult:
    apk_path: str
    package_name: str = ""
    version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    dangerous_perms: list[str] = field(default_factory=list)
    findings: list[ApkFinding] = field(default_factory=list)
    embedded_urls: list[str] = field(default_factory=list)

DANGEROUS_PERMISSIONS = [
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
    "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
    "GET_ACCOUNTS", "MANAGE_ACCOUNTS",
]

SECRET_PATTERNS = [
    (re.compile(r'(AKIA|ASIA)[A-Z0-9]{16}'), "AWS Access Key", "critical"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub Token", "critical"),
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), "OpenAI Key", "critical"),
    (re.compile(r'AIza[A-Za-z0-9_\-]{35}'), "Google API Key", "critical"),
    (re.compile(r'(?i)api[_\-]?key\s*[=:\"\']\s*([A-Za-z0-9_\-]{16,})'), "Generic API Key", "high"),
    (re.compile(r'(?i)password\s*[=:\"\']\s*([^\s\"\']{8,})'), "Hardcoded Password", "critical"),
    (re.compile(r'(?i)secret\s*[=:\"\']\s*([^\s\"\']{8,})'), "Hardcoded Secret", "high"),
    (re.compile(r'(?i)(jdbc|mongodb|mysql|postgres|redis):\/\/[^\s\"\']+'), "DB Connection String", "critical"),
    (re.compile(r'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY'), "Private Key", "critical"),
    (re.compile(r'(?i)firebase.*[=:]\s*[A-Za-z0-9_\-]{32,}'), "Firebase Key", "high"),
]

DANGEROUS_APIS = [
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\('), "Dynamic code execution (Runtime.exec)", "high"),
    (re.compile(r'DexClassLoader|PathClassLoader'), "Dynamic class loading", "high"),
    (re.compile(r'setJavaScriptEnabled\(true\)'), "WebView JavaScript enabled", "medium"),
    (re.compile(r'setAllowFileAccess\(true\)'), "WebView file access enabled", "high"),
    (re.compile(r'addJavascriptInterface\('), "WebView JS bridge (potential RCE)", "critical"),
    (re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'), "World-readable/writable storage", "medium"),
    (re.compile(r'TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER'), "SSL pinning bypass / trust-all certs", "critical"),
    (re.compile(r'HttpsURLConnection.*setHostnameVerifier'), "Custom hostname verifier", "medium"),
]

URL_PAT = re.compile(r'https?://[^\s\'"<>]{8,}')
IP_PAT = re.compile(r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[\d.]{4,}\b')


def _extract_manifest_aapt(apk_path: str) -> str:
    if not tool_exists("aapt"):
        return ""
    rc, out, _ = run_cmd(["aapt", "dump", "badging", apk_path], timeout=30)
    return out if rc == 0 else ""


def _extract_strings_from_apk(apk_path: str) -> list[tuple[str, str]]:
    """Read all text-like files from APK zip — return list of (filename, content)."""
    results = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                # Focus on DEX, XML, properties, configs
                if any(name.endswith(ext) for ext in
                       ('.xml', '.json', '.properties', '.txt', '.dex',
                        '.js', '.html', '.cfg', '.ini', '.yaml', '.yml')):
                    try:
                        data = zf.read(name)
                        text = data.decode('utf-8', errors='ignore')
                        if text.strip():
                            results.append((name, text))
                    except Exception:
                        pass
    except Exception:
        pass
    return results


def _parse_aapt_output(aapt_out: str) -> dict:
    info = {}
    for line in aapt_out.splitlines():
        if line.startswith("package:"):
            m = re.search(r"name='([^']+)'", line)
            if m: info["package"] = m.group(1)
            m = re.search(r"versionName='([^']+)'", line)
            if m: info["version"] = m.group(1)
        if "uses-permission" in line:
            m = re.search(r"name='android\.permission\.([^']+)'", line)
            if m:
                info.setdefault("permissions", []).append(m.group(1))
        if "sdkVersion" in line:
            m = re.search(r"sdkVersion:'(\d+)'", line)
            if m: info["min_sdk"] = m.group(1)
        if "targetSdkVersion" in line:
            m = re.search(r"targetSdkVersion:'(\d+)'", line)
            if m: info["target_sdk"] = m.group(1)
    return info


def apk_scan(apk_path: str, out_folder: Path) -> ApkScanResult:
    """Run static analysis on an APK file."""
    result = ApkScanResult(apk_path=apk_path)
    safe_print(f"[info]▶ APK Static Analysis — {Path(apk_path).name}[/]")

    if not os.path.exists(apk_path):
        safe_print(f"  [danger]APK not found: {apk_path}[/]")
        return result

    # Step 1: manifest via aapt
    safe_print("  [dim]Extracting manifest...[/]")
    aapt_out = _extract_manifest_aapt(apk_path)
    if aapt_out:
        info = _parse_aapt_output(aapt_out)
        result.package_name = info.get("package", "")
        result.version = info.get("version", "")
        result.min_sdk = info.get("min_sdk", "")
        result.target_sdk = info.get("target_sdk", "")
        result.permissions = info.get("permissions", [])
        result.dangerous_perms = [p for p in result.permissions if p in DANGEROUS_PERMISSIONS]
        if result.dangerous_perms:
            result.findings.append(ApkFinding(
                category="permission",
                severity="medium",
                detail=f"{len(result.dangerous_perms)} dangerous permissions declared: "
                       f"{', '.join(result.dangerous_perms[:5])}",
            ))
    else:
        safe_print("  [dim]aapt not available — skipping manifest parse[/]")

    # Step 2: scan file contents
    safe_print("  [dim]Scanning APK contents for secrets and dangerous APIs...[/]")
    file_contents = _extract_strings_from_apk(apk_path)

    for filename, content in file_contents:
        # Secret detection
        for pat, label, sev in SECRET_PATTERNS:
            m = pat.search(content)
            if m:
                result.findings.append(ApkFinding(
                    category="secret", severity=sev, file=filename,
                    detail=f"{label} found in {filename}",
                    snippet=content[max(0,m.start()-20):m.end()+30],
                ))

        # Dangerous API detection
        for pat, label, sev in DANGEROUS_APIS:
            if pat.search(content):
                result.findings.append(ApkFinding(
                    category="api", severity=sev, file=filename,
                    detail=f"{label} in {filename}",
                ))

        # URL extraction
        for m in URL_PAT.finditer(content):
            url = m.group()
            if url not in result.embedded_urls and len(result.embedded_urls) < 100:
                result.embedded_urls.append(url)

        # Internal IP exposure
        for m in IP_PAT.finditer(content):
            result.findings.append(ApkFinding(
                category="url", severity="medium", file=filename,
                detail=f"Internal/private IP hardcoded: {m.group()} in {filename}",
                snippet=m.group(),
            ))

    crit = sum(1 for f in result.findings if f.severity == "critical")
    safe_print(f"  [warning]⚑  APK: {len(result.findings)} findings "
               f"({crit} critical), {len(result.embedded_urls)} embedded URLs[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# APK Static Analysis — {Path(apk_path).name}\n\n",
             f"Package: {result.package_name}\nVersion: {result.version}\n"
             f"Min SDK: {result.min_sdk}  Target SDK: {result.target_sdk}\n\n"]
    if result.dangerous_perms:
        lines.append(f"Dangerous Permissions ({len(result.dangerous_perms)}):\n")
        for p in result.dangerous_perms:
            lines.append(f"  - {p}\n")
        lines.append("\n")
    lines.append("## Findings\n")
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}][{f.category}] {f.detail}\n")
        if f.snippet:
            lines.append(f"  Snippet: {f.snippet[:100]}\n")
        lines.append("\n")
    if result.embedded_urls:
        lines.append("## Embedded URLs (sample)\n")
        for u in result.embedded_urls[:20]:
            lines.append(f"  {u}\n")
    (out_folder / "apk_scan.txt").write_text("".join(lines), encoding="utf-8")
    return result
