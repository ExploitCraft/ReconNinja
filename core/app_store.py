"""
core/app_store.py — ReconNinja v8.0.0
App Store Scraper — Google Play + Apple App Store metadata,
version history, declared permissions, and linked developer accounts.
"""
from __future__ import annotations
import re, json, urllib.parse, urllib.request, ssl
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import safe_print

@dataclass
class AppStoreResult:
    target: str
    google_play: list[dict] = field(default_factory=list)
    app_store: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    developer_email: str = ""
    developer_website: str = ""

def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36")
        req.add_header("Accept-Language", "en-US,en;q=0.9")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(65536).decode(errors="ignore")
    except Exception: return ""

def _search_google_play(query: str, timeout: int) -> list[dict]:
    url = f"https://play.google.com/store/search?q={urllib.parse.quote(query)}&c=apps&hl=en"
    body = _fetch(url, timeout)
    apps = []
    # Extract app IDs from play store search
    id_pat = re.compile(r'href="/store/apps/details\?id=([^"&]+)"')
    title_pat = re.compile(r'<span[^>]*class="[^"]*DdYX5[^"]*"[^>]*>([^<]{3,60})</span>')
    ids = list(dict.fromkeys(id_pat.findall(body)))[:5]
    titles = title_pat.findall(body)
    for i, app_id in enumerate(ids):
        detail_url = f"https://play.google.com/store/apps/details?id={app_id}&hl=en"
        detail = _fetch(detail_url, timeout)
        # Extract metadata
        version_m = re.search(r'Current Version.*?<span[^>]*>([^<]+)</span>', detail, re.S)
        rating_m = re.search(r'"starRating"\s*:\s*"([^"]+)"', detail)
        installs_m = re.search(r'(\d[\d,]+)\+?\s+(?:downloads|installs)', detail, re.I)
        dev_email_m = re.search(r'[\w.+-]+@[\w.-]+\.\w{2,}', detail)
        dev_web_m = re.search(r'developerWebsite.*?href="([^"]+)"', detail, re.S)
        app = {
            "id": app_id,
            "name": titles[i] if i < len(titles) else app_id,
            "url": detail_url,
            "version": version_m.group(1).strip() if version_m else "",
            "rating": rating_m.group(1) if rating_m else "",
            "installs": installs_m.group(1) if installs_m else "",
            "developer_email": dev_email_m.group() if dev_email_m else "",
            "developer_website": dev_web_m.group(1) if dev_web_m else "",
        }
        apps.append(app)
    return apps

def _search_app_store(query: str, timeout: int) -> list[dict]:
    # Use iTunes Search API (public, no key)
    url = f"https://itunes.apple.com/search?term={urllib.parse.quote(query)}&entity=software&limit=5"
    body = _fetch(url, timeout)
    apps = []
    try:
        data = json.loads(body)
        for item in data.get("results", [])[:5]:
            apps.append({
                "id": str(item.get("trackId", "")),
                "name": item.get("trackName", ""),
                "url": item.get("trackViewUrl", ""),
                "version": item.get("version", ""),
                "rating": str(item.get("averageUserRating", "")),
                "installs": str(item.get("userRatingCount", "")),
                "developer_name": item.get("artistName", ""),
                "developer_url": item.get("sellerUrl", ""),
                "bundle_id": item.get("bundleId", ""),
                "min_os": item.get("minimumOsVersion", ""),
                "description_snippet": item.get("description", "")[:200],
            })
    except Exception:
        pass
    return apps

def app_store_scan(target: str, out_folder: Path, timeout: int = 12) -> AppStoreResult:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    company = domain.split(".")[0]
    result = AppStoreResult(target=target)
    safe_print(f"[info]▶ App Store Scraper — {company}[/]")

    safe_print("  [dim]Searching Google Play...[/]")
    result.google_play = _search_google_play(company, timeout)

    safe_print("  [dim]Searching Apple App Store...[/]")
    result.app_store = _search_app_store(company, timeout)

    # Extract developer intel
    for app in result.google_play:
        if app.get("developer_email"):
            result.developer_email = app["developer_email"]
            result.findings.append(f"Developer email found: {app['developer_email']}")
        if app.get("developer_website"):
            result.developer_website = app["developer_website"]

    total = len(result.google_play) + len(result.app_store)
    safe_print(f"  [dim]App Store: {total} apps found ({len(result.google_play)} Play, {len(result.app_store)} iOS)[/]")

    out_folder.mkdir(parents=True, exist_ok=True)
    lines = [f"# App Store Scraper — {company}\n\n",
             f"## Google Play ({len(result.google_play)} apps)\n"]
    for a in result.google_play:
        lines.append(f"  {a['name']} ({a['id']})\n")
        lines.append(f"    Version: {a['version']}  Installs: {a['installs']}\n")
        if a.get("developer_email"):
            lines.append(f"    Dev Email: {a['developer_email']}\n")
        lines.append(f"    URL: {a['url']}\n\n")
    lines.append(f"\n## Apple App Store ({len(result.app_store)} apps)\n")
    for a in result.app_store:
        lines.append(f"  {a['name']}  Bundle: {a.get('bundle_id','')}\n")
        lines.append(f"    Version: {a['version']}  Min iOS: {a.get('min_os','')}\n")
        lines.append(f"    URL: {a['url']}\n\n")
    (out_folder / "app_store.txt").write_text("".join(lines), encoding="utf-8")
    return result
