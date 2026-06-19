"""
core/linkedin_osint.py — ReconNinja v8.0.0
LinkedIn OSINT — Employee enumeration and tech stack inference.

Uses public LinkedIn search results (no API key, no login required)
plus Google dorking to enumerate employees, infer tech stack from
job postings, and identify high-value targets for social engineering.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
import urllib.error
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import safe_print


@dataclass
class Employee:
    name: str
    title: str
    profile_url: str = ""
    department: str = ""


@dataclass
class LinkedInResult:
    target: str
    company_name: str = ""
    employees: list[Employee] = field(default_factory=list)
    inferred_stack: list[str] = field(default_factory=list)
    job_postings_found: int = 0
    high_value_targets: list[str] = field(default_factory=list)
    email_formats: list[str] = field(default_factory=list)
    findings_summary: list[str] = field(default_factory=list)


# Tech keywords found in job postings → infer stack
TECH_KEYWORDS = {
    "aws": "AWS", "amazon web services": "AWS",
    "azure": "Azure", "gcp": "GCP", "google cloud": "GCP",
    "kubernetes": "Kubernetes", "k8s": "Kubernetes",
    "docker": "Docker", "terraform": "Terraform",
    "jenkins": "Jenkins", "github actions": "GitHub Actions",
    "react": "React", "angular": "Angular", "vue": "Vue.js",
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
    "spring boot": "Spring Boot", "node.js": "Node.js",
    "postgresql": "PostgreSQL", "mysql": "MySQL", "mongodb": "MongoDB",
    "redis": "Redis", "elasticsearch": "Elasticsearch",
    "splunk": "Splunk", "datadog": "Datadog",
    "okta": "Okta", "active directory": "Active Directory",
    "salesforce": "Salesforce", "jira": "Jira",
    "python": "Python", "java": "Java", "golang": "Go",
    "rust": "Rust", "typescript": "TypeScript",
}

HIGH_VALUE_TITLES = [
    "cto", "ciso", "vp engineering", "head of security",
    "sysadmin", "devops", "network engineer", "security engineer",
    "it manager", "infrastructure", "cloud architect",
    "database administrator", "penetration tester",
]

# Common corporate email formats
EMAIL_FORMATS = [
    "{first}@{domain}",
    "{first}.{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{last}@{domain}",
    "{first}_{last}@{domain}",
]


def _fetch(url: str, timeout: int = 10) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        # Use a realistic browser UA to avoid bot blocks
        req.add_header("User-Agent",
                       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        req.add_header("Accept", "text/html,application/xhtml+xml,*/*")
        req.add_header("Accept-Language", "en-US,en;q=0.9")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(65536).decode(errors="ignore")
    except Exception:
        return ""


def _google_dork(query: str, timeout: int) -> str:
    """Perform a Google search dork and return the HTML."""
    url = "https://www.google.com/search?q=" + urllib.parse.quote(query)
    body = _fetch(url, timeout)
    time.sleep(1.5)  # polite rate limit
    return body


def _extract_li_profiles(html: str, domain: str) -> list[Employee]:
    """Parse Google search results for LinkedIn profile snippets."""
    employees = []
    # Match LinkedIn profile URLs in Google results
    li_pat = re.compile(
        r'linkedin\.com/in/([a-z0-9\-]+).*?'
        r'<span[^>]*>([^<]{5,60})</span>.*?'
        r'<span[^>]*>([^<]{5,80})</span>',
        re.S | re.I,
    )
    for m in li_pat.finditer(html):
        slug, name_raw, title_raw = m.groups()
        name = re.sub(r'\s+', ' ', name_raw).strip()
        title = re.sub(r'\s+', ' ', title_raw).strip()
        if len(name) < 3 or name.startswith("<"):
            continue
        employees.append(Employee(
            name=name,
            title=title,
            profile_url=f"https://www.linkedin.com/in/{slug}",
        ))
    return employees


def _infer_stack_from_text(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for keyword, label in TECH_KEYWORDS.items():
        if keyword in text_lower and label not in found:
            found.append(label)
    return found


def _identify_high_value(employees: list[Employee]) -> list[str]:
    hvt = []
    for emp in employees:
        title_lower = emp.title.lower()
        for hvt_kw in HIGH_VALUE_TITLES:
            if hvt_kw in title_lower:
                hvt.append(f"{emp.name} — {emp.title}")
                break
    return hvt


def _guess_company_name(domain: str) -> str:
    """Strip TLD and subdomain to guess company name."""
    parts = domain.replace("www.", "").split(".")
    return parts[0].capitalize() if parts else domain


def linkedin_osint(target: str, out_folder: Path, timeout: int = 12) -> LinkedInResult:
    """
    Run LinkedIn OSINT against a domain:
    - Employee enumeration via Google dorking
    - Tech stack inference from job posting mentions
    - High-value target identification
    - Email format guessing
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    result = LinkedInResult(target=target)
    result.company_name = _guess_company_name(domain)

    safe_print(f"[info]▶ LinkedIn OSINT — {domain}[/]")

    # Dork 1: Find employees on LinkedIn
    safe_print("  [dim]Dorking LinkedIn for employees...[/]")
    dork1 = f'site:linkedin.com/in "{domain}" OR "{result.company_name}"'
    html1 = _google_dork(dork1, timeout)
    employees = _extract_li_profiles(html1, domain)
    result.employees = employees[:30]  # cap at 30

    # Dork 2: Job postings mentioning the company
    safe_print("  [dim]Searching job postings for tech stack clues...[/]")
    dork2 = f'site:linkedin.com/jobs "{result.company_name}"'
    html2 = _google_dork(dork2, timeout)
    result.inferred_stack = _infer_stack_from_text(html1 + html2)

    # Count job postings
    job_count_pat = re.compile(r'(\d+)\s+job', re.I)
    m = job_count_pat.search(html2)
    if m:
        result.job_postings_found = int(m.group(1))

    # Dork 3: Additional tech stack from company website job page
    dork3 = f'"careers" OR "jobs" site:{domain}'
    html3 = _google_dork(dork3, timeout)
    extra_stack = _infer_stack_from_text(html3)
    for item in extra_stack:
        if item not in result.inferred_stack:
            result.inferred_stack.append(item)

    # High-value target identification
    result.high_value_targets = _identify_high_value(result.employees)

    # Email format guessing
    result.email_formats = [
        fmt.replace("{domain}", domain) for fmt in EMAIL_FORMATS
    ]

    # Build findings summary
    if result.employees:
        result.findings_summary.append(
            f"Found {len(result.employees)} employee profiles on LinkedIn"
        )
    if result.inferred_stack:
        result.findings_summary.append(
            f"Inferred tech stack: {', '.join(result.inferred_stack[:10])}"
        )
    if result.high_value_targets:
        result.findings_summary.append(
            f"{len(result.high_value_targets)} high-value targets identified "
            f"(IT/security roles)"
        )

    # Print summary
    safe_print(f"  [dim]{len(result.employees)} employees found, "
               f"{len(result.inferred_stack)} tech stack items inferred[/]")
    if result.high_value_targets:
        safe_print(f"  [warning]⚑  {len(result.high_value_targets)} high-value targets "
                   f"(admin/security roles)[/]")

    # Save
    out_folder.mkdir(parents=True, exist_ok=True)
    out_file = out_folder / "linkedin_osint.txt"
    lines = [f"# LinkedIn OSINT — {domain}\n\n"]
    lines.append(f"Company: {result.company_name}\n")
    lines.append(f"Employees found: {len(result.employees)}\n")
    lines.append(f"Job postings indexed: {result.job_postings_found}\n\n")
    if result.employees:
        lines.append("## Employees\n")
        for emp in result.employees:
            lines.append(f"  {emp.name} — {emp.title}\n")
            if emp.profile_url:
                lines.append(f"    {emp.profile_url}\n")
        lines.append("\n")
    if result.high_value_targets:
        lines.append("## High-Value Targets\n")
        for hvt in result.high_value_targets:
            lines.append(f"  ⚑ {hvt}\n")
        lines.append("\n")
    if result.inferred_stack:
        lines.append("## Inferred Tech Stack\n")
        lines.append("  " + ", ".join(result.inferred_stack) + "\n\n")
    lines.append("## Probable Email Formats\n")
    for fmt in result.email_formats:
        lines.append(f"  {fmt}\n")
    out_file.write_text("".join(lines), encoding="utf-8")

    return result
