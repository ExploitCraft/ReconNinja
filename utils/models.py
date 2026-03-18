"""
ReconNinja v5.0.0 — Data Models
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

class ScanProfile(Enum):
    FAST       = "fast"
    STANDARD   = "standard"
    THOROUGH   = "thorough"
    STEALTH    = "stealth"
    CUSTOM     = "custom"
    FULL_SUITE = "full_suite"
    WEB_ONLY   = "web_only"
    PORT_ONLY  = "port_only"

class Phase(Enum):
    PASSIVE     = "passive"
    PORT        = "port"
    SERVICE     = "service"
    WEB         = "web"
    DIRECTORY   = "directory"
    TECH        = "tech"
    VULN        = "vuln"
    SCREENSHOT  = "screenshot"
    REPORT      = "report"

SEVERITY_PORTS: dict[str, set[int]] = {
    "critical": {21, 22, 23, 25, 53, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514},
    "high":     {80, 443, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017},
    "medium":   {8000, 8081, 8888, 9200, 9300, 11211},
}
WEB_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 3000, 5000, 9000}
VALID_TIMINGS = {"T1", "T2", "T3", "T4", "T5"}

@dataclass
class NmapOptions:
    all_ports:         bool          = False
    top_ports:         int           = 1000
    scripts:           bool          = True
    version_detection: bool          = True
    os_detection:      bool          = False
    aggressive:        bool          = False
    stealth:           bool          = False
    timing:            str           = "T4"
    extra_flags:       list[str]     = field(default_factory=list)
    script_args:       Optional[str] = None

    def __post_init__(self):
        if self.timing not in VALID_TIMINGS:
            raise ValueError(f"Invalid timing '{self.timing}'.")
        if not self.all_ports and self.top_ports < 0:
            raise ValueError("top_ports must be >= 0")

    def as_nmap_args(self) -> list[str]:
        args: list[str] = []
        if self.stealth:
            args += ["-sS"]
        elif self.aggressive:
            args += ["-A"]
        else:
            args += ["-sT"]
            if self.os_detection:      args += ["-O"]
            if self.scripts:           args += ["-sC"]
            if self.version_detection: args += ["-sV"]
        if self.script_args:
            args += [f"--script-args={self.script_args}"]
        args += [f"-{self.timing}"]
        if self.all_ports:
            args += ["-p-"]
        elif self.top_ports:
            args += ["--top-ports", str(self.top_ports)]
        args += self.extra_flags
        return args

@dataclass
class ScanConfig:
    target:           str
    profile:          ScanProfile  = ScanProfile.STANDARD
    nmap_opts:        NmapOptions  = field(default_factory=NmapOptions)
    run_subdomains:   bool = False
    run_rustscan:     bool = False
    run_feroxbuster:  bool = False
    run_masscan:      bool = False
    run_aquatone:     bool = False
    run_whatweb:      bool = False
    run_nikto:        bool = False
    run_nuclei:       bool = False
    run_httpx:        bool = False
    run_ai_analysis:  bool = False
    run_cve_lookup:   bool = False
    ai_provider:      str  = "groq"
    ai_key:           str  = ""
    ai_model:         str  = ""
    nvd_key:          str  = ""
    # v5.0.0 — new integrations
    run_shodan:       bool = False
    run_virustotal:   bool = False
    run_whois:        bool = False
    run_wayback:      bool = False
    run_ssl:          bool = False
    shodan_key:       str  = ""
    vt_key:           str  = ""
    # v5.0.0 — output control
    output_format:    str  = "all"    # all | html | json | md | txt
    exclude_phases:   list = field(default_factory=list)
    # v5.0.0 — performance
    global_timeout:   int  = 30
    rate_limit:       float = 0.0
    masscan_rate:       int   = 5000
    threads:            int   = 20
    wordlist_size:      str   = "medium"
    output_dir:         str   = "reports"
    async_concurrency:  int   = 1000
    async_timeout:      float = 1.5

    def to_dict(self) -> dict:
        d = asdict(self)
        d["profile"] = self.profile.value
        return d

@dataclass
class PortInfo:
    port:       int
    protocol:   str
    state:      str
    service:    str  = ""
    product:    str  = ""
    version:    str  = ""
    extra_info: str  = ""
    scripts:    dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        for sev, ports in SEVERITY_PORTS.items():
            if self.port in ports:
                return sev
        return "info"

    @property
    def is_web(self) -> bool:
        return self.port in WEB_PORTS

    @property
    def display_state(self) -> str:
        colors = {"open":"port.open","filtered":"port.filtered","closed":"port.closed"}
        return f"[{colors.get(self.state,'dim')}]{self.state}[/]"

@dataclass
class HostResult:
    ip:               str
    mac:              str       = ""
    hostnames:        list[str] = field(default_factory=list)
    os_guess:         str       = ""
    os_accuracy:      str       = ""
    ports:            list[PortInfo] = field(default_factory=list)
    scan_time:        str       = ""
    source_subdomain: str       = ""
    web_urls:         list[str] = field(default_factory=list)

    @property
    def open_ports(self):
        return [p for p in self.ports if p.state == "open"]

    @property
    def web_ports(self):
        return [p for p in self.open_ports if p.is_web]

@dataclass
class WebFinding:
    url:            str
    status_code:    int       = 0
    title:          str       = ""
    technologies:   list[str] = field(default_factory=list)
    server:         str       = ""
    content_length: int       = 0

@dataclass
class VulnFinding:
    tool:     str
    severity: str
    title:    str
    target:   str
    details:  str = ""
    cve:      str = ""

@dataclass
class ReconResult:
    target:           str
    start_time:       str
    end_time:         str            = ""
    subdomains:       list[str]      = field(default_factory=list)
    hosts:            list[HostResult]  = field(default_factory=list)
    web_findings:     list[WebFinding]  = field(default_factory=list)
    dir_findings:     list[str]      = field(default_factory=list)
    nikto_findings:   list[str]      = field(default_factory=list)
    whatweb_findings: list[str]      = field(default_factory=list)
    nuclei_findings:  list[VulnFinding] = field(default_factory=list)
    masscan_ports:    list[int]      = field(default_factory=list)
    ai_analysis:      str            = ""
    errors:           list[str]      = field(default_factory=list)
    phases_completed: list[str]      = field(default_factory=list)
    # v5.0.0
    shodan_results:   list[dict]     = field(default_factory=list)
    vt_results:       list[dict]     = field(default_factory=list)
    whois_results:    list[dict]     = field(default_factory=list)
    wayback_results:  list[dict]     = field(default_factory=list)
    ssl_results:      list[dict]     = field(default_factory=list)
