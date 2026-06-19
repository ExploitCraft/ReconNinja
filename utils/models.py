"""
ReconNinja — Data Models  (version → see info/version)

v9.0.0 additions:
  - AttackChain, CloudFinding, ADFinding, LLMSurface, IoTFinding
  - ContainerFinding, WirelessFinding, DarkWebFinding
  - EvidenceItem, ScopePolicy, RateProfile enum
  - VulnFinding gains cvss_v4, epss_score, rei fields
  - ReconResult gains all v9 result fields
  - ScanConfig gains all v9 flags
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ─── Enums ────────────────────────────────────────────────────────────────────

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

class RateProfile(Enum):
    AGGRESSIVE = "aggressive"
    STANDARD   = "standard"
    LOW_NOISE  = "low-noise"
    PARANOID   = "paranoid"

    @property
    def requests_per_sec(self) -> float:
        return {"aggressive": 0.0, "standard": 10.0, "low-noise": 2.0, "paranoid": 0.5}[self.value]

    @property
    def dns_per_sec(self) -> float:
        return {"aggressive": 0.0, "standard": 5.0, "low-noise": 1.0, "paranoid": 0.2}[self.value]

    @property
    def rotate_ua(self) -> bool:
        return self.value in ("standard", "low-noise", "paranoid")

    @property
    def jitter(self) -> float:
        return {"aggressive": 0.0, "standard": 0.1, "low-noise": 0.2, "paranoid": 0.4}[self.value]


# ─── Port / severity maps ──────────────────────────────────────────────────────

SEVERITY_PORTS: dict[str, set[int]] = {
    "critical": {21, 22, 23, 25, 53, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514},
    "high":     {80, 443, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017},
    "medium":   {8000, 8081, 8888, 9200, 9300, 11211},
}
WEB_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 3000, 5000, 9000}
VALID_TIMINGS = {"T1", "T2", "T3", "T4", "T5"}


# ─── Nmap options ─────────────────────────────────────────────────────────────

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
        elif self.top_ports > 0:
            args += ["--top-ports", str(self.top_ports)]
        args += self.extra_flags
        return args


# ─── v9 dataclasses ───────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    chain_id:           str
    title:              str
    steps:              list[str] = field(default_factory=list)
    probability:        float     = 0.0
    severity:           str       = "medium"
    prerequisites:      list[str] = field(default_factory=list)
    mitre_ttps:         list[str] = field(default_factory=list)
    remediation:        str       = ""
    source_finding_ids: list[str] = field(default_factory=list)


@dataclass
class CloudFinding:
    provider:   str
    service:    str
    severity:   str
    resource:   str
    detail:     str
    public:     bool = False
    region:     str  = ""
    finding_id: str  = ""


@dataclass
class ADFinding:
    category:   str
    severity:   str
    title:      str
    object_dn:  str = ""
    detail:     str = ""
    mitigation: str = ""


@dataclass
class LLMSurface:
    surface_type: str
    url:          str
    severity:     str  = "medium"
    detail:       str  = ""
    auth_bypass:  bool = False


@dataclass
class IoTFinding:
    protocol:  str
    host:      str
    port:      int
    vendor:    str       = ""
    model:     str       = ""
    firmware:  str       = ""
    cves:      list[str] = field(default_factory=list)
    severity:  str       = "high"


@dataclass
class ContainerFinding:
    check:    str
    severity: str
    host:     str
    port:     int  = 0
    detail:   str  = ""
    evidence: str  = ""


@dataclass
class WirelessFinding:
    ssid:      str
    bssid:     str   = ""
    lat:       float = 0.0
    lng:       float = 0.0
    source:    str   = "wigle"
    is_rogue:  bool  = False
    detail:    str   = ""


@dataclass
class DarkWebFinding:
    source:   str
    mention:  str
    url:      str = ""
    date:     str = ""
    severity: str = "high"


@dataclass
class EvidenceItem:
    finding_id:  str
    type:        str
    filename:    str
    sha256:      str = ""
    description: str = ""


@dataclass
class ScopePolicy:
    allowed:  list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    strict:   bool      = False

    def in_scope(self, target: str) -> bool:
        import fnmatch, ipaddress
        for excl in self.excluded:
            if fnmatch.fnmatch(target, excl):
                return False
            try:
                net = ipaddress.ip_network(excl, strict=False)
                if ipaddress.ip_address(target) in net:
                    return False
            except ValueError:
                pass
        if not self.allowed:
            return True
        for rule in self.allowed:
            if fnmatch.fnmatch(target, rule) or fnmatch.fnmatch(target, f"*.{rule}"):
                return True
            try:
                net = ipaddress.ip_network(rule, strict=False)
                if ipaddress.ip_address(target) in net:
                    return True
            except ValueError:
                pass
        return False


# ─── ScanConfig ───────────────────────────────────────────────────────────────

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
    run_shodan:       bool = False
    run_virustotal:   bool = False
    run_whois:        bool = False
    run_wayback:      bool = False
    run_ssl:          bool = False
    shodan_key:       str  = ""
    vt_key:           str  = ""
    run_github_osint:   bool = False
    github_token:       str  = ""
    run_js_extract:     bool = False
    run_cloud_buckets:  bool = False
    run_dns_zone:       bool = False
    run_waf:            bool = False
    run_cors:           bool = False
    notify_url:         str  = ""
    run_email_security: bool = False
    run_breach_check:   bool = False
    hibp_key:           str  = ""
    run_cloud_meta:     bool = False
    run_graphql:        bool = False
    run_jwt_scan:       bool = False
    run_asn_map:        bool = False
    run_supply_chain:   bool = False
    run_k8s_probe:      bool = False
    run_db_exposure:    bool = False
    run_smtp_enum:      bool = False
    run_snmp_scan:      bool = False
    run_ldap_enum:      bool = False
    run_devops_scan:    bool = False
    run_greynoise:      bool = False
    greynoise_key:      str  = ""
    run_typosquat:      bool = False
    run_censys:         bool = False
    censys_api_id:      str  = ""
    censys_api_secret:  str  = ""
    run_dns_history:    bool = False
    run_sarif_export:   bool = False
    run_api_fuzz:       bool = False
    run_oauth_scan:     bool = False
    run_web_vulns:      bool = False
    run_open_redirect:  bool = False
    run_linkedin:       bool = False
    run_paste_monitor:  bool = False
    run_se_osint:       bool = False
    apk_path:           str | None = None
    run_app_store:      bool = False
    run_anon_detect:    bool = False
    run_dns_leak:       bool = False
    run_web3_scan:      bool = False
    run_ens_lookup:     bool = False
    run_ai_consensus:   bool = False
    run_attack_paths:   bool = False
    run_ai_remediate:   bool = False
    ai_config:          dict = field(default_factory=dict)
    run_pdf_report:     bool = False
    jira_config:        dict | None = None
    github_issues_config: dict | None = None
    siem_config:        dict | None = None
    # ── v9 ────────────────────────────────────────────────────────────────────
    agent_mode:           bool  = False
    classic_mode:         bool  = False
    require_approval:     bool  = False
    agent_budget:         int   = 50
    parallel_phases:      int   = 4
    run_ad_recon:         bool  = False
    ad_dc:                str   = ""
    ad_domain:            str   = ""
    ad_user:              str   = ""
    ad_password:          str   = ""
    ad_bloodhound_output: str   = "ad_data"
    run_cloud_deep:       bool  = False
    run_llm_recon:        bool  = False
    run_iot_scan:         bool  = False
    run_container_deep:   bool  = False
    run_wireless_osint:   bool  = False
    wigle_api_token:      str   = ""
    run_darkweb_osint:    bool  = False
    telegram_token:       str   = ""
    run_correlation:      bool  = False
    local_llm_url:        str   = "http://localhost:11434"
    epss_threshold:       float = 0.0
    run_interactive_report: bool  = False
    mcp_server_mode:        bool  = False
    mcp_server_port:        int   = 8765
    defectdojo_url:         str   = ""
    defectdojo_key:         str   = ""
    defectdojo_product:     str   = ""
    run_notion_export:      bool  = False
    notion_token:           str   = ""
    notion_db_id:           str   = ""
    run_obsidian_export:    bool  = False
    obsidian_vault_path:    str   = "vault"
    monitor_mode:           bool  = False
    monitor_interval:       str   = "24h"
    monitor_passive_only:   bool  = False
    report_template:        str   = "technical"
    compliance_framework:   str   = ""
    scope_file:             str   = ""
    scope_strict:           bool  = False
    exclude_targets:        list[str] = field(default_factory=list)
    run_evidence:           bool  = False
    evidence_sign_key:      str   = ""
    rate_profile:           str   = "aggressive"
    jitter:                 float = 0.0
    proxy_list:             str   = ""
    log_format:             str   = "text"
    metrics_port:           int   = 0
    otlp_endpoint:          str   = ""
    no_tui:                 bool  = False
    graph_export:           str   = ""   # neo4j | json-ld | graphml
    neo4j_url:              str   = "bolt://localhost:7687"
    plugin_registry_url:    str   = "https://plugins.reconinja.dev"
    # output
    output_format:    str   = "all"
    exclude_phases:   list  = field(default_factory=list)
    global_timeout:   int   = 30
    rate_limit:       float = 0.0
    masscan_rate:     int   = 5000
    threads:          int   = 20
    wordlist_size:    str   = "medium"
    output_dir:       str   = "reports"
    async_concurrency: int  = 1000
    async_timeout:    float = 1.5

    def to_dict(self) -> dict:
        d = asdict(self)
        d["profile"] = self.profile.value
        return d


# ─── Primitives ───────────────────────────────────────────────────────────────

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
        colors = {"open": "port.open", "filtered": "port.filtered", "closed": "port.closed"}
        return f"[{colors.get(self.state, 'dim')}]{self.state}[/]"


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
    tool:           str
    severity:       str
    title:          str
    target:         str
    details:        str   = ""
    cve:            str   = ""
    cvss_v4:        str   = ""
    cvss_v4_vector: str   = ""
    epss_score:     float = 0.0
    rei:            float = 0.0


# ─── ReconResult ─────────────────────────────────────────────────────────────

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
    rustscan_ports:   list[int]      = field(default_factory=list)
    ai_analysis:      str            = ""
    errors:           list[str]      = field(default_factory=list)
    phases_completed: list[str]      = field(default_factory=list)
    shodan_results:   list[dict]     = field(default_factory=list)
    vt_results:       list[dict]     = field(default_factory=list)
    whois_results:    list[dict]     = field(default_factory=list)
    wayback_results:  list[dict]     = field(default_factory=list)
    ssl_results:      list[dict]     = field(default_factory=list)
    github_findings:  list[dict]     = field(default_factory=list)
    js_findings:      list[dict]     = field(default_factory=list)
    bucket_findings:  list[dict]     = field(default_factory=list)
    dns_zone_results: list[dict]     = field(default_factory=list)
    waf_results:      list[dict]     = field(default_factory=list)
    cors_findings:    list[dict]     = field(default_factory=list)
    email_security:   list[dict]     = field(default_factory=list)
    breach_results:   list[dict]     = field(default_factory=list)
    cloud_meta:       list[dict]     = field(default_factory=list)
    graphql_findings: list[dict]     = field(default_factory=list)
    jwt_findings:     list[dict]     = field(default_factory=list)
    asn_results:      list[dict]     = field(default_factory=list)
    supply_chain:     list[dict]     = field(default_factory=list)
    k8s_findings:     list[dict]     = field(default_factory=list)
    db_findings:      list[dict]     = field(default_factory=list)
    smtp_findings:    list[dict]     = field(default_factory=list)
    snmp_findings:    list[dict]     = field(default_factory=list)
    ldap_findings:    list[dict]     = field(default_factory=list)
    devops_findings:  list[dict]     = field(default_factory=list)
    greynoise_data:   list[dict]     = field(default_factory=list)
    typosquat_data:   list[dict]     = field(default_factory=list)
    censys_results:   list[dict]     = field(default_factory=list)
    dns_history:      list[dict]     = field(default_factory=list)
    api_fuzz:         list[dict]     = field(default_factory=list)
    oauth_scan:       list[dict]     = field(default_factory=list)
    web_vulns:        list[dict]     = field(default_factory=list)
    open_redirect:    list[dict]     = field(default_factory=list)
    linkedin:         list[dict]     = field(default_factory=list)
    paste_monitor:    list[dict]     = field(default_factory=list)
    se_osint:         list[dict]     = field(default_factory=list)
    apk_scan:         list[dict]     = field(default_factory=list)
    app_store:        list[dict]     = field(default_factory=list)
    anon_detect:      list[dict]     = field(default_factory=list)
    dns_leak:         list[dict]     = field(default_factory=list)
    web3_scan:        list[dict]     = field(default_factory=list)
    ens_lookup:       list[dict]     = field(default_factory=list)
    attack_paths:     list[dict]     = field(default_factory=list)
    remediations:     list[dict]     = field(default_factory=list)
    # v9
    ad_findings:           list[ADFinding]        = field(default_factory=list)
    cloud_deep_findings:   list[CloudFinding]     = field(default_factory=list)
    llm_surfaces:          list[LLMSurface]       = field(default_factory=list)
    iot_findings:          list[IoTFinding]       = field(default_factory=list)
    container_findings:    list[ContainerFinding] = field(default_factory=list)
    wireless_findings:     list[WirelessFinding]  = field(default_factory=list)
    darkweb_findings:      list[DarkWebFinding]   = field(default_factory=list)
    attack_chains:         list[AttackChain]      = field(default_factory=list)
    evidence_items:        list[EvidenceItem]      = field(default_factory=list)
    graph_nodes:           list[dict]             = field(default_factory=list)
    graph_edges:           list[dict]             = field(default_factory=list)
    # v10 — formerly lost during save/load round-trip
    ai_consensus:          dict                   = field(default_factory=dict)
    aquatone_results:      list[dict]             = field(default_factory=list)
