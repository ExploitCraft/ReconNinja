"""
ReconNinja v9 — Phase Scheduler
Dependency-aware parallel phase execution.

PHASE_DEPS maps phase_id → list[dependency_phase_ids].
Phases with empty deps start immediately; others wait for prerequisites.
Uses ThreadPoolExecutor with configurable --parallel-phases workers.
Estimated 3–5× speedup over sequential v8 execution on full-suite scans.
"""
from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, Any


# ─── Phase dependency DAG ─────────────────────────────────────────────────────
# Phase IDs must match the string keys used in result.phases_completed.

PHASE_DEPS: dict[str, list[str]] = {
    # Passive (no deps — runs immediately)
    "passive":          [],
    "whois":            [],
    "wayback":          [],
    "github_osint":     [],
    "asn_map":          [],
    "breach_check":     [],
    "email_security":   [],
    "supply_chain":     [],
    "typosquat":        [],
    "virustotal":       [],
    "censys":           [],
    "dns_history":      [],
    "shodan":           [],
    "linkedin":         [],
    "paste_monitor":    [],
    "se_osint":         [],
    "app_store":        [],
    "wireless_osint":   [],
    "darkweb_osint":    [],
    # Subdomain enum (passive, can run immediately)
    "subdomains":       [],
    # Port discovery (needs passive/subdomain to know scope)
    "async_tcp":        ["subdomains"],
    "rustscan":         ["subdomains"],
    "masscan":          ["subdomains"],
    # Nmap deep scan (needs port list)
    "nmap":             ["async_tcp"],
    # Web discovery (needs nmap for open ports)
    "httpx":            ["nmap"],
    "whatweb":          ["httpx"],
    "waf":              ["httpx"],
    "ssl":              ["nmap"],
    # Directory / content
    "feroxbuster":      ["httpx"],
    # Web analysis (needs httpx)
    "cors":             ["httpx"],
    "js_extract":       ["httpx"],
    "api_fuzz":         ["httpx"],
    "oauth_scan":       ["httpx"],
    "web_vulns":        ["httpx"],
    "open_redirect":    ["httpx"],
    "graphql":          ["httpx"],
    "jwt_scan":         ["httpx"],
    "nikto":            ["httpx"],
    # Vuln scan (needs httpx for URLs)
    "nuclei":           ["httpx"],
    # CVE lookup (needs nmap service versions)
    "cve_lookup":       ["nmap"],
    # Intelligence lookups (independent of web)
    "cloud_buckets":    ["subdomains"],
    "cloud_meta":       ["nmap"],
    "cloud_deep":       ["nmap", "cloud_meta"],
    "db_exposure":      ["nmap"],
    "devops_scan":      ["nmap"],
    "k8s_probe":        ["nmap"],
    "container_deep":   ["nmap", "k8s_probe"],
    "smtp_enum":        ["nmap"],
    "snmp_scan":        ["nmap"],
    "ldap_enum":        ["nmap"],
    "dns_zone":         ["subdomains"],
    "dns_leak":         ["subdomains"],
    "ens_lookup":       ["whois"],
    "web3_scan":        ["httpx"],
    "anon_detect":      ["httpx"],
    # Screenshots (needs httpx URLs)
    "aquatone":         ["httpx"],
    # AI & correlation (needs everything)
    "ai_consensus":     ["nuclei", "cve_lookup"],
    "attack_paths":     ["ai_consensus"],
    "ai_remediate":     ["attack_paths"],
    "correlation":      ["nuclei", "cve_lookup", "cloud_deep", "ad_recon"],
    # AD recon (independent of web, needs creds)
    "ad_recon":         [],
    # LLM / IoT (needs port data)
    "llm_recon":        ["nmap"],
    "iot_scan":         ["nmap"],
    # Reports (last)
    "sarif_export":     ["nuclei"],
    "pdf_report":       ["nuclei", "correlation"],
    "interactive_report": ["correlation"],
    "defectdojo":       ["nuclei"],
    "notion_export":    ["nuclei"],
    "obsidian_export":  ["nuclei"],
    "plugins":          ["nuclei"],
}


# ─── PhaseTask ────────────────────────────────────────────────────────────────

class PhaseTask:
    def __init__(self, phase_id: str, fn: Callable, *args, **kwargs) -> None:
        self.phase_id = phase_id
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self) -> Any:
        return self.fn(*self.args, **self.kwargs)


# ─── PhaseScheduler ───────────────────────────────────────────────────────────

class PhaseScheduler:
    """
    Runs PhaseTask objects in dependency order using a thread pool.

    Usage:
        scheduler = PhaseScheduler(max_workers=4)
        scheduler.add(PhaseTask("httpx", run_httpx, ...))
        scheduler.run()
    """

    def __init__(self, max_workers: int = 4) -> None:
        self._tasks: dict[str, PhaseTask] = {}
        self._max_workers = max_workers
        self._completed: set[str] = set()
        self._failed: set[str] = set()
        self._lock = threading.Lock()

    def add(self, task: PhaseTask) -> None:
        self._tasks[task.phase_id] = task

    def _deps_satisfied(self, phase_id: str) -> bool:
        deps = PHASE_DEPS.get(phase_id, [])
        return all(
            d in self._completed or d not in self._tasks   # dep done OR not scheduled
            for d in deps
        )

    def _any_dep_failed(self, phase_id: str) -> bool:
        deps = PHASE_DEPS.get(phase_id, [])
        return any(d in self._failed for d in deps)

    def run(
        self,
        on_start: Callable[[str], None] | None = None,
        on_done:  Callable[[str, bool], None] | None = None,
    ) -> dict[str, bool]:
        """
        Execute all registered tasks respecting dependencies.

        Args:
            on_start: called with phase_id when a phase begins
            on_done:  called with (phase_id, success) when a phase finishes

        Returns:
            dict mapping phase_id → True (success) / False (failed/skipped)
        """
        pending = set(self._tasks.keys())
        futures: dict[Future, str] = {}
        results: dict[str, bool] = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            while pending or futures:
                # Submit all ready tasks
                newly_submitted = []
                for phase_id in list(pending):
                    if self._any_dep_failed(phase_id):
                        pending.discard(phase_id)
                        results[phase_id] = False
                        with self._lock:
                            self._failed.add(phase_id)
                        if on_done:
                            on_done(phase_id, False)
                        continue
                    if self._deps_satisfied(phase_id):
                        task = self._tasks[phase_id]
                        if on_start:
                            on_start(phase_id)
                        fut = pool.submit(task.run)
                        futures[fut] = phase_id
                        newly_submitted.append(phase_id)

                for phase_id in newly_submitted:
                    pending.discard(phase_id)

                if not futures:
                    # Nothing running and nothing submittable — dependency cycle or all done
                    if pending:
                        # Remaining tasks have unresolvable deps — skip them
                        for phase_id in pending:
                            results[phase_id] = False
                            if on_done:
                                on_done(phase_id, False)
                        break
                    break

                # Wait for at least one future to complete
                done_futures = []
                for fut in list(futures.keys()):
                    if fut.done():
                        done_futures.append(fut)

                if not done_futures:
                    # Block until at least one finishes
                    import concurrent.futures
                    done_set, _ = concurrent.futures.wait(
                        list(futures.keys()), return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    done_futures = list(done_set)

                for fut in done_futures:
                    phase_id = futures.pop(fut)
                    exc = fut.exception()
                    success = exc is None
                    with self._lock:
                        if success:
                            self._completed.add(phase_id)
                        else:
                            self._failed.add(phase_id)
                    results[phase_id] = success
                    if on_done:
                        on_done(phase_id, success)

        return results

    @property
    def completed(self) -> set[str]:
        return set(self._completed)

    @property
    def failed(self) -> set[str]:
        return set(self._failed)
