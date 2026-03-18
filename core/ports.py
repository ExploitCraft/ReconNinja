"""
ReconNinja v3.3 — Port Scanning
Built-in async TCP connect scanner + RustScan + Nmap + Masscan.

The async scanner (AsyncTCPScanner) replicates nmap -sT behaviour in pure Python:
  - asyncio-based: thousands of concurrent SYN/ACK probes with zero threads
  - Full port range (1-65535) in seconds on a LAN, ~30-60s on WAN
  - Banner grabbing on open ports for quick service hints
  - Feeds discovered ports directly into Nmap for deep analysis
  - No root required (unlike -sS SYN scan)
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from utils.helpers import run_cmd, tool_exists, ensure_dir, sanitize_dirname, timestamp
from utils.logger import safe_print, log
from utils.models import PortInfo, HostResult, NmapOptions

NMAP_PER_TARGET_TIMEOUT = 1800   # 30 min per target

# ── Service name hints (port → likely service) ────────────────────────────────
PORT_HINTS: dict[int, str] = {
    21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
    80:"http", 110:"pop3", 111:"rpcbind", 135:"msrpc", 139:"netbios",
    143:"imap", 161:"snmp", 389:"ldap", 443:"https", 445:"smb",
    512:"exec", 513:"login", 514:"shell", 993:"imaps", 995:"pop3s",
    1433:"mssql", 1521:"oracle", 2181:"zookeeper", 2375:"docker",
    3000:"http-alt", 3306:"mysql", 3389:"rdp", 4444:"metasploit",
    5000:"http-alt", 5432:"postgresql", 5900:"vnc", 6379:"redis",
    8080:"http-proxy", 8443:"https-alt", 8888:"http-alt",
    9200:"elasticsearch", 9300:"elasticsearch", 11211:"memcached",
    27017:"mongodb", 27018:"mongodb",
}

BANNER_TIMEOUT = 2.0    # seconds to wait for a banner after connect
CONNECT_TIMEOUT = 1.5   # seconds per TCP connect attempt
DEFAULT_CONCURRENCY = 1000  # simultaneous asyncio coroutines


# ─── Async TCP Connect Scanner ────────────────────────────────────────────────

class AsyncTCPScanner:
    """
    Pure-Python async TCP connect port scanner.
    Equivalent to nmap -sT but implemented with asyncio for maximum speed.

    Algorithm per port:
      1. asyncio.open_connection() — full TCP 3-way handshake (SYN → SYN-ACK → ACK)
         open   = connection succeeds
         closed = ConnectionRefusedError
         filtered = asyncio.TimeoutError (packet silently dropped)
      2. On open: attempt banner grab (read up to 256 bytes within BANNER_TIMEOUT)
      3. Collect results; feed open ports to Nmap for deep analysis
    """

    def __init__(
        self,
        target: str,
        ports: list[int],
        concurrency: int = DEFAULT_CONCURRENCY,
        connect_timeout: float = CONNECT_TIMEOUT,
        banner_timeout: float = BANNER_TIMEOUT,
        show_progress: bool = True,
    ) -> None:
        self.target          = target
        self.ports           = ports
        self.concurrency     = concurrency
        self.connect_timeout = connect_timeout
        self.banner_timeout  = banner_timeout
        self.show_progress   = show_progress

        self._open:     list[int]         = []
        self._banners:  dict[int, str]    = {}
        self._filtered: list[int]         = []
        self._scanned   = 0
        self._start_time: float           = 0.0

    # ── Core probe ────────────────────────────────────────────────────────────

    async def _probe(self, port: int, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.connect_timeout,
                )
                # Port is OPEN — attempt banner grab
                banner = ""
                try:
                    # Send a generic probe to elicit a response
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                    data = await asyncio.wait_for(
                        reader.read(256), timeout=self.banner_timeout
                    )
                    banner = data.decode(errors="ignore").strip()[:120]
                except Exception:
                    pass
                finally:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

                self._open.append(port)
                if banner:
                    self._banners[port] = banner

            except ConnectionRefusedError:
                pass  # CLOSED — RST received, no need to record
            except asyncio.TimeoutError:
                self._filtered.append(port)  # FILTERED — no response
            except OSError:
                pass  # e.g. network unreachable
            finally:
                self._scanned += 1

    # ── Progress display ──────────────────────────────────────────────────────

    async def _progress_reporter(self, total: int) -> None:
        """Print a live progress line every 2 seconds."""
        while self._scanned < total:
            elapsed = time.monotonic() - self._start_time
            pct = self._scanned / total * 100
            rate = self._scanned / max(elapsed, 0.01)
            safe_print(
                f"[dim]  ⟳ {self._scanned:,}/{total:,} ports "
                f"({pct:.1f}%) — {len(self._open)} open — "
                f"{rate:.0f} ports/s[/]",
            )
            await asyncio.sleep(2)

    # ── Main entry ────────────────────────────────────────────────────────────

    async def _run(self) -> None:
        sem = asyncio.Semaphore(self.concurrency)
        total = len(self.ports)
        self._start_time = time.monotonic()

        tasks = [asyncio.create_task(self._probe(p, sem)) for p in self.ports]

        if self.show_progress:
            reporter = asyncio.create_task(self._progress_reporter(total))

        await asyncio.gather(*tasks)

        if self.show_progress:
            reporter.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reporter

    def scan(self) -> tuple[list[int], dict[int, str], list[int]]:
        """
        Run the scan synchronously.
        Returns (open_ports, banners, filtered_ports).
        """
        asyncio.run(self._run())
        self._open.sort()
        self._filtered.sort()
        return self._open, self._banners, self._filtered


# ─── High-level scanner function ─────────────────────────────────────────────

def async_port_scan(
    target: str,
    ports: Optional[list[int]] = None,
    top_n: Optional[int] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    connect_timeout: float = CONNECT_TIMEOUT,
    out_folder: Optional[Path] = None,
) -> tuple[list[PortInfo], list[int]]:
    """
    Run AsyncTCPScanner against target.
    Returns (list[PortInfo], filtered_ports).
    Port range priority: explicit ports > top_n > full 1-65535.
    """
    if ports is not None:
        scan_ports = ports
    elif top_n is not None:
        # Top N by popularity (same ordering nmap uses internally)
        scan_ports = _top_ports(top_n)
    else:
        scan_ports = list(range(1, 65536))

    safe_print(
        f"[info]▶ AsyncTCPScan → {target} "
        f"({len(scan_ports):,} ports, concurrency={concurrency})[/]"
    )

    t0 = time.monotonic()
    scanner = AsyncTCPScanner(
        target=target,
        ports=scan_ports,
        concurrency=concurrency,
        connect_timeout=connect_timeout,
    )
    open_ports, banners, filtered = scanner.scan()
    elapsed = time.monotonic() - t0

    safe_print(
        f"[success]✔ AsyncTCPScan: {len(open_ports)} open, "
        f"{len(filtered)} filtered — {elapsed:.1f}s[/]"
    )

    # Build PortInfo objects with banner hints
    port_infos: list[PortInfo] = []
    for port in open_ports:
        banner   = banners.get(port, "")
        hint     = PORT_HINTS.get(port, "")
        service  = _guess_service_from_banner(banner) or hint
        product, version = _parse_banner(banner)
        port_infos.append(PortInfo(
            port       = port,
            protocol   = "tcp",
            state      = "open",
            service    = service,
            product    = product,
            version    = version,
            extra_info = f"async-scan banner: {banner[:60]}" if banner else "",
        ))

    # Save raw results
    if out_folder:
        ensure_dir(out_folder)
        result_file = out_folder / "async_scan.txt"
        lines = [f"# AsyncTCPScan — {target} — {timestamp()}",
                 f"# Scanned {len(scan_ports):,} ports in {elapsed:.1f}s",
                 f"# Open: {len(open_ports)} | Filtered: {len(filtered)}", ""]
        for p in open_ports:
            svc = PORT_HINTS.get(p, "unknown")
            ban = banners.get(p, "")
            lines.append(f"open\ttcp\t{p}\t{svc}\t{ban[:80]}")
        result_file.write_text("\n".join(lines))

    return port_infos, filtered


# ─── Banner helpers ───────────────────────────────────────────────────────────

def _guess_service_from_banner(banner: str) -> str:
    b = banner.lower()
    if "ssh" in b:            return "ssh"
    if "http" in b:           return "http"
    if "ftp" in b:            return "ftp"
    if "smtp" in b:           return "smtp"
    if "pop3" in b:           return "pop3"
    if "imap" in b:           return "imap"
    if "mysql" in b:          return "mysql"
    if "postgresql" in b:     return "postgresql"
    if "redis" in b:          return "redis"
    if "mongodb" in b:        return "mongodb"
    if "elastic" in b:        return "elasticsearch"
    return ""


def _parse_banner(banner: str) -> tuple[str, str]:
    """Extract product/version from common banner formats."""
    import re
    # SSH: SSH-2.0-OpenSSH_8.9p1
    m = re.match(r"SSH-[\d.]+-(\S+)", banner)
    if m:
        parts = m.group(1).split("_", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    # HTTP Server header — value may be Product/Version or just Product
    m = re.search(r"Server:\s*([^/\r\n\s]+)(?:/([^\r\n\s]+))?", banner, re.I)
    if m:
        return m.group(1), m.group(2) or ""
    return "", ""


# ─── Top-N port list (nmap ordering) ─────────────────────────────────────────

_NMAP_TOP_PORTS = [
    80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,
    1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,
    6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,
    49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,
    8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,
    427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,
    5190,3000,5432,1900,3986,13,1029,9,6646,49157,1028,873,1755,
    407,9998,2717,4899,1745,8883,1337,1338,10243,1024,58080,
    # extend to 1000 common ports
    4848,5985,7634,8998,9000,9090,9100,9200,9300,27017,28017,
    6379,11211,50000,50001,50002,8161,61616,4444,4445,8649,8686,
]

def _top_ports(n: int) -> list[int]:
    """Return top N ports by nmap popularity order."""
    base = _NMAP_TOP_PORTS[:n]
    if n > len(_NMAP_TOP_PORTS):
        # Fill the rest sequentially
        existing = set(base)
        extra = [p for p in range(1, 65536) if p not in existing]
        base = base + extra[:n - len(base)]
    return base


# ─── RustScan ─────────────────────────────────────────────────────────────────

def run_rustscan(
    target: str, out_folder: Path, all_ports: bool = True
) -> set[int]:
    """
    Port DISCOVERY only — RustScan finds every open port as fast as possible.
    Does NOT run nmap internally (no -- pass-through).
    Returns raw set of open port numbers for Nmap to deep-analyse.

    This is the PRIMARY port scanner. Nmap never sweeps ports — it only does
    service/version fingerprinting on what RustScan hands it.
    """
    if not tool_exists("rustscan"):
        safe_print("[warning]rustscan not found — falling back to async TCP scan[/]")
        return set()

    ensure_dir(out_folder)
    out_file = out_folder / "rustscan_ports.txt"

    cmd = [
        "rustscan",
        "-a", target,
        "--ulimit", "5000",
        "--range", "1-65535",
        "--greppable",          # machine-readable output
    ]

    safe_print(f"[info]▶ RustScan → {target} (all 65535 ports)[/]")
    rc, stdout, stderr = run_cmd(cmd, timeout=600)

    open_ports: set[int] = set()
    combined = stdout + stderr

    for line in combined.splitlines():
        line = line.strip()
        # Greppable format:  Host: 192.168.0.105 ()  Ports: 22/open/tcp, 80/open/tcp
        if "Ports:" in line:
            ports_section = line.split("Ports:")[-1]
            for entry in ports_section.split(","):
                entry = entry.strip()
                if "/open/" in entry:
                    with contextlib.suppress(ValueError):
                        open_ports.add(int(entry.split("/")[0]))
        # Plain "Open" format fallback
        elif line.startswith("Open") and ":" in line:
            with contextlib.suppress(ValueError):
                open_ports.add(int(line.split(":")[-1].strip()))

    # Save port list
    out_file.write_text(
        f"# RustScan — {target}\n" +
        "\n".join(str(p) for p in sorted(open_ports))
    )

    if open_ports:
        safe_print(
            f"[success]✔ RustScan: {len(open_ports)} open ports → "
            f"{', '.join(str(p) for p in sorted(open_ports))}[/]"
        )
    else:
        safe_print("[warning]RustScan: no open ports found[/]")

    return open_ports


# ─── Nmap XML Parsing ─────────────────────────────────────────────────────────

def parse_nmap_xml(xml_text: str) -> tuple[list[HostResult], list[str]]:
    """Parse nmap XML → (hosts, errors)."""
    if not xml_text.strip():
        return [], []

    parse_errors: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        msg = f"Nmap XML parse error: {exc}"
        log.warning(msg)
        return [], [msg]

    hosts: list[HostResult] = []
    for host_el in root.findall("host"):
        try:
            ip = mac = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "")

            hostnames: list[str] = []
            hn_el = host_el.find("hostnames")
            if hn_el is not None:
                hostnames = [
                    h.get("name", "")
                    for h in hn_el.findall("hostname")
                    if h.get("name")
                ]

            os_guess = os_acc = ""
            os_el = host_el.find("os")
            if os_el is not None:
                matches = os_el.findall("osmatch")
                if matches:
                    os_guess = matches[0].get("name", "")
                    os_acc   = matches[0].get("accuracy", "")

            ports: list[PortInfo] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    state    = state_el.get("state", "") if state_el is not None else ""
                    svc      = port_el.find("service")
                    script_data: dict[str, str] = {
                        s.get("id", ""): s.get("output", "")
                        for s in port_el.findall("script")
                    }
                    ports.append(PortInfo(
                        port       = int(port_el.get("portid", 0)),
                        protocol   = port_el.get("protocol", "tcp"),
                        state      = state,
                        service    = svc.get("name", "")     if svc is not None else "",
                        product    = svc.get("product", "")  if svc is not None else "",
                        version    = svc.get("version", "")  if svc is not None else "",
                        extra_info = svc.get("extrainfo", "") if svc is not None else "",
                        scripts    = script_data,
                    ))

            times_el = host_el.find("times")
            scan_time = times_el.get("elapsed", "") if times_el is not None else ""

            hosts.append(HostResult(
                ip=ip, mac=mac, hostnames=hostnames,
                os_guess=os_guess, os_accuracy=os_acc,
                ports=ports, scan_time=scan_time,
            ))
        except Exception as exc:
            msg = f"Error parsing host element: {exc}"
            log.debug(msg)
            parse_errors.append(msg)

    return hosts, parse_errors


# ─── Nmap ─────────────────────────────────────────────────────────────────────

def build_nmap_cmd(
    target: str, opts: NmapOptions, xml_out: Path, normal_out: Path
) -> list[str]:
    return ["nmap"] + opts.as_nmap_args() + [
        "-oX", str(xml_out), "-oN", str(normal_out), target
    ]


def run_nmap_service_scan(
    target: str,
    open_ports: set[int],
    out_folder: Path,
    scripts: bool = True,
    version_detection: bool = True,
    timing: str = "T4",
    extra_flags: Optional[list[str]] = None,
) -> tuple[list[HostResult], Path, Path, list[str]]:
    """
    SERVICE / VERSION ANALYSIS ONLY — Nmap never discovers ports itself.

    Pipeline:
      RustScan / AsyncScan  →  finds open ports
      run_nmap_service_scan →  fingerprints ONLY those ports

    Flags always used:
      -sT   TCP connect scan (works without root)
      -Pn   skip host discovery (ports already confirmed open)
      -sV   version detection
      -sC   default scripts (optional, on by default)
      -p<ports>  only confirmed-open ports — no sweep

    Returns (hosts, xml_path, txt_path, errors).
    """
    if not open_ports:
        return [], Path("/dev/null"), Path("/dev/null"), ["No open ports to analyse"]

    ensure_dir(out_folder)

    port_str   = ",".join(str(p) for p in sorted(open_ports))
    stamp      = timestamp()
    xml_out    = out_folder / f"nmap_{stamp}.xml"
    normal_out = out_folder / f"nmap_{stamp}.txt"

    cmd = [
        "nmap",
        "-sT",          # TCP connect — no root required
        "-Pn",          # host already confirmed up by RustScan/async
        f"-{timing}",
        "-p", port_str,
    ]
    if version_detection:
        cmd.append("-sV")
    if scripts:
        cmd.append("-sC")
    if extra_flags:
        cmd.extend(extra_flags)
    cmd += ["-oX", str(xml_out), "-oN", str(normal_out), target]

    safe_print(f"[info]▶ Nmap service scan: {' '.join(cmd)}[/]")
    rc, stdout, stderr = run_cmd(cmd, timeout=NMAP_PER_TARGET_TIMEOUT)

    xml_text = xml_out.read_text(encoding="utf-8", errors="ignore") if xml_out.exists() else ""
    hosts, errors = parse_nmap_xml(xml_text)
    if rc == 124:
        errors.append(f"nmap service scan timed out for {target}")

    return hosts, xml_out, normal_out, errors


# Legacy alias so old call-sites still compile
def run_nmap(
    target: str, opts: NmapOptions, out_folder: Path,
    force_pn: bool = False,
) -> tuple[list[HostResult], Path, Path, list[str]]:
    """Thin legacy wrapper around run_nmap_service_scan."""
    port_set: set[int] = set()
    for flag in opts.extra_flags:
        if flag.startswith("-p") and len(flag) > 2:
            for part in flag[2:].split(","):
                with contextlib.suppress(ValueError):
                    port_set.add(int(part.strip()))
    clean_flags = [f for f in opts.extra_flags
                   if not f.startswith("-p") and f not in ("-Pn", "-sT", "-sS")]
    return run_nmap_service_scan(
        target=target, open_ports=port_set, out_folder=out_folder,
        scripts=opts.scripts, version_detection=opts.version_detection,
        timing=opts.timing, extra_flags=clean_flags,
    )


# ─── Nmap worker (threaded) ───────────────────────────────────────────────────

def nmap_worker(
    subdomain: str,
    open_ports: set[int],
    out_folder: Path,
    scripts: bool = True,
    version_detection: bool = True,
    timing: str = "T4",
) -> tuple[str, list[HostResult], list[str]]:
    """
    Per-subdomain service-analysis worker.
    open_ports MUST come from RustScan/async — Nmap will NOT sweep.
    """
    worker_dir = ensure_dir(out_folder / sanitize_dirname(subdomain))
    hosts, _, _, errors = run_nmap_service_scan(
        target=subdomain, open_ports=open_ports,
        out_folder=worker_dir, scripts=scripts,
        version_detection=version_detection, timing=timing,
    )
    for h in hosts:
        h.source_subdomain = subdomain
    return subdomain, hosts, errors


# ─── Masscan ──────────────────────────────────────────────────────────────────

def run_masscan(
    target: str, out_folder: Path, rate: int = 5000
) -> tuple[Optional[Path], set[int]]:
    if not tool_exists("masscan"):
        safe_print("[dim]masscan not installed — skipping[/]")
        return None, set()

    ensure_dir(out_folder)
    out_file = out_folder / "masscan.txt"
    cmd = [
        "masscan", target, "-p", "1-65535",
        "--rate", str(rate), "-oL", str(out_file),
    ]
    safe_print(f"[info]▶ Masscan (rate={rate})[/]")
    run_cmd(cmd, timeout=600)

    open_ports: set[int] = set()
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "open":
                with contextlib.suppress(ValueError):
                    open_ports.add(int(parts[2]))
        safe_print(f"[success]✔ Masscan: {len(open_ports)} open ports → {out_file}[/]")
    return out_file, open_ports
