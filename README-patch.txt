ReconNinja v10.5.1 — Critical Bug Fix Patch
============================================

This zip fixes the "scan results show nothing" bug in v10.5.0.

Files in this zip
-----------------

  version              → info/version               (bumped to 10.5.1)
  orchestrator_v9.py   → core/orchestrator_v9.py    (THE FIX)
  README.md            → README.md                  (badge bumped)
  PKGBUILD             → aur/PKGBUILD               (pkgver=10.5.1)
  .SRCINFO             → aur/.SRCINFO
  install.sh           → install.sh

What was broken
---------------

Two bugs in core/orchestrator_v9.py caused scan results to show
NOTHING — 0 hosts, 0 open ports, 0 everything — even though the scan
ran successfully and phases completed.

BUG 1: _w_async_tcp stored FILTERED ports instead of OPEN ports
  async_port_scan() returns (port_infos, filtered_ports) where
  filtered_ports is the list of CLOSED/FILTERED ports. The v10.5.0
  wrapper treated the second return value as "open port numbers"
  and stored all 1000 scanned ports (including closed ones) in
  result.rustscan_ports. This polluted the port list and made nmap
  try to scan 1000 ports.

BUG 2: No HostResult created when nmap isn't installed
  The async_tcp scanner found open ports but stored them only in
  result.rustscan_ports (a flat list of ints). The report's
  summary.open_ports reads from result.hosts[].ports — which stayed
  empty because nmap_worker (which creates HostResult objects)
  wasn't available. So the user saw "Open Ports: 0" even though
  async_tcp found 4 open ports.

The fix
-------

_w_async_tcp now:
  1. Extracts open port numbers from port_infos (the first return
     value) instead of using the filtered_ports list.
  2. Creates a HostResult with PortInfo entries from the async scan
     results — so even when nmap isn't installed, the open ports
     show up in the report.

_w_nmap now:
  1. Skips the nmap call entirely if no open ports were discovered
     (instead of calling nmap_worker with an empty port list).
  2. Merges nmap results into the existing HostResult (created by
     async_tcp) instead of appending a duplicate host entry.

Verified
--------

Before fix (v10.5.0):
  Hosts: 0, Open Ports: 0, Graph Nodes: 0

After fix (v10.5.1):
  Hosts: 1, Open Ports: 4, Graph Nodes: 7
  report.json shows:
    IP: 104.20.23.154, hostnames: ['example.com']
      port 80/tcp   state=open service=http
      port 443/tcp  state=open service=http
      port 8080/tcp state=open service=http
      port 8443/tcp state=open service=http
    SSL certs on ports 443 + 8443 (TLSv1.3, 256-bit)

Full test suite: 616 passed, 1 skipped.

Apply
-----

    cp version            /path/to/ReconNinja/info/version
    cp orchestrator_v9.py /path/to/ReconNinja/core/orchestrator_v9.py
    cp README.md          /path/to/ReconNinja/README.md
    cp PKGBUILD           /path/to/ReconNinja/aur/PKGBUILD
    cp .SRCINFO           /path/to/ReconNinja/aur/.SRCINFO
    cp install.sh         /path/to/ReconNinja/install.sh

    cd /path/to/ReconNinja
    python reconninja.py --version     # → ReconNinja v10.5.1
    python reconninja.py --whois --ssl example.com --no-tui
    # → summary should now show Hosts: 1, Open Ports: 4
