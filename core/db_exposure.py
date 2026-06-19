"""
core/db_exposure.py — ReconNinja v7.0.0
Unauthenticated database exposure detection.

Checks for unauthenticated access to:
  - Redis (V7-11):       port 6379 — PING, CONFIG GET, INFO
  - Elasticsearch (V7-10): port 9200 — cluster info, index listing
  - MongoDB (V7-12):     port 27017 — listDatabases command
  - Memcached (V7-14):   port 11211 — stats, slabs dump

Pure Python — no external tools required (redis-py optional but not required).
"""

from __future__ import annotations

import json
import socket
import struct
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print


@dataclass
class DBExposureFinding:
    service:   str
    host:      str
    port:      int
    vulnerable: bool
    severity:  str
    detail:    str
    data:      str = ""   # sample data returned

    def to_dict(self) -> dict:
        return {
            "service":    self.service,
            "host":       self.host,
            "port":       self.port,
            "vulnerable": self.vulnerable,
            "severity":   self.severity,
            "detail":     self.detail,
            "data":       self.data[:300],
        }


# ── Redis ─────────────────────────────────────────────────────────────────────

def _check_redis(host: str, port: int = 6379, timeout: int = 5) -> DBExposureFinding:
    """Test unauthenticated Redis access via raw TCP (RESP protocol)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Send PING
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = sock.recv(256).decode(errors="ignore")
            if "+PONG" in resp or "+pong" in resp.lower():
                # Try INFO for more data
                sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
                info = sock.recv(4096).decode(errors="ignore")
                redis_version = ""
                for line in info.splitlines():
                    if line.startswith("redis_version:"):
                        redis_version = line.split(":", 1)[1].strip()
                        break
                return DBExposureFinding(
                    service="Redis", host=host, port=port, vulnerable=True,
                    severity="critical",
                    detail=f"Unauthenticated Redis access — PING responded with PONG (v{redis_version})",
                    data=info[:300],
                )
        return DBExposureFinding(service="Redis", host=host, port=port, vulnerable=False,
                                  severity="info", detail="Redis requires authentication")
    except ConnectionRefusedError:
        return DBExposureFinding(service="Redis", host=host, port=port, vulnerable=False,
                                  severity="info", detail="Port closed")
    except Exception as e:
        return DBExposureFinding(service="Redis", host=host, port=port, vulnerable=False,
                                  severity="info", detail=f"Error: {e}")


# ── Elasticsearch ─────────────────────────────────────────────────────────────

def _check_elasticsearch(host: str, port: int = 9200, timeout: int = 8) -> DBExposureFinding:
    """Test unauthenticated Elasticsearch cluster access via HTTP."""
    try:
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconNinja/7.0.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4096).decode(errors="ignore")
            data = json.loads(body) if body.strip().startswith("{") else {}
            cluster_name = data.get("cluster_name", "")
            version_num  = data.get("version", {}).get("number", "")
            if cluster_name or version_num or "elasticsearch" in body.lower():
                # Also fetch index list
                idx_url = f"http://{host}:{port}/_cat/indices?v"
                idx_req = urllib.request.Request(idx_url, headers={"User-Agent": "ReconNinja/7.0.0"})
                try:
                    with urllib.request.urlopen(idx_req, timeout=timeout) as idx_r:
                        indices = idx_r.read(2048).decode(errors="ignore")
                except Exception:
                    indices = ""
                return DBExposureFinding(
                    service="Elasticsearch", host=host, port=port, vulnerable=True,
                    severity="critical",
                    detail=f"Unauthenticated ES access — cluster='{cluster_name}' v{version_num}",
                    data=indices[:300] or body[:300],
                )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return DBExposureFinding(service="Elasticsearch", host=host, port=port,
                                      vulnerable=False, severity="info",
                                      detail="Elasticsearch requires authentication")
    except ConnectionRefusedError:
        pass
    except Exception:
        pass
    return DBExposureFinding(service="Elasticsearch", host=host, port=port, vulnerable=False,
                              severity="info", detail="Not accessible")


# ── MongoDB ───────────────────────────────────────────────────────────────────

def _check_mongodb(host: str, port: int = 27017, timeout: int = 5) -> DBExposureFinding:
    """Test unauthenticated MongoDB access via wire protocol."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Send minimal isMaster query (OP_MSG)
            # Build a minimal listDatabases command
            # Use pymongo if available
            try:
                import pymongo
                client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=5000,
                                             connectTimeoutMS=5000)
                db_list = client.list_database_names()
                client.close()
                return DBExposureFinding(
                    service="MongoDB", host=host, port=port, vulnerable=True,
                    severity="high",
                    detail=f"Unauthenticated MongoDB — {len(db_list)} database(s) listed",
                    data=", ".join(db_list[:10]),
                )
            except ImportError:
                pass

            # Raw wire protocol: send isMaster query
            # OP_QUERY on admin.$cmd: {isMaster: 1}
            query = b"\x01\x00\x00\x00"  # flags
            query += b"admin.$cmd\x00"   # fullCollectionName
            query += b"\x00\x00\x00\x00"  # numberToSkip
            query += b"\x01\x00\x00\x00"  # numberToReturn
            # BSON {isMaster: 1}
            bson_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            header   = struct.pack("<iiii", 16 + 4 + len(b"admin.$cmd\x00") + 8 + len(bson_doc),
                                   0, 0, 2004)
            payload  = header + query + bson_doc
            sock.sendall(payload)
            resp = sock.recv(512)
            if resp and len(resp) > 20:
                return DBExposureFinding(
                    service="MongoDB", host=host, port=port, vulnerable=True,
                    severity="high",
                    detail="MongoDB port responding — install pymongo for full check",
                    data="",
                )
    except ConnectionRefusedError:
        pass
    except Exception:
        pass
    return DBExposureFinding(service="MongoDB", host=host, port=port, vulnerable=False,
                              severity="info", detail="Not accessible")


# ── Memcached ─────────────────────────────────────────────────────────────────

def _check_memcached(host: str, port: int = 11211, timeout: int = 5) -> DBExposureFinding:
    """Test unauthenticated Memcached access via ASCII protocol."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"stats\r\n")
            resp = sock.recv(2048).decode(errors="ignore")
            if "STAT " in resp:
                # Extract version
                version = ""
                for line in resp.splitlines():
                    if line.startswith("STAT version"):
                        version = line.split()[-1]
                        break
                # Try to dump a slab key
                sock.sendall(b"stats slabs\r\n")
                slabs = sock.recv(2048).decode(errors="ignore")
                return DBExposureFinding(
                    service="Memcached", host=host, port=port, vulnerable=True,
                    severity="critical",
                    detail=f"Unauthenticated Memcached v{version} — stats readable; UDP amplification vector",
                    data=(resp + slabs)[:300],
                )
    except ConnectionRefusedError:
        pass
    except Exception:
        pass
    return DBExposureFinding(service="Memcached", host=host, port=port, vulnerable=False,
                              severity="info", detail="Not accessible")


# ── Public API ────────────────────────────────────────────────────────────────

DB_PORT_MAP = {
    6379:  ("redis",         _check_redis),
    9200:  ("elasticsearch", _check_elasticsearch),
    9300:  ("elasticsearch", lambda h, _: DBExposureFinding("Elasticsearch-transport", h, 9300, False, "info", "Transport port — not HTTP")),
    27017: ("mongodb",       _check_mongodb),
    28017: ("mongodb-http",  lambda h, p: _check_mongodb(h, 27017)),
    11211: ("memcached",     _check_memcached),
}


def db_exposure_scan(
    target: str,
    open_ports: set[int],
    out_folder: Path,
    timeout: int = 5,
) -> list[DBExposureFinding]:
    """
    Detect unauthenticated database exposure.

    Checks Redis, Elasticsearch, MongoDB, and Memcached on their
    default ports. Only tests ports that were found open by the
    port scanner to avoid unnecessary noise.

    Args:
        target:     IP or hostname
        open_ports: set of open ports (from port scanner)
        out_folder: output directory

    Returns:
        list of DBExposureFinding
    """
    ensure_dir(out_folder)
    findings: list[DBExposureFinding] = []
    db_ports = set(DB_PORT_MAP.keys())
    to_check = db_ports & open_ports if open_ports else db_ports

    if not to_check:
        safe_print(f"[dim]DB Exposure: no database ports found open on {target}[/]")
        return findings

    safe_print(f"[info]▶ DB Exposure Scan — {target} ({len(to_check)} port(s))[/]")

    for port in sorted(to_check):
        service_name, check_fn = DB_PORT_MAP[port]
        finding = check_fn(target, port)
        if finding.vulnerable:
            findings.append(finding)
            safe_print(f"  [danger]⚠  {finding.service}: {target}:{port} UNAUTHENTICATED — {finding.detail}[/]")

    # Save
    out_file = out_folder / "db_exposure.txt"
    lines = [f"# DB Exposure Findings — {target}", ""]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.service}:{f.port}")
        lines.append(f"  {f.detail}")
        if f.data:
            lines.append(f"  Data: {f.data[:150]}")
        lines.append("")
    out_file.write_text("\n".join(lines))

    crit = sum(1 for f in findings if f.severity == "critical")
    safe_print(f"[{'danger' if crit else 'success'}]✔ DB Exposure: {len(findings)} vulnerable service(s)[/]")
    return findings
