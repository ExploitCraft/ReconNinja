"""
ReconNinja v9 — ReconGraph
Lightweight directed graph connecting all finding types through typed edges.

Node types: host | port | service | subdomain | vuln | credential | url | ad_object | cloud_resource
Edge types: has_port | runs_service | matches_cve | enables_path | resolves_to | hosts_url

No external graph library required — plain adjacency list.
Exports: JSON-LD, GraphML, Neo4j (bolt).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Iterator


# ─── Node / Edge ──────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    node_id:    str
    node_type:  str           # host | port | service | subdomain | vuln | ...
    label:      str
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def make(cls, node_type: str, label: str, **props) -> "GraphNode":
        node_id = hashlib.md5(f"{node_type}:{label}".encode()).hexdigest()[:16]
        return cls(node_id=node_id, node_type=node_type, label=label, properties=props)


@dataclass
class GraphEdge:
    edge_id:    str
    src:        str           # node_id
    dst:        str           # node_id
    edge_type:  str
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def make(cls, src: str, dst: str, edge_type: str, **props) -> "GraphEdge":
        edge_id = hashlib.md5(f"{src}:{edge_type}:{dst}".encode()).hexdigest()[:16]
        return cls(edge_id=edge_id, src=src, dst=dst, edge_type=edge_type, properties=props)


# ─── ReconGraph ───────────────────────────────────────────────────────────────

class ReconGraph:
    """
    Directed finding graph for ReconNinja v9.

    Usage:
        g = ReconGraph()
        host_node = g.add_node("host", "10.0.0.5", os="Windows Server 2019")
        port_node = g.add_node("port", "10.0.0.5:445")
        g.add_edge(host_node, port_node, "has_port")
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._out: dict[str, list[str]]   = {}   # node_id → [edge_id]
        self._in:  dict[str, list[str]]   = {}   # node_id → [edge_id]

    # ── Mutation ──────────────────────────────────────────────────────────────

    def add_node(self, node_type: str, label: str, **props) -> str:
        """Add or update a node. Returns node_id."""
        node = GraphNode.make(node_type, label, **props)
        if node.node_id in self._nodes:
            self._nodes[node.node_id].properties.update(props)
        else:
            self._nodes[node.node_id] = node
            self._out[node.node_id] = []
            self._in[node.node_id] = []
        return node.node_id

    def add_edge(self, src_id: str, dst_id: str, edge_type: str, **props) -> str:
        """Add a directed edge. Both nodes must already exist. Returns edge_id."""
        if src_id not in self._nodes:
            raise KeyError(f"Source node {src_id!r} not in graph")
        if dst_id not in self._nodes:
            raise KeyError(f"Dest node {dst_id!r} not in graph")
        edge = GraphEdge.make(src_id, dst_id, edge_type, **props)
        if edge.edge_id not in self._edges:
            self._edges[edge.edge_id] = edge
            self._out[src_id].append(edge.edge_id)
            self._in[dst_id].append(edge.edge_id)
        return edge.edge_id

    # ── Query ─────────────────────────────────────────────────────────────────

    def nodes_of_type(self, node_type: str) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def neighbors(self, node_id: str) -> list[GraphNode]:
        return [self._nodes[self._edges[eid].dst] for eid in self._out.get(node_id, [])]

    def edges_from(self, node_id: str, edge_type: str | None = None) -> list[GraphEdge]:
        edges = [self._edges[eid] for eid in self._out.get(node_id, [])]
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return edges

    def shortest_path(self, src_id: str, dst_id: str) -> list[str] | None:
        """BFS shortest path. Returns list of node_ids or None if unreachable."""
        from collections import deque
        visited = {src_id}
        queue: deque[list[str]] = deque([[src_id]])
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == dst_id:
                return path
            for nb in self.neighbors(node):
                if nb.node_id not in visited:
                    visited.add(nb.node_id)
                    queue.append(path + [nb.node_id])
        return None

    def paths_to_type(self, src_id: str, target_type: str) -> list[list[str]]:
        """BFS all paths from src to nodes of target_type (up to depth 8)."""
        from collections import deque
        results: list[list[str]] = []
        queue: deque[list[str]] = deque([[src_id]])
        visited_paths: set[tuple] = set()
        while queue:
            path = queue.popleft()
            if len(path) > 8:
                continue
            node = path[-1]
            if node != src_id and self._nodes[node].node_type == target_type:
                results.append(path)
                continue
            for nb in self.neighbors(node):
                new_path = path + [nb.node_id]
                key = tuple(new_path)
                if key not in visited_paths:
                    visited_paths.add(key)
                    queue.append(new_path)
        return results

    def __len__(self) -> int:
        return len(self._nodes)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ReconGraph":
        g = cls()
        for nd in data.get("nodes", []):
            node = GraphNode(**nd)
            g._nodes[node.node_id] = node
            g._out.setdefault(node.node_id, [])
            g._in.setdefault(node.node_id, [])
        for ed in data.get("edges", []):
            edge = GraphEdge(**ed)
            g._edges[edge.edge_id] = edge
            g._out.setdefault(edge.src, []).append(edge.edge_id)
            g._in.setdefault(edge.dst, []).append(edge.edge_id)
        return g

    def to_graphml(self) -> str:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/graphml">',
            '  <graph id="ReconNinja" edgedefault="directed">',
        ]
        for n in self._nodes.values():
            label = n.label.replace('"', "&quot;")
            lines.append(f'    <node id="{n.node_id}"><data key="label">{label}</data>'
                         f'<data key="type">{n.node_type}</data></node>')
        for e in self._edges.values():
            lines.append(f'    <edge id="{e.edge_id}" source="{e.src}" target="{e.dst}">'
                         f'<data key="type">{e.edge_type}</data></edge>')
        lines += ['  </graph>', '</graphml>']
        return "\n".join(lines)

    def to_json_ld(self) -> str:
        graph: list[dict] = []
        for n in self._nodes.values():
            obj: dict = {
                "@id":   f"rn:{n.node_id}",
                "@type": f"rn:{n.node_type}",
                "label": n.label,
            }
            obj.update(n.properties)
            graph.append(obj)
        for e in self._edges.values():
            graph.append({
                "@type":   f"rn:{e.edge_type}",
                "rn:from": {"@id": f"rn:{e.src}"},
                "rn:to":   {"@id": f"rn:{e.dst}"},
            })
        doc = {
            "@context": {"rn": "https://reconinja.dev/vocab#"},
            "@graph":   graph,
        }
        return json.dumps(doc, indent=2)

    def push_to_neo4j(self, bolt_url: str, user: str = "neo4j", password: str = "password") -> None:
        """Push the graph to a running Neo4j instance via bolt."""
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError:
            raise RuntimeError("neo4j package not installed. Run: pip install neo4j")

        driver = GraphDatabase.driver(bolt_url, auth=(user, password))
        with driver.session() as session:
            # Merge nodes
            for node in self._nodes.values():
                props = {**node.properties, "label": node.label, "node_type": node.node_type}
                session.run(
                    "MERGE (n:ReconNode {node_id: $nid}) SET n += $props",
                    nid=node.node_id, props=props,
                )
            # Merge edges
            for edge in self._edges.values():
                session.run(
                    """
                    MATCH (a:ReconNode {node_id: $src})
                    MATCH (b:ReconNode {node_id: $dst})
                    MERGE (a)-[r:RECON_EDGE {edge_id: $eid}]->(b)
                    SET r.edge_type = $etype
                    """,
                    src=edge.src, dst=edge.dst,
                    eid=edge.edge_id, etype=edge.edge_type,
                )
        driver.close()


# ─── Graph builder helpers ───────────────────────────────────────────────────

def build_graph_from_result(result) -> ReconGraph:
    """
    Populate a ReconGraph from a completed ReconResult.
    Call after the scan finishes to enable attack-chain correlation.
    """
    from utils.models import ReconResult  # avoid circular at module level
    g = ReconGraph()

    # Subdomains
    for sub in result.subdomains:
        g.add_node("subdomain", sub)

    # Hosts → ports → services
    for host in result.hosts:
        hid = g.add_node("host", host.ip, os=host.os_guess, mac=host.mac)
        for sub in host.hostnames:
            sid = g.add_node("subdomain", sub)
            g.add_edge(sid, hid, "resolves_to")
        for port in host.open_ports:
            pid = g.add_node("port", f"{host.ip}:{port.port}",
                             port=port.port, protocol=port.protocol)
            g.add_edge(hid, pid, "has_port")
            if port.service:
                svcid = g.add_node("service", port.service,
                                   product=port.product, version=port.version)
                g.add_edge(pid, svcid, "runs_service")
        for url in host.web_urls:
            uid = g.add_node("url", url)
            g.add_edge(hid, uid, "hosts_url")

    # Vuln findings → CVEs
    for vf in result.nuclei_findings:
        vid = g.add_node("vuln", vf.title,
                         severity=vf.severity, cve=vf.cve,
                         epss=vf.epss_score, rei=vf.rei)
        # Link to host if target matches
        for host in result.hosts:
            if host.ip in vf.target or any(h in vf.target for h in host.hostnames):
                hid = g.add_node("host", host.ip)
                g.add_edge(hid, vid, "matches_cve")

    # AD findings
    for adf in result.ad_findings:
        adid = g.add_node("ad_object", adf.title,
                          category=adf.category, severity=adf.severity)
        g.add_node("host", result.target)
        g.add_edge(g.add_node("host", result.target), adid, "has_ad_finding")

    # Cloud findings
    for cf in result.cloud_deep_findings:
        cid = g.add_node("cloud_resource", cf.resource,
                         provider=cf.provider, service=cf.service,
                         severity=cf.severity, public=cf.public)
        g.add_edge(g.add_node("host", result.target), cid, "has_cloud_resource")

    return g
