"""
ReconNinja v3 — Target Parser
Handles domain, IP, CIDR, and list file inputs.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from pathlib import Path
from typing import Generator


class TargetType(Enum):
    DOMAIN  = "domain"
    IP      = "ip"
    NETWORK = "network"  # CIDR
    LIST    = "list"


def detect_target_type(target: str) -> TargetType:
    """Classify a target string."""
    # File path
    if Path(target).exists():
        return TargetType.LIST

    # CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        if "/" in target:
            return TargetType.NETWORK
    except ValueError:
        pass

    # Plain IP
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass

    # Domain (rough check)
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_re.match(target):
        return TargetType.DOMAIN

    # Fallback — treat as domain anyway and let tools complain
    return TargetType.DOMAIN


def expand_targets(target: str) -> Generator[tuple[str, TargetType], None, None]:
    """
    Yield (target_str, TargetType) tuples.
    Handles single targets and list files.
    """
    t_type = detect_target_type(target)

    if t_type == TargetType.LIST:
        p = Path(target)
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line, detect_target_type(line)
    elif t_type == TargetType.NETWORK:
        net = ipaddress.ip_network(target, strict=False)
        for addr in net.hosts():
            yield str(addr), TargetType.IP
    else:
        yield target, t_type
