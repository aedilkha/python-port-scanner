"""Helper functions: resolving targets and parsing port/network arguments."""

import ipaddress
import socket


def resolve_target(target: str) -> str:
    """Resolve a hostname or IP to an IP address.

    Raises ValueError if it can't be resolved, so the caller can print
    a clean message instead of crashing on a raw socket error.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Can't resolve target: '{target}'")


def parse_ports(spec: str) -> list[int]:
    """Turn a port string into a sorted list of ints.

    Handles single ports, ranges, and comma-separated mixes:
        "80"          -> [80]
        "1-1000"      -> [1..1000]
        "22,80,443"   -> [22, 80, 443]
        "1-100,8080"  -> [1..100, 8080]
    """
    ports: set[int] = set()

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    # keep only valid port numbers
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(target: str) -> list[str]:
    """Expand a target into a list of IPs.

    A plain IP/hostname gives one address. A CIDR like 192.168.20.0/24
    gives every usable host in that range, which is what we use for
    host discovery across a subnet.
    """
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        # .hosts() skips the network and broadcast addresses
        return [str(ip) for ip in network.hosts()]

    return [resolve_target(target)]