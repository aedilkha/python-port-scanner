"""Combined scan - one command, both protocols.

Runs a TCP scan and a UDP scan on the same ports, so you get a full picture in
one go. For the TCP half it picks the best method available:
    - running as root  -> SYN scan (faster, stealthier)
    - otherwise        -> connect scan (works without privileges)

We don't run both connect AND syn: they answer the same question (which TCP
ports are open) by different means, so running both would just be redundant.
The useful pairing is TCP + UDP, which cover different protocols.
"""

import os

from tcp_connect import tcp_connect_scan
from udp_scan import udp_scan


def combined_scan(host: str, ports: list[int], timeout: float = 1.0, threads: int = 100) -> dict[str, dict[int, str]]:
    """Run a TCP scan (best method for our privileges) + a UDP scan.

    Returns a dict with two sub-results:
        {"tcp": {port: state, ...}, "udp": {port: state, ...}}
    """
    # os.geteuid() == 0 means we're root, so raw-socket SYN scanning is allowed
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    if is_root:
        # imported lazily so a non-root run never needs scapy; if scapy isn't
        # installed, fall back to a connect scan instead of crashing
        try:
            from syn_scan import syn_scan
            tcp_results = syn_scan(host, ports, timeout=max(timeout, 2.0))
            tcp_method = "syn"
        except ImportError:
            tcp_results = tcp_connect_scan(host, ports, timeout=timeout, threads=threads)
            tcp_method = "connect (scapy missing)"
    else:
        tcp_results = tcp_connect_scan(host, ports, timeout=timeout, threads=threads)
        tcp_method = "connect"

    udp_results = udp_scan(host, ports, timeout=max(timeout, 2.0))

    return {"tcp": tcp_results, "udp": udp_results, "_tcp_method": tcp_method}