#!/usr/bin/env python3
"""Command-line entry point for the port scanner.

Reads the arguments, runs the scan, prints the results. The actual
scanning logic lives in tcp_connect.py and utils.py - this file just
wires it together.

    python3 scanner.py --target 192.168.20.11 --ports 1-1000
    python3 scanner.py --target 127.0.0.1 --ports 22,80,443 --timeout 0.5

Lab use only - only scan the targets you're allowed to (the project's
192.168.20.0/24 network).
"""

import argparse
import socket
from datetime import datetime

from tcp_connect import tcp_connect_scan
from utils import parse_ports, resolve_target
from output import save_results
from syn_scan import syn_scan


def service_name(port: int) -> str:
    """Best-effort service name for a port, or "?" if unknown."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP port scanner - Red Team CTF project (authorized lab use only)."
    )
    parser.add_argument("--target", required=True,
                        help="target IP or hostname, e.g. 192.168.20.11")
    parser.add_argument("--ports", default="1-1024",
                        help="ports to scan: '1-1000' or '22,80,443' (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="max wait per port in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="how many ports to scan in parallel (default: 100)")
    parser.add_argument("--output",
                        help="save results to a file: results.json / .csv / .txt")
    parser.add_argument("--type", choices=["connect", "syn"], default="connect",
                        help="scan type: connect (default) or syn (needs sudo)")
    args = parser.parse_args()

    # resolve the target and build the port list before we start
    try:
        target_ip = resolve_target(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        return

    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No valid ports to scan - check your --ports value.")
        return

    print("=" * 60)
    print(f"  Target : {args.target} ({target_ip})")
    print(f"  Ports  : {len(ports)} to scan")
    print(f"  Start  : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 60)

    if args.type == "syn":
        results = syn_scan(target_ip, ports, timeout=args.timeout)
    else:
        results = tcp_connect_scan(target_ip, ports, timeout=args.timeout, threads=args.threads)

    # open ports are what we care about, so show those first
    open_ports = sorted(p for p, state in results.items() if state == "open")
    closed_count = sum(1 for state in results.values() if state == "closed")
    filtered_count = sum(1 for state in results.values() if state == "filtered")

    print()
    if open_ports:
        print("OPEN PORTS:")
        for port in open_ports:
            print(f"  [+] {port:>5}/tcp   OPEN     {service_name(port)}")
    else:
        print("  No open ports found.")

    # closed/filtered are usually too many to list, so just count them
    if closed_count:
        print(f"\n  ({closed_count} closed - host replied but nothing listening)")
    if filtered_count:
        print(f"  ({filtered_count} filtered - likely a firewall)")

    if args.output:
        save_results(args.target, results, args.output)
        print(f"\n  Results saved to {args.output}")

    print("\n" + "=" * 60)
    print(f"  Done   : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 60)


if __name__ == "__main__":
    main()