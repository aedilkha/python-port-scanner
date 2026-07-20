#!/usr/bin/env python3
"""Command-line entry point for the port scanner.

Reads the arguments, runs the scan, prints the results. The scanning logic
lives in the other modules - this file just wires it together.

    # scan one host
    python3 scanner.py --target 192.168.20.11 --ports 1-1000
    python3 scanner.py --target 192.168.20.11 --ports 1-1000 --type syn   # needs sudo
    python3 scanner.py --target 192.168.20.11 --ports 53,123 --type udp

    # discover live hosts on a subnet
    python3 scanner.py --target 192.168.20.0/24 --discover

Lab use only - only scan targets you're allowed to.
"""

import argparse
import socket
from datetime import datetime

from tcp_connect import tcp_connect_scan
from syn_scan import syn_scan
from udp_scan import udp_scan
from host_discovery import discover_hosts
from output import save_results
from utils import parse_ports, parse_targets, resolve_target


def service_name(port: int) -> str:
    """Best-effort service name for a port, or "?" if unknown."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def run_discovery(target: str, timeout: float) -> None:
    """Host discovery mode: list live hosts on a subnet."""
    ips = parse_targets(target)
    print("=" * 60)
    print(f"  Host discovery : {target} ({len(ips)} addresses)")
    print(f"  Start          : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 60)

    live = discover_hosts(ips, timeout=timeout)

    print()
    if live:
        print(f"LIVE HOSTS ({len(live)}):")
        for ip in live:
            print(f"  [+] {ip}")
    else:
        print("  No live hosts found.")
    print("\n" + "=" * 60)


def run_port_scan(args: argparse.Namespace) -> None:
    """Port scan mode: scan ports on a single target."""
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
    print(f"  Ports  : {len(ports)} to scan  ({args.type} scan)")
    print(f"  Start  : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 60)

    if args.type == "syn":
        results = syn_scan(target_ip, ports, timeout=args.timeout)
    elif args.type == "udp":
        results = udp_scan(target_ip, ports, timeout=args.timeout)
    else:
        results = tcp_connect_scan(target_ip, ports, timeout=args.timeout, threads=args.threads)

    # "interesting" states first (open, and udp's open|filtered)
    open_ports = sorted(p for p, s in results.items() if s in ("open", "open|filtered"))
    closed_count = sum(1 for s in results.values() if s == "closed")
    filtered_count = sum(1 for s in results.values() if s == "filtered")

    print()
    proto = "udp" if args.type == "udp" else "tcp"
    if open_ports:
        print("OPEN PORTS:")
        for port in open_ports:
            print(f"  [+] {port:>5}/{proto}   {results[port].upper():<14} {service_name(port)}")
    else:
        print("  No open ports found.")

    if closed_count:
        print(f"\n  ({closed_count} closed)")
    if filtered_count:
        print(f"  ({filtered_count} filtered)")

    if args.output:
        save_results(args.target, results, args.output)
        print(f"\n  Results saved to {args.output}")

    print("\n" + "=" * 60)
    print(f"  Done   : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Port scanner - Red Team CTF project (authorized lab use only)."
    )
    parser.add_argument("--target", required=True,
                        help="target IP/hostname, or CIDR (e.g. 192.168.20.0/24) with --discover")
    parser.add_argument("--ports", default="1-1024",
                        help="ports to scan: '1-1000' or '22,80,443' (default: 1-1024)")
    parser.add_argument("--type", choices=["connect", "syn", "udp"], default="connect",
                        help="scan type: connect (default), syn (needs sudo), udp")
    parser.add_argument("--discover", action="store_true",
                        help="host discovery mode: find live hosts on the target subnet")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="max wait per port/host in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="parallel workers for connect scan (default: 100)")
    parser.add_argument("--output",
                        help="save results to a file: results.json / .csv / .txt")
    args = parser.parse_args()

    if args.discover:
        run_discovery(args.target, args.timeout)
    else:
        run_port_scan(args)


if __name__ == "__main__":
    main()