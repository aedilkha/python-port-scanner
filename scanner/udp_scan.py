"""UDP scan.

UDP has no handshake, so scanning it is fuzzier than TCP:
    - we send an empty UDP datagram to the port
    - if we get a UDP reply back        -> open
    - if we get an ICMP "port unreachable" -> closed (the OS surfaces this as
      a socket error on the next recv)
    - if we get nothing at all          -> open|filtered (can't tell which,
      because UDP has no positive ack for "received but no response")

That "open|filtered" ambiguity is inherent to UDP scanning - even nmap reports
it the same way. We label it "open|filtered" to stay honest about it.
"""

import socket


def udp_scan_port(host: str, port: int, timeout: float) -> str:
    """Scan one UDP port. Returns open / closed / open|filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"", (host, port))
        try:
            sock.recvfrom(1024)
            return "open"            # got a UDP reply
        except socket.timeout:
            return "open|filtered"   # silence - can't tell open from filtered
        except OSError:
            return "closed"          # ICMP port unreachable surfaced here
    except OSError:
        return "open|filtered"
    finally:
        sock.close()


def udp_scan(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, str]:
    """Scan a list of UDP ports. Returns {port: state}.

    Runs sequentially - UDP scans need a longer timeout per port (waiting for a
    possible ICMP reply), and firing too many at once makes the OS rate-limit
    ICMP responses, which causes false "open|filtered" results.
    """
    results: dict[int, str] = {}
    for port in ports:
        results[port] = udp_scan_port(host, port, timeout)
    return results