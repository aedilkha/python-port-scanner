"""SYN scan (a.k.a. half-open scan).

Instead of finishing the full TCP handshake like the connect scan, we send a
SYN and look at the reply:
    SYN-ACK   -> open (we reply RST so the handshake never completes)
    RST       -> closed
    nothing   -> filtered (firewall dropping it)

Never completing the handshake makes it faster and quieter than a connect scan.
Forging raw packets needs root, so run this with sudo.

We send all the SYNs in one batch with scapy's sr() instead of one-at-a-time.
On a host with lots of filtered ports the one-by-one version waits the full
timeout on every single port, which is painfully slow - batching sends them
together and just collects whatever answers come back.

    sudo python3 scanner.py --target 192.168.20.11 --ports 1-1000 --type syn
"""


def syn_scan(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, str]:
    """Run a batched SYN scan. Returns {port: open/closed/filtered}."""
    from scapy.all import IP, TCP, sr, conf
    conf.verb = 0

    # one SYN packet per port, all fired together
    packets = IP(dst=host) / TCP(dport=ports, flags="S")

    # answered = packets that got a reply; unanswered = silent (filtered)
    answered, unanswered = sr(packets, timeout=timeout)

    results: dict[int, str] = {}

    # anything we never heard back from is filtered
    for sent in unanswered:
        results[sent[TCP].dport] = "filtered"

    # classify the ports that did reply
    rst_ports: list[int] = []
    for sent, received in answered:
        port = sent[TCP].dport
        if received.haslayer(TCP):
            flags = received[TCP].flags
            if flags == 0x12:        # SYN-ACK -> open
                results[port] = "open"
                rst_ports.append(port)
            elif flags == 0x14:      # RST-ACK -> closed
                results[port] = "closed"
            else:
                results[port] = "filtered"
        else:
            results[port] = "filtered"

    # tear down the half-open connections we opened, in one batch
    if rst_ports:
        rst = IP(dst=host) / TCP(dport=rst_ports, flags="R")
        sr(rst, timeout=timeout)

    return results