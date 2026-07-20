"""Host discovery - find which hosts on a subnet are alive.

Reproduces `nmap -sn` in Python. Rather than relying on ICMP ping (often
blocked, and raw ICMP needs root), we do a lightweight TCP connent to a few
common ports: if any of them answers or actively refuses, the host is up.
This works as a normal user and is reliable enough for a lab network.
"""

import socket
import threading
from queue import Queue

_lock = threading.Lock()

# a few ports likely to trigger a response on a live host
PROBE_PORTS = [80, 443, 22, 445, 3389, 8080]


def is_host_up(ip: str, timeout: float) -> bool:
    """Return True if the host answers (or refuses) on any probe port.

    connect_ex returns 0 when the port is open, or ECONNREFUSED when the host
    is there but nothing listens - both mean the host is alive. Only a silent
    timeout on every port means it's down (or fully firewalled).
    """
    for port in PROBE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
            if code == 0 or code == socket.errno.ECONNREFUSED:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def _worker(timeout: float, task_queue: Queue, live: list) -> None:
    while not task_queue.empty():
        ip = task_queue.get()
        if is_host_up(ip, timeout):
            with _lock:
                live.append(ip)
        task_queue.task_done()


def discover_hosts(ips: list[str], timeout: float = 0.5, threads: int = 100) -> list[str]:
    """Scan a list of IPs and return the ones that are alive, sorted."""
    live: list[str] = []
    task_queue: Queue = Queue()

    for ip in ips:
        task_queue.put(ip)

    for _ in range(min(threads, len(ips))):
        t = threading.Thread(target=_worker, args=(timeout, task_queue, live), daemon=True)
        t.start()

    task_queue.join()
    # sort numerically by the last octet-ish order
    return sorted(live, key=lambda x: tuple(int(p) for p in x.split(".")))