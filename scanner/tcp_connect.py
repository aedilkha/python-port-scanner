"""TCP connect scan.

We open a real TCP connection to each port and read the result:
    connection succeeds        -> open
    connection refused (RST)    -> closed
    no answer / timeout         -> filtered (usually a firewall dropping packets)

Nice thing about a connect scan: no root needed and no external libraries,
just the socket module, so it runs anywhere.
"""

import socket
import threading
from queue import Queue

_lock = threading.Lock()


def scan_one_port(host: str, port: int, timeout: float) -> str:
    """Scan a single port, return "open", "closed" or "filtered"."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
        if code == 0:
            return "open"
        elif code == socket.errno.ECONNREFUSED:
            return "closed"
        else:
            return "filtered"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        sock.close()


def _worker(host: str, timeout: float, task_queue: Queue, results: dict) -> None:
    while not task_queue.empty():
        port = task_queue.get()
        results[port] = scan_one_port(host, port, timeout)
        task_queue.task_done()


def tcp_connect_scan(host: str, ports: list[int], timeout: float = 1.0, threads: int = 100) -> dict[int, str]:
    """Scan a list of ports on one host, using threads to speed things up.

    Returns a dict like {22: "open", 80: "closed", 443: "filtered"}.
    """
    results: dict[int, str] = {}
    task_queue: Queue = Queue()

    for port in ports:
        task_queue.put(port)

    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=_worker, args=(host, timeout, task_queue, results), daemon=True)
        t.start()

    task_queue.join()
    return results