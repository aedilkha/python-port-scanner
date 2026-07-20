# Design Report — Python Port Scanner

**Project:** Red vs Blue CTF (Hamilton cohort)
**Role:** Red Team — scanner design
**Author:** Alvi

---

## 1. What this tool is

A port scanner written from scratch in Python. It maps a network and its
services the way the reconnaissance phase of a pentest does: find live hosts,
find open ports, and figure out each port's state. It reproduces the core
techniques of nmap so I understand *how* they work under the hood — it's a
learning tool, not an nmap replacement.

---

## 2. How the code is organised

I split the scanner into small modules, one job each, instead of one long
script. It's easier to read, easier to test, and easier to extend (adding a new
scan type is just a new file).

| File               | Job                                                    |
|--------------------|--------------------------------------------------------|
| `scanner.py`       | Command-line entry point: reads args, runs the right scan, prints and saves results |
| `tcp_connect.py`   | TCP connect scan (the "normal" TCP scan)               |
| `syn_scan.py`      | SYN (half-open) scan using scapy                        |
| `udp_scan.py`      | UDP scan                                                |
| `host_discovery.py`| Finds live hosts on a subnet                            |
| `combined.py`      | "all" mode: best TCP method + UDP in one run           |
| `utils.py`         | Shared helpers: resolve targets, parse ports and CIDR  |
| `output.py`        | Save results to JSON / CSV / TXT                        |

The main script never does the actual scanning — it just wires the modules
together. That separation is deliberate: the logic lives in focused files, and
`scanner.py` stays readable.

---

## 3. The scan types, and why they differ

The scanner supports three real techniques. Understanding the difference is the
whole point of the project.

### TCP connect scan
Opens a full TCP connection to each port (the complete 3-way handshake). If it
connects, the port is open; if the connection is refused, it's closed; if
nothing answers, it's filtered. Uses only Python's `socket` module — no special
privileges, works anywhere. This is the reliable default.

### SYN scan (half-open)
Sends only the first packet of the handshake (a SYN) and reads the reply
without ever completing the connection:
- SYN-ACK back → open (we send a RST to tear it down)
- RST back → closed
- nothing → filtered

It's faster and quieter than a connect scan because the connection is never
finished — the service often doesn't even log it. The catch: crafting a raw SYN
packet isn't something the OS does normally, so it needs **scapy** and **root**.

### UDP scan
UDP has no handshake, so it's fuzzier. We send an empty datagram; a reply means
open, an ICMP "port unreachable" means closed, and silence means we genuinely
can't tell — reported honestly as `open|filtered`. Even nmap has this same
ambiguity with UDP.

---

## 4. What scapy is, and why the SYN scan needs it

`scapy` is a Python library for building and sending network packets by hand,
byte by byte. The difference from the normal `socket` module:

- with `socket`, you ask the OS "connect me to this port" and it builds the
  packets for you, following the normal rules;
- with `scapy`, *you* build the packet yourself and decide exactly which flags
  it carries.

A SYN scan sends a lone SYN and never finishes the handshake — abnormal
behaviour the OS won't do on its own. So the packet has to be forged manually,
which is what scapy is for. Forging raw packets is a privileged operation, hence
`sudo`.

---

## 5. The "all" mode — a design decision worth explaining

There's an `all` mode that runs a TCP scan **and** a UDP scan together. One
choice I made deliberately: it does **not** run connect *and* SYN together.

Connect and SYN both answer the same question — which TCP ports are open — just
by different methods. Running both would do the same work twice for the same
result. The pairing that actually adds information is **TCP + UDP**, because
those are different protocols. So `all` runs one TCP scan (SYN if it has root,
connect otherwise) plus one UDP scan. This mirrors how nmap combines `-sS -sU`.

---

## 6. Port states

Every port ends up in one of three states, which the tool reports directly:

- **open** — a service is listening and answered.
- **closed** — the host replied but nothing is listening there.
- **filtered** — silence: a firewall is dropping the packets. (This is what
  showed up as hundreds of "filtered" ports on the real target — the firewall
  swallows probes instead of refusing them.)

Seeing "filtered" live on the lab target made the distinction concrete: closed
means "actively refused", filtered means "no answer at all".

---

## 7. How it compares to nmap

The scanner maps cleanly onto nmap's basic scan flags:

| My scanner        | nmap equivalent      |
|-------------------|----------------------|
| connect scan      | `nmap -sT`           |
| SYN scan          | `nmap -sS`           |
| UDP scan          | `nmap -sU`           |
| host discovery    | `nmap -sn`           |
| all (TCP + UDP)   | `nmap -sS -sU`       |
| port range        | `nmap -p 1-1000`     |
| save to file      | `nmap -oN` / `-oX`   |

What nmap does that this tool does **not**: service-version detection (`-sV`),
OS detection (`-O`), vulnerability scripts (`--script`), and years of speed and
reliability tuning. My scanner does the *mapping* (which ports and hosts), not
the deep *identification* (which versions, which OS, which CVEs). That's the
honest boundary of the tool — and exactly the line between a learning project
and a production scanner.

A concrete example of that boundary showed up in the lab: through the Tailscale
VPN, nmap saw the target's open ports but my SYN scan saw none. Tailscale routes
traffic in userspace, which raw-socket tooling (scapy) can't observe the same
way nmap's connect-based probing can. The connect scan worked; the SYN scan
didn't. A real limitation, and a good reminder that the environment decides
which technique is reliable.

---

## 8. Error handling & code quality

- Unresolvable targets and invalid port strings are caught and reported
  cleanly instead of crashing.
- Socket timeouts and unreachable hosts are handled per-port.
- All functions are type-hinted.
- TCP connect and host discovery are threaded for speed; UDP and SYN run at a
  measured pace on purpose (UDP needs longer timeouts; firing raw packets too
  fast causes false results).