# Design Report — Python Port Scanner

**Project:** Red vs Blue CTF (Hamilton cohort)
**Role:** Red Team — scanner design
**Author:** Alvi

---

## 1. What this tool is

A port scanner written from scratch in Python. It maps a network and its
services the way the reconnaissance phase of a pentest does: find live hosts,
find open ports, and figure out each port's state. It reproduces the core
techniques of nmap so I understand *how* they work under the hood — it does not replace nmap but could help understanding how nmap works.

---

## 2. How the code is organised

I split the scanner into small modules, each has one job. It's easier to read, easier to test, and easier to extend (adding a new
scan type is just a new file).

| File               | Job                                                    |
|--------------------|--------------------------------------------------------|
| `scanner.py`       | Command-line entry point: reads args, runs the right scan, prints and saves results |
| `tcp_connect.py`   | TCP connect scan (the "basic" TCP scan)               |
| `syn_scan.py`      | SYN (half-open) scan using scapy                        |
| `udp_scan.py`      | UDP scan                                                |
| `host_discovery.py`| Finds live hosts on a subnet                            |
| `combined.py`      | "all" mode: best TCP method + UDP in one run           |
| `utils.py`         | Shared helpers: resolve targets, parse ports and CIDR  |
| `output.py`        | Save results to JSON / CSV / TXT                        |

The main script just wires the modules together. the logic lives in focused files.

---

## 3. The scan types, and why they differ

The scanner supports three real techniques.

### TCP connect scan
Opens a full TCP connection to each port (the complete 3-way handshake). If it
connects, the port is open; if the connection is refused, it's closed; if
nothing answers, it's filtered. Uses only Python's `socket` module.

### SYN scan (half-open)
Sends only the first packet of the handshake (a SYN) and reads the reply
without ever completing the connection:
- SYN-ACK back → open (we send a RST to tear it down)
- RST back → closed
- nothing → filtered

It's faster and quieter than a connect scan because the connection is never
finished — the service often doesn't even log it. Crafting a raw SYN
packet isn't something the OS does normally, so it needs **scapy** and **root**.

### UDP scan
UDP has no handshake, so it's fuzzier. We send an empty datagram; a reply means
open, an ICMP "port unreachable" means closed, and silence means we genuinely
can't tell — reported honestly as `open|filtered`. Even nmap has this same
ambiguity with UDP.

---

## 4. (REMINDER) What scapy is, and why the SYN scan needs it

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

A concrete example of that boundary showed up in the lab, and it's more precise
than I first assumed. Through the Tailscale VPN, my SYN scan reported every port
filtered — but my connect scan AND nmap's `-sS` both correctly saw port 22 open
on the same target through the same tunnel. So it isn't that Tailscale makes SYN
scanning impossible (nmap does it fine); it's that my scapy-based SYN scan
doesn't handle a userspace-VPN tunnel robustly — nmap manages interface
selection, retransmissions and userspace routing better than my code does.

My SYN scan works correctly on a local target
(loopback), so the implementation works on a normal network — the failure is
specific to raw-packet scanning through this tunnel (Tailscale). So my connect
scan is the reliable method on this target, and the SYN scan's limit here is an
implementation gap.

---

## 8. Error handling & code quality

- Unresolvable targets and invalid port strings are caught and reported
  cleanly instead of crashing.
- Socket timeouts and unreachable hosts are handled per-port.
- All functions are type-hinted.
- TCP connect and host discovery are threaded for speed; UDP and SYN run at a
  measured pace on purpose (UDP needs longer timeouts; firing raw packets too
  fast causes false results).

---

## Wireshark Analysis — What Our Scan Looks Like on the Wire

Before and during the port scan, traffic was captured with `tshark` on the
`tailscale0` interface (`scan_capture.pcap`, ~1183 packets). Below are the five
questions from the brief, answered from our own capture.

### 1. Network discovery — which protocol, what pattern?

Discovery uses **ICMP** (ping). The capture shows a clean request/reply pair,
one per second:
```
100.95.28.3  → 192.168.20.11  ICMP  Echo (ping) request  seq=1
192.168.20.11 → 100.95.28.3   ICMP  Echo (ping) reply    seq=1
```
Pattern: a steady echo-request from us, an echo-reply from the host. This simply
confirms the host is alive before we scan its ports. Four requests, four replies,
0% loss.

### 2. What does an OPEN port look like? (TCP handshake)

An open port completes the **TCP three-way handshake**. On port 22:
```
54494 → 22  [SYN]        (we ask: are you open?)
22 → 54494  [SYN, ACK]   (server: yes, let's connect)
54494 → 22  [ACK]        (handshake complete — port is OPEN)
54494 → 22  [FIN/RST]    (we immediately tear the connection down)
```
Because the server answered SYN-ACK, we know port 22 is open. The same pattern
appears on 443. Interestingly, the server even leaked its SSH banner
(`SSH-2.0-OpenSSH_8.9p1 Ubuntu`) once the handshake completed.

### 3. What does a CLOSED / FILTERED port look like? How is it different?

Out of 1000 ports, 998 were **filtered**. A filtered port produces **no reply at
all** — our SYN is sent and nothing comes back:
```
58586 → 2   [SYN]   (no response — silently dropped by a firewall)
```
This is different from a classic **closed** port, which would answer with a
**RST** (reset). Here the firewall drops everything except 22 and 443, so the
non-open ports are *filtered* (silence), not *closed* (RST). The only RST packets
in the capture come from **us** tearing down our own open connections, not from
the server.

Summary of the three states on the wire:
- **OPEN** → SYN → SYN-ACK (handshake answered)
- **CLOSED** → SYN → RST (actively refused)
- **FILTERED** → SYN → (nothing) (silently dropped)

### 4. Can you spot the scanning pattern? What makes it recognizable?

Yes — it is obvious. The capture shows a burst of SYN packets to ports
**1, 2, 3, 4, 5, 6, 7 … 30 …** in sequence, each from a different source port,
all within milliseconds:
```
58148 → 1   [SYN]
58586 → 2   [SYN]
58774 → 3   [SYN]
44060 → 4   [SYN]
...
```
Ports 1–20 were all hit in under 0.1 second. What makes it recognizable as
reconnaissance:
- **One source host** contacting **many destination ports** in a short window.
- **Sequential / near-sequential** port order.
- **Half-open behaviour**: connections are opened and immediately closed (SYN →
  handshake → instant FIN/RST), never used to actually exchange data.
- **High rate**: hundreds of connection attempts per second — no legitimate
  client behaves this way.

### 5. What defensive indicators would alert a Blue Team?

- A single source IP hitting a large number of distinct ports in a short time.
- A spike in **SYN packets** without matching established, data-carrying sessions.
- Many connections that open and close instantly (no real payload).
- Connection attempts to closed/unused ports (a normal user never targets port 2,
  3, 4…).
- ICMP echo immediately followed by a fan-out of TCP SYNs from the same host.

These indicators feed directly into the Defensive Analysis report (04).