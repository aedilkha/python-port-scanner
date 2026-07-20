# Python Port Scanner — Red Team CTF (BeCode)

A port scanner written from scratch in Python for the Red vs Blue CTF project.
It maps a network and its services the way a pentester's reconnaissance phase
does: discover live hosts, find open ports, and classify each port's state.

> **Lab use only.** Only scan machines you are explicitly authorized to test.

---

## Features

- Scan a single target or a whole subnet (CIDR)
- Three scan techniques: **TCP connect**, **SYN** (half-open), **UDP**
- An **all** mode: best TCP method + UDP in one run
- **Host discovery** across a subnet
- Port states: **open / closed / filtered**
- Save results to **JSON / CSV / TXT**
- Clean modular code, type-hinted, with error handling

---

## Requirements

- Python 3
- [scapy](https://scapy.net/) — only needed for the SYN scan

```bash
pip install scapy --break-system-packages   # or: sudo apt install python3-scapy
```

---

## Usage

The easiest way is the `run.sh` wrapper:

```bash
chmod +x run.sh          # once

./run.sh --help                          # show help
./run.sh 192.168.20.11                   # connect scan, ports 1-1024
./run.sh 192.168.20.11 1-65535           # custom port range
./run.sh 192.168.20.11 53,123 udp        # UDP scan
sudo ./run.sh 192.168.20.11 1-1000 syn   # SYN scan (needs sudo)
sudo ./run.sh 192.168.20.11 1-1000 all   # TCP + UDP together
./run.sh 192.168.20.0/24 discover        # host discovery on a subnet
```

Or call the scanner directly for full control over the options:

```bash
python3 scanner/scanner.py --target 192.168.20.11 --ports 1-1000 --type connect --output results.json
python3 scanner/scanner.py --target 192.168.20.0/24 --discover
python3 scanner/scanner.py --help
```

### Options

| Option       | Description                                            |
|--------------|--------------------------------------------------------|
| `--target`   | IP, hostname, or CIDR (e.g. `192.168.20.0/24`)         |
| `--ports`    | Port range or list: `1-1000` or `22,80,443`           |
| `--type`     | `connect` (default), `syn`, `udp`, `all`              |
| `--discover` | Host discovery mode (find live hosts on a subnet)     |
| `--timeout`  | Max wait per port/host, in seconds                    |
| `--threads`  | Parallel workers for the connect scan                 |
| `--output`   | Save results to a file: `.json`, `.csv`, or `.txt`    |

> The SYN scan needs root (scapy forges raw packets), so run it with `sudo`.

---

## How it maps to nmap

The scanner reproduces nmap's core scan types:

| This scanner    | nmap equivalent   |
|-----------------|-------------------|
| connect scan    | `nmap -sT`        |
| SYN scan        | `nmap -sS`        |
| UDP scan        | `nmap -sU`        |
| host discovery  | `nmap -sn`        |
| all (TCP + UDP) | `nmap -sS -sU`    |
| port range      | `nmap -p 1-1000`  |
| save to file    | `nmap -oN` / `-oX`|

It does the **mapping** (which ports and hosts). It does **not** do nmap's deep
identification — no version detection (`-sV`), OS detection (`-O`), or
vulnerability scripts. It's a learning tool, not an nmap replacement.

---

## Project structure

```
python-port-scanner/
├── run.sh                 # convenience wrapper
├── requirements.txt
├── scanner/
│   ├── scanner.py         # CLI entry point
│   ├── tcp_connect.py     # TCP connect scan
│   ├── syn_scan.py        # SYN scan (scapy)
│   ├── udp_scan.py        # UDP scan
│   ├── host_discovery.py  # live-host discovery
│   ├── combined.py        # "all" mode (TCP + UDP)
│   ├── utils.py           # target / port parsing
│   └── output.py          # JSON / CSV / TXT export
└── reports/               # project reports
```

See `reports/01-design-report.md` for the technical design and the reasoning
behind each scan type.