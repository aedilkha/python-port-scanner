# Reconnaissance Report

## Target scope
- Authorized lab network: `192.168.20.0/24`
- Access via Tailscale VPN from the Red Team Kali box (`kali-3`)

## Host discovery

Done two ways — with nmap and with my own scanner — and they agree.

nmap:
```
nmap -sn 192.168.20.0/24
```

My scanner:
```
./run.sh 192.168.20.0/24 discover
```

Both report the same live hosts:

| IP              | Role (inferred)                         |
|-----------------|-----------------------------------------|
| 192.168.20.1    | Network gateway / router for the lab    |
| 192.168.20.11   | Blue Team 1 server (my target)          |
| 192.168.20.12   | Blue Team 2 server (other team)         |

3 hosts up out of 256 scanned. My scanner's host-discovery mode reproduces
nmap's `-sn` result exactly, which validates that part of the tool.

## Service enumeration — 192.168.20.11

Commands used:
```
nmap -sV -sC -p22 192.168.20.11
nmap --script vuln -p22 192.168.20.11
nmap -sS 192.168.20.11              # full re-scan, SYN
```

Findings:
- Only one port open: **22/tcp (SSH)**. All other ports filtered (firewalled) —
  confirmed again by a full `nmap -sS` (999 filtered, only 22 open).
- Service: **OpenSSH 8.9p1 Ubuntu 3ubuntu0.16** (Ubuntu 22.04).
- Host keys: ECDSA + ED25519 present.
- `--script vuln` returned no known CVEs for this version.
- The Blue Team web application is **not yet deployed** — no web port is open
  at this stage. The recon will need to be repeated once it goes live.

## Analysis

- The SSH service is current and patched — no exploitable version-based
  vulnerability. The remaining attack surface is authentication (password
  strength).
- The target stays reachable on 192.168.20.11 even when the Tailscale node
  "target" shows offline, which indicates the target is a VM on the lab network
  behind the gateway, not the Tailscale endpoint itself.
- The lab subnet route is not present in the local kernel routing table
  (`ip route` shows only the NAT interface); Tailscale routes this traffic in
  userspace.

## Note on scan methods through Tailscale

An interesting finding worth recording: my own SYN scan reports all ports
filtered on this target, while my connect scan and nmap's `-sS` both correctly
see port 22 open — same target, same tunnel. So the issue is not Tailscale
making SYN scanning impossible (nmap manages it); it's a limitation of my
scapy-based implementation in a userspace-VPN tunnel. Verified separately: my
SYN scan works correctly on a local target (loopback), so the code is sound —
the limitation is specific to raw-packet scanning through this tunnel. On this
target the reliable method is the connect scan. (See design report, section 7.)

## Recommendations for Blue Team
- Enforce strong passwords or, better, SSH key-only authentication.
- Add fail2ban to throttle/ban brute-force attempts.
- Keep the minimal exposed surface (only 22 open is already good practice).