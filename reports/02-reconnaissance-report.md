# Reconnaissance Report

## Target scope
- Authorized lab network: `192.168.20.0/24`
- Access via Tailscale VPN from the Red Team Kali box (`kali-3`)

## Host discovery

Command used:
```
nmap -sn 192.168.20.0/24
```

Live hosts found:

| IP              | Role (inferred)                         |
|-----------------|-----------------------------------------|
| 192.168.20.1    | Network gateway / router for the lab    |
| 192.168.20.11   | Blue Team 1 server (my target)          |
| 192.168.20.12   | Blue Team 2 server (other team)         |

3 hosts up out of 256 scanned.

## Service enumeration — 192.168.20.11

Command used:
```
nmap -sV -sC -p22 192.168.20.11
nmap --script vuln -p22 192.168.20.11
```

Findings:
- Only one port open: **22/tcp (SSH)**. All other ports filtered (firewalled).
- Service: **OpenSSH 8.9p1 Ubuntu 3ubuntu0.16** (Ubuntu 22.04).
- Host keys: ECDSA + ED25519 present.
- `--script vuln` returned no known CVEs for this version.

## Analysis

- The SSH service is current and patched — no exploitable version-based
  vulnerability. The remaining attack surface is authentication (password strength).
- The target stays reachable on 192.168.20.11 even when the Tailscale node
  "target" shows offline, which indicates the target is a VM on the lab network
  behind the gateway, not the Tailscale endpoint itself.
- The lab subnet route is not present in the local kernel routing table
  (`ip route` shows only the NAT interface); Tailscale routes this traffic in
  userspace. This is also why a raw-socket SYN scan can't see the replies here,
  while a TCP connect scan (which uses the OS network stack) works fine.

## Recommendations for Blue Team
- Enforce strong passwords or, better, SSH key-only authentication.
- Add fail2ban to throttle/ban brute-force attempts.
- Keep the minimal exposed surface (only 22 open is already good practice).