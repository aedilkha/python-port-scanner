# Lab Report — Network Reconnaissance & Port Scanner

**Project:** Red vs Blue CTF (Hamilton cohort)
**Role:** Red Team — Reconnaissance & tooling
**Author:** Alvi

---

## 1. Objective

Build a Python port scanner from scratch and use it, alongside standard
tooling (nmap), to perform network reconnaissance of the lab environment:
discover live hosts, enumerate exposed services, and classify port states.
This report covers the tooling built and the recon performed.

---

## 2. Environment

- Attacker box: Kali Linux VM (Red Team scanner), Python 3.13
- Lab network reached over a Tailscale VPN
- Work tracked in a Git repository (`python-port-scanner`)

---

## 3. Tooling built — the scanner

Modular Python scanner (`scanner/` package):

| File              | Responsibility                                        |
|-------------------|-------------------------------------------------------|
| `scanner.py`      | CLI entry point, orchestration, result display        |
| `tcp_connect.py`  | Threaded TCP connect scan, OPEN/CLOSED/FILTERED states |
| `syn_scan.py`     | SYN (half-open) scan via scapy (batched)              |
| `utils.py`        | Target resolution, port + CIDR parsing                |
| `output.py`       | Save results to JSON / CSV / TXT                       |

Features implemented against the project brief:
- target IP/hostname + port range as input
- three port states: OPEN / CLOSED / FILTERED
- two scan types: TCP connect and SYN
- structured file output (JSON/CSV/TXT)
- error handling (unresolved host, invalid ports, timeouts)
- type-hinted, one-responsibility-per-module structure

Example:
```
python3 scanner.py --target <ip> --ports 1-1000 --type connect --output results.json
```

---

## 4. Reconnaissance performed

### 4.1 Host discovery
```
nmap -sn 192.168.20.0/24
```
Live hosts:

| IP             | Inferred role            |
|----------------|--------------------------|
| 192.168.20.1   | Lab gateway / router     |
| 192.168.20.11  | Blue Team 1 server       |
| 192.168.20.12  | Blue Team 2 server       |

### 4.2 Service enumeration — 192.168.20.11
```
nmap -sV -sC -p22 192.168.20.11
nmap --script vuln -p22 192.168.20.11
```
- Only 22/tcp open; all other ports filtered.
- OpenSSH 8.9p1 Ubuntu (Ubuntu 22.04), patched, no CVEs flagged.
- My own scanner reproduced this: 22 OPEN, the rest filtered.

---

## 5. Technical analysis

**Connect scan vs SYN scan over Tailscale.** My TCP connect scan matched
nmap on the real target (22 open). The SYN scan, however, reported
everything filtered. Root cause: Tailscale routes traffic in userspace over
a TUN interface, so scapy's raw packets and their replies bypass what the
connect scan (which uses the OS network stack) can see. This is a genuine
environment limitation worth knowing: raw-socket scanning is unreliable
through a userspace VPN tunnel, while connect scans stay accurate.

**Port states in practice.** The target showed one open port and hundreds of
filtered ones — filtered meaning the firewall drops packets silently rather
than replying (as opposed to closed, where the host actively refuses). Seeing
this live made the three-state distinction concrete.

---

## 6. Findings & recommendations (recon-level)

- Minimal exposed surface on 192.168.20.11 (only SSH) is good practice.
- The remaining attack surface is authentication: a patched SSH service means
  password strength / key policy is what matters.

Recommendations for the Blue Team:
- SSH key-based auth, disable password login where possible
- strong password policy if passwords are kept
- fail2ban or rate-limiting to slow brute-force attempts
- keep the exposed surface minimal (current state is already sound)

---

## 7. What I learned

- How TCP connect vs SYN scans work at the packet level, and why the state
  (open/closed/filtered) depends on what comes back.
- Why an environment (a userspace VPN) can change which tools give correct
  results — a debugging lesson as much as a networking one.
- How to structure a small Python tool cleanly (modules, type hints, error
  handling) rather than one long script.

---

## 8. Exploitation Phase (Target: 100.66.55.46)
Following the initial network reconnaissance, the analysis was extended to the host 100.66.55.46 to evaluate its application and system attack surface.

### 8.1 Service Enumeration

MinIO (9000/tcp): Object storage service identified. Connection attempts using default credentials (minioadmin) were unsuccessful; however, the service confirmed its active status via an HTTP 400 Bad Request error during curl requests.

Splunk (8000/tcp) & Golang App (44359/tcp): Web interfaces were identified, significantly expanding the application attack surface.

### 8.2 Initial Access

Attack Vector: SSH service (port 22).

Tooling: hydra (brute-force dictionary attack).

Result: Discovery and validation of default credentials (admin / admin).

## 9. Post-Exploitation & Data Exfiltration
Following the successful initial access (ssh admin@100.66.55.46), the following actions were conducted to assess the impact of the compromise:

System Enumeration: Exploration of the environment with admin user privileges.

Exfiltration: Discovery of the hidden .aws/ directory in the user home folder.

Critical Finding: Read access to the configuration file (cat .aws/credentials) revealed AWS keys in plaintext:

aws_access_key_id = AKIAZ4NRGGZUBS4RDR3V

region = us-east-2

Impact: This discovery allows for direct privilege escalation to the target's Cloud infrastructure (AWS), providing potential programmatic access to storage buckets (S3) or server management (EC2).

## 10. Findings & Recommendations (Update)
The audit revealed critical flaws that extend beyond simple network configuration.

Identified Vulnerabilities:

Default Credentials (CWE-521): The use of a trivial password for the privileged admin account allowed for immediate system compromise.

Cleartext Storage of Secrets (CWE-312): The presence of Cloud keys on disk compromises the integrity of the AWS infrastructure.

Recommendations for the Blue Team:

Immediate Rotation: Revoke and regenerate the compromised AWS access key (AKIAZ4NRGGZUBS4RDR3V) via the IAM console.

Secret Management: Prioritize the use of IAM Roles attached directly to EC2 instances instead of storing static credentials files on disk.

Hardening: Disable password authentication on the SSH service in favor of strict public key authentication.

Supervision: Analyze logs for MinIO and SSH services to detect brute-force attempts conducted during the reconnaissance phase.

## 11. What I learned (Updated)

Chain of Vulnerabilities: A basic lack of IT hygiene (default password) very often serves as a pivot to critical infrastructure compromise (Cloud key leakage).

Cloud Security Perimeter: Security does not end at network firewalls; Identity and Access Management (IAM) and secret protection are the true bulwarks in an AWS environment.

Tooling Strategy: Combining targeted automation (hydra) with discrete manual enumeration (ls -la, cat) is more effective and stealthy than relying solely on massive automated scanners.

## Phase 1 & 2: Log Investigation & Forensic Analysis
### 1. Initial Methodology and Challenges
The initial approach was broad and lacked technical focus. I began by attempting to brute-force a discovery using a recursive grep for the "CTF" string across the entire /var/log/ directory.

Obstacles Encountered: This immediately triggered a wave of "Permission denied" errors, as many critical system logs are owned by root.

Failed Iterations: I attempted to bypass restricted directories using sudo and tried to cd into directories like /var/log/auth (which was actually a file, not a directory). My efforts to manipulate the environment were fragmented and lacked a systematic audit trail.

Outcome: Despite these aggressive attempts, the standard logs contained too much "noise" and administrative overhead to reveal the flag through simple keyword searches.

### 2. The Unintended Discovery
During the investigation, I accessed the .bash_history file in the user's home directory. This file contained the exact commands used by the system administrator (the professor) to set up the challenge.

The Shortcut: The history log clearly displayed the commands:

Bash
echo "CTF{l0g_h4nt1ng_1s_th3_w4y}" | sudo tee /opt/splunkforwarder/etc/auth/.sys_audit_report.conf
echo "... target audit: Suspicious file access attempt..." | sudo tee -a /var/log/auth.log
Result: By reading the history, I retrieved the flag CTF{l0g_h4nt1ng_1s_th3_w4y} and identified the file path /opt/splunkforwarder/etc/auth/.sys_audit_report.conf.

### 3. Critical Reflection (Methodological Critique)
I consider this a failure of methodology. Using .bash_history is functionally equivalent to cheating; it bypasses the forensic logic the challenge is designed to teach. Relying on the administrator's previous commands provides the answer without understanding the underlying system compromise.

### 4. The Correct Procedural Approach (Intended Logic)
To solve this without relying on command history, one must filter the log noise to identify the injected audit event. The /var/log/auth.log file is too voluminous to search manually, and a simple grep for "CTF" ignores the context of the breach.

The correct technical workflow is as follows:

Isolate the Anomaly: Instead of searching for the flag, search for "Suspicious" activity markers. This filters out the background noise of standard system authentication logs.

Bash
grep -i "Suspicious" /var/log/auth.log
Analyze the Output: This command would return the audit line:
target audit: Suspicious file access attempt in /opt/splunkforwarder/etc/auth/.sys_audit_report.conf

Path Traversal: This log entry provides the exact location of the compromised file (/opt/splunkforwarder/etc/auth/.sys_audit_report.conf).

Hidden File Enumeration: Since the file starts with a dot (.), it is hidden from standard ls commands. The correct action is to use ls -la to identify the file:

Bash
ls -la /opt/splunkforwarder/etc/auth/
Retrieval: Once identified, accessing the file with sudo cat would reveal the flag.

Summary: The challenge was not about finding "CTF"; it was about identifying an injected audit log entry that acted as a breadcrumb. Future investigations should prioritize searching for "indicators of compromise" (terms like suspicious, failed, unauthorized) over searching for the final answer string.
