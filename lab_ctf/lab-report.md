# Lab Report — Red Team CTF: Break-In & Forensic Trail

**Project:** Red vs Blue CTF (Hamilton cohort)
**Role:** Red Team
**Author:** Alvi
**Target:** 100.66.55.46

---

## 1. Objective

Authorized lab exercise set up by the coach. Two connected goals:
1. **Break in** — scan the target, brute-force SSH, gain a shell.
2. **Investigate** — locate secrets on the host, then trace a flagged
   "suspicious" log entry to recover the forensic flag `CTF{...}`.

All actions performed against the coach's designated lab host over the
project Tailscale VPN.

---

## 2. Environment

- Attacker box: Kali Linux (Python 3.13, nmap, hydra)
- Target reached over the lab Tailscale VPN
- Custom Python scanner used alongside nmap

---

## Phase 1 — Break In

### 3.1 Port scan / service enumeration

`nmap -sV -p- 100.66.55.46`:

| Port      | Service                    |
|-----------|----------------------------|
| 22/tcp    | OpenSSH 9.6p1 (Ubuntu)     |
| 8000/tcp  | Splunkd httpd              |
| 8080/tcp  | HTTP                       |
| 8088/tcp  | Splunkd httpd (ssl)        |
| 9000/tcp  | MinIO (object storage)     |
| 9997/tcp  | Splunk forwarder           |
| 44359/tcp | Golang net/http            |

- **MinIO (9000):** object-storage service; default `minioadmin` login was
  unsuccessful, service confirmed live via HTTP 400 on malformed requests.
- **Splunk (8000) & Golang app (44359):** web interfaces, broadening the
  application attack surface.
- **SSH (22):** selected entry point per the brief.

> Tooling note: my Python scanner reported all ports filtered on this target
> while nmap saw them open. Cause: traffic runs over Tailscale's userspace TUN
> interface, which raw-socket tooling can't observe the same way the OS network
> stack (used by nmap's connect probing) can. A documented limitation of
> scanning through a userspace VPN, and a useful result in itself.

### 3.2 Initial access

Dictionary brute-force of the SSH login (simple password per the hint):

```
hydra -L usernames.txt -P passwords.txt -t 4 -o hydra-results.txt ssh://100.66.55.46
```

Valid credentials recovered (`admin` / `admin`), SSH session established with
user privileges.

---

## Phase 2 — Secrets Enumeration

With a shell as `admin`:

- Enumerated the filesystem and the user's home directory.
- Found a hidden `.aws/` directory containing a `credentials` file.
- The file stored AWS keys in plaintext:

```
aws_access_key_id = AKIA**************** (masked)
region             = us-east-2
```

> The key value is masked in this report as a matter of practice — secrets,
> real or lab, are never published in cleartext in a deliverable that lands in
> a Git repository. The finding is the plaintext storage itself, not the exact
> characters.

**Impact:** cloud credentials sitting readable on disk mean a host compromise
can pivot to the AWS environment (e.g. S3/EC2), turning a single weak SSH
password into a path to cloud infrastructure.

---

## Phase 3 — Forensic Investigation (flag recovery)

### 4.1 First approach and dead ends

Initial approach was too broad: recursive `grep` for "CTF" across
`/var/log/`. Result: mostly "Permission denied" (root-owned logs) and too
much noise. Lesson learned — search for the *anomaly*, not the answer string.

### 4.2 Correct workflow — following the breadcrumb

1. **Isolate the anomaly** — search for the "suspicious" marker rather than
   the flag:
   ```
   grep -i "suspicious" /var/log/auth.log
   ```
   Returns the injected audit line naming a file path.

2. **Trace the path** — the entry points to
   `/opt/splunkforwarder/etc/auth/.sys_audit_report.conf`.

3. **Enumerate the hidden file** — leading `.` hides it from plain `ls`:
   ```
   ls -la /opt/splunkforwarder/etc/auth/
   ```

4. **Retrieve** — restricted location, elevated read needed:
   ```
   sudo cat /opt/splunkforwarder/etc/auth/.sys_audit_report.conf
   ```

**Flag recovered:** `CTF{l0g_h4nt1ng_1s_th3_w4y}`

### 4.3 Methodological note

I first found the flag by reading `.bash_history` (it held the setup
commands). I count that as a shortcut, not a solution — it bypasses the
forensic reasoning the challenge teaches. The workflow in 4.2 is the intended
path: spot an indicator of compromise (`suspicious`, `failed`, `unauthorized`)
and let it lead to the artifact.

---

## 5. Findings & Recommendations

Identified weaknesses:

- **Default credentials (CWE-521):** trivial password on a privileged account
  → immediate compromise.
- **Cleartext storage of secrets (CWE-312):** AWS keys readable on disk →
  potential pivot to cloud infrastructure.

Recommendations for the Blue Team:

- **Rotate** any exposed AWS key via the IAM console; treat it as burned.
- **Secret management:** prefer IAM roles attached to instances over static
  credential files on disk; use a secrets manager.
- **SSH hardening:** key-based auth, disable password login; add fail2ban /
  rate limiting.
- **Monitoring:** analyze SSH and MinIO logs for the brute-force pattern —
  the very trail this exercise is built on.

---

## 6. What I Learned

- **Chain of vulnerabilities:** a basic hygiene failure (default password) is
  rarely the whole story — it's the pivot that exposes everything behind it
  (here, cloud keys).
- **Cloud perimeter:** security doesn't stop at the network firewall; IAM and
  secret protection are the real controls in an AWS environment.
- **Forensics = search for the anomaly:** filtering for indicators of
  compromise beats grepping for the answer string.
- **Hidden + restricted files:** `ls -la` for dotfiles, and knowing when
  elevated privileges are legitimately required to read an artifact.
- **Tooling has limits:** scanner vs nmap through Tailscale showed the
  environment can decide which tool gives correct results.