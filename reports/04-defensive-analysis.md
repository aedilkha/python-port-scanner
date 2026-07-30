# Defensive Analysis Report

**Project:** Red vs Blue CTF (BeCode)
**Role:** Red Team
**Target:** `192.168.20.11`, the Blue Team "Bank of Belgium" server

This report looks at our own attack from the defender's side: what our scan looks
like in the logs, how a Blue Team would catch it, and what they should do to make
it harder. It is based on our own Wireshark capture plus what the Blue Team's
monitoring actually caught during the exercise.

---

## 1. What our scan looks like in the logs

From our capture (`scan_capture.pcap`, about 1183 packets):

The ping (host discovery):
```
100.95.28.3 -> 192.168.20.11   ICMP Echo request   (once a second, 4 times)
```
Just checking the host is alive.

The port scan: a burst of SYN packets to ports 1, 2, 3, 4 and up, in order, from
one machine, within milliseconds.
- Open ports (22 and 443): full handshake, then closed straight away.
- Filtered ports (998 of them): SYN sent, no reply.

What stands out:
- one source IP hitting hundreds of ports in seconds,
- lots of SYNs but almost no real sessions,
- connections that open and close instantly,
- attempts on ports nobody uses (1, 2, 3).

No normal traffic looks like this.

---

## 2. How a Blue Team detects it

On the network:
- An IDS like Snort or Suricata has ready-made rules for "one host, many ports,
  short time". Our scan matches them instantly.
- Rate limits: counting new connections per source per minute, our rate (hundreds
  a second) is clearly not human.
- Half-open connections: watching for connections that never carry data flags our
  scan.

On the application (this is what actually caught us):
The Blue Team did not only watch the network. They planted traps in the app, and
we triggered three of them:
- `config.json` (fake credentials): reading it was logged.
- `database.sqlite3` (fake data): downloading it was logged.
- `/admin` (fake login): our injection attempts and password guesses were logged,
  including the usernames and password lengths we typed.

All three fed their monitoring (ARGUS/SOC) with a threat score. The lesson: you
do not only get caught on the wire. A quiet scan still gets you the moment you
touch bait inside the app.

In the web server logs:
The same client asking for `/config.json`, `/backup/*`, `/admin` and dozens of
pages back to back reads as a bot enumerating the site, not a person browsing.

---

## 3. We got caught: honest debrief

We were detected. Being straight about it:
- We avoided the `/security` decoy page, which was good.
- But we tripped three other traps (config.json, backup, /admin), each scored
  against us.
- A TCP connect scan is the loudest kind. It completes full handshakes, which are
  easy to log. A SYN scan (never finishing the handshake) would have been a bit
  quieter, but the rate alone would still have flagged us.

Real-world takeaway: if a finding looks too easy, assume it might be bait. Check
before you act, and do not touch anything that looks wired up to alert.

---

## 4. What the Blue Team should do (mitigations)

Based on how we attacked:

Network:
1. Rate-limit new connections per source (iptables `recent`, or fail2ban) to slow
   scans down.
2. Run an IDS with port-scan rules to alert on SYN bursts from one host.
3. Drop, do not reject. Silent filtering tells the attacker less than a RST. Our
   capture proved the filtered ports gave us nothing.
4. Only expose the ports you actually need. Here just 22 and 443 answered, which
   is already good.

Application:
5. Alert on any hit to trap paths (`/config.json`, `/backup/*`, fake admin). A
   real user never touches them, so any hit is almost certainly an attacker.
6. Keep the honeypots. They are cheap and give a strong signal.
7. Lock out repeated failed logins on the real login.
8. Pull network, web and auth logs into one view so enumeration is easy to spot.

General:
9. Know what normal traffic looks like, so a scan stands out.
10. Alert on a ping followed by a burst of TCP connections from the same host,
    which is exactly the pattern our scan made.

---

## 5. Conclusion

Our recon did its job. It found 22/ssh and 443/https and led us to the web app and
its real vulnerabilities. But it was not quiet: the scan is loud on the network,
and the app's honeypots caught us as soon as we touched the bait. The main lesson
is that layered detection wins. Network scan detection plus app-level traps
together make an attacker very hard to hide, even when the individual steps seem
to be working.