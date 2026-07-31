# Detecting and Preventing SSH Brute-Force with Wazuh — and the Five Things That Broke

*Draft — a walkthrough of building a real detection-and-prevention pipeline, and the debugging that tutorials skip.*

## Why this lab

SSH brute-forcing is the "hello world" of attack detection, which is exactly why most
write-ups of it are shallow: single box, copy-paste rule, screenshot, done. I wanted the
real version — a distributed Wazuh deployment where an attacker on one machine hits a
victim on another, gets detected, and gets *stopped* two different ways. What follows is
how it works, and — more usefully — the five things that broke on the way, because that's
where the actual learning was.

## The setup

Three roles: a **Wazuh manager** (Ubuntu) with the indexer and dashboard, a **victim**
(Kali) running the **Wazuh agent**, and an **attacker** (my Mac) running hydra. The victim
runs sshd; the agent ships its logs to the manager; the manager analyzes them and, on a
brute-force pattern, tells the agent to block the attacker.

## Detection: turning 3 failures into one alert

Wazuh ships a built-in `sshd` decoder, so individual failed logins are already parsed and
tagged with a source IP. The job of *detection* is correlation: recognizing that N
failures from one IP in a short window is an attack, not noise. That's a custom frequency
rule:

```xml
<rule id="100100" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SSHD brute force: 3 failed login attempts from same source IP</description>
</rule>
```

Three failures from one IP within 120 seconds → one high-level alert.

## Prevention: two layers, because one isn't enough

The subtle point most tutorials miss: **Wazuh active response is reactive.** It fires
*after* the alert reaches the manager and the command travels back to the agent. For a
small file over a fast link, the damage can be done by then. So prevention needs to be
layered:

- **Network layer** — the `firewall-drop` active response adds an iptables DROP for the
  attacker's IP on the victim, for 600 seconds. Fast, but reactive.
- **Account layer** — `pam_faillock` locks the targeted account after 3 failures. The
  important part: while locked, PAM's `preauth` check denies the attempt *before* the
  password is evaluated. So even the **correct** password is refused for the full window.

The demo payoff: I put the correct password *in* the attacker's wordlist. hydra still
reports "0 valid password found" — because by the time it reaches the right password, the
account is locked and the IP is blocked. The credential is present but useless.

## The five things that broke

**1. The SID was wrong.** Every tutorial builds this rule on SID 5716. On my build (modern
OpenSSH logging through journald) real failures came through as **5760**, so my rule
matched nothing and silently never fired. Fix: confirm the actual rule ID your own
failures produce before building on it. Don't trust the tutorial's SID.

**2. journald vs auth.log — double counting.** My agent collected logs via journald. When
I "helpfully" also added an `/var/log/auth.log` collector, every failure was ingested
twice, which would trip a `frequency=3` rule after ~2 real attempts. More inputs isn't
more signal.

**3. A nested XML tag took down the whole manager.** Pasting my rule inside the `<group>`
that `local_rules.xml` already opens produced `'group' is not a valid element`, and the
manager refused to start at all. Lesson burned in: always `wazuh-analysisd -t` before
restarting — a bad ruleset is a full outage, not a local error.

**4. OpenSSH now logs as `sshd-session`.** OpenSSH 9.x split the daemon into a per-session
process, so log lines carry a different program name. It happened to still decode, but
it's the kind of thing that quietly breaks custom decoders.

**5. The attacker couldn't reach the victim.** The VMs were bridged onto a network with
client isolation, so the attacker's SSH attempts timed out even though the agent→manager
path worked fine (that's outbound). Moving to a private NAT network I controlled — and
pinning the IPs so they survive reboots — fixed it.

## What I'd tell my past self

The detection rule is five lines. Everything hard was *environmental*: which SID, which
log source, which network path, which XML context. That's the actual skill in detection
engineering — not writing the rule, but making it fire reliably in a real environment and
proving it did. The next step is automating exactly that: generating and *validating*
these rules against real attack traffic, which is where I'm taking this next.

*Code and full runbook: [link to repo].*
