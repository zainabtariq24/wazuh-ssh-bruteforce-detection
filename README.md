# Wazuh SSH Brute-Force Detection & Prevention

A hands-on blue-team lab: detect an SSH brute-force attack with Wazuh and prevent it
at **two independent layers** — network (iptables via active response) and account
(pam_faillock) — with auditd for forensics. Built on a real distributed setup, not a
single-box tutorial.

## Architecture

```
   Attacker (macOS)        Victim + Agent (Kali)          Manager (Ubuntu)
   ┌──────────────┐  SSH x3  ┌──────────────────────┐  1514  ┌──────────────────┐
   │ hydra ───────┼─────────►│ sshd → journald      │───────►│ Wazuh manager    │
   │              │◄──DROP───┤ Wazuh agent          │◄───────┤ rule 100100 fires│
   │              │          │ firewall-drop→iptables│ ◄tells │ → firewall-drop  │
   └──────────────┘          │ pam_faillock lock    │  agent └──────────────────┘
                             │ auditd records       │
                             └──────────────────────┘
```

- **Manager**: Ubuntu — Wazuh manager + indexer + dashboard, detection rule, active response
- **Agent/Victim**: Kali (ARM64) — sshd, pam_faillock, auditd; the iptables block executes here
- **Attacker**: macOS host — hydra

## How it works

1. Kali's sshd logs are collected via **journald** and forwarded to the manager.
2. Failed logins decode with the built-in `sshd` decoder and classify as rule **5760**.
3. Custom rule **100100** fires when **3 failures from one source IP** occur within 120s.
4. Rule 100100 triggers two controls:
   - **Network**: Wazuh active response `firewall-drop` → iptables DROP of the attacker
     IP on the agent for 600s (alert **651**).
   - **Account**: `pam_faillock` locks the `demo` account after 3 failures for 600s.
     While locked, `preauth` denies every attempt *before* the password is checked —
     so even a **correct** password is refused.
5. **auditd** keeps an independent record of the failed authentications.

Result: during a hydra run, the correct password is present in the wordlist but is
**never confirmed** — the account locks and the IP is blocked before hydra reaches it.

## Key IDs

| ID | Meaning |
|----|---------|
| 5760 | sshd: authentication failed (single event) |
| 100100 | SSHD brute force: 3 failed attempts (custom rule) |
| 651 | Host blocked by firewall-drop (active response) |

Dashboard filter: `rule.id:(5760 OR 100100 OR 651)`

## Repo layout

```
rules/local_rules.xml                     # detection rule 100100  (manager)
decoders/local_decoder.xml                # optional additive decoder (manager)
manager-ubuntu/ossec-active-response...   # active-response block   (manager)
agent-kali/faillock.conf                  # lockout policy          (agent)
agent-kali/common-auth.auth-section       # PAM wiring              (agent)
agent-kali/ssh-forensics.rules            # auditd rules            (agent)
attack/wordlist.txt, run-attack.sh        # the attack              (attacker)
docs/RUNBOOK.md                           # full step-by-step build + verify
docs/LESSONS.md                           # what broke and how it was fixed
```

## Quick start

See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the full build. Short version:
deploy `rules/` + active-response on the manager, deploy `agent-kali/` files on Kali,
then from the attacker: `./attack/run-attack.sh <victim-ip>`.

## Notes

Educational lab, isolated network. The "attack" targets a throwaway `demo` account on
a VM you control. See [`docs/LESSONS.md`](docs/LESSONS.md) for the real debugging story
(SID mismatch, journald vs auth.log, XML pitfalls, VM networking).

## License

MIT
