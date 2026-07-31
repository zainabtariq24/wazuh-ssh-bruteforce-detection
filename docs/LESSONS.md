# Lessons learned — what actually broke

The value of a real lab is in what doesn't go to plan. Five issues cost real time and
each has a generalizable fix.

## 1. The SID mismatch (5716 vs 5760)
The common tutorials build the brute-force rule on top of SID **5716** ("sshd:
authentication failed"). On this build (Kali + modern OpenSSH logging via journald),
real failed logins classify as **5760** instead. A rule matching 5716 therefore *never
fired*. **Lesson:** never trust the SID from a tutorial — confirm the actual rule ID
your own failures produce (check `alerts.json` or `wazuh-logtest`) before building a
frequency rule on it.

## 2. journald vs /var/log/auth.log (double counting)
This agent collects logs via **journald**, not `/var/log/auth.log`. Adding an
`auth.log` localfile "to be safe" meant every failure was ingested twice, which would
trip a `frequency=3` rule after ~2 real attempts. **Lesson:** confirm the single log
source before adding collectors; more inputs is not more signal.

## 3. Nested `<group>` crashes the manager
Pasting the custom rule *inside* the `<group>` that `local_rules.xml` already opens
produced `'group' is not a valid element` and the manager refused to start. **Lesson:**
always `wazuh-analysisd -t` before restarting the manager; a bad ruleset takes the
whole manager down, not just the new rule.

## 4. modern OpenSSH logs as `sshd-session`
OpenSSH 9.x splits the daemon into a per-session `sshd-session` process, so log lines
carry that program name. Wazuh's sshd decoder still matched (its prematch is
prefix-flexible), but it's a gotcha worth knowing when writing custom decoders.

## 5. VM networking: bridged + client isolation
The VMs were bridged onto a campus LAN with client isolation, so the attacker could not
reach the victim's port 22 (`no route to host` / `operation timed out`) even though the
Wazuh agent→manager path worked (outbound). **Lesson:** for a self-contained attacker
→victim lab, use a private NAT/host-only network you control, and pin the IPs so they
survive reboots.

## Bonus: active response is not prevention on its own
Wazuh active response is *reactive* — it fires after the alert round-trips. The account
lock (pam_faillock) is what guarantees "correct password still refused"; the iptables
block adds a network layer. Layering both is the point.
