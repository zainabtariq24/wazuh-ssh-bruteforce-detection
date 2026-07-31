# Runbook — build & verify

Roles: **Manager** = Ubuntu, **Agent/Victim** = Kali, **Attacker** = macOS.
Use a private NAT network and pin the IPs. Placeholders: `<victim-ip>`, `<manager-ip>`, `<attacker-ip>`.

## 1. Agent → manager (Kali)
Install the agent pointed at the manager, confirm it's Active on the manager
(`sudo /var/ossec/bin/agent_control -lc`). SSH logs are collected via journald
(confirm the `journald` localfile in the agent's `ossec.conf`; do NOT also add auth.log).

## 2. Target account (Kali)
```
sudo useradd -m -s /bin/bash demo
echo 'demo:CorrectHorse!42' | sudo chpasswd
```

## 3. Detection rule (Manager)
Copy `rules/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`, then:
```
sudo /var/ossec/bin/wazuh-analysisd -t          # must be clean
sudo systemctl restart wazuh-manager
```
Confirm the rule fires at 3: run 3 failed `ssh demo@<victim-ip>` and check
`alerts.json` for rule 100100. (Verify the SID: on this build failures are 5760.)

## 4. Active response (Manager)
Add `manager-ubuntu/ossec-active-response.snippet.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`, then `sudo systemctl restart wazuh-manager`.

## 5. Account lockout (Kali)
Set `agent-kali/faillock.conf` values in `/etc/security/faillock.conf`; wire
`agent-kali/common-auth.auth-section` into `/etc/pam.d/common-auth` (back it up first).
Keep a second root shell open while testing. Reset with `sudo faillock --user demo --reset`.

## 6. auditd (Kali)
```
sudo cp agent-kali/ssh-forensics.rules /etc/audit/rules.d/ssh-forensics.rules
sudo systemctl enable --now auditd && sudo auditctl -e 1
sudo augenrules --load && sudo auditctl -l
```

## 7. Attack (Attacker)
```
./attack/run-attack.sh <victim-ip>
```

## 8. Verify
```
# [KALI]
sudo faillock --user demo                                 # 3 failures, Valid=V
sudo tail -n 20 /var/ossec/logs/active-responses.log
sudo iptables -L INPUT -n | grep <attacker-ip>            # the DROP rule
# [UBUNTU]
sudo tail -n 80 /var/ossec/logs/alerts/alerts.json | jq -c \
  'select(.rule.id=="100100" or .rule.id=="651") | {id:.rule.id, srcip:.data.srcip}'
```

## 9. Reset between runs (Kali)
```
sudo faillock --user demo --reset
sudo iptables -F
```
