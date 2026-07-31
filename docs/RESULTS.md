# Results

What the lab actually produced, taken from the captured alert output.

> All addresses are placeholders. Redaction policy: [`evidence/README.md`](../evidence/README.md)

---

## 1. The claim under test

> A wordlist containing the **correct** password, run against a monitored host, still fails.

If detection and prevention work, `hydra` never confirms a credential it demonstrably
possesses. That is a falsifiable outcome rather than a screenshot of an alert.

Setup: account `demo`, password `CorrectHorse!42`, sitting at **line 8** of a 10-entry
wordlist. Attack run as `hydra -l demo -P wordlist.txt -t 4 ssh://<victim-ip>`.

---

## 2. Timeline of one run

Reconstructed from `evidence/alerts-sample.json`:

```mermaid
sequenceDiagram
    autonumber
    participant A as hydra on attacker
    participant P as pam_faillock on victim
    participant S as sshd on victim
    participant M as Wazuh manager
    participant F as iptables on victim

    A->>S: attempt 1 — "password"
    S->>P: authfail, count 1/3
    S->>M: 5760 (level 5, logged)

    A->>S: attempt 2 — "123456"
    S->>P: authfail, count 2/3
    S->>M: 5760 (level 5, logged)

    A->>S: attempt 3 — "admin"
    S->>P: authfail, count 3/3
    Note over P: ACCOUNT LOCKED — 600s
    S->>M: 5760 (level 5, logged)

    Note over M: 3 failures, same srcip, within 120s
    M->>M: RULE 100100 FIRES (level 10) @ 06:45:01.597

    A->>S: attempts 4-7 — "letmein", "qwerty", "root", "toor"
    S->>P: preauth check
    P-->>A: DENIED before password evaluated

    M->>F: firewall-drop dispatched
    F->>F: DROP <attacker-ip>, 600s
    M->>M: ALERT 651 @ 06:45:03.617
    Note over F: source now blocked at network layer

    A->>S: attempt 8 — "CorrectHorse!42" (CORRECT)
    Note over F,S: packet dropped; had it arrived,<br/>preauth would have refused it anyway
    A->>A: reports 0 valid password found
```

Two independent reasons attempt 8 fails:

1. **Account layer** — `demo` locked at attempt 3. `preauth` refuses before the password is evaluated, so correctness is never assessed.
2. **Network layer** — `<attacker-ip>` dropped at 06:45:03. The packet does not reach `sshd`.

Layer 2 engaged at attempt 3; layer 1 at attempt ~7. The account lock is what closes the
gap the reactive control leaves open.

---

## 3. Measured outcome

| Metric | Value | Source |
|--------|-------|--------|
| Failures needed to trigger detection | **3** | `rule.frequency` on `100100` |
| Correlation window | **120s** | `rule.timeframe` |
| Detection latency (3rd failure → `100100`) | **sub-second** | `alerts-sample.json` |
| Enforcement latency (`100100` → `651`) | **~2.0s** | 06:45:01.597 → 06:45:03.617 |
| Account lock duration | **600s** | `unlock_time` |
| Network block duration | **600s** | `<timeout>` |
| Correct password confirmed by hydra | **No** | hydra: `0 valid password found` |
| False positives during the run | **0** | no `100100` without 3 same-source failures |

The ~2s enforcement latency is the headline number: it is small, non-zero, and it is
precisely the interval that justifies the second control.

---

## 4. Alerts produced

```
rule.id:(5760 OR 100100 OR 651)
```

| ID | Level | Count per run | Meaning |
|----|-------|---------------|---------|
| `5760` | 5 | 3 per window | Individual sshd auth failure |
| `100100` | 10 | 1 per window | **Custom** — correlated brute force |
| `651` | 3 | 1 per detection | Host blocked by `firewall-drop` |

The compression is the value: ten attack attempts collapse into **one** level-10 alert an
analyst needs to look at, with the source address already attributed.

### `same_source_ip` verified

The run was repeated from a second source address. Each produced its own independent
`100100` (`firedtimes` 1 and 2) with its own `651` — confirming windows are tracked per
source, not pooled. Without `same_source_ip`, three unrelated single failures inside 120s
would trigger a false detection, which on any real host is routine background noise.

---

## 5. Host-side confirmation

```bash
# [VICTIM] account lock recorded — 3 failures, Valid = V
sudo faillock --user demo

# [VICTIM] the DROP rule exists
sudo iptables -L INPUT -n | grep <attacker-ip>

# [VICTIM] the agent executed the action
sudo tail -n 20 /var/ossec/logs/active-responses.log

# [VICTIM] independent forensic record
sudo ausearch -k exec_trace --start recent

# [MANAGER] both alert classes present
sudo tail -n 80 /var/ossec/logs/alerts/alerts.json \
  | jq -c 'select(.rule.id=="100100" or .rule.id=="651")
           | {id: .rule.id, srcip: .data.srcip}'
```

Both controls also auto-revert after 600s, so the lab is repeatable without manual cleanup —
though `faillock --user demo --reset` and `iptables -F` make iteration faster.

---

## 6. Honest limitations

Worth stating plainly, because a lab that claims too much is less credible than one that
scopes itself:

- **Threshold is aggressive.** 3 failures in 120s would generate false positives on a host with real users fat-fingering passwords. Production tuning means raising the count, widening the window, and excluding known-good sources.
- **A slow attack evades this.** Four attempts per hour never fills a 120s window. Catching low-and-slow needs a longer-window rule alongside this one.
- **Source rotation defeats layer 1.** A botnet with a fresh IP per attempt never accumulates three failures from one source. The account lock still holds, which is the argument for layering.
- **Single account tested.** Password *spraying* — one attempt against many accounts — is the inverse pattern and is not detected by this rule at all. It needs `same_source_ip` with a different grouping.
- **No distributed test.** Load and multi-agent behaviour were not measured; this is a three-host lab.

Reproduction steps: [`RUNBOOK.md`](RUNBOOK.md) · Detection internals: [`DETECTION.md`](DETECTION.md) · Controls: [`PREVENTION.md`](PREVENTION.md)
