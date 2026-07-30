# Architecture

A three-host lab: the attacker, the victim, and the monitoring stack are separate
machines. That separation is the point — detection has to survive a real network hop,
agent enrollment, and a round-trip before it can act.

> **Addressing note.** All addresses in this repository are placeholders
> (`<attacker-ip>`, `<victim-ip>`, `<manager-ip>`). The lab ran on real private
> subnets; live addresses and hostnames are redacted throughout.

---

## 1. Topology

```mermaid
flowchart LR
    subgraph ATK["ATTACKER — macOS host"]
        H["hydra<br/>10-entry wordlist<br/>(correct password included)"]
    end

    subgraph VIC["VICTIM + AGENT — Kali ARM64"]
        SSHD["sshd<br/>OpenSSH 9.x"]
        JD["journald"]
        AG["Wazuh agent"]
        IPT["iptables<br/>DROP chain"]
        PAM["pam_faillock"]
        AUD["auditd"]
    end

    subgraph MGR["MANAGER — Ubuntu"]
        AND["wazuh-analysisd<br/>decoders + rules"]
        ARS["active response<br/>firewall-drop"]
        IDX["indexer + dashboard"]
    end

    H -->|"SSH auth attempts :22"| SSHD
    SSHD --> JD
    JD --> AG
    AG -->|"encrypted events :1514"| AND
    AND -->|"rule 100100 fires"| ARS
    ARS -->|"command back to agent"| IPT
    IPT -.->|"DROP source for 600s"| H
    SSHD --> PAM
    SSHD --> AUD
    AND --> IDX
```

| Role | OS | Runs | Why it matters |
|------|----|------|----------------|
| **Attacker** | macOS host | `hydra` | Generates the attack from a genuinely separate host |
| **Victim / Agent** | Kali (ARM64) | `sshd`, Wazuh agent, `pam_faillock`, `auditd`, `iptables` | Both the target *and* where enforcement executes |
| **Manager** | Ubuntu | Wazuh manager, indexer, dashboard | Decoding, correlation, and the active-response decision |

Network requirement: a **private NAT / host-only network** with pinned IPs. A bridged
LAN with client isolation blocks attacker→victim port 22 while leaving the outbound
agent→manager path working — which fails in a confusing, asymmetric way.

---

## 2. Log and decision pipeline

Where a single failed login goes, and where it turns into enforcement.

```mermaid
flowchart TD
    A["Failed SSH login on victim"] --> B["sshd writes to journald"]
    B --> C["Wazuh agent journald localfile<br/>(single collector — NOT auth.log too)"]
    C --> D["Agent to manager over :1514, encrypted"]
    D --> E["wazuh-analysisd"]
    E --> F["Built-in sshd decoder<br/>extracts srcip, dstuser"]
    F --> G["Rule 5760<br/>sshd: authentication failed"]
    G --> H{"3 failures from the<br/>same srcip within 120s?"}
    H -->|"no"| I["Logged only<br/>level 5, no action"]
    H -->|"yes"| J["Rule 100100 fires<br/>level 10"]
    J --> K["Active response<br/>firewall-drop"]
    K --> L["Alert 651<br/>Host blocked by firewall-drop"]
    K --> M["iptables DROP on agent<br/>timeout 600s"]

    style J fill:#c0392b,color:#fff,stroke:#7b241c
    style M fill:#1e8449,color:#fff,stroke:#145a32
    style I fill:#7f8c8d,color:#fff,stroke:#515a5a
```

The single most important detail: **only one collector.** Adding an `/var/log/auth.log`
localfile alongside journald double-ingests every failure, so a `frequency=3` rule trips
after roughly two real attempts.

---

## 3. Two independent enforcement layers

Active response is **reactive** — it fires only after the event reaches the manager and
the command travels back. That round-trip is why one layer is not enough.

```mermaid
flowchart TD
    ATK["Attacker: continued<br/>SSH attempts"]

    subgraph NET["LAYER 1 — Network (reactive)"]
        direction TB
        N1["Wazuh active response"]
        N2["iptables DROP on victim<br/>600s timeout"]
        N3["Packets never reach sshd"]
        N1 --> N2 --> N3
    end

    subgraph ACC["LAYER 2 — Account (pre-emptive)"]
        direction TB
        A1["pam_faillock: deny=3"]
        A2["Account 'demo' locked<br/>unlock_time 600s"]
        A3["preauth denies BEFORE<br/>the password is checked"]
        A4["Correct password is<br/>STILL refused"]
        A1 --> A2 --> A3 --> A4
    end

    ATK --> NET
    ATK --> ACC
    NET --> R["hydra reports:<br/>0 valid password found"]
    ACC --> R

    style ACC fill:#1a5276,color:#fff
    style NET fill:#7e5109,color:#fff
    style R fill:#c0392b,color:#fff
```

| | Layer 1 — network | Layer 2 — account |
|---|---|---|
| Mechanism | Wazuh active response → `iptables` | `pam_faillock` |
| Runs on | Victim (pushed by manager) | Victim (local, standalone) |
| Timing | **Reactive** — after manager round-trip | **Pre-emptive** — evaluated in the auth path |
| Scope | Blocks that source IP entirely | Locks that account from any source |
| Depends on Wazuh? | Yes | **No** — survives manager outage |
| Duration | 600s (`<timeout>`) | 600s (`unlock_time`) |

Because `pam_faillock`'s `preauth` module runs *before* `pam_unix` evaluates the
password, a locked account rejects even valid credentials. That is what makes the demo
conclusive: the correct password sits in the attacker's wordlist and is never confirmed.

---

## 4. Signals to look for

| ID | Source | Meaning |
|----|--------|---------|
| `5760` | Built-in sshd ruleset | Single failed authentication |
| `100100` | `rules/local_rules.xml` | **Custom** — 3 failures, same source IP, 120s |
| `651` | Active-response ruleset | Host blocked by `firewall-drop` |

Dashboard filter:

```
rule.id:(5760 OR 100100 OR 651)
```

The custom rule itself lives in [`rules/local_rules.xml`](../rules/local_rules.xml).
