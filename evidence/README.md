# Evidence

Alert output from the live lab run, **hand-redacted** before publication.

## What is here

| File | Contents |
|------|----------|
| `alerts-sample.json` | Four alerts from one attack run: two `100100` detections and the two `651` enforcement alerts that followed |

## Redaction policy

The lab ran on real private subnets, so raw Wazuh output embeds live internal addresses and
hostnames. Every published artifact is redacted with a consistent mapping:

| Field | Real value | Published as |
|-------|-----------|--------------|
| `data.srcip` (attacker) | *redacted* | `<attacker-ip>`, `<attacker-ip-2>` |
| `agent.ip` (victim) | *redacted* | `<victim-ip>` |
| `predecoder.hostname` | *redacted* | `victim-kali` |
| `manager.name` | *redacted* | `wazuh-manager` |
| `agent.name` | *redacted* | `kali-agent` |

Process IDs, ports, alert IDs and timestamps are preserved — they carry no identifying
information and removing them would make the correlation timings unreadable.

**Nothing else from the raw capture is published.** The full `alerts.json`, dashboard
spreadsheet exports, terminal recordings and the report PDF all contain live addresses —
several of them baked into screenshots, where find-and-replace redaction is not possible.
Those files are excluded by `.gitignore` at the repository root and stay local.

## Format note

Wazuh writes `/var/ossec/logs/alerts/alerts.json` as **newline-delimited JSON** — one object
per line, no enclosing array. `alerts-sample.json` is reformatted as a pretty-printed array
with `_note` objects interleaved for readability. To work with the native format:

```bash
# what was actually run against the live file
sudo tail -n 80 /var/ossec/logs/alerts/alerts.json \
  | jq -c 'select(.rule.id=="100100" or .rule.id=="651")
           | {id: .rule.id, srcip: .data.srcip, desc: .rule.description}'
```

## Reading the sample

The interesting detail is the **timing**: alert `651` lands roughly two seconds after the
`100100` that triggered it. That gap is the active-response round-trip — agent to manager,
correlation, command back to agent — and it is the entire reason a second, pre-emptive
control (`pam_faillock`) is layered alongside the network block rather than relying on it
alone.

The two independent `100100` alerts, one per source address, also confirm `same_source_ip`
behaves correctly: each source accumulates its own window instead of being pooled into a
single count.
