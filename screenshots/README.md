# Screenshots

## Redaction is mandatory

Screenshots from this lab show live internal IP addresses, hostnames and shell prompts
**baked into the image**, where find-and-replace redaction is impossible. `.gitignore`
therefore excludes `screenshots/*.png` and `*.jpg` by default.

Before committing any image:

1. Black out every octet of every IP address, in the terminal output **and** in dashboard
   fields (`agent.ip`, `data.srcip`, `rule.description`).
2. Black out hostnames — including the shell prompt, `predecoder.hostname`, and the
   manager name in the dashboard header.
3. Re-read the image at full size afterwards. Wazuh repeats `srcip` inside
   `rule.description`, `full_log` and `previous_output`, so it is easy to miss an instance.
4. Un-ignore that specific file explicitly, never the whole directory:

   ```gitignore
   !screenshots/100100-alert-redacted.png
   ```

Name files with a `-redacted` suffix so an unredacted image is obvious in `git status`.

## Shot list

The five images that carry the write-up:

| Shot | Shows | Redact |
|------|-------|--------|
| `100100` alert, expanded | Correlated detection with `frequency: 3` and the 3 underlying failures | `srcip`, `agent.ip`, `rule.description`, `full_log`, `previous_output` |
| `651` alert | "Host Blocked by firewall-drop Active Response" | `srcip`, `agent.ip`, manager name |
| `iptables -L INPUT -n` on the victim | The DROP rule created by active response | Source address column, shell prompt/hostname |
| `faillock --user demo` | 3 failures logged, `Valid = V` | Source address column, shell prompt/hostname |
| hydra output | `0 valid password found`, despite the correct password being in the wordlist | Target address in the hydra banner and per-attempt lines |

The last one is the payoff shot — it is the evidence that the credential was present and
still never confirmed.

## Alternative

Where redaction would obscure the point, the equivalent evidence is published as text in
[`../evidence/alerts-sample.json`](../evidence/alerts-sample.json), where placeholder
substitution is exact and reviewable.
