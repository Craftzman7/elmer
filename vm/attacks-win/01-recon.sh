#!/usr/bin/env bash
# Stage 1 — recon from the attacker box. Nothing executes on the target,
# which is exactly the point: a host monitor only sees what runs on the
# host. Detections start at stage 2.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need nmap "brew install nmap / apt install nmap"

say "scanning $TARGET from the attacker box"
nmap -sV -p 22,80,445,3389,5985 "$TARGET"

note "expected on the target: silence — nmap against the box never runs there."
note "SSH on 22 and the IIS injection on 80 are the ways in; detections start at stage 2."
