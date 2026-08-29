#!/usr/bin/env bash
# The full attack chain against the vm/ test target. Start the blue-team
# view first, in another terminal:
#   vagrant ssh -c 'sudo journalctl -u elmer -f'
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh

say "attack chain against $TARGET (attacker: $HOST_IP)"
for stage in 01-recon 02-foothold-redis 03-foothold-web 04-privesc 05-persist 06-c2; do
  printf '\n\033[1;35m### stage %s\033[0m\n' "$stage"
  bash "$stage.sh"
  sleep 3
done
say "chain complete"
note "keep watching journalctl: the cron beacon re-fires download-exec"
note "every 2 minutes, and the persistence sweep reports within 5."
note "alt-bruteforce.sh is the optional SSH-spray demo, run it by hand."
