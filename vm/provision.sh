#!/usr/bin/env bash
# provision.sh — turn a vanilla Ubuntu (22.04 or 24.04) box into an
# attackable elmer test target: weak accounts, a command-injection web app,
# a sudo misconfiguration, and elmer itself as a root systemd service.
#
# Vagrant runs this as root with the binary and elmer.yaml already
# uploaded to /tmp. On any other VM (Multipass, UTM, bare metal):
#   sudo bash provision.sh /path/to/elmer-linux-<arch>
set -euo pipefail

if [[ $EUID -ne 0 ]]; then exec sudo bash "$0" "$@"; fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BIN=""
for cand in "${1:-}" "${ELMER_BIN:-}" /tmp/elmer "/vagrant/dist/elmer-linux-$ARCH"; do
  if [[ -n $cand && -x $cand ]]; then BIN=$cand; break; fi
done
if [[ -z $BIN ]]; then
  cat >&2 <<EOF
elmer binary not found.
  build it:   make build-linux     (repo root)
  then run:   vagrant provision    (from vm/)
or pass it:   provision.sh /path/to/elmer-linux-$ARCH
EOF
  exit 1
fi

YAML=/tmp/elmer.yaml
[[ -f $YAML ]] || YAML=$SCRIPT_DIR/elmer.yaml
if [[ ! -f $YAML ]]; then
  echo "elmer.yaml not found (looked in /tmp and $SCRIPT_DIR)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Cloud images run unattended-upgrades shortly after boot and hold the apt
# lock, which makes first provisioning fail intermittently.
systemctl stop unattended-upgrades.service apt-daily-upgrade.service 2>/dev/null || true
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done

say "installing packages"
apt-get update -qq
# rsyslog guarantees /var/log/auth.log (24.04 drops it by default), which
# elmer's auth monitor prefers over journald. nmap/socat/sshpass are
# attacker conveniences for the demo chain (ncat comes with nmap).
apt-get install -y -qq nginx php-fpm rsyslog redis-server nmap socat sshpass >/dev/null
systemctl enable --now rsyslog >/dev/null

say "creating weak accounts"
id analyst >/dev/null 2>&1 || useradd -m -s /bin/bash analyst
id svc_backup >/dev/null 2>&1 || useradd -m -s /bin/bash svc_backup
echo 'analyst:Analyst2024!' | chpasswd
echo 'svc_backup:backup123' | chpasswd

say "planting flags"
echo 'flag{brut3_f0rc3_st1ll_w0rks}' > /home/svc_backup/flag.txt
chown svc_backup:svc_backup /home/svc_backup/flag.txt
chmod 0600 /home/svc_backup/flag.txt
echo 'flag{c0mm4nd_1nj3ct10n}' > /var/www/flag.txt
chown www-data:www-data /var/www/flag.txt
chmod 0640 /var/www/flag.txt
echo 'flag{gtf0b1ns_f1nd}' > /root/flag.txt
chmod 0600 /root/flag.txt

say "enabling SSH password authentication"
# sshd uses the first match for a keyword and includes sshd_config.d/* at
# the top of the main file, so 50- wins over cloud-init's 60- file.
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/50-elmer-lab.conf
systemctl restart ssh

say "adding the sudo misconfiguration (GTFOBins: find)"
printf 'www-data ALL=(root) NOPASSWD: /usr/bin/find\n' > /etc/sudoers.d/www-data-find
chmod 0440 /etc/sudoers.d/www-data-find
visudo -cf /etc/sudoers.d/www-data-find >/dev/null

say "installing the vulnerable web app"
cat > /var/www/html/index.php <<'EOF'
<?php $host = php_uname('n'); ?>
<!doctype html>
<html>
<head><title><?= $host ?> — service status</title></head>
<body style="font-family: monospace; max-width: 40em; margin: 4em auto;">
<h1><?= $host ?> service status</h1>
<ul>
  <li>nginx — serving this page</li>
  <li>nightly backups — handled by svc_backup</li>
  <li><a href="/ping.php">network diagnostics (ping)</a></li>
</ul>
</body>
</html>
EOF
cat > /var/www/html/ping.php <<'EOF'
<?php
// network diagnostics tool
$ip = $_GET['ip'] ?? '127.0.0.1';
// FIXME: validate $ip before handing it to the shell (ticket #4712)
echo '<pre>' . shell_exec('ping -c 1 ' . $ip) . '</pre>';
EOF
rm -f /var/www/html/index.nginx-debian.html

say "configuring nginx + php-fpm"
# systemctl enable rejects glob patterns, so find the versioned unit the
# package installed (php8.1-fpm on jammy, php8.3-fpm on noble).
PHP_FPM_UNIT=$(basename "$(ls /lib/systemd/system/php*-fpm.service /usr/lib/systemd/system/php*-fpm.service 2>/dev/null | head -n1)")
[[ -n $PHP_FPM_UNIT ]] || { echo "no php*-fpm.service unit found" >&2; exit 1; }
systemctl enable --now "$PHP_FPM_UNIT" >/dev/null
PHP_SOCK=$(ls /run/php/php*fpm.sock | head -n1)
cat > /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.php index.html;
    server_name _;
    location / { try_files $uri $uri/ =404; }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:__PHP_SOCK__;
    }
}
EOF
sed -i "s|__PHP_SOCK__|$PHP_SOCK|" /etc/nginx/sites-available/default
nginx -t
systemctl reload nginx
curl -sf 'http://127.0.0.1/ping.php?ip=127.0.0.1' >/dev/null

say "misconfiguring redis (no auth, world-reachable)"
# The competition classic: no requirepass, protected-mode off, bound to
# 0.0.0.0, and able to write the webroot, so the redis-to-web-shell
# technique (CONFIG SET dir + dbfilename, SAVE) works.
# Stop first: the packaged instance flushes its RDB to /var/lib/redis on
# shutdown, and changing that dir's ownership while it runs strands the
# stop job forever (TimeoutStopSec=0 with Restart=always still blocks).
# 24.04's unit is heavily sandboxed (ProtectSystem=strict, PrivateUsers),
# so keep the stock user and open the webroot to the redis group instead
# of fighting the sandbox with a user swap.
systemctl stop redis-server
sed -i -e 's/^bind .*/bind 0.0.0.0/' \
       -e 's/^protected-mode .*/protected-mode no/' /etc/redis/redis.conf
# Redis 7 blocks CONFIG SET dir/dbfilename at runtime ("can't set
# protected config") unless this is on — without it the web-shell drop
# dies silently. Un-commenting/re-setting is fiddly; appending wins.
printf 'enable-protected-configs yes\n' >> /etc/redis/redis.conf
chown root:redis /etc/redis/redis.conf
chmod 0640 /etc/redis/redis.conf
chown -R redis:redis /var/lib/redis /var/log/redis 2>/dev/null || true
# Webroot: owned by the app user, writable by redis; setgid keeps dropped
# files in the redis group.
chown www-data:redis /var/www/html
chmod 2775 /var/www/html
install -d -m 0755 /etc/systemd/system/redis-server.service.d
cat > /etc/systemd/system/redis-server.service.d/elmer-lab.conf <<'EOF'
[Service]
# ProtectSystem=strict mounts the fs read-only; let redis reach the webroot.
ReadWritePaths=/var/www/html
# The unit's 007 would leave dropped files unreadable by nginx/php-fpm.
UMask=0022
EOF
systemctl daemon-reload
systemctl restart redis-server
[[ $(redis-cli ping) == PONG ]] || { echo "redis did not come up" >&2; exit 1; }
ss -tln | grep -q '0.0.0.0:6379' || { echo "redis is not on 0.0.0.0:6379" >&2; exit 1; }

say "installing elmer"
install -m 0755 "$BIN" /usr/local/bin/elmer
install -d -m 0755 /etc/elmer
install -m 0644 "$YAML" /etc/elmer/elmer.yaml
install -d -m 0700 /var/lib/elmer

cat > /etc/systemd/system/elmer.service <<'EOF'
[Unit]
Description=elmer blue team host monitor
After=network-online.target
Wants=network-online.target

[Service]
# Root enables the eBPF tier: full argv on execve plus connect tracing.
ExecStart=/usr/local/bin/elmer start -c /etc/elmer/elmer.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Baseline the persistence surface after every intentional change, so the
# sweep only reports what attackers add from here on. Re-running provision
# re-baselines, absorbing whatever is currently on the box.
/usr/local/bin/elmer audit -c /etc/elmer/elmer.yaml --write-baseline >/dev/null

systemctl daemon-reload
systemctl enable elmer >/dev/null 2>&1
systemctl restart elmer
sleep 2
systemctl is-active --quiet elmer || { journalctl -u elmer -n 30; exit 1; }

say "target ready"
cat <<'EOF'

  vulnerable app : http://192.168.56.10/ping.php?ip=127.0.0.1
  accounts       : analyst / Analyst2024!
                   svc_backup / backup123   (brute-forceable)
  privesc        : www-data may run sudo /usr/bin/find
  redis          : 192.168.56.10:6379 — no auth, webroot writable by redis
  flags          : /home/svc_backup/flag.txt, /var/www/flag.txt, /root/flag.txt

  watch elmer    : vagrant ssh -c 'sudo journalctl -u elmer -f'   # web01
  attack it      : vm/attacks/run-all.sh   (from the repo root, on the host)

EOF
