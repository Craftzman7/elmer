package config

// DefaultYAML is the commented config written by `elmer init-config`.
const DefaultYAML = `# elmer — blue team host monitor configuration
#
# Durations use Go syntax: 250ms, 5m, 1h.

# Process/net polling interval when the netlink proc connector is unavailable.
poll_interval: 250ms
# Periodic persistence sweep (users, SUID, systemd, cron, kernel modules).
sweep_interval: 5m
# Where baselines/snapshots are stored. Writable by the elmer user.
state_dir: /var/lib/elmer

# Networks considered in-scope for the competition. Alerts about connections
# to anything else are flagged as external.
internal_cidrs:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8

# Repeat alerts sharing a dedupe key are suppressed for this long.
dedupe_cooldown: 60s
# Periodic "still alive" line on stdout. 0 disables.
heartbeat: 5m
# Stream every process exec at INFO to stdout (alert channels unaffected).
log_all_process_events: true

monitors:
  process: true
  auth: true
  fim: true
  net: true
  persistence: true

fim:
  # Trailing "/" = recursive watch. Globs supported (/home/*/.ssh/).
  # Defaults cover passwd/shadow/sudoers, sshd_config, authorized_keys,
  # cron, systemd, profiles, hosts/resolv.conf, binary dirs, /tmp and
  # /dev/shm. List your competition-specific paths here instead.
  extra_paths: []

# Alert channels. Empty URL = disabled. min_severity filters each channel.
alerts:
  discord:
    url: ""            # https://discord.com/api/webhooks/...
    username: elmer
    min_severity: high
    batch_window: 5s   # coalesce bursts into one message
  ntfy:
    url: https://ntfy.sh
    topic: ""          # e.g. elmer-f19hv; leave empty to disable
    token: ""          # optional access token for protected topics
    min_severity: high
  webhook:
    url: ""            # any HTTP endpoint accepting JSON POST
    secret: ""         # if set, adds X-Elmer-Signature (HMAC-SHA256 hex)
    min_severity: medium

# Extra detection rules on top of the built-in set. target is one of:
# process (exe+cmdline), path (file path), line (log message), any.
# rules:
#   - id: my-golden-flag
#     category: process
#     target: process
#     pattern: '(?i)/tmp/.*flag'
#     severity: critical
#     title: "Golden flag access"
#     technique: T1005

# Disable built-in rules by id here.
disabled_rules: []

suspicious_listen_ports: [4444, 5555, 1337, 31337, 9001, 9002, 8000, 8081]
known_bad_filenames:
  [chisel, frpc, frps, iodine, dnscat2, hydra, medusa, mimikatz, rubeus,
   seatbelt, winpeas, linpeas, pspy, socat, ncat, nc64, plink, hak5,
   empire, cobalt, sliver, meterpreter]

# SSH failure thresholds for brute-force correlation.
brute_force_window: 2m
brute_force_count: 5
brute_force_high_count: 20
`
