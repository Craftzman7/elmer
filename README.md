# elmer

Blue team host monitor for Red v Blue competitions. One static binary,
Linux and Windows, command line only, **zero listening sockets** — elmer only
makes outbound HTTPS calls to your alert channels, so running it never adds
attack surface.

elmer watches a host for attacker activity and alerts on it:

- **Process execution** — every exec with full command line
- **Authentication** — SSH logons/failures (with brute-force correlation),
  sudo, account changes; on Windows: logon events, account/service/task
  audit events
- **File integrity** — /etc/passwd, sudoers, authorized_keys, cron, systemd,
  ld.so.preload, binary directories, /tmp (inotify); Windows: startup
  folders, hosts file, registry Run keys
- **Network** — new listeners, outbound connections (with pid attribution),
  suspicious ports, external destinations
- **Persistence** — periodic sweep diffing users, SUID binaries, systemd
  units, cron, kernel modules, SSH keys, Run keys, services, scheduled
  tasks, local admins against a baseline

Built-in detections cover reverse shells (bash/dev/tcp, nc -e, socat,
python/perl/ruby/php one-liners, mkfifo), tunnels (chisel, frp, ngrok,
ssh -D/-L/-R, DNS tunnelers), credential access (shadow reads, mimikatz,
LSASS dumps, SAM saves), LOLBins (certutil, bitsadmin, mshta, rundll32,
regsvr32), persistence actions (useradd, chmod u+s, setcap, schtasks, net
user /add), anti-forensics (history -c, log shredding), and recon tools.
Rules are regex-based and extensible via config.

## Quick start

```sh
# Linux (root for full telemetry)
sudo ./elmer-linux-amd64 start

# Windows (elevated terminal — enables 4688 auditing first)
.\elmer-windows-amd64.exe harden
.\elmer-windows-amd64.exe start
```

Configure channels with a config file:

```sh
elmer init-config          # writes elmer.yaml
$EDITOR elmer.yaml         # set discord url / ntfy topic / webhook url
elmer test-alerts          # verify delivery end to end
sudo elmer start -c elmer.yaml
```

Channels: **stdout** (always, colored or `--json` NDJSON for jq),
**Discord** webhook (batched embeds, rate-limit aware), **ntfy** push
(severity → priority), **generic webhook** (full event JSON, optional
HMAC-SHA256 `X-Elmer-Signature`). Each channel filters by `min_severity`
and has its own queue — a hung webhook never blocks the others.

## Linux telemetry tiers

elmer picks the best telemetry source available and degrades loudly:

1. **eBPF** (root, kernel ≥ 5.8): execve/execveat tracepoints with full
   argv, connect/bind tracepoints with peer address and owning pid. No
   CO-RE, no vmlinux.h, no kernel headers — the bytecode is embedded in
   the binary. `tools/ebpfcheck` verifies eBPF works on a box.
2. **Netlink proc connector** (root): exec and setuid events, enriched
   from /proc.
3. **/proc polling** (any user): exec diffs every `poll_interval` —
   misses processes that exec and die between scans.

## Commands

| Command | Purpose |
|---|---|
| `elmer start [-c cfg] [--json]` | Run all monitors until interrupted |
| `elmer audit [--write-baseline]` | One-shot persistence surface report |
| `elmer test-alerts` | Synthetic alert through every channel |
| `elmer init-config [path]` | Write a commented default config |
| `elmer harden` | Platform steps to maximize telemetry (Windows: runs them) |
| `elmer version` | Print version |

Config discovery: `-c` → `$ELMER_CONFIG` → `./elmer.yaml` →
`/etc/elmer/elmer.yaml` (or `%ProgramData%\elmer\elmer.yaml`). With no
config file elmer runs on built-in defaults.

## Building

```sh
make test           # unit tests (host platform)
make build          # dist/elmer-{linux,windows}-{amd64,arm64}[.exe]
make generate       # regenerate embedded BPF objects (Linux container;
                    # only needed when internal/monitors/ebpf/bpf/*.c changes)
```

Static binaries, `CGO_ENABLED=0`. Dependencies: cobra, x/sys, yaml.v3,
cilium/ebpf (loader only — BPF bytecode is precompiled and embedded).

## Notes for competition use

- Start from `elmer.example.yaml` — a commented, competition-ready config
  (internal CIDRs, flag rule, suspicious ports, relayed alerting).
- Competition boxes are usually air-gapped. Route Discord alerts through
  `tools/discord_relay.py` running on a blue team box that has internet:
  elmer's webhook channel POSTs to it over the LAN (HMAC-signed), and it
  forwards to Discord while logging every alert locally.
- Run `elmer audit --write-baseline` at gold-image/clean time so sweeps
  alert on deltas, not stock state.
- Set `internal_cidrs` to the competition ranges — external connections
  stand out immediately.
- Red team will try to kill elmer. Consider a cron entry or systemd timer
  that restarts it, and watch the Discord channel for silence.
- `state_dir` (default `/var/lib/elmer` or `C:\ProgramData\elmer`) holds
  baselines; make sure it's writable.
- On Windows, 4688 command lines require `elmer harden` (auditpol + registry).
