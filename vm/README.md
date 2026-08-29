# elmer test target

A deliberately vulnerable Ubuntu VM ("web01") running elmer as a root
systemd service, plus a staged attack chain that walks a realistic Red v
Blue kill chain — recon, an unauthenticated-redis foothold, command
injection, privesc, persistence, and C2 — so you can watch every monitor
fire.

**This box is intentionally vulnerable.** It sits on a host-only network
(`192.168.56.0/24`) — never expose it anywhere else.

## Layout

```
vm/
  Vagrantfile             Ubuntu box, host-only net, pushes binary + config
  provision.sh            builds the vulnerable target and installs elmer
  elmer.yaml              elmer config for the box (custom flag rule, FIM paths)
  attacks/
    run-all.sh            the whole chain, in order
    01-recon.sh           attacker-side nmap scan (elmer stays quiet)
    02-foothold-redis.sh  unauth redis → CONFIG SET + SAVE web shell drop
    03-foothold-web.sh    command injection in ping.php, curl|bash payload
    04-privesc.sh         sudo find misconfiguration, shadow dump, anti-forensics
    05-persist.sh         backdoor user, root SSH key, cron beacon, SUID shell
    06-c2.sh              reverse/bind shells, tunneling, outbound recon, exfil
    alt-bruteforce.sh     optional SSH spray (not in the main chain)
```

## Quickstart (VirtualBox + Vagrant)

Prereqs: VirtualBox 7.1+ (already installed here), Vagrant, and on the
attacker host `nmap` plus `sshpass` or `expect` (macOS ships `expect`;
everything else — curl, nc, python3 — is already there).

```sh
brew install --cask vagrant    # once
brew install nmap              # once
make build-linux               # from the repo root
cd vm && vagrant up            # first run downloads the box + provisions

# terminal 1 — the blue team view:
vagrant ssh -c 'sudo journalctl -u elmer -f'

# terminal 2 — the red team:
cd attacks && bash run-all.sh
```

Notes on the box choice:

- **Apple Silicon macs** use `cloudicio/ubuntu-server` 24.04.1 — the only
  maintained arm64 box for VirtualBox's ARM build. Your existing
  VirtualBox 7.2 runs it natively (no Rosetta, no emulation).
- **Intel hosts** (competition infrastructure) use `bento/ubuntu-22.04`
  (jammy) instead. `provision.sh` handles both; the only visible
  difference is php-fpm's version and Ubuntu's.

The binary and `elmer.yaml` reach the guest over SSH via the file
provisioner, so no guest additions or synced folders are involved.

## The target

| Thing            | Detail                                                      |
|------------------|-------------------------------------------------------------|
| Web app          | `http://192.168.56.10/ping.php?ip=...` — command injection  |
| Redis            | `192.168.56.10:6379` — no auth; webroot writable by redis |
| SSH              | password auth on; `analyst / Analyst2024!`, `svc_backup / backup123` |
| Privesc          | `www-data` may run `sudo /usr/bin/find` (GTFOBins)          |
| Flags            | `/home/svc_backup/flag.txt`, `/var/www/flag.txt`, `/root/flag.txt` |
| elmer            | root systemd service (`elmer.service`), eBPF tier enabled   |
| Watch alerts     | `vagrant ssh -c 'sudo journalctl -u elmer -f'`              |

The attack helper functions live in `attacks/lib.sh`: `rce CMD` runs a
command as www-data through the injection, `root CMD` runs one as root
through the sudo misconfiguration, and `ssh_try` drives password guesses.

## Attack chain → detections

| Stage | Attacker action | elmer detections (rule / severity) |
|-------|-----------------|-------------------------------------|
| 01 | nmap from the host | none — host monitors see the host, not the wire |
| 02 | unauth redis → web shell | FIM write under /var/www/, exec INFO stream, **flag-access CRITICAL** — nothing network-side, the exploit is inbound-only |
| 03 | injection (second way in), web flag, `curl \| bash` | **flag-access CRITICAL** (custom rule), **download-exec HIGH**, exec INFO stream, outbound net event |
| 04 | sudo find, `cat /etc/shadow`, `history -c` | sudo COMMAND INFO, **cred-shadow-read HIGH**, flag-access CRITICAL, antiforensics-history MEDIUM |
| 05 | useradd, root key, cron, SUID | **persist-useradd CRITICAL** + auth "user account created", **fim-auth-db / fim-ssh CRITICAL**, fim-persist HIGH, **persist-chmod-suid HIGH**, sweep diffs within 5m, download-exec re-fires every 2m |
| 06 | shells, tunnels, recon, exfil | **rshell-devtcp / rshell-netcat CRITICAL**, tunnel-socat-listen HIGH + known-bad filename, suspicious listeners 31337/9050, recon-nmap MEDIUM, tunnel-ssh-forward MEDIUM, external connection to 203.0.113.66 |

Severities in bold are the ones worth paging someone about. Everything
also lands in the Info exec stream because `log_all_process_events` is on.

SSH brute force is deliberately out of the main chain — competition red
teams rarely bother when redis is sitting open — but `bash
alt-bruteforce.sh` shows the brute-force correlation alerts if you want
them, and the scripts speak RESP over plain `nc`, so no redis-cli is
needed on the attacker box.

## Things to try by hand

```sh
# your own attack ideas — anything goes
ssh svc_backup@192.168.56.10

# re-check the persistence surface from inside
vagrant ssh -c 'sudo elmer audit'

# push a synthetic alert through every configured channel
vagrant ssh -c 'sudo elmer test-alerts'

# NDJSON instead of the pretty stream
vagrant ssh -c 'sudo journalctl -u elmer -o cat -f | ...'
```

Alert channels are intentionally empty in `vm/elmer.yaml` (stdout to
journald is the demo channel). Add an `alerts.ntfy` block and re-provision
to watch phone notifications arrive instead.

## Resetting

```sh
vagrant ssh -c 'sudo elmer audit --write-baseline'   # re-baseline elmer's view
vagrant provision                                    # re-provision (also re-baselines)
vagrant destroy && vagrant up                        # clean slate
```

Note that re-provisioning absorbs current state into the baseline — do it
after cleaning up attacker leftovers, or use `destroy` for a truly clean box.

## Troubleshooting

- **eBPF unavailable** — check `vagrant ssh -c 'sudo journalctl -u elmer | grep -i degraded'`.
  elmer still works via netlink/polling, but connect events get sparser.
- **Reverse shells never arrive** — macOS asks to allow incoming
  connections for `nc`/Python the first time; allow it. Scripts also
  assume the attacker is `192.168.56.1` (override with `HOST_IP=`).
- **Payload server fails** — port 8000 busy on the host; kill the squatter.
- **Wrong target IP** — `TARGET=10.x.x.x bash 03-foothold.sh` per script
  or export it once.
