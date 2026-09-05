# elmer test targets

Two deliberately vulnerable VMs on a host-only network (`192.168.56.0/24`),
each running elmer, plus staged attack chains that walk a realistic Red v
Blue kill chain so you can watch every monitor fire.

| Machine | OS | IP | Attack chain |
|---------|----|----|--------------|
| **web01** (primary) | Ubuntu | 192.168.56.10 | `attacks/` |
| **win01** (opt-in) | Windows 11 | 192.168.56.20 | `attacks-win/` |

**These boxes are intentionally vulnerable.** Never expose them anywhere
else. `vagrant up` brings up Linux only — Windows is a multi-GB download
and wants 4 GB RAM, so it is `vagrant up win01`.

If you already had the Ubuntu box from before this was a multi-machine
Vagrantfile, destroy it once (`VBoxManage unregistervm elmer-target --delete`
if Vagrant's state is stale) so the new `web01` machine can reuse the
VirtualBox name.

## Layout

```
vm/
  Vagrantfile             web01 + win01, host-only net, pushes binary + config
  provision.sh            Ubuntu: vulnerable target + elmer systemd unit
  provision-features.ps1  Windows: IIS + ASP (Vagrant reboots after this)
  provision.ps1           Windows: vulnerable target + elmer scheduled task
  win-www/                IIS pages uploaded into the guest (ping.asp injection)
  elmer.yaml              Linux config (custom flag rule, FIM paths)
  elmer-windows.yaml      Windows config (same rules, Windows paths)
  attacks/                Linux chain (see below)
  attacks-win/            Windows chain (see below)
```

## Quickstart (VirtualBox + Vagrant)

Prereqs: VirtualBox 7.1+ (already installed here), Vagrant, and on the
attacker host `nmap` plus `sshpass` or `expect` (macOS ships `expect`;
everything else — curl, nc, python3 — is already there).

### Linux (web01)

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

Notes on the Linux box choice:

- **Apple Silicon macs** use `cloudicio/ubuntu-server` 24.04.1 — the only
  maintained arm64 box for VirtualBox's ARM build. Your existing
  VirtualBox 7.2 runs it natively (no Rosetta, no emulation).
- **Intel hosts** (competition infrastructure) use `bento/ubuntu-22.04`
  (jammy) instead. `provision.sh` handles both; the only visible
  difference is php-fpm's version and Ubuntu's.

### Windows (win01)

```sh
make build-windows             # from the repo root
cd vm && vagrant up win01      # first run downloads a ~10 GB box + provisions
                               # (IIS install reboots the guest once)

# terminal 1 — the blue team view:
vagrant winrm win01 -s powershell -c "Get-Content C:\\elmer\\elmer.log -Wait"

# terminal 2 — the red team:
cd attacks-win && bash run-all.sh
```

Notes on the Windows box choice:

- **Apple Silicon macs** use `gusztavvargadr/windows-11-25h2-professional`
  (ARM64). Native, same VirtualBox 7.1+ ARM build as the Ubuntu box.
- **Intel hosts** use `gusztavvargadr/windows-11` (25H2 Enterprise AMD64).
- Defender, UAC, and Windows Update are already off in these boxes;
  `provision.ps1` turns off the firewall and relaxes password complexity
  so the lab accounts match Linux (`backup123`).
- WinRM uses plaintext Basic auth — a workaround for a host-side OpenSSL
  digest failure that otherwise breaks `vagrant provision` on macOS.

The binary and config reach each guest over SSH/WinRM via the file
provisioner, so no guest additions or synced folders are involved.

## Linux target (web01)

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

### Attack chain → detections

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

### Things to try by hand

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

## Windows target (win01)

| Thing            | Detail                                                                 |
|------------------|------------------------------------------------------------------------|
| Web app          | `http://192.168.56.20/ping.asp?ip=...` — command injection (cmd `&`) |
| SSH / RDP        | password auth on; `analyst / Analyst2024!`, `svc_backup / backup123` |
| Privesc          | IIS app pool may `schtasks /run` **BackupSvc** (writable `C:\BackupSvc\backup.bat`, runs as SYSTEM) |
| Flags            | `C:\Users\svc_backup\flag.txt`, `C:\inetpub\wwwroot\flag.txt`, `C:\Windows\flag.txt` |
| elmer            | SYSTEM scheduled task at startup; log is `C:\elmer\elmer.log`          |
| Watch alerts     | `vagrant winrm win01 -s powershell -c "Get-Content C:\\elmer\\elmer.log -Wait"`        |

Helpers in `attacks-win/lib.sh`: `rce CMD` is the ping.asp injection,
`rce_ps` / `root_ps` wrap PowerShell `-EncodedCommand` (fires **ps-enc**),
and `root CMD` overwrites the BackupSvc script and runs the SYSTEM task.

### Attack chain → detections

| Stage | Attacker action | elmer detections (rule / severity) |
|-------|-----------------|-------------------------------------|
| 01 | nmap from the host | none — host monitors see the host, not the wire |
| 02 | SSH as svc_backup | auth 4624 logon, **flag-access CRITICAL** |
| 03 | IIS injection, web flag, certutil pull | **flag-access CRITICAL**, FIM create under wwwroot, **lol-certutil HIGH**, **ps-enc HIGH**, recon-whoami-priv LOW, outbound to :8000 |
| 04 | BackupSvc task → SYSTEM, `reg save` SAM, `wevtutil cl` | **cred-regsave CRITICAL**, flag-access CRITICAL, **antiforensics-shred HIGH** |
| 05 | `net user /add`, admin group, Run key, startup, schtasks | **persist-netuser CRITICAL**, auth 4720/4732, **persist-schtasks HIGH**, FIM Run key + startup folder, sweep diffs within 5m, lol-certutil re-fires every 2m |
| 06 | encoded PS reverse/bind shells, recon, exfil | **ps-enc HIGH**, suspicious connect 4444 CRITICAL, bind 31337 HIGH, recon-whoami-priv (`net user`), external connection to 203.0.113.66 |

`bash alt-bruteforce.sh` is the optional SSH spray (4625 + brute-force
correlation), same as Linux.

### Things to try by hand

```sh
ssh svc_backup@192.168.56.20
vagrant rdp win01                         # analyst / Analyst2024!

vagrant winrm win01 -c "C:\elmer\elmer.exe audit -c C:\elmer\elmer.yaml"
vagrant winrm win01 -c "C:\elmer\elmer.exe test-alerts -c C:\elmer\elmer.yaml"
```

## Alert relay (both boxes)

Alert channels: both YAML files ship a webhook block pointing at
`http://192.168.56.1:8080/alert` — the host end of the VirtualBox
network, standing in for the air-gapped blue-team laptop. Run the relay
on the host to forward alerts to Discord:

```sh
python3 tools/discord_relay.py --discord <webhook-url> --secret <secret>
```

(Generate a secret with
`python3 -c 'import secrets; print(secrets.token_urlsafe(18))'` and use it
for both the relay's `--secret` and `alerts.webhook.secret` — the value
committed in the YAML is a placeholder. Without the relay running,
alerts back up and are dropped — stdout remains the channel of record:
journald on Linux, `C:\elmer\elmer.log` on Windows.)
Keep the webhook `min_severity` at `medium` or higher here: these boxes
log all process events, and an `info` webhook both floods and feeds
back on itself — elmer's net monitor sees elmer's own POSTs to the relay.

## Resetting

```sh
# Linux
vagrant ssh -c 'sudo elmer audit --write-baseline'
vagrant provision web01
vagrant destroy web01 && vagrant up

# Windows
vagrant winrm win01 -c "C:\elmer\elmer.exe audit -c C:\elmer\elmer.yaml --write-baseline"
vagrant provision win01
vagrant destroy win01 && vagrant up win01
```

Note that re-provisioning absorbs current state into the baseline — do it
after cleaning up attacker leftovers, or use `destroy` for a truly clean box.
`vagrant provision win01` reboots the guest once (IIS feature stage).

## Troubleshooting

- **eBPF unavailable** (Linux) — check `vagrant ssh -c 'sudo journalctl -u elmer | grep -i degraded'`.
  elmer still works via netlink/polling, but connect events get sparser.
- **4688 unavailable** (Windows) — `provision.ps1` runs `elmer harden`; if
  process events have no command line, `vagrant winrm win01 -c "C:\\elmer\\elmer.exe harden"`
  from an elevated session and restart the `elmer` scheduled task.
- **Reverse shells never arrive** — macOS asks to allow incoming
  connections for `nc`/Python the first time; allow it. Scripts also
  assume the attacker is `192.168.56.1` (override with `HOST_IP=`).
- **Payload server fails** — port 8000 busy on the host; kill the squatter.
- **Wrong target IP** — `TARGET=10.x.x.x bash 03-foothold-web.sh` per script
  or export it once.
- **win01 WinRM digest error** — the Vagrantfile already forces plaintext
  Basic; if provision still dies, the box is still booting (first sysprep
  is slow — `boot_timeout` is 15 minutes).
- **win01 IIS not serving** — the features provisioner reboots once; a
  failed first `vagrant up win01` is usually fixed by `vagrant provision win01`.
- **IIS 500 on `start /b` or certutil** — old `ping.asp` used `WScript.Shell.Exec`
  and blocked on the child's stdout. Current `win-www/ping.asp` uses `Run` plus
  a temp file; upload it (`vagrant upload win-www/ping.asp C:/inetpub/wwwroot/ping.asp win01`)
  if the guest predates that change.
- **Persistence sweep re-pages leftovers** — write a new baseline
  (`elmer audit --write-baseline`) after you absorb attacker changes; the
  running Windows monitor reloads the file on the next sweep.
