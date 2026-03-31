# Domain Controller Hardening - Stage 1: Emergency Lockdown
## Securing Active Directory After a Network Compromise

*Version: 1.0*

Assumes the attacker has had prior access to the environment. All credentials, tickets, and GPOs should be treated as compromised. Execute this entire stage within the first 20 minutes.

> **Stages overview:**
> - **Stage 1 (this document):** Emergency lockdown - first 20 minutes
> - **Stages 2-4:** See `dc-hardening-stages2-4-extended.md` - fortification, comprehensive hardening, and advanced measures

---

## Recommended Tooling

> **Note:** Only free, open-source, and limited-demo tools are listed here. Commercial EDR, SIEM,
> and AD security products (e.g. CrowdStrike, Microsoft Defender for Identity, Semperis, etc.)
> can work equally well or better - use whatever is available in your environment.

### Must-Have (Deploy in Stage 2)
| Tool | Purpose | Deploy Method |
|------|---------|---------------|
| Velociraptor | EDR, hunting, remote forensics | MSI via SCP/SMB or GPO startup script |
| Sysmon | Detailed endpoint logging (process, network, registry, file) | EXE + config via SCP, install via SSH |
| Defender | AV/AM - ensure enabled, not disabled by GPO | Registry fix + service start |
| OpenSSH | Primary remote management channel | Enable via remote exec if needed |

### Reconnaissance & Audit (Deploy in Stage 2)
| Tool | Purpose |
|------|---------|
| BloodHound | AD attack path analysis - finds ACL backdoors that other tools miss |
| PingCastle | AD security scoring and compliance baseline |
| certipy-ad | ADCS vulnerability scanning (ESC1-ESC8) |
| Chainsaw / Hayabusa | Offline Windows event log analysis |
| NetExec (nxc) | Mass remote execution, BloodHound collection, SMB/LDAP enumeration |
| ADRecon | Comprehensive AD enumeration and reporting |

---

## Operational Strategy: Parallel Workstreams

When responding with a team, split into parallel workstreams to maximize speed:

| Workstream | Focus | Priority |
|------------|-------|----------|
| **Hardening** | Passwords, ACLs, GPOs, services, firewall | Highest - do first |
| **Reconnaissance** | BloodHound, PingCastle, certipy-ad, rogue account detection | High - runs in parallel with hardening |
| **Deployment** | SSH, Velociraptor, Sysmon, Defender on all endpoints | High - runs in parallel |

**Sync points:**
- Recon team waits for password changes before collecting BloodHound (needs valid creds)
- Deployment team uses the new passwords set by the hardening team
- Recon findings (ACL backdoors, rogue accounts) feed back to hardening team for immediate fix
- Deployment must finish before disabling local admin accounts on workstations

---

## Step 1: Passwords (Minute 0-3)

Change all privileged passwords before the attacker can use known/default credentials.

```powershell
# 1a. Change Domain Admin password on DC1 (replicates to DC2 via AD)
net user Administrator <NewSecurePassword>

# 1b. Reset krbtgt TWICE to invalidate all Golden Tickets
#     The krbtgt hash signs all Kerberos TGTs - if compromised, attacker can forge tickets indefinitely.
#     Windows keeps one previous hash for in-flight validation, so two resets are required.
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ([System.Guid]::NewGuid().ToString()) -Force)
Start-Sleep -Seconds 600  # Wait for replication
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ([System.Guid]::NewGuid().ToString()) -Force)

# 1c. Create dedicated admin accounts (backup DA + separate workstation admin)
New-ADUser -Name "admin-backup" -AccountPassword (ConvertTo-SecureString "<Password>" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "admin-backup"

New-ADUser -Name "ws-admin" -AccountPassword (ConvertTo-SecureString "<Password>" -AsPlainText -Force) -Enabled $true
# ws-admin gets local admin on workstations via GPO Restricted Groups - NOT Domain Admin

# 1d. Change DSRM password on BOTH DCs
#     DSRM is a local admin account on every DC, separate from domain accounts.
#     With DsrmAdminLogonBehavior=2, it can authenticate over the network - a known persistence technique.
ntdsutil "set dsrm password" "reset password on server null" quit quit
```

**Use different passwords per tier:** DCs ≠ workstations ≠ service accounts.

---

## Step 2: ACL Cleanup (Minute 3-5)

Attackers commonly grant Domain Users or Authenticated Users GenericAll/GenericWrite on all AD objects as a backdoor. This is the single highest-impact fix.

```powershell
# 2a. Mass ACL cleanup - remove non-inherited dangerous ACEs from all AD objects
$domainDN = (Get-ADDomain).DistinguishedName
$dangerousRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
)
$domainSID = (Get-ADDomain).DomainSID.Value
$dangerousPrincipals = @("$domainSID-513", "S-1-5-11")

foreach ($obj in Get-ADObject -Filter * -SearchBase $domainDN) {
    $acl = Get-Acl "AD:\$($obj.DistinguishedName)"
    $modified = $false
    foreach ($ace in $acl.Access) {
        if ($ace.IsInherited) { continue }
        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($dangerousPrincipals -contains $sid -and $dangerousRights -contains $ace.ActiveDirectoryRights) {
            $acl.RemoveAccessRule($ace) | Out-Null
            $modified = $true
        }
    }
    if ($modified) { Set-Acl "AD:\$($obj.DistinguishedName)" $acl }
}

# 2b. Verify DCSync permissions - only DCs should have replication rights
$domainObj = "AD:\$domainDN"
(Get-Acl $domainObj).Access | Where-Object {
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes-All
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"      # DS-Replication-Get-Changes
} | Select-Object IdentityReference, ActiveDirectoryRights

# 2c. Check AdminSDHolder for backdoor ACEs
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,$domainDN").Access |
    Where-Object { -not $_.IsInherited } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
```

**Run this BEFORE PingCastle or BloodHound** - it fixes the root cause of most attack paths.

---

## Step 3: Privileged Group Cleanup (Minute 5-7)

```powershell
# 3a. Audit all privileged groups
$groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
            "Backup Operators","Account Operators","DnsAdmins",
            "Group Policy Creator Owners","Remote Desktop Users")
foreach ($g in $groups) {
    Write-Host "=== $g ===" -ForegroundColor Yellow
    Get-ADGroupMember $g | Select-Object Name, SamAccountName, objectClass
}

# 3b. Remove unauthorized members (example)
Remove-ADGroupMember -Identity "Domain Admins" -Members "unauthorized_user" -Confirm:$false

# 3c. Remove service accounts from local Administrators on DCs
Remove-LocalGroupMember -Group "Administrators" -Member "DOMAIN\<service_account>"

# 3d. Remove Domain Users from RDP Users on DCs
Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "DOMAIN\Domain Users"

# 3e. Clean Pre-Windows 2000 Compatible Access (allows any authenticated user to enumerate AD)
Remove-ADGroupMember "Pre-Windows 2000 Compatible Access" -Members "Authenticated Users" -Confirm:$false

# 3f. Empty Schema Admins (should be empty when not making schema changes)
Get-ADGroupMember "Schema Admins" | ForEach-Object {
    Remove-ADGroupMember "Schema Admins" -Members $_.SamAccountName -Confirm:$false
}

# 3g. Document baseline membership for ongoing monitoring
foreach ($g in $groups) {
    Get-ADGroupMember $g | Select-Object @{N='Group';E={$g}}, Name, SamAccountName |
        Export-Csv -Path "C:\baseline-groups.csv" -Append -NoTypeInformation
}
```

---

## Step 4: DC Services & Registry (Minute 7-10)

```powershell
# 4a. Disable Print Spooler - PrintNightmare (CVE-2021-34527)
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled

# 4b. Enable LSA Protection - prevents Mimikatz from reading LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# Requires reboot to take effect

# 4c. Disable WDigest - prevents cleartext password storage in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

# 4d. Disable WPAD - prevents NTLM relay via proxy auto-discovery poisoning
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f

# 4e. Disable RC4 for Kerberos - forces AES, makes Kerberoasting infeasible
#     Via GPO: "Network security: Configure encryption types allowed for Kerberos" = AES128 + AES256 only

# 4f. Disable NetBIOS over TCP/IP - prevents Responder/NTLM poisoning
#     Via GPO or per-adapter: WINS tab > Disable NetBIOS over TCP/IP

# 4g. Set DSRM registry to prevent network logon abuse
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f

# 4h. Mark DA accounts as "Sensitive and cannot be delegated"
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Set-ADAccountControl -Identity $_.SamAccountName -AccountNotDelegated $true
}

# 4i. Disable Guest account
Disable-ADAccount -Identity Guest

# 4j. Set MachineAccountQuota to 0 - prevents users from joining rogue machines
Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="0"}

# 4k. Fix password policy weaknesses
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Set-ADUser -PasswordNeverExpires $false
Get-ADUser -Filter {PasswordNotRequired -eq $true} | Set-ADUser -PasswordNotRequired $false
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -MinPasswordLength 14
```

---

## Step 5: SYSVOL / GPO Cleanup (Minute 10-15)

Attackers poison GPOs to maintain persistence. The local security database (`secedit.sdb`) caches applied policy and keeps re-applying poisoned settings even after SYSVOL is cleaned.

```powershell
# 5a. Check Default Domain Controllers Policy GptTmpl.inf
$dcPolicyPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
Get-Content $dcPolicyPath
# Look for:
#   - Foreign domain SIDs (SID prefix doesn't match your domain)
#   - S-1-5-11 (Authenticated Users) in privilege assignments
#   - *-513__Memberof = *-512 (Domain Users → Domain Admins via Restricted Groups)

# 5b. Check Default Domain Policy GptTmpl.inf the same way
$domPolicyPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
Get-Content $domPolicyPath

# 5c. Scan ALL GPOs for malicious content
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include "scripts.ini","Groups.xml","ScheduledTasks.xml","Registry.pol" |
    ForEach-Object { Write-Host $_.FullName -ForegroundColor Yellow; Get-Content $_ }

# 5d. After cleaning, bump GPT.INI version to 99999 to win DFSR replication conflicts

# 5e. Nuke secedit.sdb on BOTH DCs - ESSENTIAL
Remove-Item C:\Windows\Security\Database\secedit.sdb -Force
gpupdate /force

# 5f. Verify SYSVOL replication - GPT.INI versions must match on both DCs
Get-Content "\\DC1\SYSVOL\$env:USERDNSDOMAIN\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\gpt.ini"
Get-Content "\\DC2\SYSVOL\$env:USERDNSDOMAIN\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\gpt.ini"
```

**Rule: After ANY GPO or security policy change, ALWAYS nuke `secedit.sdb` on all affected machines.**

---

## Step 6: GPOs (Minute 15-20)

Create and link two GPOs:

**Tier0-Isolation** (linked to domain root, DCs excluded via security filtering):
```
Deny log on locally                              → Domain Admins, Enterprise Admins
Deny log on through Remote Desktop Services       → Domain Admins, Enterprise Admins
Deny access to this computer from the network     → Domain Admins, Enterprise Admins
Outbound firewall block: powershell.exe, pwsh.exe
UAC: Behavior of elevation prompt for admins      → Prompt for credentials
UAC: Run all admins in Admin Approval Mode        → Enabled
Turn on PowerShell Script Block Logging           → Enabled
Turn on PowerShell Transcription                  → Enabled
Turn off multicast name resolution (LLMNR)        → Enabled
Restricted Groups: ws-admin → local Administrators
```

**DC-Hardening** (linked to OU=Domain Controllers):
```
Microsoft network server: Digitally sign communications (always)  → Enabled
Microsoft network client: Digitally sign communications (always)  → Enabled
Domain controller: LDAP server signing requirements               → Require signing
Domain controller: LDAP server channel binding token requirements → Always
Network security: LAN Manager authentication level                → Send NTLMv2 only. Refuse LM & NTLM
KDC support for claims, compound auth and Kerberos armoring       → Enabled
Kerberos client support for claims, compound auth and armoring    → Enabled
Require NLA for Remote Desktop                                    → Enabled
Turn on PowerShell Script Block Logging                           → Enabled
Include command line in process creation events                   → Enabled
Turn off multicast name resolution (LLMNR)                        → Enabled
```

**Advanced Audit Policy (via GPO or command line on DCs):**
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

## Step 7: Enable Defender + Sticky Keys Check (Minute 20)

```powershell
# Remove GPO-level Defender disablement
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f 2>$null
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f 2>$null
Start-Service WinDefend
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled

# If "Access Denied" - attacker tampered with WinDefend service DACL
# Requires TrustedInstaller-level access or offline registry edit to fix
# Check: sc.exe sdshow WinDefend

# Sticky keys / accessibility tool backdoor check
$cmd = (Get-Item C:\Windows\System32\cmd.exe).Length
foreach ($tool in @("sethc.exe","utilman.exe","osk.exe","narrator.exe","magnify.exe")) {
    $size = (Get-Item "C:\Windows\System32\$tool").Length
    if ($size -eq $cmd) { Write-Host "BACKDOOR: $tool replaced with cmd.exe!" -ForegroundColor Red }
}
```

---

## Stage 1 Complete - Next Steps

Stage 1 stops the bleeding. Proceed immediately to **Stage 2: Fortification** in `dc-hardening-stages2-4-extended.md`:
- DC Firewall rules
- Tool deployment (SSH, Velociraptor, Sysmon)
- Full backdoor hunting
- ADCS/certipy-ad vulnerability scan
- BloodHound analysis
- Monitoring setup
- And more
