# Domain Controller Hardening - Stages 2-4: Extended Hardening
## Fortification, Comprehensive Hardening & Advanced Measures

*Version: 1.0*

> **Prerequisites:** Complete Stage 1 first - see `dc-hardening-stage1-emergency.md`
>
> **Stages overview:**
> - **Stage 1:** Emergency lockdown - first 20 minutes (separate document)
> - **Stage 2:** Fortification - first 2 hours
> - **Stage 3:** Comprehensive hardening - first day
> - **Stage 4:** Advanced hardening - when stable

---

## Table of Contents

**Stage 2: Fortification (First 2 Hours)**
- 2.1 DC Firewall
- 2.2 Tool Deployment (SSH, Velociraptor, Sysmon) + VR Artifacts
- 2.3 Backdoor Hunting
- 2.4 ADCS / certipy-ad Vulnerability Scan
- 2.5 BloodHound Analysis + Rogue Account Detection
- 2.6 Kerberoast / AS-REP Roast Audit
- 2.7 Honey Tokens + DNS Canaries
- 2.8 Monitoring Setup + Event IDs + Audit Log Protection
- 2.9 Quick Wins (AD Recycle Bin, Disable Local Admin)

**Stage 3: Comprehensive Hardening (First Day)**
- 3.1 LAPS Deployment
- 3.2 DNS Zone Hardening
- 3.3 Protected Users Group
- 3.4 PingCastle Full Scan
- 3.5 Unique Per-Machine Passwords
- 3.6 Backup + GPO Export + Volume Shadow Copy
- 3.7 Post-Hardening Verification

**Stage 4: Advanced Hardening (When Stable)**
- 4.1 Credential Guard
- 4.2 LOLBin Execution Blocking
- 4.3 NetCease + SAM-R Restrictions
- 4.4 Defender ASR Rules
- 4.5 Windows Event Forwarding to SIEM
- 4.6 Fine-Grained Password Policies

**Reference Sections**
- Key Principles
- Password Strategy
- DFSR / SYSVOL Replication Notes
- Incident Response Playbook
- Credential Exposure Recovery
- Common Pitfalls & Hard-to-Automate Tasks

---

# Stage 2: Fortification (First 2 Hours)

The walls are up from Stage 1. Now add sensors, patrols, and detection.

---

## 2.1 DC Firewall

### Inbound: Block all, allow AD-essential only
| Port | Protocol | Service |
|------|----------|---------|
| 53 | TCP+UDP | DNS |
| 88 | TCP+UDP | Kerberos |
| 123 | UDP | NTP |
| 135 | TCP | RPC Endpoint Mapper |
| 389 | TCP+UDP | LDAP |
| 445 | TCP | SMB |
| 464 | TCP+UDP | Kpasswd |
| 636 | TCP | LDAPS |
| 3268 | TCP | Global Catalog |
| 3269 | TCP | Global Catalog SSL |
| 3389 | TCP | RDP (restrict source IPs) |
| 5985 | TCP | WinRM |
| 5986 | TCP | WinRM SSL |
| 9389 | TCP | AD Web Services |
| 49152-65535 | TCP | RPC dynamic range |

### Outbound: Block all, allow essential
| Port | Protocol | Service |
|------|----------|---------|
| 53 | TCP+UDP | DNS |
| 80 | TCP | HTTP (updates/CRL) |
| 88 | TCP+UDP | Kerberos |
| 123 | UDP | NTP |
| 135 | TCP | RPC |
| 389 | TCP+UDP | LDAP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 464 | TCP+UDP | Kpasswd |
| 636 | TCP | LDAPS |
| ICMP + ICMPv6 | - | Ping + IPv6 ND |
| 49152-65535 | TCP | RPC dynamic range |

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

# Inbound
New-NetFirewallRule -DisplayName "AD-DNS-In" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD-DNS-UDP-In" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kerberos-In" -Direction Inbound -Protocol TCP -LocalPort 88 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kerberos-UDP-In" -Direction Inbound -Protocol UDP -LocalPort 88 -Action Allow
New-NetFirewallRule -DisplayName "AD-NTP-In" -Direction Inbound -Protocol UDP -LocalPort 123 -Action Allow
New-NetFirewallRule -DisplayName "AD-RPC-In" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAP-In" -Direction Inbound -Protocol TCP -LocalPort 389 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAP-UDP-In" -Direction Inbound -Protocol UDP -LocalPort 389 -Action Allow
New-NetFirewallRule -DisplayName "AD-SMB-In" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kpasswd-In" -Direction Inbound -Protocol TCP -LocalPort 464 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kpasswd-UDP-In" -Direction Inbound -Protocol UDP -LocalPort 464 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAPS-In" -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow
New-NetFirewallRule -DisplayName "AD-GC-In" -Direction Inbound -Protocol TCP -LocalPort 3268 -Action Allow
New-NetFirewallRule -DisplayName "AD-GC-SSL-In" -Direction Inbound -Protocol TCP -LocalPort 3269 -Action Allow
New-NetFirewallRule -DisplayName "AD-RDP-In" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "AD-WinRM-In" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "AD-WinRM-SSL-In" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
New-NetFirewallRule -DisplayName "AD-ADWS-In" -Direction Inbound -Protocol TCP -LocalPort 9389 -Action Allow
New-NetFirewallRule -DisplayName "AD-RPC-Dynamic-In" -Direction Inbound -Protocol TCP -LocalPort 49152-65535 -Action Allow

# Outbound
New-NetFirewallRule -DisplayName "AD-DNS-Out" -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD-DNS-UDP-Out" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD-HTTP-Out" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kerberos-Out" -Direction Outbound -Protocol TCP -RemotePort 88 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kerberos-UDP-Out" -Direction Outbound -Protocol UDP -RemotePort 88 -Action Allow
New-NetFirewallRule -DisplayName "AD-NTP-Out" -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow
New-NetFirewallRule -DisplayName "AD-RPC-Out" -Direction Outbound -Protocol TCP -RemotePort 135 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAP-Out" -Direction Outbound -Protocol TCP -RemotePort 389 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAP-UDP-Out" -Direction Outbound -Protocol UDP -RemotePort 389 -Action Allow
New-NetFirewallRule -DisplayName "AD-HTTPS-Out" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
New-NetFirewallRule -DisplayName "AD-SMB-Out" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kpasswd-Out" -Direction Outbound -Protocol TCP -RemotePort 464 -Action Allow
New-NetFirewallRule -DisplayName "AD-Kpasswd-UDP-Out" -Direction Outbound -Protocol UDP -RemotePort 464 -Action Allow
New-NetFirewallRule -DisplayName "AD-LDAPS-Out" -Direction Outbound -Protocol TCP -RemotePort 636 -Action Allow
New-NetFirewallRule -DisplayName "AD-RPC-Dynamic-Out" -Direction Outbound -Protocol TCP -RemotePort 49152-65535 -Action Allow
New-NetFirewallRule -DisplayName "AD-ICMP-Out" -Direction Outbound -Protocol ICMPv4 -Action Allow
New-NetFirewallRule -DisplayName "AD-ICMPv6-Out" -Direction Outbound -Protocol ICMPv6 -Action Allow
```

---

## 2.2 Tool Deployment

### Deploy OpenSSH
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic
```
```bash
# Mass deploy via NetExec
nxc smb <target_IPs> -u <user> -p <password> -x 'powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd; Set-Service sshd -StartupType Automatic"'
```

### Deploy Velociraptor
```bash
# SCP + install
scp Velociraptor.msi Administrator@<target_IP>:C:/Windows/Temp/
ssh Administrator@<target_IP> 'msiexec /i C:\Windows\Temp\Velociraptor.msi /quiet /norestart'

# Mass deploy via NetExec
nxc smb <target_IPs> -u <user> -p <password> --put-file Velociraptor.msi 'C:\Windows\Temp\Velociraptor.msi'
nxc smb <target_IPs> -u <user> -p <password> -x 'msiexec /i C:\Windows\Temp\Velociraptor.msi /quiet /norestart'
```

Both Velociraptor and Sysmon run as SYSTEM - they survive account disablement and password changes.

**Deployment order:** Deploy VR → Deploy Sysmon → Enable Defender → THEN disable local admin on workstations.

### Velociraptor Artifacts

**One-time baseline hunts (run immediately):**
| Artifact | Purpose |
|----------|---------|
| `Windows.System.Pslist` | Baseline running processes - diff later to find suspicious ones |
| `Windows.System.Services` | Baseline services - detect rogue service persistence |
| `Windows.System.TaskScheduler` | Baseline scheduled tasks - detect task-based persistence |
| `Windows.Sys.AutoRuns` | All persistence mechanisms in one scan |
| `Windows.Sys.Programs` | Installed programs baseline |
| `Windows.Detection.Impersonation` | Token impersonation (may false-positive on CertPropSvc) |
| `Windows.Persistence.PermanentWMIEvents` | Fileless WMI persistence |
| `Windows.Registry.Run` | Registry autorun entries |

**Continuous monitoring (Client Events in VR GUI):**
| Artifact | Purpose |
|----------|---------|
| `Windows.Events.ProcessCreation` | Watch for mimikatz, rubeus, encoded PowerShell, certutil |
| `Windows.Events.ServiceCreation` | Any new service = investigate |
| `Windows.Events.DNSQueries` | C2 detection - high frequency, long subdomains, unusual TLDs |
| `Windows.Detection.FileAccess` | Canary file access monitoring |

### SSH-First Strategy: Restrict WinRM

Once SSH is verified on all machines, restrict WinRM to cut off a major lateral movement vector:
- WinRM supports NTLM → vulnerable to pass-the-hash, relay, token impersonation
- SSH does not support NTLM → eliminates that entire attack class
- Attackers who dump NTLM hashes cannot use them over SSH

```powershell
# Option A: Disable WinRM on workstations (strongest)
Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled

# Option B: Restrict WinRM to management IPs only (if needed for GPO/DSC)
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -RemoteAddress <management_subnet>

# Option C: Disable PSRemoting only
Disable-PSRemoting -Force
```

**Caveats:** Test before disabling - some environments need WinRM for GPO, DSC, SCCM. On DCs, prefer Option B. Always keep a backup access channel (RDP to jump host).

---

## 2.3 Backdoor Hunting

```powershell
# Scheduled tasks - random names, cmd.exe, powershell, GUIDs
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
    Select-Object TaskName, TaskPath, State,
    @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "}}

# Services - non-standard binary paths
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notlike "*\Windows\*" -and
    $_.PathName -notlike "*\Microsoft*" -and $_.PathName -notlike "*VMware*"
} | Select-Object Name, StartMode, State, PathName

# WMI event subscriptions (fileless persistence)
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer
Get-WMIObject -Namespace root\Subscription -Class ActiveScriptEventConsumer

# Registry run keys
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" |
    ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue }

# Recently created users
Get-ADUser -Filter * -Properties WhenCreated | Sort-Object WhenCreated -Descending |
    Select-Object -First 20 Name, SamAccountName, WhenCreated, Enabled

# SYSVOL scripts and GPP files
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Include "*.ps1","*.bat","*.cmd","*.vbs","Groups.xml","ScheduledTasks.xml","scripts.ini" |
    Select-Object FullName, LastWriteTime
```

---

## 2.4 ADCS / certipy-ad Vulnerability Scan

ESC1 lets any user become DA with a single certificate request - as devastating as DCSync. Scan and fix immediately.

```bash
# Full scan from Linux
certipy-ad find -u <user>@<domain> -p <password> -dc-ip <DC_IP> -vulnerable
```

```powershell
# Fix ENROLLEE_SUPPLIES_SUBJECT on vulnerable templates
Get-ADObject -Filter {objectClass -eq "pKICertificateTemplate"} -Properties msPKI-Certificate-Name-Flag |
    Where-Object { $_.'msPKI-Certificate-Name-Flag' -band 1 } |
    ForEach-Object {
        Write-Host "Fixing template: $($_.Name)" -ForegroundColor Yellow
        Set-ADObject $_ -Replace @{
            'msPKI-Certificate-Name-Flag' = ($_.'msPKI-Certificate-Name-Flag' -band (-bnot 1))
        }
    }
```

---

## 2.5 BloodHound Analysis + Rogue Account Detection

> **Tip:** Modern AI models (e.g. Claude Opus, GPT-4) can parse the raw BloodHound JSON, identify
> dangerous ACL paths, and generate ready-to-run PowerShell remediation scripts - often faster and
> more thoroughly than manual GUI analysis.

```bash
# Collect via NetExec
nxc ldap <DC_IP> -u <user> -p <password> --bloodhound -c All --dns-server <DC_IP>
# Import JSON into BloodHound CE - check shortest paths to DA, ACL abuse, delegation, Kerberoastable accounts
```

### Rogue Account Detection

Compare AD users against a known-good source (HR system, provisioning DB, pre-compromise export):

```powershell
$adUsers = Get-ADUser -Filter {Enabled -eq $true} | Select-Object -ExpandProperty SamAccountName
$knownGood = Get-Content "C:\known-good-users.txt"
$excludePatterns = @("Administrator","krbtgt","Guest","svc_*","SM_*","HealthMailbox*")

$rogue = $adUsers | Where-Object {
    $user = $_
    $user -notin $knownGood -and -not ($excludePatterns | Where-Object { $user -like $_ })
}
$rogue | ForEach-Object {
    Write-Host "ROGUE: Disabling $_" -ForegroundColor Red
    Disable-ADAccount -Identity $_
}
```

**Re-run every 2 hours** to catch newly created rogue accounts.

---

## 2.6 Kerberoast / AS-REP Roast Audit

```powershell
# Kerberoastable accounts - have SPNs, attackers request TGS and crack offline
Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName
# Fix: change passwords to 25+ chars, or remove unnecessary SPNs

# AS-REP Roastable - don't require pre-authentication
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName
# Fix:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} |
    Set-ADAccountControl -DoesNotRequirePreAuth $false
```

---

## 2.7 Honey Tokens + DNS Canaries

### Honey Tokens
```powershell
# Fake DA - any auth attempt = attacker detected
New-ADUser -Name "svc_backup" -AccountPassword (ConvertTo-SecureString ([System.Guid]::NewGuid().ToString()) -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_backup"

# Kerberoasting bait - fake SPN, any TGS request = alert
New-ADUser -Name "svc_sql_prod" -AccountPassword (ConvertTo-SecureString ([System.Guid]::NewGuid().ToString()) -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_sql_prod" -ServicePrincipalNames @{Add="MSSQLSvc/sql-prod:1433"}
```

### DNS Canaries (MITRE TA0043)
```powershell
Add-DnsServerResourceRecordA -Name "internal-admin" -ZoneName "<domain>" -IPv4Address "<canary_IP>"
Add-DnsServerResourceRecordA -Name "backup-dc" -ZoneName "<domain>" -IPv4Address "<canary_IP>"
Add-DnsServerResourceRecordA -Name "legacy-sql" -ZoneName "<domain>" -IPv4Address "<canary_IP>"
# Any DNS query for these = attacker doing recon. Monitor via DNS debug log or Sysmon Event ID 22.
```

---

## 2.8 Monitoring Setup

### Continuous Monitoring Loop (every 30 seconds)
```powershell
# 1. GptTmpl.inf hash - detects GPO tampering
$hash = Get-FileHash "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

# 2. DA group membership - compare against baseline
$currentDA = (Get-ADGroupMember "Domain Admins").SamAccountName | Sort-Object

# 3. Honey token hits
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddSeconds(-30)} |
    Where-Object { $_.Properties[5].Value -in @("svc_backup","svc_sql_prod") }

# 4. Failed logon spike (password spray)
$failures = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddSeconds(-30)}).Count
if ($failures -gt 10) { Write-Host "PASSWORD SPRAY DETECTED" -ForegroundColor Red }

# 5. New service installation
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddSeconds(-30)}
```

### Key Event IDs
| Event ID | Log | What |
|----------|-----|------|
| 4624 | Security | Successful logon (watch LogonType 3,10 from unusual IPs) |
| 4625 | Security | Failed logon (password spray detection) |
| 4720 | Security | User created |
| 4728/4732/4756 | Security | Group membership changed |
| 4769 | Security | Kerberos ticket request (Kerberoasting detection) |
| 5136 | Security | AD object modified (GPO changes) |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared (attacker covering tracks) |
| 4719 | Security | System audit policy changed (attacker disabling logging) |

### Audit Log Protection (MITRE TA0005)
```powershell
# Increase log sizes (defaults are too small)
wevtutil sl Security /ms:1073741824  # 1GB
wevtutil sl System /ms:268435456      # 256MB
wevtutil sl "Windows PowerShell" /ms:268435456

# Velociraptor collects events independently - even if local logs are cleared, VR server retains the data
```

---

## 2.9 Quick Wins

```powershell
# AD Recycle Bin - one command, zero downside, enables recovery of deleted AD objects
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false

# Disable local Administrator on workstations (AFTER tools are deployed)
# Use dedicated workstation admin account for post-lockdown management
Disable-LocalUser -Name "Administrator"
```

---

# Stage 3: Comprehensive Hardening (First Day)

Thorough sweep. Fix everything PingCastle and certipy-ad find. Environment is monitored and defended.

---

## 3.1 LAPS Deployment

```powershell
# LAPS requires Schema Admin - add temporarily
Add-ADGroupMember "Schema Admins" -Members Administrator
# IMPORTANT: Must use a NEW logon session after adding (cached tokens won't have the new group)

Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Computers,DC=<domain>"
Set-LapsADReadPasswordPermission -Identity "OU=Computers,DC=<domain>" -AllowedPrincipals "Domain Admins"

# Remove from Schema Admins immediately
Remove-ADGroupMember "Schema Admins" -Members Administrator -Confirm:$false
```

---

## 3.2 DNS Zone Hardening

```powershell
Set-DnsServerPrimaryZone -Name "<domain>" -DynamicUpdate Secure
Set-DnsServerPrimaryZone -Name "<domain>" -SecureSecondaries NoTransfer
```

---

## 3.3 Protected Users Group

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "service-account"
# Disables NTLM, WDigest, CredSSP, and delegation for these accounts
```

**⚠️ WARNING: NEVER add accounts used with NTLM-based tools** (NetExec wmiexec, mmcexec, atexec) to Protected Users - it breaks all NTLM remote management immediately.

**⚠️ WARNING: NEVER add the primary Administrator account** - you will lose remote access.

```powershell
# If accidentally added:
Remove-ADGroupMember -Identity "Protected Users" -Members "accountname" -Confirm:$false
```

---

## 3.4 PingCastle Full Scan

Run PingCastle on a DC for a comprehensive AD security score. Fix all critical and high findings. Key areas:
- SMB signing, TLS, NTLMv2, LDAP signing + channel binding
- LLMNR/NetBIOS, PowerShell logging, audit policies
- Guest account, MachineAccountQuota, Pre-Win2000 group
- Password policies, adminCount cleanup, DNS zone permissions
- OU structure, DsHeuristics, AES-only Kerberos
- Certificate templates, delegation review, SYSVOL permissions

**Always nuke `secedit.sdb` before running PingCastle** for accurate results - the local security database caches old policy.

---

## 3.5 Unique Per-Machine Passwords

Replace shared local admin passwords with unique per-machine passwords. LAPS automates this long-term, but for immediate coverage:

```powershell
# Generate and apply unique passwords per machine, save to secure CSV
# After applying, nuke secedit.sdb on each machine:
Remove-Item C:\Windows\Security\Database\secedit.sdb -Force
gpupdate /force
```

---

## 3.6 Backup + GPO Export

```powershell
# Windows Server Backup - System State (AD database, SYSVOL, registry)
wbadmin start systemstatebackup -backupTarget:<backup_drive>:

# Export all GPOs for offline backup
Get-GPO -All | ForEach-Object { Backup-GPO -Guid $_.Id -Path "C:\GPO-Backup" }
```

### Volume Shadow Copy Protection
```powershell
vssadmin create shadow /for=C:
# Monitor for deletion: vssadmin delete shadows, wmic shadowcopy delete
```

Ensure at least one DC backup exists **offline or offsite** - an attacker with DA can delete online backups.

---

## 3.7 Post-Hardening Verification

Attackers may revert your changes. Re-verify periodically (every 2-4 hours, or after any incident).

```powershell
# 1. Passwords still changed (try default - should FAIL)
# nxc smb <DC_IP> -u Administrator -p 'DefaultPassword' - should get ACCESS_DENIED

# 2. Privileged group membership unchanged
foreach ($g in @("Domain Admins","Enterprise Admins","Schema Admins")) {
    Write-Host "=== $g ===" -ForegroundColor Yellow
    Get-ADGroupMember $g | Select-Object SamAccountName
}

# 3. GPOs still applied
gpresult /r /scope:computer

# 4. DC services still hardened
Get-Service Spooler | Select-Object Status, StartType  # Stopped/Disabled
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RunAsPPL  # 1
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest").UseLogonCredential  # 0

# 5. Defender still running
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled  # True

# 6. Firewall rules intact
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction

# 7. SYSVOL not re-poisoned (compare hash against known-good)
Get-FileHash "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

# 8. No new rogue accounts
Get-ADUser -Filter {Enabled -eq $true} -Properties WhenCreated |
    Where-Object { $_.WhenCreated -gt (Get-Date).AddHours(-4) } | Select-Object SamAccountName, WhenCreated

# 9. VR / Sysmon still running
# nxc smb <target_IPs> -u <user> -p <password> -x 'sc query Velociraptor & sc query Sysmon64'

# 10. Kerberoast/AS-REP status unchanged
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName
```

**Automate this as a script and run on a schedule.** Any deviation from baseline = investigate immediately.

---

# Stage 4: Advanced Hardening (When Stable)

Nice-to-haves that need testing, specific hardware, or infrastructure. Apply when the environment is stable and monitored.

---

## 4.1 Credential Guard (MITRE TA0006 / TA0008)

Virtualization-based security isolates LSASS secrets. Even with kernel access, attacker cannot dump credentials. Complements RunAsPPL.

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f
# Requires reboot. Needs UEFI, Secure Boot, TPM. Not available on all VMs.
```

---

## 4.2 LOLBin Execution Blocking (MITRE TA0002 / TA0011)

Block outbound network access for commonly abused Living Off the Land Binaries. Admins can still run them locally.

```powershell
$lolbins = @(
    "$env:SystemRoot\System32\mshta.exe",
    "$env:SystemRoot\System32\certutil.exe",
    "$env:SystemRoot\System32\bitsadmin.exe",
    "$env:SystemRoot\System32\cscript.exe",
    "$env:SystemRoot\System32\wscript.exe",
    "$env:SystemRoot\System32\regsvr32.exe",
    "$env:SystemRoot\System32\rundll32.exe",
    "$env:SystemRoot\System32\msiexec.exe",
    "$env:SystemRoot\System32\wmic.exe"
)
foreach ($bin in $lolbins) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($bin)
    New-NetFirewallRule -DisplayName "Block-LOLBin-$name" -Direction Outbound -Program $bin -Action Block
}
```

**Test carefully** - blocking certutil/msiexec outbound can break legitimate admin workflows. For stronger control, consider AppLocker or Windows Defender Application Control (WDAC).

---

## 4.3 NetCease + SAM-R Restrictions (MITRE TA0007)

Restrict attacker enumeration of who is logged in where.

```powershell
# SAM-R restrictions - limit remote SAM enumeration to Administrators only
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f

# NetCease - restrict NetSessionEnum to Administrators only
# Download: https://github.com/p0w3rsh3ll/NetCease
# Or apply the registry fix at HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity
# Requires reboot
```

---

## 4.4 Defender ASR Rules

```powershell
# Block Office child processes
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
# Block Office executable content creation
Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
```

Needs per-environment testing - can break Office workflows.

---

## 4.5 Windows Event Forwarding to SIEM

Forward logs to an external collector so attackers can't destroy evidence by clearing local logs. Options:
- Windows Event Forwarding (WEF) to a central collector
- Syslog forwarding via NXLog or similar
- Velociraptor's client event monitoring (already collects independently)

---

## 4.6 Fine-Grained Password Policies

Apply stricter password policies to privileged accounts without affecting regular users:

```powershell
New-ADFineGrainedPasswordPolicy -Name "Tier0-PasswordPolicy" `
    -Precedence 10 -MinPasswordLength 20 -MaxPasswordAge "30.00:00:00" `
    -LockoutThreshold 5 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00" `
    -ComplexityEnabled $true -ReversibleEncryptionEnabled $false

Add-ADFineGrainedPasswordPolicySubject -Identity "Tier0-PasswordPolicy" -Subjects "Domain Admins"
```

---

# Reference Sections

These are not stage-bound - use them anytime.

---

## Key Principles

- **Harden authentication, not connectivity** - disabling accounts is more effective than blocking ports
- **Always nuke secedit.sdb** after any GPO, password, or security policy change
- **Fix BOTH DCs** - never assume DFSR will replicate your fix
- **Never use DA credentials on workstations** - use a separate workstation admin account
- **Deploy tools before disabling accounts** - tools running as SYSTEM survive, but installation requires admin access
- **Baseline everything early** - scheduled tasks, services, group memberships, GPOs - then diff against baseline periodically

---

## Password Strategy

1. Change ALL passwords immediately - before the attacker can use known/default credentials
2. Use non-English words or passphrases - resists dictionary attacks
3. Different passwords per tier - DCs ≠ workstations ≠ service accounts
4. Rotate again after finding compromise - assume attacker captured the first password
5. Disable local Administrator on workstations after tools are deployed

```powershell
# After EVERY password change - nuke secedit.sdb
Remove-Item C:\Windows\Security\Database\secedit.sdb -Force
gpupdate /force
```

---

## DFSR / SYSVOL Replication Notes

1. **Always fix BOTH DCs** - fixing one doesn't guarantee replication
2. **Check GPT.INI versions** - higher version wins in DFSR conflicts
3. **Bump version to 99999** after cleaning to force your version to win
4. **Check DFSR ConflictAndDeleted folder** for old copies being restored
5. **secedit.sdb is per-machine** - must be nuked on EACH DC separately
6. **Check DFSR status early** - if stuck in initial sync (Event 4612/4614), plan for manual SYSVOL sync

```powershell
Get-WinEvent -FilterHashtable @{LogName='DFS Replication'; Id=@(4612,4614)} -MaxEvents 5
# If stuck, manually copy GptTmpl.inf + Registry.pol + gpt.ini between DCs after every GPO change
```

---

## Incident Response Playbook

### Machine Isolation
```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
# Or surgically - allow only your management IP:
netsh advfirewall firewall add rule name="Block All" dir=in action=block
netsh advfirewall firewall add rule name="Block All Out" dir=out action=block
netsh advfirewall firewall add rule name="Allow Mgmt" dir=in action=allow remoteip=<your_management_IP> protocol=tcp
netsh advfirewall firewall add rule name="Allow Mgmt Out" dir=out action=allow remoteip=<your_management_IP> protocol=tcp
```

### Emergency krbtgt Reset (Golden Ticket Detected)
```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ([System.Guid]::NewGuid().ToString()) -Force)
Start-Sleep -Seconds 600  # Wait for replication
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ([System.Guid]::NewGuid().ToString()) -Force)
```

### New Unauthorized DA Member
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "<rogue_account>" -Confirm:$false
Disable-ADAccount -Identity "<rogue_account>"
# Reset krbtgt - attacker may have already forged tickets
```

### Kerberoasting Detected (Event 4769 with RC4 / 0x17)
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalName |
    ForEach-Object {
        $newPw = [System.Guid]::NewGuid().ToString() + [System.Guid]::NewGuid().ToString()
        Set-ADAccountPassword -Identity $_.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPw -Force)
    }
```

### Password Spray Detected (Event 4625 Spike)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-10)} |
    ForEach-Object {
        [PSCustomObject]@{ Time=$_.TimeCreated; Account=$_.Properties[5].Value; SourceIP=$_.Properties[19].Value }
    } | Group-Object SourceIP | Sort-Object Count -Descending
```

### Kill Suspicious Process
```powershell
taskkill /F /PID <pid>
```

---

## Credential Exposure Recovery

If DA credentials are accidentally used on a compromised machine:

1. **Reboot the compromised machine immediately** - clears LSASS memory
2. **Change the exposed account's password on a DC**
3. **Reset krbtgt twice** (10 min apart)
4. **Check for logons from the compromised machine's IP:**
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1000 |
       Where-Object { $_.Properties[18].Value -eq "<compromised_machine_IP>" } |
       Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
   ```
5. **Rule: NEVER use DA credentials on workstations.** Use a dedicated workstation admin account. No exceptions.

---

## Common Pitfalls & Hard-to-Automate Tasks

Lessons from real-world DC hardening operations. These are the things that break your automation and waste hours.

### Remote Command Quoting Hell

Passwords with special characters (`!`, `#`, `%`, `&`) get mangled through multi-layer quoting: bash → SSH → nxc → cmd → PowerShell. The `net user` command with passwords longer than 14 characters triggers an interactive "Do you want to continue? (Y/N)" prompt that **silently fails** via remote execution (atexec/wmiexec) because there's no stdin.

**Solution:** Don't try inline `net user` with complex passwords remotely. Instead:
```bash
# 1. Write a PowerShell script locally
echo 'net user Administrator "YourComplex!Password#123" /y' > /tmp/setpw.ps1

# 2. Upload it
scp /tmp/setpw.ps1 Administrator@<target>:C:/Windows/Temp/

# 3. Execute it
ssh Administrator@<target> 'powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\setpw.ps1'

# 4. Clean up
ssh Administrator@<target> 'del C:\Windows\Temp\setpw.ps1'
```

Also: `&&` doesn't work in atexec - use `&` (cmd) or separate commands.

### Account Lockout from Password Guessing

When trying multiple passwords against machines (especially workgroup machines not on the domain), lockout kicks in fast. You lock yourself out, then have to wait for the lockout timer to expire - or find another way in.

**Rules:**
- Try ONE password at a time, wait for lockout to expire before retrying
- Document which password works on which machine
- If locked out of a workgroup machine, use Velociraptor shell (runs as SYSTEM, bypasses lockout):
  ```
  # In VR GUI → select client → VQL shell
  SELECT * FROM execve(argv=["net", "user", "Administrator", "/active:yes"])
  ```

### Legitimate-Looking Persistence

Attackers name their persistence to look like real software. Examples:
- `MicrosoftEdgeUpdateTaskMachineCore{random-GUID}` - looks like Edge update but the GUID suffix and `/c` argument are not standard
- Services with paths in `C:\ProgramData\` that mimic legitimate software names
- Scheduled tasks under `\Microsoft\Windows\` that blend in with real ones

**Mitigation:** Baseline ALL scheduled tasks, services, and autoruns on clean machines BEFORE the attacker acts. Diff against baseline periodically. Any new entry that wasn't in the baseline = investigate.

### DSRM Reset is Interactive

The `ntdsutil` DSRM password reset requires an interactive terminal - it prompts for the new password twice. This cannot be piped through nxc, atexec, or wmiexec.

**Solution:** Use SSH with TTY allocation:
```bash
ssh -t Administrator@<DC_IP>
# Then inside the session:
ntdsutil "set dsrm password" "reset password on server null" quit quit
```

### Workgroup Machines

Non-domain-joined machines cannot be managed via Group Policy or domain accounts. They require direct local credentials. If the local admin is locked out and you have no other local account:

1. Use Velociraptor shell (runs as SYSTEM, bypasses all lockout)
2. Create a new local admin via VR
3. Or boot from recovery media for offline password reset

**Plan for these machines separately** - maintain a list with their local credentials.

### PingCastle Misses ACL Backdoors

PingCastle is excellent for configuration compliance but does NOT detect ACL-based backdoors (e.g. Domain Users having GenericAll on Domain Admins). BloodHound catches these.

**Always run both tools.** PingCastle for configuration, BloodHound for attack paths.

### PingCastle Score Inconsistency Between DCs

The same domain can show different PingCastle scores on different DCs because `secedit.sdb` caches old security policy locally. DC1 might show score 100 while DC2 shows 88 - same fixes applied.

**Fix:** Always nuke `secedit.sdb` on the DC you're scanning before running PingCastle.

### auditpol Subcategory Names Vary by OS Language/Version

`auditpol /set /subcategory:"Logon"` may fail on some Windows Server versions with a parameter error. The subcategory name might be "Logon/Logoff" or localized differently.

**Fix:** Use the GUID instead of the name:
```powershell
# Logon subcategory GUID (works regardless of language/version)
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

### Velociraptor API Limitations

VR's API for creating hunts and labeling clients can be unreliable in some versions. Don't assume full API automation will work - plan for GUI-based operations as fallback. The GUI is fast enough for most hunt operations.

### SMB Upload vs Command Execution Mismatch

Some admin accounts can execute commands remotely (via atexec/wmiexec) but cannot write files to the C$ admin share. This is a permissions difference - command execution runs as the user, but C$ write requires specific share permissions.

**Workaround:** Use SSH + SCP for file uploads instead of SMB:
```bash
scp file.exe Administrator@<target>:C:/Windows/Temp/
ssh Administrator@<target> 'C:\Windows\Temp\file.exe'
```

### Protected Users Locks You Out

Adding the primary Administrator account to Protected Users **immediately breaks all NTLM-based remote access** (nxc, wmiexec, mmcexec, atexec, SMB). Only Kerberos-based access (RDP, SSH) continues to work.

If you accidentally do this and lose access:
- RDP still works (uses Kerberos) - remove the account from Protected Users via RDP
- SSH still works - remove via PowerShell over SSH
- If neither is available, you need console/physical access

**Rule:** Only add service accounts or secondary admin accounts to Protected Users. Never the primary account you use for remote management.
