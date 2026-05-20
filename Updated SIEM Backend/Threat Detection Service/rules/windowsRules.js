// Simple rule list. Each rule: id, description, match function or conditions.
// Extend this with more rules or load from JSON files.

const windowsRules = [
    // Privilege assignment (EventID 4672) - look for dangerous privileges
  {
    id: 'win-priv-assigned',
    description: 'Special privileges assigned (several admin-level privileges)',
    severity: 'high',
    match: (decoded) => {
      if (decoded.eventId !== 4672) return false;
      const desc = (decoded.description || '').toLowerCase();
      return ['sedebugprivilege', 'seloaddriverprivilege', 'setcbprivilege']
        .some(priv => desc.includes(priv.toLowerCase()));
    }
  },

  // Successful SYSTEM service logon (EventID 4624, logonType 5) - monitor
  {
    id: 'win-system-service-logon',
    description: 'SYSTEM service logon (4624, LogonType 5)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 5 && /system/i.test(decoded.description || '')
  },

  // Kerberos service ticket request (EventID 5379) - baseline/monitor
  {
    id: 'win-kerberos-service-ticket',
    description: 'Kerberos service ticket requested (5379)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 5379
  },

  // WiFi driver error (example from your logs) - not security but record as low severity
  {
    id: 'net-driver-error',
    description: 'Intel Wi-Fi driver error (Netwtw10)',
    severity: 'low',
    match: (decoded) => String(decoded.source).toLowerCase() === 'netwtw10' && decoded.level === 2
  },

  // Failed logon (EventID 4625) - captured for brute force detection (stateless here)
  {
    id: 'win-failed-logon',
    description: 'Failed logon (4625) - candidate for brute force',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4625
  },

  //==============================================================================================================
  //                                    THREAT DETECTION BASED ON DESCRIPTION
  //==============================================================================================================

  //======================================CREDENTIAL ACCESS=======================================================
  {
  id: 'mimikatz-detected',
  description: 'Possible credential dumping attempt (Mimikatz)',
  severity: 'critical',
  match: (decoded) =>
    decoded.description &&
    /(mimikatz|sekurlsa|kerberos::ptt|dcsync)/i.test(decoded.description)
},
{
  id: 'lsass-access',
  description: 'Suspicious access to LSASS process memory',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(lsass.exe.*read|dump|credential)/i.test(decoded.description)
},
{
  id: 'sam-database-access',
  description: 'Attempt to access SAM database',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(SAM|Security Account Manager).*access/i.test(decoded.description)
},

//=========================EXECUTION AND PERSISTENCES==============================================================

{
  id: 'suspicious-powershell',
  description: 'Potential malicious PowerShell command detected',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /powershell.*(Invoke-Expression|IEX|DownloadString|EncodedCommand)/i.test(decoded.description)
},
{
  id: 'cmd-suspicious',
  description: 'Suspicious command line execution detected',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(cmd.exe.*\/c.*net user|cmd.exe.*\/c.*whoami)/i.test(decoded.description)
},
{
  id: 'scheduled-task-persistence',
  description: 'Suspicious scheduled task creation',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(schtasks.*create|task scheduler).*suspicious/i.test(decoded.description)
},
{
  id: 'service-install',
  description: 'Suspicious service installation detected',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(Service Control Manager.*service was installed|new service)/i.test(decoded.description)
},

//===========================================LATERAL MOVEMENT========================================================

{
  id: 'rdp-bruteforce',
  description: 'Multiple failed RDP login attempts',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(RDP.*failed login|RemoteInteractive.*failed)/i.test(decoded.description)
},
{
  id: 'psexec-detected',
  description: 'PsExec execution detected',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(psexec|remcomsvc|paexec)/i.test(decoded.description)
},
{
  id: 'wmic-remote-exec',
  description: 'Remote execution via WMI detected',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(wmic.*process call create|remote wmi execution)/i.test(decoded.description)
},

//================================================MALWARE AND EXPLOITS================================================

{
  id: 'malware-keywords',
  description: 'Event description contains malware indicators',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(trojan|backdoor|ransomware|keylogger|cryptominer)/i.test(decoded.description)
},
{
  id: 'suspicious-exe',
  description: 'Execution of suspicious file in temp directory',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(C:\\Users\\.*\\AppData\\Local\\Temp\\.*\.exe)/i.test(decoded.description)
},
{
  id: 'office-macro',
  description: 'Suspicious Office macro execution',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(winword.exe.*macro|excel.exe.*macro|vba.*shell)/i.test(decoded.description)
},
{
  id: 'exploit-attempt',
  description: 'Exploit attempt detected in description',
  severity: 'critical',
  match: (decoded) =>
    decoded.description &&
    /(buffer overflow|privilege escalation|exploit|heap corruption)/i.test(decoded.description)
},

//======================================DATA EXFILTRATION===========================================================

{
  id: 'large-data-transfer',
  description: 'Large data transfer or unusual outbound traffic',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(unusually large data transfer|megabytes sent|gigabytes uploaded)/i.test(decoded.description)
},
{
  id: 'suspicious-ftp',
  description: 'FTP usage detected (possible exfiltration)',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(ftp.exe|File Transfer Protocol).*upload/i.test(decoded.description)
},
{
  id: 'cloud-storage-exfil',
  description: 'Suspicious cloud storage access',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(dropbox|onedrive|google drive).*upload/i.test(decoded.description)
},

//===================================================DEFENSIVE EVASION==============================================

{
  id: 'av-disabled',
  description: 'Antivirus or Defender disabled',
  severity: 'critical',
  match: (decoded) =>
    decoded.description &&
    /(Windows Defender.*disabled|antivirus.*stopped|real-time protection off)/i.test(decoded.description)
},
{
  id: 'clearing-logs',
  description: 'Attempt to clear event logs',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(wevtutil cl|event log cleared|log deletion)/i.test(decoded.description)
},
{
  id: 'firewall-disabled',
  description: 'Firewall settings modified or disabled',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(firewall.*disabled|netsh advfirewall set allprofiles state off)/i.test(decoded.description)
},

//==============================================RECONNAISANCE=======================================================

{
  id: 'network-scan',
  description: 'Port scanning or network probing detected',
  severity: 'medium',
  match: (decoded) =>
    decoded.description &&
    /(nmap scan|masscan|port scan detected)/i.test(decoded.description)
},
{
  id: 'ad-enum',
  description: 'Active Directory enumeration attempt',
  severity: 'high',
  match: (decoded) =>
    decoded.description &&
    /(ldap query|dsquery|net user \/domain|adfind)/i.test(decoded.description)
},
//=======================================================================================================================

//                                                      SECURITY LOGS RULES

//=======================================================================================================================

// Detects interactive logons (local console, LogonType 2)
{
  id: 'win-logon-success',
  description: 'Successful logon (4624, LogonType 2)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 2
},

// Detects service account logons (services starting, LogonType 5)
{
  id: 'win-logon-service',
  description: 'Service logon (4624, LogonType 5)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 5
},

// Detects network logons (SMB, file shares, LogonType 3)
{
  id: 'win-logon-network',
  description: 'Network logon (4624, LogonType 3)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 3
},

// Detects Remote Desktop Protocol logons (LogonType 10)
{
  id: 'win-logon-remote-desktop',
  description: 'Remote Desktop logon (4624, LogonType 10)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 10
},

// Detects failed logons (wrong password attempts)
{
  id: 'win-failed-logon',
  description: 'Failed logon (4625)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4625
},

// Detects account lockouts after multiple failed logins
{
  id: 'win-account-lockout',
  description: 'Account locked out (4740)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4740
},

// Detects creation of new local users
{
  id: 'win-user-created',
  description: 'User account created (4720)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4720
},

// Detects deletion of users
{
  id: 'win-user-deleted',
  description: 'User account deleted (4726)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4726
},

// Detects addition of users to privileged groups (e.g., Administrators)
{
  id: 'win-user-added-to-group',
  description: 'User added to group (4728)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4728
},

// Detects removal of users from groups
{
  id: 'win-user-removed-from-group',
  description: 'User removed from group (4729)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4729
},

// Detects password reset events
{
  id: 'win-password-reset',
  description: 'Password reset (4724)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4724
},

// Detects user password changes
{
  id: 'win-password-change',
  description: 'Password changed (4723)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4723
},

// Detects elevated privilege use
{
  id: 'win-privilege-assigned',
  description: 'Special privileges assigned (4672)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4672
},

// Detects Kerberos TGT requests (ticket-granting ticket)
{
  id: 'win-kerberos-tgt',
  description: 'Kerberos TGT requested (4768)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4768
},

// Detects Kerberos service ticket requests
{
  id: 'win-kerberos-service-ticket',
  description: 'Kerberos service ticket requested (4769)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 4769
},

// Detects clearing of the Security log (suspicious)
{
  id: 'win-security-log-cleared',
  description: 'Security log cleared (1102)',
  severity: 'critical',
  match: (decoded) => decoded.eventId === 1102
},

// Detects explicit user logoffs
{
  id: 'win-user-logoff',
  description: 'User logoff (4634)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 4634
},

// Detects scheduled task creation
{
  id: 'win-scheduled-task-created',
  description: 'Scheduled task created (4698)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4698
},

// Detects scheduled task deletion
{
  id: 'win-scheduled-task-deleted',
  description: 'Scheduled task deleted (4699)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4699
},

// Detects login attempts with disabled accounts
{
  id: 'win-disabled-account-logon',
  description: 'Logon attempt with disabled account (4625 substatus 0xC0000072)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4625 && decoded.subStatus === '0xC0000072'
},

// Detects anonymous logons
{
  id: 'win-anonymous-logon',
  description: 'Anonymous logon (4624, LogonType 3, ANONYMOUS LOGON)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 3 && /ANONYMOUS LOGON/i.test(decoded.accountName || '')
},

// Detects creation of a new login session (generic)
{
  id: 'win-new-logon-session',
  description: 'New logon session created (4624)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 4624
},

// Detects credential validation failures
{
  id: 'win-credential-validation-failure',
  description: 'Credential validation failed (4776)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4776
},

// Detects security policy changes
{
  id: 'win-security-policy-change',
  description: 'Security policy changed (4739)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 4739
},

// Detects enabling/disabling of user accounts
{
  id: 'win-account-enabled-disabled',
  description: 'User account enabled/disabled (4722 / 4725)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 4722 || decoded.eventId === 4725
},

 {
    id: 'win-logon-expired-password',
    description: 'Logon attempt with expired password (4625 substatus 0xC0000071)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4625 && decoded.subStatus === '0xC0000071'
  },

  // Detects logon attempt with expired account
  {
    id: 'win-logon-expired-account',
    description: 'Logon attempt with expired account (4625 substatus 0xC0000193)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4625 && decoded.subStatus === '0xC0000193'
  },

  // Detects logon attempt outside allowed hours
  {
    id: 'win-logon-outside-hours',
    description: 'Logon attempt outside allowed logon hours (4625 substatus 0xC000006F)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4625 && decoded.subStatus === '0xC000006F'
  },

  // Detects user added to Enterprise Admins group
  {
    id: 'win-user-added-enterprise-admins',
    description: 'User added to Enterprise Admins group (4728)',
    severity: 'critical',
    match: (decoded) => decoded.eventId === 4728 && /Enterprise Admins/i.test(decoded.groupName || '')
  },

  // Detects user added to Domain Admins group
  {
    id: 'win-user-added-domain-admins',
    description: 'User added to Domain Admins group (4728)',
    severity: 'critical',
    match: (decoded) => decoded.eventId === 4728 && /Domain Admins/i.test(decoded.groupName || '')
  },

  // Detects user logged on with explicit credentials (runas)
  {
    id: 'win-logon-explicit-credentials',
    description: 'Explicit credential logon (4648)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4648
  },

  // Detects workstation trust relationship failure
  {
    id: 'win-trust-failure',
    description: 'Workstation trust relationship failed (5722)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 5722
  },

  // Detects attempt to reset account lockout counter
  {
    id: 'win-account-lockout-reset',
    description: 'Account lockout counter reset (4767)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 4767
  },

  // Detects attempt to change auditing settings
  {
    id: 'win-audit-policy-changed',
    description: 'Audit policy changed (4719)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4719
  },

  // Detects attempt to clear audit logs
  {
    id: 'win-audit-log-cleared',
    description: 'Audit log cleared (1102)',
    severity: 'critical',
    match: (decoded) => decoded.eventId === 1102
  },

  // Detects attempt to create a new group
  {
    id: 'win-group-created',
    description: 'Security group created (4731)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4731
  },

  // Detects attempt to delete a security group
  {
    id: 'win-group-deleted',
    description: 'Security group deleted (4734)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4734
  },

  // Detects attempt to modify a security group
  {
    id: 'win-group-modified',
    description: 'Security group modified (4735)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4735
  },

  // Detects backup/restore privilege use
  {
    id: 'win-backup-restore-privilege',
    description: 'Backup/restore privilege used (4673)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4673
  },

  // Detects attempt to change account password by self
  {
    id: 'win-self-password-change',
    description: 'User changed own password (4723)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4723
  },

  // Detects attempt to change another user’s password
  {
    id: 'win-other-password-change',
    description: 'Password reset for another user (4724)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4724
  },

  // Detects kerberos ticket-granting service (TGS) request
  {
    id: 'win-kerberos-tgs-request',
    description: 'Kerberos service ticket request (4769)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4769
  },

  // Detects kerberos pre-authentication failure
  {
    id: 'win-kerberos-preauth-failure',
    description: 'Kerberos pre-authentication failed (4771)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4771
  },

  // Detects logon using cached credentials
  {
    id: 'win-logon-cached-credentials',
    description: 'Logon with cached credentials (4624, LogonType 11)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 11
  },

  // Detects logon attempt with smart card
  {
    id: 'win-logon-smart-card',
    description: 'Smart card logon (4624, LogonType 7)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4624 && decoded.logonType === 7
  },

//========================================================================================================================

//                                                      SYSTEM LOGS RULES

//========================================================================================================================

// Detects system reboot/shutdown events
{
  id: 'sys-shutdown',
  description: 'System shutdown (1074)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 1074
},

// Detects unexpected shutdown (crash or power loss)
{
  id: 'sys-unexpected-shutdown',
  description: 'Unexpected shutdown (6008)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 6008
},

// Detects Windows Update installation
{
  id: 'sys-windows-update',
  description: 'Windows update installed (19)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 19
},

// Detects driver failures
{
  id: 'sys-driver-failure',
  description: 'Driver failed to load (7026)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 7026
},

// Detects service start failures
{
  id: 'sys-service-start-failure',
  description: 'Service start failure (7000)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 7000
},

// Detects service termination unexpectedly
{
  id: 'sys-service-terminated',
  description: 'Service terminated unexpectedly (7031)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 7031
},

// Detects disk errors
{
  id: 'sys-disk-error',
  description: 'Disk error (7)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 7
},

// Detects memory errors
{
  id: 'sys-memory-error',
  description: 'Memory error detected (1000)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 1000
},

// Detects time synchronization issues
{
  id: 'sys-time-sync-failure',
  description: 'Time synchronization failure (36)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 36
},

// Detects blue screen of death crashes
{
  id: 'sys-bsod',
  description: 'System crash (1001)',
  severity: 'critical',
  match: (decoded) => decoded.eventId === 1001
},

// Detects network adapter disconnects
{
  id: 'sys-network-disconnect',
  description: 'Network adapter disconnected (27)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 27
},

// Detects system log cleared
{
  id: 'sys-log-cleared',
  description: 'System log cleared (104)',
  severity: 'critical',
  match: (decoded) => decoded.eventId === 104
},

// Detects battery/power issues
{
  id: 'sys-power-issue',
  description: 'Power issue detected (12)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 12
},

// Detects network driver errors
{
  id: 'sys-network-driver-error',
  description: 'Network driver error (5002)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 5002
},

// Detects system entering sleep/hibernate
{
  id: 'sys-sleep-mode',
  description: 'System sleep/hibernate (42)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 42
},

// Detects DNS server failure
  {
    id: 'sys-dns-server-failure',
    description: 'DNS server failure (4013)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 4013
  },

  // Detects DHCP server startup failure
  {
    id: 'sys-dhcp-failure',
    description: 'DHCP server failed to start (1059)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 1059
  },

  // Detects time service sync failure
  {
    id: 'sys-time-service-failure',
    description: 'Windows Time Service failed (36)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 36
  },

  // Detects Windows Defender service failure
  {
    id: 'sys-defender-failure',
    description: 'Windows Defender service failed (5007)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 5007
  },

  // Detects printer service error
  {
    id: 'sys-printer-error',
    description: 'Printer service error (808)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 808
  },

  // Detects disk space low warning
  {
    id: 'sys-low-disk-space',
    description: 'Low disk space (2013)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 2013
  },

  // Detects NIC driver reset
  {
    id: 'sys-nic-reset',
    description: 'Network adapter reset (10400)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 10400
  },

  // Detects storage device removed
  {
    id: 'sys-storage-removed',
    description: 'Storage device removed (11)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 11
  },

  // Detects thermal shutdown warning
  {
    id: 'sys-thermal-shutdown',
    description: 'Thermal shutdown warning (13)',
    severity: 'critical',
    match: (decoded) => decoded.eventId === 13
  },

  // Detects Windows update rollback
  {
    id: 'sys-update-rollback',
    description: 'Windows update rollback detected (20)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 20
  },

//===========================================================================================================================

//                                                        APPLICATION LOGS RULES

//===========================================================================================================================

// Detects application crashes
{
  id: 'app-crash',
  description: 'Application crash (1000)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 1000
},

// Detects application hang (not responding)
{
  id: 'app-hang',
  description: 'Application hang (1002)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 1002
},

// Detects .NET runtime errors
{
  id: 'app-dotnet-error',
  description: '.NET Runtime error (1026)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 1026
},

// Detects SQL Server failures
{
  id: 'app-sql-failure',
  description: 'SQL Server failure (18456)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 18456
},

// Detects Exchange Server transport errors
{
  id: 'app-exchange-error',
  description: 'Exchange transport error (12014)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 12014
},

// Detects Outlook errors
{
  id: 'app-outlook-error',
  description: 'Outlook application error (25)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 25
},

// Detects antivirus alerts
{
  id: 'app-antivirus-detection',
  description: 'Antivirus threat detected (1116)',
  severity: 'critical',
  match: (decoded) => decoded.eventId === 1116
},

// Detects Office application crashes
{
  id: 'app-office-crash',
  description: 'Microsoft Office crash (1005)',
  severity: 'medium',
  match: (decoded) => decoded.eventId === 1005
},

// Detects IIS web server errors
{
  id: 'app-iis-error',
  description: 'IIS web server error (500)',
  severity: 'high',
  match: (decoded) => decoded.eventId === 500
},

// Detects custom application warnings
{
  id: 'app-custom-warning',
  description: 'Custom application warning (3001)',
  severity: 'low',
  match: (decoded) => decoded.eventId === 3001
},

// Detects MS SQL login failed due to disabled account
  {
    id: 'app-sql-disabled-account',
    description: 'SQL login failed - disabled account (18456, state 7)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 18456 && decoded.state === 7
  },

  // Detects SQL login failed due to wrong password
  {
    id: 'app-sql-wrong-password',
    description: 'SQL login failed - wrong password (18456, state 8)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 18456 && decoded.state === 8
  },

  // Detects Exchange service authentication failure
  {
    id: 'app-exchange-auth-failure',
    description: 'Exchange service authentication failure (1009)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 1009
  },

  // Detects IIS worker process crash
  {
    id: 'app-iis-worker-crash',
    description: 'IIS worker process crash (5010)',
    severity: 'high',
    match: (decoded) => decoded.eventId === 5010
  },

  // Detects .NET application unhandled exception
  {
    id: 'app-dotnet-unhandled-exception',
    description: '.NET unhandled exception (1026)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 1026
  },

  // Detects antivirus definition update
  {
    id: 'app-antivirus-update',
    description: 'Antivirus definition update (2001)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 2001
  },

  // Detects Office license activation failure
  {
    id: 'app-office-license-failure',
    description: 'Office license activation failed (1008)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 1008
  },

  // Detects Outlook connection to Exchange failed
  {
    id: 'app-outlook-connection-failed',
    description: 'Outlook failed to connect to Exchange (26)',
    severity: 'low',
    match: (decoded) => decoded.eventId === 26
  },

  // Detects custom application startup failure
  {
    id: 'app-custom-startup-failure',
    description: 'Custom application startup failure (4001)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 4001
  },

  // Detects browser crash
  {
    id: 'app-browser-crash',
    description: 'Browser crash (1003)',
    severity: 'medium',
    match: (decoded) => decoded.eventId === 1003
  },


];

module.exports = windowsRules;
