# Success Local Logon with Admin Account

## Context

This log sequence represents a **local interactive logon** by a user with **administrative privileges**  
on a standalone Windows machine (`DESKTOP-PKG4R8C`).  
The events illustrate how Windows handles **split-token logons** for admin users under  
**User Account Control (UAC)**.

## Event summary

| Event ID | Type     | Description                                         |
|----------|----------|-----------------------------------------------------|
| 4624     | Logon    | Logon using **elevated token** (admin privileges)   |
| 4624     | Logon    | Logon using **standard token** (limited privileges) |
| 4672     | Privilege Assignment | Special privileges assigned to admin session |
| 4634     | Logoff   | Logoff of the **elevated token** session            |

## Key characteristics 

- **First Logon Event (Logon ID: `0x4EA518`)**
  - Elevated token (admin privileges granted by UAC)
  - Linked to standard token `0x4EA536`
- **Second Logon Event (Logon ID: `0x4EA536`)**
  - Standard token (default user context)
  - Linked back to elevated token `0x4EA518`
- **Special Privileges Assigned (Event 4672)**
  - Issued **immediately after** elevated token logon
  - Includes:
    - `SeDebugPrivilege`
    - `SeBackupPrivilege`
    - `SeTakeOwnershipPrivilege`
    - `SeRestorePrivilege`
    - `SeImpersonatePrivilege`
    - Others tied to full administrative control
- **Logoff Event**
  - For Logon ID `0x4EA518`
  - Marks the end of the **elevated** session
- **Authentication Context**
  - **Logon Process:** `User32`
  - **Authentication Package:** `Negotiate`
  - Common for local GUI logins
- **Source IP Address**
  - `127.0.0.1` — confirms **local login**

## Security relevance

Monitoring this **multi-event sequence** is critical to:

- **Track elevated logons** and privileged session activity
- Identify potential **unauthorized privilege escalation**
- Separate **normal user activity** from admin-level actions

If Event ID **4672** is seen **without a corresponding elevated logon**, or outside business hours,  
it may indicate suspicious behavior—especially on critical systems.

## Relevant resources

- [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [Logon types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)
- [Blog about Windows Privilege Abuse](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)


## Examples

```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T20:44:24.8142716Z","eventRecordID":"88669","processID":"652","threadID":"2632","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-PKG4R8C$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t2\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x4EA518\r\n\tLinked Logon ID:\t\t0x4EA536\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x5e0\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-PKG4R8C\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-PKG4R8C$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x4ea518","logonType":"2","logonProcessName":"User32","authenticationPackageName":"Negotiate","workstationName":"DESKTOP-PKG4R8C","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x5e0","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipAddress":"127.0.0.1","ipPort":"0","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x4ea536","elevatedToken":"%%1842"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T20:44:24.8142892Z","eventRecordID":"88670","processID":"652","threadID":"2632","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-PKG4R8C$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t2\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x4EA536\r\n\tLinked Logon ID:\t\t0x4EA518\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x5e0\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-PKG4R8C\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-PKG4R8C$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x4ea536","logonType":"2","logonProcessName":"User32","authenticationPackageName":"Negotiate","workstationName":"DESKTOP-PKG4R8C","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x5e0","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipAddress":"127.0.0.1","ipPort":"0","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x4ea518","elevatedToken":"%%1843"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4672","version":"0","level":"0","task":"12548","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T20:44:24.8143020Z","eventRecordID":"88671","processID":"652","threadID":"2632","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"Special privileges assigned to new logon.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x4EA518\r\n\r\nPrivileges:\t\tSeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\""},"eventdata":{"subjectUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","subjectUserName":"Alejandro Rodriguez","subjectDomainName":"DESKTOP-PKG4R8C","subjectLogonId":"0x4ea518","privilegeList":"SeSecurityPrivilege     SeTakeOwnershipPrivilege     SeLoadDriverPrivilege     SeBackupPrivilege     SeRestorePrivilege     SeDebugPrivilege     SeSystemEnvironmentPrivilege     SeImpersonatePrivilege     SeDelegateSessionUserImpersonatePrivilege"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4634","version":"0","level":"0","task":"12545","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T20:44:25.4138681Z","eventRecordID":"88673","processID":"652","threadID":"8144","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was logged off.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x4EA518\r\n\r\nLogon Type:\t\t\t2\r\n\r\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.\""},"eventdata":{"targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x4ea518","logonType":"2"}}}
```
