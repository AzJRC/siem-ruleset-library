# Success RDP Logon with Admin Account

## Context

This log sequence captures a remote interactive logon via Windows RDP from IP address 10.147.18.23,
by the user Alejandro Rodriguez, on the host DESKTOP-PKG4R8C.
The session included administrative privileges, triggering special privilege assignment.
This is a classic example of split-token logon behavior in RDP scenarios.

## Event summary

| Event ID | Type                   | Description                                               |
|----------|------------------------|-----------------------------------------------------------|
| 4624     | Logon                  | RDP Logon using **elevated token** (admin privileges)     |
| 4624     | Logon                  | RDP logon using **standard token** (limited privileges)   |
| 4672     | Privilege Assignment   | Special privileges assigned to admin session              |
| 4634     | Logoff                 | Logoff of the **elevated token** session                  |

## Key characteristics

- **First Logon Event (Logon ID: `0x7B4A46`)**
  - **Logon Type:** `10` (Remote Interactive - RDP)
  - **Elevated Token:** Yes
  - **Source IP:** `10.147.18.23`
  - **Linked Logon ID:** `0x7B4A64`
  - **Process:** `C:\Windows\System32\svchost.exe`

- **Second Logon Event (Logon ID: `0x7B4A64`)**
  - **Standard Token:** Yes
  - **Linked to Elevated Token:** `0x7B4A46`
  - Also originated from the same IP and machine

- **Special Privileges Assigned (Event 4672)**
  - For Logon ID: `0x7B4A46` (elevated session)
  - Assigned Privileges.
    - `SeSecurityPrivilege`
    - `SeDebugPrivilege`
    - `SeTakeOwnershipPrivilege`
    - `SeBackupPrivilege`
    - `SeRestorePrivilege`
    - `SeImpersonatePrivilege`
    - `SeLoadDriverPrivilege`
    - `SeSystemEnvironmentPrivilege`
    - `SeDelegateSessionUserImpersonatePrivilege`

- **Logoff Event**
  - Occurs for Logon ID: `0x7B4A46` (elevated)
  - Indicates session teardown
  - Matches RDP behavior—session ends cleanly

- **Authentication Context**
  - **Logon Process:** `User32`
  - **Authentication Package:** `Negotiate`
  - **Workstation Name:** `DESKTOP-PKG4R8C`
  - **Impersonation Level:** `Impersonation`

- **Remote Details**
  - **Source IP:** `10.147.18.23`
  - **Port:** `0` (common in Windows logs—may not reflect true port)
  - **Remote Admin Mode:** No

## Security Relevance

Monitoring this sequence is crucial for:

- Detecting **remote logons** via RDP, especially those with **admin privileges**
- Identifying **privilege escalation opportunities** or lateral movement
- Distinguishing **split-token activity** (UAC behavior)
- Investigating **potential abuse** of powerful privileges like `SeDebugPrivilege`

If **4672** occurs without a valid RDP logon (`4624` with `Logon Type 10`) or from unusual IPs, it may suggest **malicious access**.
Use `TargetLogonId` and `LinkedLogonId` to **correlate sessions**, especially when reviewing RDP and service logons in forensic investigations.

## Relevant resources

- [Event 4624 (Logon)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Event 4672 (Privileges)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [Event 4634 (Logoff)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634)
- [Logon Types Reference](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)
- [Detecting RDP Abuse (Blog)](https://posts.specterops.io/rdp-tunneling-and-detection-3d5e058a1e4d)

## Examples

```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T22:21:13.0846337Z","eventRecordID":"88863","processID":"652","threadID":"2324","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-PKG4R8C$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t10\r\n\tRestricted Admin Mode:\tNo\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x7B4A46\r\n\tLinked Logon ID:\t\t0x7B4A64\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x5e0\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-PKG4R8C\r\n\tSource Network Address:\t10.147.18.23\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-PKG4R8C$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x7b4a46","logonType":"10","logonProcessName":"User32","authenticationPackageName":"Negotiate","workstationName":"DESKTOP-PKG4R8C","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x5e0","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipAddress":"10.147.18.23","ipPort":"0","impersonationLevel":"%%1833","restrictedAdminMode":"%%1843","virtualAccount":"%%1843","targetLinkedLogonId":"0x7b4a64","elevatedToken":"%%1842"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T22:21:13.0846622Z","eventRecordID":"88864","processID":"652","threadID":"2324","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-PKG4R8C$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t10\r\n\tRestricted Admin Mode:\tNo\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x7B4A64\r\n\tLinked Logon ID:\t\t0x7B4A46\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x5e0\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-PKG4R8C\r\n\tSource Network Address:\t10.147.18.23\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-PKG4R8C$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x7b4a64","logonType":"10","logonProcessName":"User32","authenticationPackageName":"Negotiate","workstationName":"DESKTOP-PKG4R8C","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x5e0","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipAddress":"10.147.18.23","ipPort":"0","impersonationLevel":"%%1833","restrictedAdminMode":"%%1843","virtualAccount":"%%1843","targetLinkedLogonId":"0x7b4a46","elevatedToken":"%%1843"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4672","version":"0","level":"0","task":"12548","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T22:21:13.0846670Z","eventRecordID":"88865","processID":"652","threadID":"2324","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"Special privileges assigned to new logon.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x7B4A46\r\n\r\nPrivileges:\t\tSeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\""},"eventdata":{"subjectUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","subjectUserName":"Alejandro Rodriguez","subjectDomainName":"DESKTOP-PKG4R8C","subjectLogonId":"0x7b4a46","privilegeList":"SeSecurityPrivilege     SeTakeOwnershipPrivilege     SeLoadDriverPrivilege     SeBackupPrivilege     SeRestorePrivilege     SeDebugPrivilege     SeSystemEnvironmentPrivilege     SeImpersonatePrivilege     SeDelegateSessionUserImpersonatePrivilege"}}}

{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4634","version":"0","level":"0","task":"12545","opcode":"0","keywords":"0x8020000000000000","systemTime":"2025-04-07T22:21:23.4614925Z","eventRecordID":"88874","processID":"652","threadID":"2632","channel":"Security","computer":"DESKTOP-PKG4R8C","severityValue":"AUDIT_SUCCESS","message":"\"An account was logged off.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-1632818884-2934230513-1744596819-1001\r\n\tAccount Name:\t\tAlejandro Rodriguez\r\n\tAccount Domain:\t\tDESKTOP-PKG4R8C\r\n\tLogon ID:\t\t0x7B4A46\r\n\r\nLogon Type:\t\t\t10\r\n\r\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.\""},"eventdata":{"targetUserSid":"S-1-5-21-1632818884-2934230513-1744596819-1001","targetUserName":"Alejandro Rodriguez","targetDomainName":"DESKTOP-PKG4R8C","targetLogonId":"0x7b4a46","logonType":"10"}}}
```