# Account Lockout Status Check

**MITRE:** [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)  
**Phase:** Reconnaissance / Post-Exploitation  
**Auth Required:** Yes (Domain Admin preferred)  
**Tags:** #recon #lockout #active-directory #powershell #domain-admin

---

## Summary
After credential validation or spraying activity, verify no accounts were locked out. With DA access, query Active Directory directly for lockout status, bad password count, and last bad password time. Essential for post-activity cleanup and client debrief documentation.

## Mechanism
- **Protocol:** LDAP / PowerShell (Get-ADUser)
- **Function:** Reads lockoutTime, badPwdCount, and LockedOut attributes from AD
- **Effect:** Confirms whether testing activity caused any account lockouts

## Commands
```bash
# Single account check via nxc
nxc smb <DC_IP> -u <DA_user> -p <DA_pass> --exec-method wmiexec -X \
"Get-ADUser <username> -Properties LockedOut,BadLogonCount,BadPasswordTime | Select SamAccountName,LockedOut,BadLogonCount | Format-List"

# All locked accounts at once (PowerShell directly on DC)
Search-ADAccount -LockedOut | Select SamAccountName,LockedOut,LastLogonDate

# Bulk check list of usernames (PowerShell on DC)
Get-Content C:\temp\usernames.txt | ForEach-Object {
    Get-ADUser $_ -Properties LockedOut,BadLogonCount |
    Select SamAccountName,LockedOut,BadLogonCount
}

# Check all locked accounts via LDAP query
nxc ldap <DC_IP> -u <DA_user> -p <DA_pass> \
  --query "(&(objectClass=user)(lockoutTime>=1))" "sAMAccountName,lockoutTime"
```

## Expected Output
```powershell
SamAccountName : jsmith
LockedOut      : False
BadLogonCount  : 1

SamAccountName : bwilliams
LockedOut      : True     ← locked out
BadLogonCount  : 25
```

## Notes
- **LockedOut: True** = account is currently locked; requires unlock or wait for lockout window
- **BadLogonCount** resets after successful auth or after lockout window expires
- DA access required for `Get-ADUser` with `-Properties LockedOut` — low-priv can't read lockout attributes
- File transfer to DC options (if needed): impacket SMB share (`impacket-smbserver`), Windows share relay, or certutil download
- nxc `-x` (cmd.exe) vs `-X` (PowerShell directly) — use `-X` for Get-ADUser; `-x` may not inherit AD module
- wmiexec exec method returns output more reliably than default smbexec

## Relay / Follow-On Attack Path
- Unlock accounts if needed: `Unlock-ADAccount -Identity <username>`
- Document lockout state pre/post testing for client debrief

## Remediation
- N/A (defender-side: monitor badPwdCount spikes for spray detection)
- Alert on accounts exceeding 3+ bad password attempts within lockout window

## Related
- [[ntds-account-mapping]]
- [[domain-password-policy]]
- [[ntlm-hash-cracking]]
