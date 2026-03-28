# Impacket — addcomputer.py

**Part of:** Impacket suite  
**Install:** `pipx install impacket` or pre-installed on Kali  
**Tags:** #tool #AD #impacket #machineaccount

---

## Overview
Adds a machine account to an Active Directory domain. Used as a prerequisite for AD CS ESC1 attacks when vulnerable certificate templates restrict enrollment to `Domain Computers` rather than `Domain Users`.

## Usage

```bash
addcomputer.py '[domain]/[username]:[password]' \
  -dc-ip [dc-ip] \
  -method LDAPS \
  -computer-name [machine-name] \
  -computer-pass [machine-password]
```

### Methods
| Method | Notes |
|--------|-------|
| `LDAPS` | Preferred — uses LDAP over SSL (636/TCP) |
| `SAMR` | Fallback — uses MS-SAMR RPC |

## Expected Output
```
[*] Successfully added machine account EVILPC$ with password P@ssw0rd123
```

The `$` suffix is appended automatically — the machine account will be `[machine-name]$`.

## Notes
- Any domain user can add up to **10 machine accounts** by default (Machine Account Quota = 10)
- If MAQ = 0, this technique fails — need an existing machine account or different enrollment path
- Machine accounts have broader certificate template enrollment rights than regular users by default
- Use the machine account in `certipy req` as `-u '[machine-name]$' -p '[machine-pass]'`
- Check MAQ value: `nxc ldap [dc-ip] -u [user] -p [pass] -M maq`

## Relay / Follow-On Attack Path
- Machine account created → use in [[adcs-esc1-san-impersonation]] certipy req

## Related
- [[ttps/credential-access/adcs-esc1-san-impersonation]]
- [[tools/certipy]]
