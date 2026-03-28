# AD User Enumeration

**MITRE:** [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)  
**Phase:** Reconnaissance  
**Auth Required:** Yes (low-priv domain creds)  
**Tags:** #recon #AD #ldap #enumeration

---

## Summary
Enumerate domain users, privileged accounts, and service accounts via LDAP using NetExec. Used to identify high-value targets for follow-on attacks such as ESC1 certificate impersonation or Pass-the-Hash.

## Mechanism
- **Protocol:** LDAP (389/TCP or 636/TCP)
- **RPC/Function:** LDAP queries against Active Directory
- **Effect:** Returns user accounts, group memberships, and privilege indicators

## Commands

```bash
# Enumerate all domain users
nxc ldap [dc-ip] -u '[user]' -p '[password]' --users

# Enumerate Domain Admins group
nxc ldap [dc-ip] -u '[user]' -p '[password]' --groups "Domain Admins"

# Enumerate Enterprise Admins group
nxc ldap [dc-ip] -u '[user]' -p '[password]' --groups "Enterprise Admins"

# Find accounts with AdminCount=1 (were ever in a privileged group)
nxc ldap [dc-ip] -u '[user]' -p '[password]' --admin-count

# Get UPN + SID for a specific target account
nxc ldap [dc-ip] -u '[user]' -p '[password]' --query "(sAMAccountName=[target])" "sAMAccountName objectSid userPrincipalName"
```

## Expected Output
```
LDAP  10.0.0.10  389  DC01  [*] Domain Users:
LDAP  10.0.0.10  389  DC01  svc_scanner  S-1-5-21-1234567890-987654321-1122334455-1234
```

## Notes
- `--admin-count` is the sleeper hit — catches over-privileged service accounts that aren't directly in DA group but were granted elevated rights at some point and never cleaned up (e.g. `svc_scanner`)
- UPN format is typically `sAMAccountName@domain` (e.g. `svc_scanner@corp.local`)
- SID format: `S-1-5-21-[domain-SID]-[RID]` — needed for certipy req `-sid` flag

## Relay / Follow-On Attack Path
- Identified DA/high-priv accounts → target for [[adcs-esc1-san-impersonation]]
- UPN + SID → feed directly into `certipy req -upn -sid`

## Remediation
- Enforce least privilege — audit AdminCount=1 accounts regularly
- Remove accounts from privileged groups when no longer needed (AdminCount does not auto-reset)
- Service accounts should have minimum required permissions only

## Related
- [[ttps/recon/dc-discovery-dns]]
- [[ttps/credential-access/adcs-esc1-san-impersonation]]
- [[tools/nxc]]
