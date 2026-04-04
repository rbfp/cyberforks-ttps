# Domain Password Policy Enumeration

**MITRE:** [T1201 - Password Policy Discovery](https://attack.mitre.org/techniques/T1201/)  
**Phase:** Reconnaissance  
**Auth Required:** Yes (low-priv domain creds)  
**Tags:** #recon #password-policy #nxc #active-directory

---

## Summary
Enumerate the domain password policy to document minimum length, complexity requirements, lockout threshold, and password history. Critical for understanding cracking constraints, spray safety windows, and identifying gaps between stated policy and actual account state.

## Mechanism
- **Protocol:** SMB / LDAP
- **Function:** Reads domain password policy via NetLogon/LDAP
- **Effect:** Reveals lockout thresholds, minimum length, complexity rules, and history depth

## Commands
```bash
# Enumerate password policy via NetExec
nxc smb <DC_IP> -u <user> -p <password> --pass-pol

# Save output for reference
nxc smb <DC_IP> -u <user> -p <password> --pass-pol | tee password_policy.txt

# Via LDAP (more detail on fine-grained policies)
nxc ldap <DC_IP> -u <user> -p <password> --password-not-required
```

## Expected Output
```
SMB   10.0.0.10  445  DC01  [+] DOMAIN\user:password
SMB   10.0.0.10  445  DC01  [*] Dumping password info for domain: DOMAIN
SMB   10.0.0.10  445  DC01  Minimum password length: 12
SMB   10.0.0.10  445  DC01  Password history length: 24
SMB   10.0.0.10  445  DC01  Maximum password age: 90 days
SMB   10.0.0.10  445  DC01  Password Complexity Flags: 0x00000001
SMB   10.0.0.10  445  DC01  Account Lockout Threshold: 25
SMB   10.0.0.10  445  DC01  Account Lockout Duration: 30 mins
SMB   10.0.0.10  445  DC01  Account Lockout Window: 30 mins
```

## Notes
- **Lockout Threshold** is critical before any spray — know your limit; lockout threshold of 25 = safe for targeted validation (1 attempt per account)
- **Azure AD Smart Lockout is separate** — on-prem AD and Azure AD lockout counters are independent; O365 default = 10 failed attempts
- **Policy gap finding:** if min length = 12 but cracked passwords are 7-8 chars → accounts predate policy change and were never forced to rotate
- Fine-grained password policies (PSOs) may apply to specific OUs/groups — default policy may not reflect all accounts
- Null session may expose policy without creds on misconfigured DCs: `enum4linux -P <DC_IP>`

## Relay / Follow-On Attack Path
- Use lockout threshold to calculate safe spray window
- Document policy gap as standalone finding if cracked passwords violate stated minimums
- Feed minimum length into hashcat mask attack tuning

## Remediation
- Enforce policy retroactively — force password reset for accounts with non-compliant passwords
- Implement Azure AD Password Protection on-prem to block common/seasonal patterns
- Consider reducing lockout threshold to 5-10 (balance security vs helpdesk load)
- Enable fine-grained policies for privileged accounts (stricter requirements)

## Related
- [[ntlm-hash-cracking]]
- [[ntds-account-mapping]]
- [[account-lockout-check]]
