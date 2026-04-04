# MFASweep

**Purpose:** Test M365/O365 endpoints for MFA enforcement gaps using known valid credentials  
**Install:** `git clone https://github.com/dafthack/MFASweep` (PowerShell module)  
**Tags:** #tool #mfasweep #mfa #m365 #o365 #duo #legacy-auth

---

## Requirements
- PowerShell (Linux: `sudo apt install -y powershell` → `pwsh`)
- Valid username (UPN format: `user@domain.com`) + password
- No admin required — outbound HTTPS only

---

## Basic Usage

```bash
# Single account
pwsh -c "Import-Module ./MFASweep.ps1; Invoke-MFASweep -Username user@domain.com -Password 'Summer2023!'"

# Bulk loop with output saved
pwsh << 'EOF' 2>&1 | tee mfasweep_results.txt
Import-Module ./MFASweep.ps1

$users = Get-Content ./upn_usernames.txt   # must be UPN format
$passes = Get-Content ./passwords.txt

for ($i = 0; $i -lt $users.Count; $i++) {
    Write-Host "`n=== Testing: $($users[$i]) ===" -ForegroundColor Cyan
    Invoke-MFASweep -Username $users[$i] -Password $passes[$i]
    Start-Sleep -Seconds 2   # avoid Smart Lockout triggering
}
EOF
```

---

## Endpoints Tested

| Endpoint | Notes |
|----------|-------|
| Microsoft Graph API | Modern auth |
| Azure AD | Modern auth |
| Exchange Web Services (EWS) | Legacy — common bypass |
| ActiveSync | Legacy — common bypass |
| Outlook Web Access | Browser flow |
| M365 w/ iPhone UA | Mobile UA spoof — **most common finding** |
| MSOnline | Windows-native module; may fail on Linux |

---

## Output Interpretation

| Result | Meaning |
|--------|---------|
| `Single Factor Access: Yes` | Authenticated without MFA — **finding** |
| `Single Factor Access: No` | MFA enforced correctly on this endpoint |
| No output / error | Bad credentials or endpoint unreachable |

**Wrong password returns `No`, not an error — a `Yes` result confirms both valid credential AND MFA bypass.**

---

## iPhone UA Bypass Proof

When MFASweep returns `M365 w/ iPhone UA | Yes`:
1. Install Firefox extension: "User Agent Switcher and Manager" (from addons.mozilla.org)
2. Set custom UA: `Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/605.1.15`
3. Navigate to `https://outlook.office365.com`
4. Login — if inbox loads without Duo prompt → exploited

---

## Notes
- **No built-in output file** — always pipe to `tee`
- Usernames must be UPN format (`user@domain.com`), not bare `username`
- 3/3 same result on iPhone UA = systemic tenant policy gap; no need to test all accounts
- Azure AD Smart Lockout: 10 failed attempts default; testing 1 attempt/endpoint per confirmed valid cred = safe
- MFASweep has no built-in rate limiting — add `Start-Sleep -Seconds 2` between accounts

---

## Related
- [[mfa-bypass-legacy-auth]]
- [[ntds-account-mapping]]
