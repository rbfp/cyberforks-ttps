# Null Session Enumeration

**MITRE:** [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)  
**Phase:** Reconnaissance  
**Auth Required:** No  
**Tags:** #recon #smb #null-session #unauthenticated #windows

---

## Summary
Null sessions are unauthenticated SMB connections that allow anonymous access to Windows systems. When not properly restricted, an attacker with only network access can enumerate users, groups, shares, password policy, and OS information — before obtaining any credentials.

Run early in every Windows/AD engagement to establish an unauthenticated baseline before using supplied creds.

## Mechanism
- **Protocol:** SMB (445/TCP) + RPC
- **Function:** Anonymous bind to IPC$ share, then RPC calls over the session
- **Registry key:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous`
  - `0` → full null session access
  - `1` → null session connects but share/SAM enum restricted
  - `2` → null sessions blocked entirely (you won't get a `[+]`)

## Commands
```bash
# Step 1 — Test null session connectivity on DCs
nxc smb <DC_IP_range> -u '' -p ''

# Step 2 — Full enumeration sweep
enum4linux -a <DC_IP>

# Step 3 — If enum4linux blocked, try nxc fallback
nxc smb <DC_IP> -u '' -p '' --users
nxc smb <DC_IP> -u '' -p '' --pass-pol
```

## Expected Output
```
# nxc null session connect
SMB   10.0.0.10  445  DC01  [+] domain.net\: (null session)
SMB   10.0.0.10  445  DC01  [-] Error enumerating shares: STATUS_ACCESS_DENIED

# [+] with STATUS_ACCESS_DENIED = RestrictAnonymous=1
# Still attempt enum4linux — RPC user/policy enum may still work
```

## Interpreting Results

| nxc Output | Meaning |
|------------|---------|
| `[+] domain\:` + shares visible | RestrictAnonymous=0, fully open |
| `[+] domain\:` + STATUS_ACCESS_DENIED | RestrictAnonymous=1, partial — try enum4linux |
| No `[+]`, connection refused | RestrictAnonymous=2, blocked |

## Notes
- `[+]` on null session connection is itself the finding — document even if share enum is denied
- Run **before** using any supplied test credentials — establishes unauthenticated attacker baseline
- Compare unauthenticated vs authenticated results in report to show delta
- Pairs with [[domain-account-discovery-rpc]] for user enumeration follow-on

## Remediation
- Set `RestrictAnonymous = 2` via GPO to block null sessions entirely
- Set `RestrictAnonymousSAM = 1` to block SAM enumeration
- GPO path: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
  - `Network access: Do not allow anonymous enumeration of SAM accounts` → Enabled
  - `Network access: Do not allow anonymous enumeration of SAM accounts and shares` → Enabled
  - `Network access: Restrict anonymous access to Named Pipes and Shares` → Enabled

## Related
- [[domain-account-discovery-rpc]] — user/group enum via null session
- [[dc-discovery-dns]] — DC enumeration prerequisite
- [[tools/enum4linux]]
- [[tools/nxc]]
