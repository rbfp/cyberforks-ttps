# SMB Signing Audit

**MITRE:** [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)  
**Phase:** Reconnaissance  
**Auth Required:** Yes (low-priv domain creds)  
**Tags:** #recon #smb #signing #relay-prereq

---

## Summary
Enumerate hosts with SMB signing disabled or not required. These hosts are vulnerable to NTLM relay attacks — an attacker who can coerce or capture NTLM authentication can relay it to unsigned hosts to execute commands or access shares as the coerced identity.

## Mechanism
- **Protocol:** SMB (445/TCP)
- **Function:** SMB negotiation flags — `SecurityMode` field indicates whether signing is required, enabled, or disabled
- **Effect:** Identifies relay targets; hosts with signing not required will accept relayed NTLM auth without verifying message integrity

## Commands
```bash
# Scan a subnet for SMB signing status
nxc smb 10.0.0.0/24 -u <user> -p <password> --gen-relay-list /tmp/unsigned-smb.txt

# Output file contains only hosts with signing NOT required
# These are valid targets for ntlmrelayx
```

Alternative (unauthenticated, less reliable):
```bash
nmap --script smb2-security-mode -p 445 10.0.0.0/24
```

## Expected Output
```
SMB   10.0.0.50  445  HOST01  [*] Windows 10 x64 (signing:False)
SMB   10.0.0.51  445  HOST02  [*] Windows 10 x64 (signing:False)
...
[*] Saved 142 hosts to /tmp/unsigned-smb.txt
```

## Notes
- Domain Controllers typically enforce signing by default (GPO: `Microsoft network server: Digitally sign communications (always)`)
- Workstations and member servers often do NOT enforce signing — this is the common gap
- The number of unsigned hosts is itself a finding (142 out of a /24 = significant exposure)
- Even if DCs enforce signing, coerced DC auth can be relayed to unsigned member servers

## Relay / Follow-On Attack Path
1. Generate unsigned host list (`--gen-relay-list`)
2. Start relay: `ntlmrelayx -tf /tmp/unsigned-smb.txt -socks`
3. Coerce a high-value target (DC via PetitPotam/PrinterBug)
4. Relay lands on unsigned host → SOCKS tunnel established
5. `proxychains` through tunnel for lateral movement as coerced identity

Also feeds into: [[petitpotam]], [[printerbug]], [[dfscoerce]], [[mseven]]

## Remediation
- Enable SMB signing via GPO: **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options**
  - `Microsoft network server: Digitally sign communications (always)` → Enabled
  - `Microsoft network client: Digitally sign communications (always)` → Enabled
- Apply to ALL domain-joined hosts, not just DCs
- Monitor for signing negotiation downgrades

## Related
- [[petitpotam]] — coercion source for relay
- [[printerbug]] — coercion source for relay
- [[ntlmv1-permitted]] — NTLMv1 makes relay even more dangerous
