# PrinterBug (SpoolSS)

**MITRE:** [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)  
**Phase:** Credential Access  
**Auth Required:** Yes (any domain user)  
**Tags:** #coercion #AD #NTLM #windows #DC #spooler

---

## Summary
Abuses MS-RPRN (Print Spooler / spoolss) to force a target machine to authenticate outbound via NTLM. A feature, not a bug — Microsoft considers this intended behavior. No patch available; remediation is disabling the service.

## Mechanism
- Protocol: MS-RPRN
- RPC call: `spoolss\` (RpcRemoteFindFirstPrinterChangeNotification)
- Forces target to initiate NTLM auth to attacker listener

## Key Notes
- **Misconfiguration-based** — no CVE, no patch
- Print Spooler enabled by default on most Windows hosts including DCs
- DCs do not need the Print Spooler service — safe to disable

## Detection
- `coerce_plus` module in [[tools/nxc]]
- Passive scanners cannot reliably detect — requires active coercion attempt

## Relay Attack Path
Same as [[ttps/coercion/petitpotam]] — relay captured hash to AD CS, LDAP, etc.

## Remediation
- **Disable Print Spooler on all Domain Controllers**
  ```powershell
  Stop-Service -Name Spooler -Force
  Set-Service -Name Spooler -StartupType Disabled
  ```
- Enable SMB signing and LDAP signing

## Related
- [[ttps/coercion/petitpotam]]
- [[ttps/coercion/dfscoerce]]
- [[playbooks/ad-coercion-validation]]
