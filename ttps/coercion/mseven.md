# MSEven (Event Log Coercion)

**MITRE:** [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)  
**Phase:** Credential Access  
**Auth Required:** Yes (low-priv domain user)  
**Tags:** #coercion #AD #NTLM #windows #DC #eventlog

---

## Summary
Abuses MS-EVEN (Event Log) protocol to force NTLM authentication from a target. Newer coercion vector, less commonly seen in the wild but confirmed functional.

## Mechanism
- Protocol: MS-EVEN (Event Log)
- Forces target to initiate NTLM auth to attacker listener

## Notes
- Less documented than PetitPotam/PrinterBug but same impact
- Detected by `coerce_plus` module in [[tools/nxc]]

## Remediation
- Enable SMB signing and LDAP signing
- Network segmentation limiting port 445 access to DCs
- Monitor for unusual Event Log service RPC calls

## Related
- [[ttps/coercion/petitpotam]]
- [[ttps/coercion/printerbug]]
- [[ttps/coercion/dfscoerce]]
- [[playbooks/ad-coercion-validation]]
