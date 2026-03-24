# PetitPotam

**MITRE:** [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)  
**Phase:** Credential Access  
**Auth Required:** Yes (low-priv domain user)  
**Tags:** #coercion #AD #NTLM #windows #DC

---

## Summary
Abuses MS-EFSRPC (Encrypting File System Remote Protocol) to force a target machine to authenticate outbound via NTLM. Particularly dangerous against Domain Controllers — captured machine account hash can be relayed to AD CS or LDAP for domain compromise.

## Mechanism
- Protocol: MS-EFSRPC
- RPC call: `EfsRpcAddUsersToFile` (and others)
- Forces target to initiate NTLM authentication to attacker-controlled listener

## Relay Attack Path
```
Coerce DC auth → Relay to AD CS (ESC8) → Get DC certificate → DCSync → Domain Admin
Coerce DC auth → Relay to LDAP → Shadow credentials / RBCD
```

## Remediation
- Disable EFS RPC where not needed
- Enable EPA (Extended Protection for Authentication) on AD CS
- Enable SMB signing and LDAP signing to neuter relay even if coercion succeeds
- Patch: KB5005413

## Related
- [[ttps/coercion/printerbug]]
- [[ttps/coercion/dfscoerce]]
- [[ttps/coercion/mseven]]
- [[playbooks/ad-coercion-validation]]
