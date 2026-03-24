# DFSCoerce

**MITRE:** [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)  
**Phase:** Credential Access  
**Auth Required:** Yes (low-priv domain user)  
**Tags:** #coercion #AD #NTLM #windows #DC #dfs

---

## Summary
Abuses MS-DFSNM (Distributed File System Namespace Management) to force NTLM authentication from a target machine. Multiple RPC methods available, making it harder to fully block without disabling DFS entirely.

## Mechanism
- Protocol: MS-DFSNM
- RPC calls: `netdfs\NetrDfsRemoveRootTarget`, `netdfs\NetrDfsAddStdRoot`, `netdfs\NetrDfsRemoveStdRoot`
- Forces target to initiate NTLM auth to attacker listener

## Remediation
- Disable DFS Namespace service where not needed
- Enable SMB signing and LDAP signing
- Network segmentation to limit who can reach DC on port 445

## Related
- [[ttps/coercion/petitpotam]]
- [[ttps/coercion/printerbug]]
- [[ttps/coercion/mseven]]
- [[playbooks/ad-coercion-validation]]
