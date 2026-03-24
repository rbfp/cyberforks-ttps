# Responder

**Install:** Pre-installed on Kali; `pip install responder`  
**Tags:** #tool #NTLM #credential-capture #poisoning

---

## Overview
Network poisoner and NTLM hash capture tool. Responds to LLMNR, NBT-NS, and mDNS broadcast queries to capture credentials from machines on the local network.

## Modes

### Analyze Mode (passive — use for validation)
Listens and logs without actively poisoning. Safe for production environments.
```bash
sudo responder -I <interface> -A
```

### Active Mode (poisoning — noisy)
Actively responds to broadcast queries. Will disrupt legitimate name resolution.
```bash
sudo responder -I <interface>
```

## What It Captures
- NTLMv1-SSP hashes
- NTLMv2-SSP hashes
- From: SMB, HTTP, FTP, LDAP, MSSQL, and more

## Output to Watch For
```
[SMB] NTLMv2-SSP Client   : <source_IP>
[SMB] NTLMv2-SSP Username : DOMAIN\<account>$
[SMB] NTLMv2-SSP Hash     : <hash>
```
Machine accounts end with `$` — a DC machine account hash = coercion confirmed.

## NTLMv1 vs NTLMv2
- **NTLMv1** — weaker, crackable via rainbow tables / crack.sh
- **NTLMv2** — stronger, requires offline cracking (hashcat)
- Capturing NTLMv1 from a DC = separate finding (NTLMv1 permitted on domain)

## Notes
- Always run in `-A` mode unless active poisoning is in scope
- Interface is typically `eth0` or `tun0` (VPN)

## Related
- [[tools/nxc]]
- [[playbooks/ad-coercion-validation]]
