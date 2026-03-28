# DC Discovery via DNS (SRV Records)

**MITRE:** [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)  
**Phase:** Recon  
**Auth Required:** No  
**Tags:** #recon #AD #dns #unauthenticated

---

## Summary
Domain Controllers register SRV records in DNS. Querying `_ldap._tcp.dc._msdcs.<domain>` returns all DCs without requiring any credentials.

## Command
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```

## Extract Hostnames Only
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> \
  | grep ldap \
  | cut -d' ' -f 6 \
  | sed 's/\.$//'
```

## Extract Hostname + IP in One Line
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> | grep ldap | cut -d' ' -f 6 | sed 's/\.$//' | while read -r host; do ping $host -c1; done | grep PING
```
Output example:
```
PING DC01.corp.local (10.0.0.10): 56 data bytes
PING DC02.corp.local (172.16.1.10): 56 data bytes
```
Hostname and IP side by side — ready to feed into `-dc-ip` for subsequent steps.

## Notes
- Works from any machine that can reach the domain's DNS server
- Returns FQDNs — pipe through ping to resolve to IPs
- Reliable across all Windows domain configurations

## Related
- [[tools/nxc]]
- [[playbooks/ad-coercion-validation]]
