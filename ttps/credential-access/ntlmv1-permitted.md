# NTLMv1 Permitted on Domain

**MITRE:** [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)  
**Phase:** Credential Access  
**Auth Required:** No (passive capture)  
**Tags:** #NTLM #credential-access #AD #windows #domain-config

---

## Summary
NTLMv1 is a deprecated authentication protocol with known cryptographic weaknesses. If a domain permits NTLMv1, any captured NTLMv1 hash is significantly easier to crack than NTLMv2 — recoverable via rainbow tables or online cracking services in minutes.

## Why It's a Separate Finding
When coercion attacks (PetitPotam, PrinterBug, etc.) result in an NTLMv1 hash rather than NTLMv2, it indicates the domain has not disabled NTLMv1. This is a distinct misconfiguration from the coercion vulnerability itself and carries its own remediation.

## Detection
Confirmed during coercion validation — Responder output shows:
```
[SMB] NTLMv1-SSP Client   : <DC_IP>
[SMB] NTLMv1-SSP Username : DOMAIN\<hostname>$
[SMB] NTLMv1-SSP Hash     : <hash>
```
`NTLMv1-SSP` in the output = NTLMv1 is permitted.

## Why NTLMv1 Is Weaker Than NTLMv2
- NTLMv1 uses DES encryption — computationally cheap to crack
- Vulnerable to rainbow table attacks
- Can be submitted to crack.sh for near-instant cracking in many cases
- NTLMv2 requires targeted offline cracking (hashcat) — significantly more effort

## Cracking NTLMv1
```bash
# Submit to crack.sh (free, rainbow table based)
# https://crack.sh/netntlm/

# Or hashcat
hashcat -m 5500 <hash_file> <wordlist>
```

## Impact
- Captured NTLMv1 hashes (including DC machine accounts) are much more likely to be cracked
- Cracked DC machine account hash = potential for pass-the-hash, DCSync, domain compromise
- Elevates severity of any coercion finding where NTLMv1 is observed

## Remediation
Disable NTLMv1 via Group Policy:

```
Computer Configuration →
  Windows Settings →
    Security Settings →
      Local Policies →
        Security Options →
          Network security: LAN Manager authentication level
          → Set to: "Send NTLMv2 response only. Refuse LM & NTLM"
```

Or via registry:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LmCompatibilityLevel" -Value 5
```

Value 5 = NTLMv2 only, refuse LM and NTLMv1.

## Notes
- Test in a lab environment first — some legacy applications may break if they depend on NTLMv1
- Audit for legacy systems before enforcing domain-wide
- Common in older environments that haven't revisited authentication policy in years

## Related
- [[ttps/coercion/petitpotam]]
- [[ttps/coercion/printerbug]]
- [[ttps/coercion/dfscoerce]]
- [[ttps/coercion/mseven]]
- [[tools/responder]]
- [[playbooks/ad-coercion-validation]]
