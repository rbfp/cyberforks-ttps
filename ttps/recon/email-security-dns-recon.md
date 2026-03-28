# Email Security Posture Recon via DNS

**MITRE:** [T1596.005 - Search Open Technical Databases: DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/005/)  
**Phase:** Recon  
**Auth Required:** No  
**Tags:** #recon #email #dns #spf #dkim #dmarc #unauthenticated

---

## Summary
Enumerate the target domain's email authentication records (SPF, DKIM, DMARC) and MX infrastructure to assess security posture before attempting email spoofing. Results determine which spoofing techniques are viable and which mail gateway vendor's controls you're up against.

## Mechanism
- **Protocol:** DNS (UDP/53)
- **RPC/Function:** TXT record queries for SPF, DMARC, DKIM selectors; MX record queries
- **Effect:** Reveals enforcement gaps, mail gateway vendor, and dual-layer mail architectures (e.g., IronPort perimeter + M365 internal)

## Commands
```bash
DOMAIN="targetdomain.com"

# MX — identifies mail gateway vendor
dig +short MX $DOMAIN

# SPF
dig +short TXT $DOMAIN | grep -i spf

# DMARC
dig +short TXT _dmarc.$DOMAIN

# DKIM — common selectors
for sel in default google selector1 selector2 k1 mail dkim s1 s2 smtp sendgrid mandrill mailjet; do
  result=$(dig +short TXT ${sel}._domainkey.$DOMAIN 2>/dev/null)
  [ -n "$result" ] && echo "  [$sel]: $result"
done

# All TXT records — may reveal selectors or additional context
dig +short TXT $DOMAIN
```

## Expected Output
```
# corp.local — actual engagement output (2026-03-08)
MX:    10 mx1.target.iphmx.com.  (Cisco IronPort ESA)
       10 mx2.target.iphmx.com.

SPF:   "v=spf1 mx a ip4:8.28.219.30 ... include:spf.protection.outlook.com -all"
       → -all hardfail; includes M365 → dual-layer architecture confirmed

DMARC: "v=DMARC1; p=none; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com"
       → p=none — monitor only, no enforcement; Proofpoint receiving reports

DKIM:  No selectors found on common names
       → DKIM not configured for outbound mail
```

## Notes
- **corp.local engagement (2026-03-08):** IronPort gateway → M365 EOP internally (confirmed via `include:spf.protection.outlook.com` in SPF and multiple `MS=` TXT records)
- `p=none` DMARC = reports sent to Proofpoint but mail delivered regardless of failure — header-from spoof viable
- Proofpoint receives DMARC reports (`fo=1` = forensic reports on any failure) — security team may be monitoring
- No DKIM selectors found = outbound mail unsigned; spoofed mail won't look worse than legitimate mail

**MX vendor fingerprinting:**
- `*.iphmx.com` → Cisco IronPort ESA — uses Talos SenderBase reputation; may have custom Anti_Spoof content filters
- `include:spf.protection.outlook.com` in SPF → M365 EOP is the internal delivery layer
- `*.pphosted.com` → Proofpoint — stricter; often blocks residential IPs
- `*.mimecast.com` → Mimecast — strict; residential IP hostile

**Spoofability verdict from recon:**
- SPF `-all` + DMARC `p=none` + no DKIM = header-from spoof viable if no custom Anti_Spoof filter
- If custom Anti_Spoof filter exists (IronPort or EOP) → display name spoof is the reliable path

## Relay / Follow-On Attack Path
Recon output feeds directly into:
- Domain selection (typosquat) — avoid Microsoft product strings if M365 detected
- Spoofing technique selection — `p=none` opens header-from spoof; Anti_Spoof filters push to display name

## Remediation
- Escalate DMARC from `p=none` to `p=quarantine` → `p=reject`
- Implement DKIM signing on all outbound mail
- Enable strict Anti_Spoof policies in IronPort/EOP

## Related
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
