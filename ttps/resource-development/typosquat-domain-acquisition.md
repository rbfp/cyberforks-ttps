# Typosquat Domain Acquisition

**MITRE:** [T1583.001 - Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)  
**Phase:** Resource Development  
**Auth Required:** No  
**Tags:** #resource-development #domain #typosquat #phishing #email

---

## Summary
Register a domain visually similar to the target's own domain for use as spoofing infrastructure. A typosquat of the target's domain is more effective than generic-sounding domains — it's contextually plausible and avoids mail provider brand protection filters.

## Mechanism
- **Protocol:** Domain registration (WHOIS/EPP)
- **RPC/Function:** DNS TXT/SPF/DKIM/MX record publication
- **Effect:** Attacker-controlled domain with legitimate-looking authentication records; envelope sender passes SPF; display name impersonation survives Anti_Spoof filters

## Commands
```bash
# Vet candidate domain
DOMAIN="candidate-domain.com"
whois $DOMAIN | grep -i "no match\|not found\|available"
dig +short A $DOMAIN
dig +short TXT $DOMAIN

# Check reputation
REV=$(dig +short A $DOMAIN | head -1 | awk -F. '{print $4"."$3"."$2"."$1}')
dig +short $REV.zen.spamhaus.org   # empty = clean

# Verify propagation after DNS setup
dig @8.8.8.8 +short TXT $DOMAIN
dig @1.1.1.1 +short TXT mail._domainkey.$DOMAIN
dig +short A mail.$DOMAIN
dig +short MX $DOMAIN
```

## Expected Output
```
# corp.local engagement — selected domain: target-portal.com (one char substitution)
# All records propagated within 60s of Cloudflare save:
dig +short TXT target-portal.com    → "v=spf1 ip4:165.162.30.26 -all"
dig +short TXT mail._domainkey...  → "v=DKIM1; k=rsa; p=<pubkey>"
dig +short A mail.target-portal.com → 165.162.30.26
dig +short MX target-portal.com     → 10 mail.target-portal.com.
```

## Notes
**corp.local engagement (2026-03-08):**
- First domain used: `m365-verify.com` — BLOCKED by M365 EOP brand impersonation protection. The string `m365` in the domain triggers Microsoft's explicit brand protection regardless of SPF/DKIM/DMARC pass status. Mail quarantined even at 8.9/10 mail-tester score.
- Second domain: `target-portal.com` (typosquat of `corp.local`, one char substitution: `dardh` vs `dandh`) — BYPASSED all filters, landed in inbox.
- Lesson: When targeting M365 tenants, never use Microsoft product strings (`m365`, `outlook`, `azure`, `microsoft`, `office365`) in the sending domain.

**Domain selection criteria:**
- Visually similar at a glance (one char off, hyphenated suffix, TLD swap)
- No existing reputation or blocklist entries (fresh registration preferred)
- Avoid brand names of large companies (Nike, Apple, Google) — may trigger their brand protection
- For M365 targets: avoid Microsoft product strings entirely
- `[target]-portal.com` or `[target]-support.com` pattern reads as a plausible IT subsidiary

**DNS records required (Cloudflare):**
```
TXT  @                  "v=spf1 ip4:<IP> -all"
TXT  mail._domainkey    "v=DKIM1; k=rsa; p=<pubkey>"
TXT  mail               "v=spf1 ip4:<IP> -all"   ← HELO hostname SPF
A    mail               <IP>
MX   @    10            mail.<domain>
```
All records: Proxy = DNS only (grey cloud). Cloudflare proxy is HTTP/HTTPS only — breaks SMTP.

## Relay / Follow-On Attack Path
Typosquat domain is the envelope sender for display name spoofing. Combined with DKIM signing, SPF passes, DMARC aligns on your domain, Anti_Spoof filters have nothing to flag.

## Remediation
- DMARC `p=reject` prevents header-from spoof but not display name spoof
- EOP anti-impersonation policies can detect display names matching internal users sent from external domains
- User awareness training: verify sender address, not just display name

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
