# Typosquat Domain Acquisition

**MITRE:** [T1583.001 - Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)  
**Phase:** Resource Development  
**Auth Required:** No  
**Tags:** #resource-development #domain #typosquat #phishing #email

---

## Summary
Register a domain that closely resembles the target's own domain for use as spoofing infrastructure. A typosquat of the target domain is more effective than generic-sounding domains because it's contextually plausible and avoids mail provider brand protection filters.

---

## Typosquatting Techniques

| Technique | Example (target: `globex.com`) | Notes |
|---|---|---|
| Character substitution | `gl0bex.com` | One letter changed |
| Character omission | `globx.com` | Letter dropped |
| Character addition | `globexx.com` | Letter added |
| Character transposition | `lgobex.com` | Letters swapped |
| Homoglyph | `ɡlobex.com` | Unicode lookalike |
| Hyphenation | `glo-bex.com` | Hyphen inserted |
| TLD swap | `globex.net`, `globex.co` | Different extension |
| Subdomain-style | `globex-portal.com` | Adds plausible suffix |

> **Best choice for email spoofing:** `[target]-portal.com` or `[target]-support.com` style. Reads as a legitimate subsidiary or IT portal — contextually plausible if a recipient checks the address.

---

## Domain Selection Criteria
- Visually similar to target domain at a glance
- No existing reputation or blocklist entries
- Avoid strings that trigger mail provider brand protection (e.g., `m365`, `microsoft`, `outlook`, `azure` → triggers Microsoft EOP brand impersonation detection regardless of DKIM/SPF pass)
- Available to register (check Namecheap, Cloudflare Registrar, GoDaddy)

---

## Domain Vetting

```bash
DOMAIN="candidate-domain.com"

# Check if registered
whois $DOMAIN | grep -i "no match\|not found\|available"

# Check existing DNS (should be empty for fresh domain)
dig +short A $DOMAIN
dig +short TXT $DOMAIN
dig +short MX $DOMAIN

# Check reputation
REV=$(dig +short A $DOMAIN | head -1 | awk -F. '{print $4"."$3"."$2"."$1}')
dig +short $REV.zen.spamhaus.org   # empty = clean
```

---

## DNS Setup After Registration (Cloudflare)

```
SPF:   TXT  @                    "v=spf1 ip4:<SENDING_IP> -all"
DKIM:  TXT  mail._domainkey      "v=DKIM1; k=rsa; p=<PUBKEY>"
HELO:  TXT  mail                 "v=spf1 ip4:<SENDING_IP> -all"
A:     A    mail                 <SENDING_IP>
MX:    MX   @    10              mail.<domain>
```

> Always set proxy to **DNS only (grey cloud)** for all mail-related records — Cloudflare proxying only works for HTTP/HTTPS and will break SMTP.

---

## Verify Propagation

```bash
dig @8.8.8.8 +short TXT $DOMAIN           # SPF
dig @1.1.1.1 +short TXT mail._domainkey.$DOMAIN  # DKIM
dig @208.67.222.222 +short A mail.$DOMAIN  # A record
```

All three resolvers should return identical records within ~60 seconds of saving in Cloudflare.

---

## Notes
- Microsoft EOP specifically detects brand-impersonating domains (`m365`, `outlook`, `azure`, etc.) — these domains will be quarantined regardless of authentication scores when targeting M365 tenants
- Typosquatting the target's own domain (e.g., `globex-portal.com` for `globex.com`) avoids this entirely and is more socially convincing
- Register domains close to the engagement start to minimize time the domain could be reported/blocklisted pre-engagement

---

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
