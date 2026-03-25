# Email Display Name Spoofing / Executive Impersonation

**MITRE:** [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/) | [T1036.005 - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/) | [T1656 - Impersonation](https://attack.mitre.org/techniques/T1656/)  
**Phase:** Initial Access  
**Auth Required:** No  
**Tags:** #initial-access #phishing #email #spoofing #impersonation #defense-evasion

---

## Summary
Craft email where the display name impersonates a trusted executive or internal identity while the actual sending address belongs to attacker-controlled infrastructure. Most mail clients — especially mobile — show only the display name, not the underlying address. When combined with a typosquat domain, this bypasses Anti_Spoof content filters that detect envelope/From header mismatches.

---

## Two Approaches

### Approach 1 — Display Name Spoof (Recommended)
Envelope sender and `From:` header both use the attacker domain. Display name carries the impersonated identity. No domain mismatch — passes Anti_Spoof filters.

```bash
swaks -4 \
  --to target@victim.com \
  --from executive@attacker-domain.com \
  --server localhost --port 25 \
  --header "From: Jane Smith, CFO <executive@attacker-domain.com>" \
  --header "Reply-To: executive@attacker-domain.com" \
  --header "Subject: Quick approval needed" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@attacker-domain.com>" \
  --header "Date: $(date -R)" \
  --body "Body text here"
```

**What victim sees:** `Jane Smith, CFO`  
**Address visible if expanded:** `executive@attacker-domain.com` (typosquat — reads plausible at a glance)

### Approach 2 — Header-From Spoof (Demonstrates DMARC p=none Gap)
Envelope sender uses attacker domain (passes SPF), `From:` header shows the real target domain address. Only works when DMARC is `p=none` AND no custom Anti_Spoof content filter is present.

```bash
swaks -4 \
  --to target@victim.com \
  --from bounce@attacker-domain.com \
  --server localhost --port 25 \
  --header "From: Jane Smith, CFO <jsmith@victim.com>" \
  --header "Reply-To: jsmith@victim.com" \
  --header "Subject: Quick approval needed" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@attacker-domain.com>" \
  --header "Date: $(date -R)" \
  --body "Body text here"
```

**What victim sees:** `Jane Smith, CFO <jsmith@victim.com>` — the real address  
**Risk:** Higher detection — enterprise gateways (EOP, IronPort) often have custom Anti_Spoof rules that detect the envelope/From mismatch

---

## Decision Matrix

| Target DMARC | Custom Anti_Spoof Filter | Use |
|---|---|---|
| `p=none` | No | Approach 2 (demonstrates gap) |
| `p=none` | Yes | Approach 1 |
| `p=quarantine` or `p=reject` | Any | Approach 1 only |
| No DMARC | No | Either |

---

## Domain Selection for Attacker Domain

Critical for Approach 1 — the visible address must hold up to casual inspection:
- **Best:** Typosquat of the target's own domain (e.g., `gl0bex-portal.com` for `globex.com`)
- **Avoid:** Microsoft product names (`m365`, `outlook`, `azure`) — triggers EOP brand impersonation protection in Microsoft 365 tenants regardless of SPF/DKIM scores

---

## Body Content Guidelines
- Short, authoritative, time-pressured (not alarmist)
- Match the organization's writing style if samples are available
- Plain text outperforms HTML for deliverability
- Fewer links = better spam score
- Include a realistic signature block with title, phone, company

---

## Evidence to Capture
- [ ] Screenshot: email in target inbox showing display name only (not address)
- [ ] Screenshot: email headers showing SPF/DKIM pass, DMARC policy
- [ ] Screenshot: Anti_Spoof quarantine alert (if Approach 2 was attempted first — demonstrates defense + gap)
- [ ] Note: which approach landed, which was blocked

---

## Notes
- Approach 2 blocked + Approach 1 delivered = two distinct findings in one test. Report both.
- On mobile clients (iOS Mail, Android Gmail), the sender address is hidden behind the display name by default — the attack surface is larger than desktop
- `Reply-To` pointing to attacker-controlled address ensures any reply goes to attacker even when `From:` is spoofed

---

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
- [[playbooks/email-spoofing-chain]]
