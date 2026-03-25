# Email Security Posture Recon via DNS

**MITRE:** [T1596.005 - Search Open Technical Databases: DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/005/)  
**Phase:** Recon  
**Auth Required:** No  
**Tags:** #recon #email #dns #spf #dkim #dmarc #unauthenticated

---

## Summary
Before attempting email spoofing, enumerate the target domain's email authentication records to determine security posture and identify the best attack approach. SPF, DKIM, and DMARC configurations reveal enforcement gaps, mail gateway vendor, and which spoofing techniques are viable.

---

## Full Recon Script

```bash
DOMAIN="targetdomain.com"

echo "=== MX (mail servers + vendor fingerprint) ==="
dig +short MX $DOMAIN

echo ""
echo "=== SPF ==="
dig +short TXT $DOMAIN | grep -i spf

echo ""
echo "=== DMARC ==="
dig +short TXT _dmarc.$DOMAIN

echo ""
echo "=== DKIM (common selectors) ==="
for sel in default google selector1 selector2 k1 mail dkim s1 s2 smtp sendgrid mandrill mailjet; do
  result=$(dig +short TXT ${sel}._domainkey.$DOMAIN 2>/dev/null)
  [ -n "$result" ] && echo "  [$sel]: $result"
done

echo ""
echo "=== All TXT records ==="
dig +short TXT $DOMAIN
```

---

## Interpreting SPF

| Record | Meaning | Spoofing Impact |
|---|---|---|
| No record | No policy | Easiest — envelope spoof unrestricted |
| `~all` softfail | Weak policy | Likely delivered, may junk |
| `-all` hardfail | Strict policy | Some servers reject envelope spoof; header-from still works |
| `include:spf.protection.outlook.com` | Target runs M365 | Two-layer filtering: IronPort/gateway + EOP |

> SPF only protects the envelope sender (`MAIL FROM`). It does **not** protect the `From:` header the recipient sees.

## Interpreting DMARC

| Policy | Effect | Attack Viability |
|---|---|---|
| No record | No enforcement | Header-from spoof works freely |
| `p=none` | Monitor only | Header-from spoof delivers; reports sent to rua/ruf |
| `p=quarantine` | Failing mail → spam | Header-from goes to junk |
| `p=reject` | Failing mail rejected | Display name spoof only |

> Check `rua`/`ruf` tags — they reveal who monitors DMARC reports (e.g., Proofpoint). Check `pct` — partial enforcement means some mail still delivers.

## Interpreting DKIM Selectors

| Selector | Provider |
|---|---|
| `google` | Google Workspace |
| `selector1` / `selector2` | Microsoft 365 |
| `k1` | Mailchimp / Klaviyo |
| No selectors | DKIM not configured |

## MX Vendor Fingerprint

| MX Pattern | Provider | Notes |
|---|---|---|
| `*.protection.outlook.com` | Microsoft 365 / EOP | Built-in anti-spoof; check for brand protection on sending domain |
| `*.iphmx.com` | Cisco IronPort ESA | Uses Talos SenderBase reputation; may have custom Anti_Spoof content filters |
| `*.pphosted.com` | Proofpoint | Strict; often advanced threat protection |
| `*.mimecast.com` | Mimecast | Strict; blocks residential IPs aggressively |
| `*.barracudanetworks.com` | Barracuda | Moderate; IP reputation-heavy |

---

## Spoofability Decision Matrix

| SPF | DMARC | Custom Filter | Best Approach |
|---|---|---|---|
| None | None | Unknown | Header-from spoof |
| `-all` | `p=none` | No | Header-from spoof |
| `-all` | `p=none` | Yes (Anti_Spoof) | Display name spoof |
| `-all` | `p=quarantine` | Any | Display name spoof |
| `-all` | `p=reject` | Any | Display name spoof or lookalike domain |

---

## Notes
- Always check `include:spf.protection.outlook.com` in SPF — confirms M365 internally even if IronPort is the MX gateway
- Multiple `MS=` TXT records confirm M365 tenant verification
- DMARC `fo=1` means forensic reports are sent on any failure — security team may be monitoring

---

## Related
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
