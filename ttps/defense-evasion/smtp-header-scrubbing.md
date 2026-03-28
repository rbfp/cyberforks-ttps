# SMTP Header Scrubbing

**MITRE:** [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  
**Phase:** Defense Evasion  
**Auth Required:** No  
**Tags:** #defense-evasion #email #postfix #headers #opsec

---

## Summary
Strip or replace SMTP headers that expose sending infrastructure before mail leaves the local MTA. Without scrubbing, Postfix and swaks leak operator hostname, internal IPs, and tool fingerprints into headers visible to analysts and mail security tools.

## Mechanism
- **Protocol:** SMTP header injection / Postfix regexp filter
- **RPC/Function:** `header_checks = regexp:` in Postfix main.cf; `myhostname`, `smtp_helo_name` overrides
- **Effect:** Internal hostnames, tool fingerprints, and Postfix-generated identifiers are removed before mail is signed and relayed

## Commands
```bash
# Fix HELO hostname
sudo postconf -e "myhostname = mail.yourdomain.com"
sudo postconf -e "mydomain = yourdomain.com"
sudo postconf -e "smtp_helo_name = mail.yourdomain.com"
sudo postconf -e "header_checks = regexp:/etc/postfix/header_checks"

# Header scrubbing rules
sudo tee /etc/postfix/header_checks > /dev/null << 'EOF'
/^Received: from.*localhost/    IGNORE
/^X-Mailer:/                    IGNORE
/^Message-Id:.*localdomain/     IGNORE
EOF
# Do NOT run postmap — regexp files are read directly

# Supply clean headers via swaks
swaks ... \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@yourdomain.com>" \
  --header "Date: $(date -R)"
```

## Expected Output
```
# Before scrubbing (visible to analyst in raw headers)
Received: from kali-linux-2024-2.localdomain (localhost [127.0.0.1])
X-Mailer: swaks v20201014.0
Message-ID: <20260308153426.121668@kali-linux-2024-2.localdomain>

# After scrubbing
Message-ID: <1773019553.9931@target-portal.com>
Date: Sun, 08 Mar 2026 18:25:53 -0800
# Internal Received hop, X-Mailer, and localdomain Message-ID all gone
```

## Notes
**corp.local engagement (2026-03-08):**
- Before scrubbing: headers showed `kali-linux-2024-2.localdomain` in Received, X-Mailer: swaks, and Postfix-generated Message-ID with localdomain suffix
- After scrubbing: headers clean — HELO shows `mail.target-portal.com`, no tool fingerprint, clean Message-ID

**What cannot be scrubbed:**
- Outermost `Received:` header added by target's MX — always records your sending IP
- PTR record on sending IP — ISP controls for residential; VPS allows custom PTR
- DKIM signature covers headers at signing time — scrubbing processes before OpenDKIM milter, so signed headers are already clean

**HELO SPF record:**
- mail-tester.com flagged `SPF: HELO does not publish an SPF record` — add TXT record on `mail.yourdomain.com` with same SPF as root domain
- This brought mail-tester score from ~7 to 8.9/10

## Relay / Follow-On Attack Path
Scrubbing is most impactful when the target has a SOC that reviews email headers on suspicious mail. Combined with DKIM signing, the mail looks fully legitimate from a technical standpoint.

## Remediation
- End-user: inspect raw headers on suspicious mail (Gmail: Show original; Outlook: View source)
- Gateway: configure header inspection rules to flag mail where HELO doesn't match From domain

## Related
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
