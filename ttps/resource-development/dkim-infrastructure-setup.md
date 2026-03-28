# DKIM Signing Infrastructure Setup (Postfix + OpenDKIM)

**MITRE:** [T1587.003 - Develop Capabilities: Digital Certificates](https://attack.mitre.org/techniques/T1587/003/) | [T1583.004 - Acquire Infrastructure: Server](https://attack.mitre.org/techniques/T1583/004/)  
**Phase:** Resource Development  
**Auth Required:** No  
**Tags:** #resource-development #email #dkim #postfix #opendkim #infrastructure

---

## Summary
Stand up a self-controlled mail sending stack (Postfix + OpenDKIM) with DKIM signing. Unsigned mail scores poorly with enterprise spam filters; DKIM-signed mail significantly improves inbox delivery. Signing also enables display name spoofing to pass authentication checks cleanly.

## Mechanism
- **Protocol:** SMTP (port 25); milter protocol (OpenDKIM ↔ Postfix via inet socket)
- **RPC/Function:** RSA-2048 DKIM signature on outbound mail; Postfix header scrubbing
- **Effect:** Outbound mail is DKIM-signed, SPF-aligned, and stripped of operator infrastructure fingerprints

## Commands
```bash
# Generate keypair
mkdir -p ~/dkim && cd ~/dkim
openssl genrsa -out dkim-private.key 2048
openssl rsa -in dkim-private.key -pubout -out dkim-public.key
grep -v "^-----" dkim-public.key | tr -d '\n'   # → paste into DNS TXT record

# Install
sudo apt install postfix opendkim opendkim-tools swaks -y
# Postfix: "Internet Site" → mail name = yourdomain.com

# OpenDKIM key setup
sudo mkdir -p /etc/opendkim/keys/yourdomain.com
sudo cp ~/dkim/dkim-private.key /etc/opendkim/keys/yourdomain.com/mail.private
sudo chown -R opendkim:opendkim /etc/opendkim
sudo chmod 600 /etc/opendkim/keys/yourdomain.com/mail.private

# opendkim.conf (replace entirely)
sudo tee /etc/opendkim.conf > /dev/null << 'EOF'
Mode                sv
Selector            mail
Socket              inet:12301@localhost
RequireSafeKeys     no
Canonicalization    relaxed/simple
SigningTable        refile:/etc/opendkim/signing.table
KeyTable            /etc/opendkim/key.table
EOF

# Signing table — wildcard signs ALL outbound regardless of From domain
echo "*    yourdomain.com" | sudo tee /etc/opendkim/signing.table
echo "yourdomain.com    yourdomain.com:mail:/etc/opendkim/keys/yourdomain.com/mail.private" \
  | sudo tee /etc/opendkim/key.table

# Systemd fix (Kali/Debian — PID file issue)
sudo mkdir -p /run/opendkim && sudo chown opendkim:opendkim /run/opendkim
echo 'd /run/opendkim 0750 opendkim opendkim -' | sudo tee /etc/tmpfiles.d/opendkim.conf
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

# Postfix config
sudo postconf -e "myhostname = mail.yourdomain.com"
sudo postconf -e "mydomain = yourdomain.com"
sudo postconf -e "smtp_helo_name = mail.yourdomain.com"
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

## Expected Output
```
# OpenDKIM running
sudo systemctl status opendkim → Active: active (running)

# Postfix running
sudo systemctl status postfix → Active: active (running)

# Mail log on send (journalctl -u postfix)
postfix/smtp: to=<target>, relay=mx1.target.com[IP]:25,
  status=sent (250 2.0.0 OK)
```

## Notes
**corp.local engagement (2026-03-08):**
- Sending infra: Kali VM (home lab), residential Spectrum IP `165.162.30.26`
- No PTR control (Spectrum owns it: `syn-165-162-030-026.res.spectrum.com`)
- Passed Cisco IronPort/Talos reputation check — Talos ≠ Spamhaus; residential IP was neutral in Talos
- Gmail hard-rejected with 550 5.7.1 (residential IP block) — Gmail irrelevant to this engagement
- mail-tester.com score: **8.9/10** after adding HELO SPF record and MX record

**Critical gotchas:**
- Use `inet:localhost:12301` NOT `unix:` for milter — Postfix runs chrooted in `/var/spool/postfix/`; unix socket paths are relative to chroot and won't find OpenDKIM
- Double `ExecStart=` in systemd override clears original value before setting new one — required syntax
- `-f` flag on opendkim keeps it in foreground, matching `Type=simple` — without it, opendkim daemonizes and systemd loses track
- Do NOT run `postmap` on header_checks — regexp files are read directly

**Troubleshooting:**
- `smfi_opensocket() failed` → `sudo pkill -9 opendkim && sudo rm -f /run/opendkim/opendkim.sock`
- `Address already in use` → change port from 12301 to another unused port in both configs
- No DKIM-Signature on mail → Postfix chroot issue; switch to inet: socket
- Signing wrong domain → wildcard `*    yourdomain.com` in signing.table covers all

**Sending IP options:**
- Home lab (residential): no PTR control, ISP may block port 25, Gmail rejects — but passes Talos for IronPort targets
- Non-AWS VPS (Vultr/DO/Linode): full PTR control, port 25 open, clean IP — best for all targets
- AWS EC2: port 25 blocked at network level — not viable

## Relay / Follow-On Attack Path
Once stack is verified (test send to mail-tester.com or Outlook account), proceed to:
1. Header-From spoof attempt (if DMARC p=none, no Anti_Spoof)
2. Display name spoof (fallback, highest deliverability)

## Remediation
- Implement DMARC `p=reject` to block header-from spoof
- EOP/IronPort anti-impersonation blocks display name spoof only if policy is configured to detect external senders with internal display names

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
- [[playbooks/email-spoofing-chain]]
