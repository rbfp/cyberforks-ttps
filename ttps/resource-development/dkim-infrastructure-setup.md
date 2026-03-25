# DKIM Signing Infrastructure Setup (Postfix + OpenDKIM)

**MITRE:** [T1587.003 - Develop Capabilities: Digital Certificates](https://attack.mitre.org/techniques/T1587/003/) | [T1583.004 - Acquire Infrastructure: Server](https://attack.mitre.org/techniques/T1583/004/)  
**Phase:** Resource Development  
**Auth Required:** No  
**Tags:** #resource-development #email #dkim #postfix #opendkim #infrastructure

---

## Summary
Set up a self-controlled mail sending stack with DKIM signing to improve deliverability and pass authentication checks during email spoofing engagements. Unsigned mail scores poorly with enterprise spam filters; DKIM-signed mail from a properly configured domain significantly improves inbox delivery rates.

---

## Stack
- **Postfix** — MTA for outbound relay
- **OpenDKIM** — milter that signs outbound mail with RSA private key
- **swaks** — mail composition and injection
- **Cloudflare** — DNS management (SPF, DKIM TXT records)

---

## Step 1 — Generate DKIM Keypair

```bash
mkdir -p ~/dkim && cd ~/dkim
openssl genrsa -out dkim-private.key 2048
openssl rsa -in dkim-private.key -pubout -out dkim-public.key

# Extract public key for DNS record
grep -v "^-----" dkim-public.key | tr -d '\n'
```

Add the output to Cloudflare:
```
Type: TXT
Name: mail._domainkey
Value: v=DKIM1; k=rsa; p=<OUTPUT>
Proxy: DNS only
```

---

## Step 2 — Install

```bash
sudo apt update && sudo apt install postfix opendkim opendkim-tools swaks -y
# Postfix installer: select "Internet Site", mail name = yourdomain.com
```

---

## Step 3 — OpenDKIM Config

```bash
sudo mkdir -p /etc/opendkim/keys/yourdomain.com
sudo cp ~/dkim/dkim-private.key /etc/opendkim/keys/yourdomain.com/mail.private
sudo chown -R opendkim:opendkim /etc/opendkim
sudo chmod 600 /etc/opendkim/keys/yourdomain.com/mail.private

# Write clean config
sudo tee /etc/opendkim.conf > /dev/null << 'EOF'
Mode                sv
Selector            mail
Socket              inet:12301@localhost
RequireSafeKeys     no
Canonicalization    relaxed/simple
SigningTable        refile:/etc/opendkim/signing.table
KeyTable            /etc/opendkim/key.table
EOF

# Wildcard signing table — signs ALL outbound mail regardless of From domain
echo "*    yourdomain.com" | sudo tee /etc/opendkim/signing.table
echo "yourdomain.com    yourdomain.com:mail:/etc/opendkim/keys/yourdomain.com/mail.private" | sudo tee /etc/opendkim/key.table
```

---

## Step 4 — Fix Systemd on Kali/Debian

OpenDKIM's default service type (`forking`) expects a PID file that Kali never creates. Fix:

```bash
sudo mkdir -p /run/opendkim
sudo chown opendkim:opendkim /run/opendkim
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
```

> The double `ExecStart=` clears the original value before setting the new one — required syntax for systemd overrides.

---

## Step 5 — Postfix Config

```bash
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

> Use `inet:localhost:12301` (not `unix:`) — Postfix runs chrooted in `/var/spool/postfix/` and cannot reach unix sockets outside the chroot.

---

## Verify DKIM Signing

Send test to mail-tester.com or your own Gmail-visible mailbox:
```bash
swaks -4 --to test@youremail.com --from support@yourdomain.com \
  --server localhost --port 25 \
  --header "From: Test <support@yourdomain.com>" \
  --header "Subject: DKIM Test" \
  --header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@yourdomain.com>" \
  --header "Date: $(date -R)" \
  --body "DKIM verification test"
```

In Gmail "Show original" — look for `dkim=pass` and `DKIM-Signature:` header.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `smfi_opensocket() failed` | Stale socket/process | `sudo pkill -9 opendkim && sudo rm -f /run/opendkim/opendkim.sock` |
| `Address already in use` | Port held by ghost process | Kill processes, change port in both configs |
| Service timeout | Missing `-f` in ExecStart | Ensure override has `ExecStart=/usr/sbin/opendkim -f -x ...` |
| No DKIM-Signature on mail | Postfix chroot can't reach socket | Use `inet:` not `unix:` in milter config |
| Mail not signing correct domain | Signing table mismatch | Wildcard `*    yourdomain.com` in signing.table covers all |

---

## Sending Infrastructure Notes
- **Home lab (residential IP):** Port 25 may be blocked by ISP; Talos reputation is neutral; no PTR control; Gmail hard-rejects residential IPs but many enterprise gateways (e.g., Cisco IronPort) do not
- **Non-AWS VPS (Vultr/DO/Linode):** Port 25 open; full PTR control; clean datacenter IP; best deliverability
- **AWS EC2:** Port 25 blocked by default at network level — not viable without AWS Support approval

---

## Related
- [[ttps/recon/email-security-dns-recon]]
- [[ttps/resource-development/typosquat-domain-acquisition]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[ttps/defense-evasion/smtp-header-scrubbing]]
- [[playbooks/email-spoofing-chain]]
