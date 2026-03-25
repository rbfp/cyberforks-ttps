# SMTP Header Scrubbing

**MITRE:** [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  
**Phase:** Defense Evasion  
**Auth Required:** No  
**Tags:** #defense-evasion #email #postfix #headers #opsec

---

## Summary
Strip or replace mail headers that expose sending infrastructure identity before mail leaves the local MTA. Without scrubbing, Postfix and swaks leak the operator's hostname, internal IPs, and tool fingerprints into headers that analysts and mail security tools inspect.

---

## Headers That Leak Identity

| Header | Default Value | Problem |
|---|---|---|
| `Received: from` (internal hop) | `kali-linux-2024-2.localdomain (localhost [127.0.0.1])` | Exposes operator hostname and OS |
| `X-Mailer` | `swaks vX.X.X` | Identifies attack tool |
| `Message-ID` (Postfix-generated) | `<timestamp.pid@kali-linux-2024-2.localdomain>` | Exposes operator hostname |
| `EHLO` / `HELO` | `kali-linux-2024-2.localdomain` | Exposes operator hostname to receiving MX |

---

## Postfix Header Scrubbing Config

### 1 — Fix HELO/Hostname

```bash
sudo postconf -e "myhostname = mail.yourdomain.com"
sudo postconf -e "mydomain = yourdomain.com"
sudo postconf -e "smtp_helo_name = mail.yourdomain.com"
```

### 2 — Strip Leaking Headers via Regexp Filter

```bash
sudo postconf -e "header_checks = regexp:/etc/postfix/header_checks"

sudo tee /etc/postfix/header_checks > /dev/null << 'EOF'
/^Received: from.*localhost/    IGNORE
/^X-Mailer:/                    IGNORE
/^Message-Id:.*localdomain/     IGNORE
EOF

sudo systemctl restart postfix
```

> **Do NOT run `postmap` on this file.** Regexp files are read directly — running postmap produces a harmless warning but does nothing useful.

---

## Supply Clean Message-ID via swaks

Override Postfix's auto-generated Message-ID by injecting your own via `--header`:

```bash
--header "Message-ID: <$(date +%s).$(shuf -i 1000-9999 -n1)@yourdomain.com>"
--header "Date: $(date -R)"
```

Postfix's regexp filter then drops its own generated `Message-Id:` header (matches `.*localdomain`) and uses the swaks-supplied one.

---

## Before/After

**Before scrubbing (headers visible to analyst):**
```
Received: from kali-linux-2024-2.localdomain (localhost [127.0.0.1])
X-Mailer: swaks v20201014.0
Message-ID: <20260308153426.121668@kali-linux-2024-2.localdomain>
```

**After scrubbing:**
```
Message-ID: <1773019553.9931@yourdomain.com>
Date: Sun, 08 Mar 2026 18:25:53 -0800
```

Internal Received hop, tool fingerprint, and hostname all gone.

---

## Remaining Observable (Cannot Scrub)

| Observable | What It Reveals | Mitigation |
|---|---|---|
| Sending IP in outermost `Received:` | Your public IP | Use VPS with clean PTR; home lab = residential ISP visible |
| PTR record on sending IP | ISP hostname (e.g., `syn-165-162-030-026.res.spectrum.com`) | VPS only — ISP controls PTR for residential |
| IP reputation (Talos, Spamhaus) | ISP/VPN reputation | Use clean VPS IP; avoid VPN exits with poor Talos scores |

---

## Notes
- Scrubbing is most important when sending to security-aware targets who inspect raw headers
- Even after scrubbing, the outermost `Received:` header added by the target's MX will always record your sending IP — scrubbing only controls what you inject
- DKIM signature covers headers at signing time — scrubbing must happen before signing (Postfix processes header_checks before passing to OpenDKIM milter)

---

## Related
- [[ttps/resource-development/dkim-infrastructure-setup]]
- [[ttps/initial-access/email-display-name-spoofing]]
- [[playbooks/email-spoofing-chain]]
