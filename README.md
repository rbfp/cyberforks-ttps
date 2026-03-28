# Cyberforks TTPs

A public reference of penetration testing techniques, tools, and playbooks maintained by [Cyberforks LLC](https://cyberforks.com).

Techniques are documented with MITRE ATT&CK mappings, validation steps, and remediation guidance.

---

## Attack Chain Mind Map

```
                            CYBERFORKS TTPs
                                  │
          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
   ── AD / WINDOWS ──      ── EMAIL / PHISHING ──    ── TOOLS ──
          │                       │                        │
    ┌─────┴──────┐          ┌─────┴──────┐          nxc (netexec)
    │            │          │            │          responder
  RECON      ATTACK       RECON       ATTACK        certipy
    │         PATHS          │         CHAIN        enum4linux
    │            │           │            │         addcomputer
    │     ┌──────┴──────┐    │     ┌──────┴──────┐
    │     │             │    │     │             │
    │  COERCION     AD CS    │  RESOURCE      INITIAL
    │     │        ATTACKS   │    DEV         ACCESS
    │     │             │    │     │             │
    │  ┌──┴──┐    ┌─────┴─┐  │  typosquat   display-name
    │  │     │    │       │  │  domain      spoof
    │  │  DFS│    │  ESC1 │  │  dkim-infra     │
    │  │  Pot│    │  ESC8 │  │             def-evasion
    │  │  PBg│    └─────┬─┘  │           smtp-headers
    │  │  MSE│          │    │
    │  └──┬──┘    ┌─────┴──────────────┐
    │     │       │                    │
    │  Responder  adcs-cert-auth   PLAYBOOKS
    │  (hash      (pfx → hash)         │
    │   capture)       │          ┌────┴────┐
    │     │       DCSync /    ESC8-domain  ESC1-domain
    │     │       Golden Tick  -compromise  -admin
    │     │
    │  NTLMv1-permitted (separate finding)
    │
  dc-discovery-dns
  null-session-enum
  domain-acct-discovery
  ad-user-enum
  smb-signing-audit
```

### AD Attack Path — Coercion → Hash Capture
```
dc-discovery-dns ──► smb-signing-audit ──► null-session-enum
        │                                          │
        ▼                                          ▼
 [low-priv creds]                       domain-acct-discovery
        │
        ▼
  coerce_plus (nxc)
  ┌─────┴──────────────┬──────────────┬──────────────┐
  │                    │              │              │
DFSCoerce         PetitPotam     PrinterBug        MSEven
  └─────┬──────────────┴──────────────┴──────────────┘
        │
        ▼
   Responder -A
   (NTLMv2 hash / NTLMv1 if permitted ← separate finding)
```

### AD Attack Path — AD CS ESC8 → Domain Compromise
```
certipy find -vulnerable
        │
        ▼
  ESC8 confirmed (HTTP web enrollment, no EPA)
        │
        ▼
certipy relay ──► PetitPotam coerces DC
        │               │
        └───────────────┘
        DC auth relayed to CA over HTTP
        │
        ▼
  DC machine cert (.pfx)
        │
        ▼
certipy auth → DC NT hash
        │
        ▼
  secretsdump DCSync → all domain hashes
                            │
                     ┌──────┴──────┐
                     │             │
               golden ticket   kerberoast
               (persistence)   svc accounts
```

### AD Attack Path — AD CS ESC1 → Domain Admin
```
certipy find -vulnerable
        │
        ▼
  ESC1 confirmed (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        │
        ▼
ad-user-enum → find AdminCount=1 target (svc acct / DA)
        │
        ▼
addcomputer.py (if Domain Computers enrollment required)
        │
        ▼
certipy req -upn [target] -sid [SID] → target.pfx
        │
        ▼
certipy auth → TGT + NTLM hash
        │
        ▼
nxc smb -H [hash] → (Pwn3d!)
        │
        ▼
secretsdump DCSync
```

### Email Attack Path — Spoofing Chain
```
email-security-dns-recon (SPF / DMARC / DKIM / MX fingerprint)
        │
        ▼
  ┌─────┴────────────────────┐
  │                          │
DMARC p=none             DMARC p=reject
  │                          │
  ▼                          ▼
Attempt header-from      Display name spoof only
spoof (Approach 2)             │
  │                            ▼
  ├─ blocked by Anti_Spoof    typosquat-domain-acquisition
  │  → document finding       dkim-infrastructure-setup
  │                           smtp-header-scrubbing
  └──► Display name spoof ◄──────────────┘
       (Approach 1)
             │
             ▼
       Delivered to inbox
```

---

## Structure

```
ttps/                   → Individual techniques by kill chain phase
  coercion/             → NTLM coercion via MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-EVEN
  credential-access/    → AD CS ESC1/ESC8, certificate auth, NTLMv1
  defense-evasion/      → SMTP header scrubbing
  initial-access/       → Email display name spoofing
  recon/                → DC discovery, user enum, SMB signing, null sessions
  resource-development/ → Typosquat domains, DKIM infrastructure
tools/                  → Tool references (nxc, responder, certipy, enum4linux, addcomputer)
playbooks/              → Full attack chains with step-by-step execution
```

## MITRE ATT&CK Reference
https://attack.mitre.org

---

> ⚠️ All content is for authorized penetration testing and educational purposes only.
