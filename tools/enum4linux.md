# enum4linux

**Type:** Enumeration wrapper  
**Language:** Perl (original) / Python (enum4linux-ng)  
**Auth Required:** No (null session) or low-priv  
**Tags:** #tool #recon #smb #windows #samba

---

## Summary
Wrapper that automates unauthenticated (or low-auth) enumeration of Windows and Samba systems via SMB and RPC. Chains rpcclient, smbclient, nmblookup, and net commands into a single sweep. Standard tool for early recon on every Windows/AD engagement.

## Install
```bash
# Kali — pre-installed
enum4linux --help

# enum4linux-ng (modern Python rewrite — preferred for newer targets)
pipx install enum4linux-ng
# or
git clone https://github.com/cddmp/enum4linux-ng && cd enum4linux-ng && pip3 install -r requirements.txt
```

## Flags

| Flag | What it does |
|------|-------------|
| `-U` | Enumerate users |
| `-G` | Enumerate groups |
| `-S` | Enumerate shares |
| `-P` | Get password policy |
| `-R` | RID cycling (brute-force user SIDs) |
| `-o` | OS information |
| `-n` | NetBIOS info |
| `-i` | Printer info |
| `-a` | All of the above |

## Common Commands
```bash
# Full sweep — run this first
enum4linux -a <target_IP>

# Targeted: users + password policy only
enum4linux -U -P <target_IP>

# RID cycling when direct enum blocked
enum4linux -R <target_IP>

# enum4linux-ng equivalent (faster, handles modern Windows)
enum4linux-ng -A <target_IP>

# enum4linux-ng with JSON output
enum4linux-ng -A <target_IP> -oJ /tmp/enum4linux-output
```

## Underlying Tools It Wraps
- **rpcclient** — user/group/policy enumeration over RPC
- **smbclient** — share enumeration
- **nmblookup** — NetBIOS name resolution
- **net** — Samba net commands

## Engagement Run Order
1. DC discovery: `nslookup` SRV records or `nxc smb` sweep → [[dc-discovery-dns]]
2. Null session test: `nxc smb <DCs> -u '' -p ''` → [[null-session-enumeration]]
3. **`enum4linux -a <DC_IPs>`** ← here
4. If blocked: fall back to `nxc smb --users / --pass-pol`
5. Use results to inform spray, roasting, or BloodHound collection

## Modern Caveat
Original enum4linux is Perl-based and struggles with newer Windows versions (2019+) that enforce stricter RPC restrictions. **enum4linux-ng** is the maintained Python rewrite — handles modern targets better, outputs JSON, faster execution. Use ng on newer environments.

## What to Look For in Output
- Service accounts in user list → spray/roast targets
- Lockout threshold = 0 → unlimited spraying possible (separate finding)
- Short min password length → weak policy finding
- Open shares → data exposure

## Related
- [[null-session-enumeration]] — technique this tool supports
- [[domain-account-discovery-rpc]] — account discovery TTP
- [[tools/nxc]] — modern fallback / complement
- [[tools/responder]] — pair for capture after enum
