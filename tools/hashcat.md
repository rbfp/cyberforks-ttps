# hashcat

**Purpose:** Offline password hash cracking  
**Install:** Pre-installed on Kali; `sudo apt install hashcat`  
**Tags:** #tool #hashcat #cracking #ntlm

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-m 1000` | Hash mode: NTLM |
| `-m 0` | Hash mode: MD5 |
| `-m 1800` | Hash mode: SHA-512 (Linux shadow) |
| `-a 0` | Attack mode: dictionary |
| `-a 3` | Attack mode: mask (brute force) |
| `-r` | Rules file |
| `-o` | Output file for cracked hashes |
| `--append` | Append to existing output file |
| `--show` | Display cracked hashes from potfile |
| `--no-self-test` | Skip self-test on startup |
| `--force` | Force run (ignore warnings, e.g. on VMs) |

---

## NTLM Workflow (mode 1000)

```bash
# Dictionary + rules (first pass)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -o cracked.txt

# Bigger ruleset
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/d3ad0ne.rule \
  -o cracked.txt --append

# Seasonal mask: Summer2023!, Fall2022@, Spring2024#
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?d?d?d?d?s -o cracked.txt --append

# Export cracked pairs (hash:plaintext)
hashcat -m 1000 hashes.txt --show > cracked_pairs.txt
```

---

## Mask Syntax

| Placeholder | Character Set |
|-------------|--------------|
| `?u` | Uppercase A-Z |
| `?l` | Lowercase a-z |
| `?d` | Digits 0-9 |
| `?s` | Special chars |
| `?a` | All printable |

---

## Potfile
`~/.hashcat/hashcat.potfile` — stores all cracked hashes persistently. Run `--show` against any hashlist to see previously cracked results without re-running.

---

## Performance Notes
- RTX 3090: ~70B NTLM hashes/sec
- CPU only: ~1-5B/sec depending on cores
- NTLM is unsalted — crack once, applies to all accounts sharing that hash
- VM GPU passthrough required for GPU cracking in VMs

---

## Related
- [[ntlm-hash-cracking]]
- [[pipal]]
