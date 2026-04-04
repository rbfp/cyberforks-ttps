# pipal

**Purpose:** Password pattern analysis — generates statistics from a list of plaintext passwords  
**Install:** `gem install pipal` or `git clone https://github.com/digininja/pipal`  
**Tags:** #tool #pipal #password-analysis #reporting

---

## Basic Usage

```bash
# Input must be plaintext passwords, one per line
pipal plaintexts_only.txt

# If cloned from git
ruby pipal.rb plaintexts_only.txt

# Extract passwords from username:password file first
cut -d: -f2 accounts_cracked.txt > plaintexts_only.txt
pipal plaintexts_only.txt
```

---

## Key Output Sections

| Section | What It Shows |
|---------|--------------|
| **Top passwords** | Most common exact passwords |
| **Top base words** | Most common word roots (ignoring numbers/symbols) |
| **Password length** | Distribution of password lengths |
| **Character classes** | % alpha only, alpha+num, alpha+num+special, etc. |
| **Top masks** | Most common patterns (e.g., `?u?l?l?l?l?d?d?d?s`) |
| **Months/seasons** | % containing month/season names |
| **Years** | % containing year digits |

---

## Report-Ready Findings from Pipal Output

Pull these numbers for the report narrative:
- Top 5 base words (shows company name, seasons, sports teams)
- % of passwords 8 chars or fewer (policy gap evidence)
- % following Season+Year pattern
- % that are purely alphabetic (no complexity)

---

## Notes
- Input = **plaintext passwords only** — not hashes, not username:password pairs
- No built-in output file — pipe to tee: `pipal plaintexts.txt | tee pipal_results.txt`
- Results are more impactful when sample size is larger (100+ passwords)
- "47% followed a Season+Year pattern" is more compelling to a client than technical hash details

---

## Related
- [[ntlm-hash-cracking]]
- [[hashcat]]
