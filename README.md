<div align="center">

# 🦈 tshark2hashcat

**From network captures to ready-to-crack Hashcat hashes, powered by Tshark.**

[![Python](https://img.shields.io/badge/python-%E2%89%A5%203.7-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#)
[![Dependencies](https://img.shields.io/badge/python%20dependencies-none-success)](#)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Version française : [README.md](README.md)

</div>

---

## Overview

`tshark2hashcat` parses a `.pcap` / `.pcapng` file using **Tshark** — its sole data
source —, detects **NetNTLM** and **Kerberos** authentication, rebuilds crackable
material in the **exact format expected by Hashcat**, **validates every line**
against the official module tokenizers, then writes the output files together
with the matching **`hashcat` command**.

It is built for pentesters, forensic analysts and CTF players, and removes the
two classic failure points of this workflow: hand-rebuilt hashes (misplaced
checksum, wrong separators) and picking the wrong Hashcat mode among the eleven
relevant variants.

> **Legal disclaimer.** This tool is intended for authorized use only: labs,
> test environments, CTFs and contracted assessments. You are solely responsible
> for complying with applicable law.

## Table of contents

- [Features](#features)
- [Supported hash formats](#supported-hash-formats)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Sample session](#sample-session)
- [Cracking with Hashcat](#cracking-with-hashcat)
- [Missing-data policy](#missing-data-policy)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

| Feature | Description |
|---|---|
| Automatic protocol detection | NTLMSSP and Kerberos identified with zero configuration, including both protocols in a single capture |
| Broad coverage | 11 Hashcat modes: NetNTLMv1/v2, AS-REP roasting, Kerberos pre-authentication, Kerberoasting — RC4 **and** AES 128/256 |
| Strict validation | Every line is checked against the exact constraints of the Hashcat tokenizer (separators, lengths, bounds) **before** being written to disk |
| Anomaly reporting | Any incomplete frame is logged with the precise rejection reason; no malformed hash is ever produced |
| Raw-byte fallback | Scans for the `NTLMSSP\0` signature — cleartext or Base64-encoded — when the dissector failed to recognize the encapsulation (HTTP, IMAP, SMTP, RPC…) |
| Kerberos diagnostics | Inventory of observed identities: user, realm, SPN, ETYPE-INFO2 salt, etype, message type, frame number |
| Normalized output | Deduplication, one global file + one file per Hashcat mode, ready-to-run `hashcat` commands |
| Portability | Windows, Linux, macOS — standard-library Python only, no third-party dependency |

## Supported hash formats

| Protocol / attack | Condition in capture | Hashcat mode | Generated format |
|---|---|:---:|---|
| NetNTLMv2 | NT response > 24 bytes | `5600` | `user::domain:challenge:NTProofStr:blob` |
| NetNTLMv1 (±ESS) | NT response = 24 bytes | `5500` | `user::domain:challenge:LM:NT` |
| AS-REP roasting | AS-REP, etype 23 (RC4) | `18200` | `$krb5asrep$23$user@realm:chk$edata2` |
| AS-REP roasting | AS-REP, etype 17 / 18 (AES) | `32100` / `32200` | `$krb5asrep$18$user$realm$chk$edata2` |
| Pre-authentication | AS-REQ, etype 23 | `7500` | `$krb5pa$23$user$realm$timestamp` |
| Pre-authentication | AS-REQ, etype 17 / 18 | `19800` / `19900` | `$krb5pa$18$user$realm$timestamp` |
| Kerberoasting | TGS-REP, etype 23 (RC4) | `13100` | `$krb5tgs$23$*user$realm$spn*$chk$edata2` |
| Kerberoasting | TGS-REP, etype 17 / 18 | `19600` / `19700` | `$krb5tgs$18$service$realm$chk$edata2` |

Format subtleties handled for you:

- **Checksum position** — first 16 bytes for RC4 (etype 23), **last** 12 bytes for
  AES (etypes 17/18);
- **NetNTLMv2 split** — `NTProofStr` (16 bytes) separated from the blob;
- **TGS formats** — asterisks present in RC4 (`$krb5tgs$23$*…$…$…*$`), absent in AES;
- **`krbtgt` tickets skipped** — encrypted with the KDC key, hence uncrackable;
  emitting them would be worthless.

## Requirements

| Component | Version / note |
|---|---|
| Python | ≥ 3.7 — no third-party packages |
| Tshark | Installed with [Wireshark](https://www.wireshark.org/download.html) (tick the *TShark* component) |

Auto-detected paths, in priority order:

```
1. C:\Program Files\Wireshark\tshark.exe
2. C:\Program Files (x86)\Wireshark\tshark.exe
3. tshark (resolved through PATH)
```

A custom path can be supplied with `--tshark`.

## Installation

```bash
git clone https://github.com/<org>/tshark2hashcat.git
cd tshark2hashcat
```

Nothing else: no `pip install`, no build step.

## Usage

```
usage: tshark2hashcat.py [-h] [-o OUTPUT] [--tshark PATH] [-v] pcap
```

| Argument | Description | Default |
|---|---|---|
| `pcap` | `.pcap` / `.pcapng` capture, or a Tshark JSON export (offline analysis) | — |
| `-o`, `--output` | Global file aggregating all hashes | `hashes.txt` |
| `--tshark` | Full path to the Tshark executable | auto-detection |
| `-v`, `--verbose` | Verbose logging | off |

```bash
# Standard analysis
python tshark2hashcat.py capture.pcapng

# Custom output, non-standard Tshark location
python tshark2hashcat.py capture.pcap -o hashes.txt --tshark "D:\Tools\Wireshark\tshark.exe"

# Replay a Tshark JSON export (tests, CI)
python tshark2hashcat.py tshark_export.json
```

**Windows drag-and-drop.** Create `run.bat` next to the script to drop captures
onto a shortcut:

```bat
@echo off
python "%~dp0tshark2hashcat.py" %*
pause
```

## Sample session

```console
C:\tools> python tshark2hashcat.py capture.pcapng
[i] tshark : C:\Program Files\Wireshark\tshark.exe
[i] tshark -r capture.pcapng -T json -x
    [m5600]  frame #18 NTLM (j.doe)
    [m32200] frame #61 Kerberos

=== RESULTS ===
[i] detected protocols: kerberos, ntlmssp
[i] Kerberos accounts WITH pre-auth seen: j.doe

=== KERBEROS IDENTITIES (diagnostics) ===
    frame #61    AS-REQ   user=j.doe realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL salt=EXAMPLE.LOCALj.doe etypes=18
    frame #62    AS-REP   user=j.doe realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL etypes=18

[+]   1 hash (5600)  -> hashes_m5600.txt
      hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
      hashcat -m 32200 hashes_m32200.txt wordlist.txt

[i] 2 hashes also written to .\hashes.txt
```

Output files, next to the capture:

| File | Contents |
|---|---|
| `hashes.txt` | All hashes, every mode combined |
| `hashes_m<mode>.txt` | One file per Hashcat mode, ready for `-m` |

## Cracking with Hashcat

```bash
# Dictionary attack
hashcat -m 5600  hashes_m5600.txt  rockyou.txt
hashcat -m 32200 hashes_m32200.txt rockyou.txt

# Dictionary + rules
hashcat -m 32200 hashes_m32200.txt rockyou.txt -r rules/best64.rule

# Mask attack (known password policy)
hashcat -m 19700 hashes_m19700.txt -a 3 ?u?l?l?l?l?l?l?d

# Show results
hashcat -m 32200 hashes_m32200.txt --show
```

Hashes are also accepted by **John the Ripper jumbo** (`netntlm`, `netntlmv2`,
`krb5asrep`, `krb5pa-sha1`, `krb5tgs`).

> **Note — modes 19600/19700 (AES TGS).** The Kerberos AES salt is
> `REALM + sAMAccountName` of the **service account**. The script defaults to the
> first SPN component (machine-account convention: `HOST/srv` → salt `REALMHOST$`).
> If cracking fails, identify the real service account in the *Kerberos
> identities* section and adjust the `user` field accordingly.

## Missing-data policy

The program never guesses. Every unusable frame is reported in a final summary
stating the exact cause:

```console
[!] Missing data / skipped items:
    - NTLM frame #51: 'server_challenge' missing -> hash not generated
    - Kerberos frame #77: TGS-REP but cname/realm/spn missing (user=j.doe, realm=EXAMPLE.LOCAL, spn=None) -> skipped
    - Kerberos frame #80: AS-REP unknown etype (1) -> skipped
```

This policy guarantees no output line can be rejected by Hashcat for a format
error (`Separator unmatched`, `Token length exception`).

## Architecture

```
capture.pcapng
      |
      v
+-------------------------------+
| tshark -r capture -T json -x  |   Single call: dissected fields
+-------------------------------+   + raw bytes of every layer
        |                    |
        v                    v
  Dissected fields      Raw bytes (-x)
  ntlmssp.* /           NTLMSSP\0 signature
  kerberos.*            scan (clear, Base64)
        |                    |
        v                    |
  Challenge/response         |
  pairing by IP:port tuple   |
        +----------+---------+
                   v
       Per-mode Hashcat validators
            (official grammar)
                   v
    hashes.txt  +  hashes_m<mode>.txt
```

1. **Dissected fields first** — the reliable path: message types, etypes and
   security buffers are already interpreted by Tshark.
2. **Raw scan as fallback** — essential when the encapsulation went unrecognized
   (HTTP `Authorization: NTLM …` header, `AUTH NTLM` command, RPC…).
3. **Validation before writing** — every candidate line is checked against the
   constraints of the official Hashcat modules (lengths, separators, bounds:
   `user` ≤ 60 chars, domain ≤ 45, checksum sizes…).

## Known limitations

- An **incomplete or truncated** authentication exchange yields no hash — by
  design, and reported in the anomaly summary.
- Kerberos **PKINIT / FAST** provides no crackable material: the absence of
  results is cryptographically expected.
- NetNTLM challenge/response pairing relies on the IP:port tuple, then on
  appearance order as a last resort; heavily interleaved flows may require
  prior capture filtering.

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `tshark not found` | Tshark outside standard paths | `--tshark "C:\path\to\tshark.exe"` |
| `no protocol detected` | Capture has no NTLM/Kerberos auth | Check: `tshark -q -r capture.pcapng -z io,phs` |
| `tshark failed` | Corrupted or unexpected file | Open the capture in Wireshark to validate |
| Hashcat: `Separator unmatched` | Manually written line in the file | Regenerate the file using this script only |
| Mode 19700 not cracking | Wrong service account (salt) | See the [19600/19700 note](#cracking-with-hashcat) |

## Contributing

Contributions are welcome: new hash formats, support for additional
encapsulations, test corpora. Please open an *issue* to discuss any new
validator before implementing it, and attach a (sanitized) sample capture
together with the expected Hashcat output.

## License

Distributed under the [Apache License 2.0](LICENSE) — © 2026 tshark2hashcat contributors.

Free usage, modification and redistribution, including commercially, with an
express patent-litigation safeguard. Copyright and license notices must be
preserved in every copy.
