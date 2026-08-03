#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tshark2hashcat.py
==================

Extrait, avec Tshark comme unique source de données, les éléments de
captures .pcap/.pcapng utilisables par Hashcat :

* NetNTLMv2 (mode 5600) et NetNTLMv1/ESS (mode 5500) ;
* Kerberos AS-REQ avec PA-ENC-TIMESTAMP (modes 7500, 19800, 19900) ;
* Kerberos AS-REP (modes 18200, 32100, 32200) ;
* Kerberos TGS-REP (modes 13100, 19600, 19700) ;
* APOP (mode 20) ;
* SNMPv3 USM (mode 25000) ;
* WPA/WPA2 PMKID et EAPOL (mode 22000) ;
* identifiants transmis en clair dans credentials.txt.

Le programme n'ouvre jamais un fichier de capture avec une bibliothèque
pcap : il effectue un seul appel à Tshark (``-T json -x``), puis travaille
sur le JSON disséqué et les octets bruts fournis par Tshark. Pour les très
gros échantillons, un filtre Tshark sélectionne les protocoles/signatures
utiles afin d'éviter de produire plusieurs gigaoctets de JSON ;
``--full-packets`` désactive ce filtre.

Exemples :

    python tshark2hashcat.py capture.pcapng
    python tshark2hashcat.py capture.pcap -o hashes.txt \
        --tshark "C:\\Program Files\\Wireshark\\tshark.exe"
    python tshark2hashcat.py export_tshark.json

Les noms de champs Kerberos ont changé entre les versions de Wireshark.
Le code accepte à la fois les anciens champs spécialisés
(``encryptedKDCREPData_cipher``, ``encryptedTicketData_cipher`` et
``PA_ENC_TIMESTAMP_cipher``) et le champ générique moderne
``kerberos.cipher``, en utilisant le contexte ASN.1 du champ pour ne pas
confondre le ticket chiffré et l'enc-part du message.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import json
import lzma
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import unquote_plus


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",
]

HEX = frozenset("0123456789abcdef")
NTLMSSP_MAGIC = b"NTLMSSP\x00"

# Hashcat modes supported by this program.
MODE_ASREP = {17: 32100, 18: 32200, 23: 18200}
MODE_TGS = {17: 19600, 18: 19700, 23: 13100}
MODE_ASREQ = {17: 19800, 18: 19900, 23: 7500}
MODE_SNMP = 25000  # SNMPv3 HMAC-MD5-96/HMAC-SHA1-96 (Hashcat universal mode)
MODE_WPA = 22000   # WPA-PBKDF2-PMKID+EAPOL
MT_NAMES = {"10": "AS-REQ", "11": "AS-REP", "13": "TGS-REP"}

NTLM_MESSAGE_TYPE_KEYS = ("ntlmssp.messagetype",)
NTLM_CHALLENGE_KEYS = (
    "ntlmssp.ntlmserverchallenge",
    "ntlmssp.serverchallenge",
    "ntlmssp.challenge",
)
NTLM_LM_KEYS = ("ntlmssp.auth.lmresponse", "ntlmssp.lmresponse")
NTLM_NT_KEYS = ("ntlmssp.auth.ntresponse", "ntlmssp.ntresponse")
NTLM_USER_KEYS = ("ntlmssp.auth.username", "ntlmssp.username")
NTLM_DOMAIN_KEYS = ("ntlmssp.auth.domain", "ntlmssp.domain")

KRB_USER_KEYS = (
    "kerberos.CNameString",
    "kerberos.cname-string",
    "kerberos.cname_string_value",
)
KRB_REALM_KEYS = ("kerberos.crealm", "kerberos.realm")
KRB_SNAME_KEYS = ("kerberos.SNameString", "kerberos.sname-string")
KRB_ETYPE_KEYS = (
    "kerberos.etype",
    "kerberos.PA_ENC_TIMESTAMP_etype",
    "kerberos.pa-enc-timestamp.etype",
)
KRB_SALT_KEYS = (
    "kerberos.salt",
    "kerberos.info_salt",
    "kerberos.info2_salt",
    "kerberos.pw_salt",
)

KRB_PA_TIMESTAMP_CIPHER_KEYS = {
    "kerberos.PA_ENC_TIMESTAMP_cipher",
    "kerberos.PA-ENC-TIMESTAMP_cipher",
    "kerberos.pa_enc_timestamp_cipher",
    "kerberos.pa-enc-timestamp.cipher",
}
KRB_ASREP_CIPHER_KEYS = {
    "kerberos.encryptedKDCREPData_cipher",
    "kerberos.encryptedKDCRepData_cipher",
    "kerberos.asrep_cipher",
}
KRB_TGS_CIPHER_KEYS = {
    "kerberos.encryptedTicketData_cipher",
    "kerberos.encrypted_ticket_data_cipher",
    "kerberos.tgs_cipher",
}

# The filter keeps the single Tshark call practical for very large samples
# (some wiki files contain hundreds of thousands of unrelated packets).  It
# still selects all supported dissectors and raw signatures used by the
# fallback scanners.  ``--full-packets`` disables it for forensic use.
INTEREST_FILTER = (
    'ntlmssp or kerberos or snmp or eapol or wlan or ftp or telnet or http or smtp or imap or pop '
    'or tcp contains "NTLMSSP" or udp contains "NTLMSSP" '
    'or tcp contains "TlRMTVNTUA" or udp contains "TlRMTVNTUA" '
    'or tcp contains "APOP" or udp contains "APOP" '
    'or tcp contains "AUTH " or udp contains "AUTH " '
    'or tcp contains "USER " or udp contains "USER " '
    'or tcp contains "PASS " or udp contains "PASS " '
    'or tcp contains "user=" or udp contains "user=" '
    'or tcp contains "username=" or udp contains "username=" '
    'or tcp contains "password=" or udp contains "password=" '
    'or tcp contains "Authorization: Basic" '
    'or tcp contains "login:" or tcp contains "Password:"'
)

# HTTP/IMAP/SMTP authentication often transports NTLM in base64.  The
# boundary assertions prevent a long ASCII paragraph from being considered
# one base64 token.
BASE64_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}(?:={0,2}))(?![A-Za-z0-9+/=])"
)


# ---------------------------------------------------------------------------
# Generic JSON helpers
# ---------------------------------------------------------------------------


def walk(node: Any) -> Iterator[tuple[str, Any]]:
    """Yield every ``(key, value)`` pair in a Tshark JSON structure."""

    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def walk_context(
    node: Any,
    ancestors: tuple[tuple[str, dict[str, Any]], ...] = (),
) -> Iterator[
    tuple[
        str,
        Any,
        tuple[tuple[str, dict[str, Any]], ...],
        dict[str, Any] | None,
    ]
]:
    """Like :func:`walk`, but also returns the containing dictionaries.

    ``ancestors`` contains pairs ``(key_used_to_enter_dict, dict)``.  It is
    enough to distinguish, for example, ``kerberos.cipher`` in an AS-REP
    enc-part from ``kerberos.cipher`` in the encrypted Ticket of the same
    packet.
    """

    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value, ancestors, node
            yield from walk_context(value, ancestors + ((key, node),))
    elif isinstance(node, list):
        for value in node:
            yield from walk_context(value, ancestors)


def scalar_strings(value: Any) -> Iterator[str]:
    """Yield text values recursively, ignoring numeric JSON metadata."""

    if isinstance(value, str):
        if value:
            yield value
    elif isinstance(value, list):
        for item in value:
            yield from scalar_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from scalar_strings(item)


def first_str(value: Any) -> str | None:
    """Return the first non-empty string in a JSON value."""

    return next(scalar_strings(value), None)


def clean_text(value: Any) -> str | None:
    """Clean a Tshark display value without changing its case."""

    value = first_str(value)
    if value is None:
        return None
    value = value.strip(" \t\r\n\x00")
    if not value or value.upper() in {"NULL", "<MISSING>", "N/A"}:
        return None
    return value


def norm_hex(value: Any) -> str | None:
    """Normalize a Tshark hex field to continuous lower-case hex.

    With ``-T json -x``, a raw field is normally a list whose first member is
    the hex string and whose following members are offset/length metadata.
    Only the first textual member is considered.
    """

    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                result = norm_hex(item)
                if result:
                    return result
        return None
    if not isinstance(value, str):
        return None

    text = value.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    # Tshark may display raw bytes as aa:bb or aa bb.
    text = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    if not text or len(text) % 2:
        return None
    if any(ch not in HEX for ch in text):
        return None
    return text


def field_values(node: Any, keys: Iterable[str]) -> Iterator[Any]:
    wanted = set(keys)
    for key, value in walk(node):
        if key in wanted:
            yield value


def find_str(node: Any, keys: Sequence[str]) -> str | None:
    """Find the first textual value, respecting the alias priority."""

    for wanted in keys:
        for key, value in walk(node):
            if key == wanted:
                result = clean_text(value)
                if result is not None:
                    return result
    return None


def find_all_str(node: Any, keys: Sequence[str]) -> list[str]:
    """Return all textual values for aliases, in JSON order."""

    wanted = set(keys)
    result: list[str] = []
    for key, value in walk(node):
        if key in wanted:
            for item in scalar_strings(value):
                item = item.strip(" \t\r\n\x00")
                if item and item.upper() not in {"NULL", "<MISSING>", "N/A"}:
                    result.append(item)
    return result


def find_hex(node: Any, keys: Sequence[str]) -> str | None:
    for wanted in keys:
        for key, value in walk(node):
            if key == wanted:
                result = norm_hex(value)
                if result:
                    return result
    return None


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = re.search(r"0x[0-9a-fA-F]+|[-+]?\d+", text)
    if not match:
        return None
    try:
        token = match.group(0)
        return int(token, 0 if token.lower().startswith(("0x", "+0x", "-0x")) else 10)
    except ValueError:
        return None


def find_int(node: Any, keys: Sequence[str]) -> int | None:
    for wanted in keys:
        for key, value in walk(node):
            if key == wanted:
                values = [value] if not isinstance(value, list) else value
                for item in values:
                    result = parse_int(item)
                    if result is not None:
                        return result
    return None


def packet_layers(packet: Any) -> dict[str, Any]:
    """Accept normal Tshark JSON and the two common exported variants."""

    if not isinstance(packet, dict):
        return {}
    source = packet.get("_source")
    if isinstance(source, dict) and isinstance(source.get("layers"), dict):
        return source["layers"]
    if isinstance(packet.get("layers"), dict):
        return packet["layers"]
    return {}


def tuple4(layers: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """Return (source, destination, source port, destination port)."""

    source = find_str(layers, ("ip.src", "ipv6.src"))
    destination = find_str(layers, ("ip.dst", "ipv6.dst"))
    sport = find_str(layers, ("tcp.srcport", "udp.srcport"))
    dport = find_str(layers, ("tcp.dstport", "udp.dstport"))
    if all((source, destination, sport, dport)):
        return source, destination, sport, dport
    return None


def reverse_tuple(flow: tuple[str, str, str, str] | None):
    if flow is None:
        return None
    return flow[1], flow[0], flow[3], flow[2]


def first_raw_field(layers: dict[str, Any], key: str) -> bytes | None:
    value = find_hex(layers, (key,))
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def frame_bytes(layers: dict[str, Any]) -> bytes:
    """Return the complete captured frame supplied by ``-x``."""

    raw = first_raw_field(layers, "frame_raw")
    if raw is not None:
        return raw

    # A few old Tshark versions omit frame_raw.  Choose the largest genuine
    # protocol raw field as a safe fallback; never concatenate all *_raw
    # fields, since that duplicates every header and field.
    candidates: list[bytes] = []
    for key, value in walk(layers):
        if not key.endswith("_raw") or key in {"frame_raw"}:
            continue
        raw_value = norm_hex(value)
        if not raw_value:
            continue
        # Bit-field raw values are JSON lists beginning with "0"/"1" and
        # are not useful as a frame fallback.
        if isinstance(value, list) and len(value) > 1 and len(raw_value) <= 2:
            continue
        try:
            candidates.append(bytes.fromhex(raw_value))
        except ValueError:
            pass
    return max(candidates, key=len, default=b"")


# ---------------------------------------------------------------------------
# Hashcat validators
# ---------------------------------------------------------------------------


def is_hex(value: str, length: int | None = None, minlen: int = 0, maxlen: int | None = None) -> bool:
    if not value or any(ch not in HEX for ch in value):
        return False
    if length is not None and len(value) != length:
        return False
    if len(value) < minlen or (maxlen is not None and len(value) > maxlen):
        return False
    return len(value) % 2 == 0


def _field_len_ok(value: str, low: int, high: int) -> bool:
    return low <= len(value) <= high and len(value) % 2 == 0


def validate(mode: int, line: str) -> bool:
    """Validate exactly the formats accepted by the official Hashcat modes."""

    if mode in (5500, 5600):
        parts = line.split(":")
        if len(parts) != 6:
            return False
        user, empty, domain, first, second, third = parts
        if not (0 <= len(user) <= 60 and empty == "" and len(domain) <= 45):
            return False
        if mode == 5500:
            # Hashcat 5500: user::domain:LM:NT:server-challenge.
            return is_hex(first, 48) and is_hex(second, 48) and is_hex(third, 16)
        # Hashcat 5600: user::domain:server-challenge:NTProofStr:blob.
        return is_hex(first, 16) and is_hex(second, 32) and is_hex(third, minlen=2, maxlen=1024)

    if mode == 18200:
        match = re.fullmatch(
            r"\$krb5asrep\$23\$([^@$:$]+)@([^:$]+):([0-9a-f]{32})\$([0-9a-f]+)",
            line,
        )
        return bool(match) and _field_len_ok(match.group(4), 2, 40960)

    if mode in (32100, 32200):
        etype = 17 if mode == 32100 else 18
        match = re.fullmatch(
            rf"\$krb5asrep\${etype}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)",
            line,
        )
        return bool(match) and _field_len_ok(match.group(4), 2, 40960)

    if mode in (19800, 19900):
        etype = 17 if mode == 19800 else 18
        match = re.fullmatch(
            rf"\$krb5pa\${etype}\$([^$]+)\$([^$]+)\$([0-9a-f]+)",
            line,
        )
        return bool(match) and _field_len_ok(match.group(3), 104, 112)

    if mode == 7500:
        # Official mode 7500:
        # $krb5pa$23$user$realm$salt$timestamp(36 bytes)+checksum(16 bytes)
        match = re.fullmatch(
            r"\$krb5pa\$23\$([^$]+)\$([^$]+)\$([^$]*)\$([0-9a-f]{104})",
            line,
        )
        return bool(match)

    if mode == 13100:
        match = re.fullmatch(
            r"\$krb5tgs\$23\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$([0-9a-f]{32})\$([0-9a-f]+)",
            line,
        )
        if match:
            return _field_len_ok(match.group(5), 2, 40960)
        # Official mode 13100 also accepts the compact form.  It is needed
        # for an AD machine account such as ``HOST$`` because '$' is the
        # Hashcat field separator and cannot occur in the account token.
        compact = re.fullmatch(
            r"\$krb5tgs\$23\$([0-9a-f]{32})\$([0-9a-f]+)", line
        )
        return bool(compact) and _field_len_ok(compact.group(2), 2, 40960)

    if mode in (19600, 19700):
        etype = 17 if mode == 19600 else 18
        # Hashcat accepts both the short AES form and the form carrying the
        # SPN between a pair of asterisks.  We emit the latter so the exact
        # SPN seen in the packet is retained.
        match = re.fullmatch(
            rf"\$krb5tgs\${etype}\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$([0-9a-f]{{24}})\$([0-9a-f]+)",
            line,
        )
        if not match:
            match = re.fullmatch(
                rf"\$krb5tgs\${etype}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)",
                line,
            )
            return bool(match) and _field_len_ok(match.group(4), 2, 40960)
        return _field_len_ok(match.group(5), 2, 40960)

    if mode == 25000:
        # Hashcat official universal SNMPv3 mode:
        # $SNMPv3$0$packet-number$packet-with-zeroed-auth$engine-id$digest
        match = re.fullmatch(
            r"\$SNMPv3\$0\$([0-9]{1,8})\$([0-9a-f]{24,3000})\$([0-9a-f]{26,68})\$([0-9a-f]{24})",
            line,
        )
        return bool(match)

    if mode == 22000:
        # WPA*01 (PMKID) and WPA*02 (EAPOL) are both accepted by Hashcat's
        # unified WPA mode.  The detailed field checks are intentionally
        # delegated to Hashcat; this guard only prevents malformed lines.
        if line.startswith("WPA*01*"):
            parts = line.split("*")
            return (
                len(parts) == 9
                and is_hex(parts[2], 32)
                and is_hex(parts[3], 12)
                and is_hex(parts[4], 12)
                and is_hex(parts[5], minlen=2, maxlen=64)
                and parts[6] == ""
                and parts[7] == ""
                and parts[8] == ""
            )
        if line.startswith("WPA*02*"):
            parts = line.split("*")
            return (
                len(parts) == 9
                and is_hex(parts[2], 32)
                and is_hex(parts[3], 12)
                and is_hex(parts[4], 12)
                and is_hex(parts[5], minlen=2, maxlen=64)
                and is_hex(parts[6], 64)
                and is_hex(parts[7], minlen=2, maxlen=8192)
                and re.fullmatch(r"[0-9a-f]{2}", parts[8] or "") is not None
            )
        return False

    if mode == 20:
        if ":" not in line:
            return False
        digest, salt = line.split(":", 1)
        return is_hex(digest, 32) and 0 < len(salt) <= 256

    return False


# ---------------------------------------------------------------------------
# NTLM (NetNTLMv1 / NetNTLMv2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Challenge:
    frame: int
    flow: tuple[str, str, str, str] | None
    value: str


def ntlm_build(
    user: str | None,
    domain: str | None,
    challenge: str | None,
    lm: str | None,
    nt: str | None,
    frame: int | str,
    missing: list[str],
) -> list[tuple[int, str]]:
    """Build only a complete NetNTLMv1/v2 line."""

    user = clean_text(user)
    domain = clean_text(domain) or ""
    challenge = norm_hex(challenge)
    lm = norm_hex(lm)
    nt = norm_hex(nt)

    if not user:
        missing.append(f"NTLM frame #{frame}: username absent -> hash non généré")
        return []
    if not challenge:
        missing.append(f"NTLM frame #{frame}: server challenge absent -> hash non généré")
        return []
    if not nt:
        missing.append(f"NTLM frame #{frame}: NT response absent -> hash non généré")
        return []

    if len(challenge) != 16:
        missing.append(f"NTLM frame #{frame}: server challenge de longueur invalide -> ignoré")
        return []

    if len(nt) == 48 and lm and len(lm) == 48:
        # Hashcat mode 5500's official order is LM:NT:challenge.
        return [(5500, f"{user}::{domain}:{lm}:{nt}:{challenge}")]

    if len(nt) > 48:
        # NetNTLMv2 stores the 16-byte proof first, then the blob.
        return [(5600, f"{user}::{domain}:{challenge}:{nt[:32]}:{nt[32:]}")]

    missing.append(
        f"NTLM frame #{frame}: NT response de {len(nt) // 2} octets "
        f"(v1=24 octets ou v2>24 octets attendus) -> ignoré"
    )
    return []


def ntlm_secbuf(message: bytes, offset: int) -> bytes | None:
    """Read an NTLM security buffer safely."""

    if offset < 0 or offset + 8 > len(message):
        return None
    length, _maximum, relative = struct.unpack_from("<HHI", message, offset)
    if relative > len(message) or length > len(message) - relative:
        return None
    return message[relative : relative + length]


def _decode_ntlm_text(data: bytes | None, unicode_hint: bool) -> str:
    if not data:
        return ""
    if unicode_hint and len(data) % 2 == 0:
        try:
            text = data.decode("utf-16-le", "replace")
            if text.count("\ufffd") <= max(1, len(text) // 20):
                return text.rstrip("\x00")
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1", "replace").rstrip("\x00")


def ntlm_parse_t2(message: bytes) -> tuple[str, str] | None:
    """Return (server challenge, target domain) from NTLMSSP type 2."""

    if len(message) < 32 or not message.startswith(NTLMSSP_MAGIC):
        return None
    try:
        if struct.unpack_from("<I", message, 8)[0] != 2:
            return None
        flags = struct.unpack_from("<I", message, 20)[0]
        target = ntlm_secbuf(message, 12)
        domain = _decode_ntlm_text(target, bool(flags & 0x1))
        return message[24:32].hex(), domain
    except struct.error:
        return None


def ntlm_parse_t3(message: bytes) -> tuple[str, str, str, str] | None:
    """Return (LM response, NT response, domain, username) from type 3."""

    if len(message) < 64 or not message.startswith(NTLMSSP_MAGIC):
        return None
    try:
        if struct.unpack_from("<I", message, 8)[0] != 3:
            return None
        lm = ntlm_secbuf(message, 12)
        nt = ntlm_secbuf(message, 20)
        domain = ntlm_secbuf(message, 28)
        user = ntlm_secbuf(message, 36)
        flags = struct.unpack_from("<I", message, 60)[0]
        unicode_hint = bool(flags & 0x1)
        if lm is None or nt is None or domain is None or user is None:
            return None
        return (
            lm.hex(),
            nt.hex(),
            _decode_ntlm_text(domain, unicode_hint),
            _decode_ntlm_text(user, unicode_hint),
        )
    except struct.error:
        return None


def _base64_decode_token(token: bytes) -> bytes | None:
    try:
        # Some protocol implementations omit padding.
        padded = token + b"=" * ((-len(token)) % 4)
        decoded = base64.b64decode(padded, validate=True)
        return decoded if decoded.startswith(NTLMSSP_MAGIC) else None
    except (binascii.Error, ValueError):
        return None


def ntlm_blobs(data: bytes) -> list[bytes]:
    """Find binary NTLMSSP messages and base64-wrapped messages."""

    result: list[bytes] = []
    seen: set[bytes] = set()

    # Binary signatures.  Keep the remainder of the containing stream; the
    # security buffers contain their own offsets and the parsers are bounded.
    position = 0
    while True:
        position = data.find(NTLMSSP_MAGIC, position)
        if position < 0:
            break
        blob = data[position : position + 65536]
        if blob not in seen:
            seen.add(blob)
            result.append(blob)
        position += 1

    for match in BASE64_TOKEN_RE.finditer(data):
        token = match.group(1)
        if len(token) > 32768:
            continue
        decoded = _base64_decode_token(token)
        if decoded is not None and decoded not in seen:
            seen.add(decoded)
            result.append(decoded)

    return result


def ntlm_messages(data: bytes) -> list[tuple[int, bytes]]:
    """Return all (message type, message bytes) found in a byte string."""

    messages: list[tuple[int, bytes]] = []
    seen: set[tuple[int, bytes]] = set()
    for blob in ntlm_blobs(data):
        position = 0
        while True:
            position = blob.find(NTLMSSP_MAGIC, position)
            if position < 0 or position + 12 > len(blob):
                break
            candidate = blob[position : position + 65536]
            try:
                message_type = struct.unpack_from("<I", candidate, 8)[0]
            except struct.error:
                position += 1
                continue
            if message_type not in (2, 3):
                position += 1
                continue
            item = (message_type, candidate)
            # A candidate can be seen once from frame_raw and once from an
            # ntlmssp_raw field.  Deduplicate before parsing it.
            fingerprint = (message_type, candidate[:4096])
            if fingerprint not in seen:
                seen.add(fingerprint)
                messages.append(item)
            position += 1
    return messages


def choose_challenge(
    challenges: Sequence[Challenge],
    frame: int,
    flow: tuple[str, str, str, str] | None,
) -> str | None:
    wanted = reverse_tuple(flow)
    if wanted is not None:
        for challenge in reversed(challenges):
            if challenge.frame <= frame and challenge.flow == wanted:
                return challenge.value
        # Captures can omit IP/port fields on one side.  A same-flow match is
        # less precise, but better than mixing in an unrelated conversation.
        for challenge in reversed(challenges):
            if challenge.frame <= frame and challenge.flow == flow:
                return challenge.value
    for challenge in reversed(challenges):
        if challenge.frame <= frame:
            return challenge.value
    return None


# ---------------------------------------------------------------------------
# APOP and clear-text credentials
# ---------------------------------------------------------------------------


def _b64d(value: str) -> str | None:
    try:
        raw = re.sub(r"\s+", "", value).encode("ascii")
        raw += b"=" * ((-len(raw)) % 4)
        return base64.b64decode(raw, validate=True).decode("latin-1", "replace")
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return None


def _credential_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip(" \t\r\n\x00")
    if not value or len(value) > 4096 or any(ord(ch) < 9 for ch in value):
        return None
    return value


def apop_scan(raw: bytes, missing: list[str]) -> list[tuple[int, str]]:
    """Extract ``digest:challenge`` for Hashcat mode 20."""

    text = raw.decode("latin-1", "replace")
    events: list[tuple[int, str, str, str | None]] = []

    for match in re.finditer(r"(?im)\+OK[^\r\n]*<([^>\r\n]+)>", text):
        events.append((match.start(), "challenge", match.group(1), None))
    for match in re.finditer(r"(?i)\bAPOP\s+(\S+)\s+([0-9a-f]{32})\b", text):
        events.append((match.start(), "apop", match.group(1), match.group(2).lower()))

    events.sort(key=lambda item: item[0])
    current: str | None = None
    result: list[tuple[int, str]] = []
    for _position, kind, first, second in events:
        if kind == "challenge":
            current = first
        elif current:
            result.append((20, f"{second}:{current}"))
        else:
            missing.append(
                f"APOP ({first}): challenge introuvable (bannière <...> absente) -> ignoré"
            )
    return result


def _telnet_visible(raw: bytes) -> str:
    """Remove Telnet IAC negotiation while preserving user-visible text."""

    visible = bytearray()
    position = 0
    while position < len(raw):
        byte = raw[position]
        if byte != 0xFF:
            visible.append(byte)
            position += 1
            continue
        if position + 1 >= len(raw):
            break
        command = raw[position + 1]
        if command == 0xFF:  # escaped 0xff data byte
            visible.append(0xFF)
            position += 2
        elif command == 0xFA:  # subnegotiation: skip through IAC SE
            end = raw.find(b"\xff\xf0", position + 2)
            position = len(raw) if end < 0 else end + 2
        elif command in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT
            position += 3
        else:  # ordinary two-byte command
            position += 2
    return bytes(visible).decode("latin-1", "replace")


def creds_scan(raw: bytes) -> list[tuple[str, str, str]]:
    """Extract clear-text credentials from one reassembled byte stream."""

    text = _telnet_visible(raw)
    found: list[tuple[str, str, str]] = []

    # Telnet login/password prompts.  These are normally recovered from the
    # packet-order timeline because the prompt and the typed answer use
    # opposite TCP directions.
    login_matches = list(
        re.finditer(r"(?im)(?:^|\r?\n)[ \t]*(?:login|username)[ \t]*:[ \t]*([^\r\n]*)", text)
    )
    password_matches = list(
        re.finditer(r"(?im)(?:^|\r?\n)[ \t]*password[ \t]*:[ \t]*([^\r\n]*)", text)
    )

    def collapse_telnet_echo(value: str) -> str:
        # In character-at-a-time Telnet captures the server echoes each input
        # character, so ``fake`` appears as ``ffaakkee``.  Collapse only the
        # unambiguous pairwise echo pattern.
        if len(value) >= 2 and len(value) % 2 == 0 and all(
            value[index] == value[index + 1] for index in range(0, len(value), 2)
        ):
            return value[::2]
        return value

    for login_match in login_matches:
        login = _credential_text(collapse_telnet_echo(login_match.group(1)))
        if login is None:
            continue
        password = next(
            (
                _credential_text(collapse_telnet_echo(match.group(1)))
                for match in password_matches
                if match.start() >= login_match.end()
            ),
            None,
        )
        if password is not None:
            found.append(("Telnet login/password", login, password))

    # FTP, POP3 and simple Telnet USER/PASS command streams.
    events: list[tuple[int, str, str]] = []
    for match in re.finditer(r"(?im)(?:^|\r?\n)USER[ \t]+([^\r\n]*)", text):
        events.append((match.start(), "user", match.group(1)))
    for match in re.finditer(r"(?im)(?:^|\r?\n)PASS[ \t]+([^\r\n]*)", text):
        events.append((match.start(), "pass", match.group(1)))
    events.sort(key=lambda item: item[0])
    current_user: str | None = None
    for _position, kind, value in events:
        value = _credential_text(value)
        if kind == "user":
            current_user = value
        elif current_user is not None and value is not None:
            found.append(("FTP/Telnet USER/PASS", current_user, value))
            current_user = None

    # HTTP Basic.
    for match in re.finditer(
        r"(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/]+={0,2})", text
    ):
        decoded = _b64d(match.group(1))
        if decoded and ":" in decoded:
            user, password = decoded.split(":", 1)
            user = _credential_text(user)
            password = _credential_text(password)
            if user is not None and password is not None:
                found.append(("HTTP Basic", user, password))

    # SMTP/IMAP/POP AUTH PLAIN and IMAP AUTHENTICATE PLAIN.
    for match in re.finditer(
        r"(?im)\b(?:AUTH|AUTHENTICATE)\s+PLAIN(?:[ \t]+|\r?\n+)([A-Za-z0-9+/]+={0,2})",
        text,
    ):
        decoded = _b64d(match.group(1))
        if decoded is None:
            continue
        parts = decoded.split("\x00")
        if len(parts) >= 3:
            user, password = parts[-2], parts[-1]
        elif len(parts) == 2:
            user, password = parts
        else:
            continue
        user = _credential_text(user)
        password = _credential_text(password)
        if user is not None and password is not None:
            found.append(("AUTH PLAIN", user, password))

    # AUTH LOGIN, with the two usual layouts:
    #   AUTH LOGIN\r\nbase64(user)\r\nbase64(pass)
    #   AUTH LOGIN base64(user)\r\nbase64(pass)
    auth_login = re.compile(
        r"(?im)\b(?:AUTH|AUTHENTICATE)\s+LOGIN(?:[ \t]+([A-Za-z0-9+/]+={0,2}))?"
        r"[ \t]*\r?\n+[ \t]*([A-Za-z0-9+/]+={0,2})[ \t]*\r?\n+[ \t]*([A-Za-z0-9+/]+={0,2})"
    )
    for match in auth_login.finditer(text):
        inline_user = match.group(1)
        user_b64 = inline_user or match.group(2)
        pass_b64 = match.group(3) if inline_user else match.group(3)
        # When there is no inline value, groups 2 and 3 are user/password.
        if inline_user:
            pass_b64 = match.group(2)
        user = _b64d(user_b64)
        password = _b64d(pass_b64)
        user = _credential_text(user)
        password = _credential_text(password)
        if user is not None and password is not None:
            found.append(("AUTH LOGIN", user, password))

    # HTTP query/form credentials.  Decode percent-encoding and '+' as a
    # space, while retaining the exact clear-text value in the report.
    form_re = re.compile(
        r"(?i)(?:^|[?&\s])(?:user(?:name)?|login)=([^&\s]+)"
        r"[&;](?:pass(?:word)?|pwd)=([^&\s]+)"
    )
    reverse_form_re = re.compile(
        r"(?i)(?:^|[?&\s])(?:pass(?:word)?|pwd)=([^&\s]+)"
        r"[&;](?:user(?:name)?|login)=([^&\s]+)"
    )
    for match in form_re.finditer(text):
        user = _credential_text(unquote_plus(match.group(1)))
        password = _credential_text(unquote_plus(match.group(2)))
        if user is not None and password is not None:
            found.append(("HTTP form", user, password))
    for match in reverse_form_re.finditer(text):
        password = _credential_text(unquote_plus(match.group(1)))
        user = _credential_text(unquote_plus(match.group(2)))
        if user is not None and password is not None:
            found.append(("HTTP form", user, password))

    # Stable deduplication.
    seen: set[tuple[str, str, str]] = set()
    result: list[tuple[str, str, str]] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# WPA/WPA2 EAPOL -> Hashcat mode 22000
# ---------------------------------------------------------------------------


def _wlan_ssid_from_raw(raw: bytes) -> str | None:
    """Read the SSID information element from a beacon/probe response."""

    if len(raw) < 12:
        return None
    frame_control = int.from_bytes(raw[0:2], "little")
    if ((frame_control >> 2) & 0x03) == 0 and len(raw) >= 36:
        subtype = (frame_control >> 4) & 0x0F
        if subtype not in (5, 8):  # probe response or beacon
            return None
        position = 24 + 12  # full WLAN header + fixed beacon parameters
    else:
        # Tshark's wlan.mgt_raw starts immediately at the fixed management
        # parameters, without the 24-byte WLAN header.
        position = 12
    while position + 2 <= len(raw):
        tag, length = raw[position], raw[position + 1]
        position += 2
        if position + length > len(raw):
            break
        if tag == 0:
            ssid = raw[position : position + length]
            # Hashcat stores ESSIDs as hex and permits an empty SSID only for
            # hidden networks; skip hidden beacons here because a later
            # directed probe/association may reveal the name.
            return ssid.hex() if ssid else None
        position += length
    return None


def wpa_pmkid_line(layers: dict[str, Any], ssids: dict[str, str]) -> str | None:
    """Build a WPA*01 PMKID line when an RSN PMKID is present."""

    pmkid = find_hex(layers, ("wlan.rsn.ie.pmkid",))
    ap = find_str(layers, ("wlan.bssid",))
    source = find_str(layers, ("wlan.sa",))
    destination = find_str(layers, ("wlan.da",))
    if not (pmkid and len(pmkid) == 32 and ap and source and destination):
        return None
    ap = ap.replace(":", "").lower()
    source = source.replace(":", "").lower()
    destination = destination.replace(":", "").lower()
    client = destination if source == ap else source if destination == ap else None
    ssid = ssids.get(ap)
    if not (client and ssid and len(client) == 12):
        return None
    return f"WPA*01*{pmkid}*{ap}*{client}*{ssid}***"


def wpa_eapol_line(
    layers: dict[str, Any],
    ssids: dict[str, str],
    m1_nonces: dict[tuple[str, str, str], str],
) -> str | None:
    """Build a WPA*02 M1+M2 line from a captured 4-way handshake."""

    message_number = find_int(layers, ("wlan_rsna_eapol.keydes.msgnr",))
    if message_number not in (1, 2):
        return None
    ap = find_str(layers, ("wlan.bssid",))
    source = find_str(layers, ("wlan.sa",))
    destination = find_str(layers, ("wlan.da",))
    nonce = find_hex(layers, ("wlan_rsna_eapol.keydes.nonce",))
    replay = find_str(
        layers,
        ("eapol.keydes.replay_counter", "wlan_rsna_eapol.keydes.replay_counter"),
    )
    if not (ap and source and destination and nonce and replay and len(nonce) == 64):
        return None
    ap = ap.replace(":", "").lower()
    source = source.replace(":", "").lower()
    destination = destination.replace(":", "").lower()
    if len(ap) != 12 or len(source) != 12 or len(destination) != 12:
        return None

    raw_eapol = first_raw_field(layers, "eapol_raw")
    if raw_eapol is None:
        return None
    if message_number == 1 and source == ap:
        ssid = find_hex(layers, ("wlan.ssid", "wlan_mgt.ssid", "wlan.tag.ssid"))
        if ssid:
            ssids[ap] = ssid
        # The client address is the destination of M1.
        m1_nonces[(ap, destination, replay)] = nonce
        return None

    if message_number != 2 or source == ap:
        return None
    client = source
    anonce = m1_nonces.get((ap, client, replay))
    if anonce is None:
        # Replay counters are occasionally rewritten by a bridge.  Use the
        # most recent M1 for the same AP/client as a conservative fallback.
        for (candidate_ap, candidate_client, _candidate_replay), value in reversed(
            list(m1_nonces.items())
        ):
            if candidate_ap == ap and candidate_client == client:
                anonce = value
                break
    ssid = ssids.get(ap)
    mic = find_hex(layers, ("wlan_rsna_eapol.keydes.mic",))
    if not (anonce and ssid and mic and len(mic) == 32):
        return None
    mic_bytes = bytes.fromhex(mic)
    mic_offset = raw_eapol.find(mic_bytes)
    if mic_offset < 0:
        return None
    # Hashcat expects the EAPOL frame with the MIC field zeroed.
    eapol_zeroed = raw_eapol[:mic_offset] + (b"\x00" * 16) + raw_eapol[mic_offset + 16 :]
    return (
        f"WPA*02*{mic}*{ap}*{client}*{ssid}*{anonce}*"
        f"{eapol_zeroed.hex()}*a2"
    )


# ---------------------------------------------------------------------------
# SNMPv3 USM -> Hashcat mode 25000
# ---------------------------------------------------------------------------


def snmpv3_line(layers: dict[str, Any], frame: int) -> str | None:
    """Build the official universal SNMPv3 Hashcat line.

    Hashcat mode 25000 accepts both HMAC-MD5-96 and HMAC-SHA1-96, so the
    packet itself does not need to reveal which USM authentication protocol
    was configured for the user.  The authenticationParameters OCTET STRING
    is replaced by twelve zero bytes in the packet salt, exactly as required
    by the Hashcat module.
    """

    flags = find_int(layers, ("snmp.msgFlags",))
    if flags is None or not (flags & 0x01):
        return None
    packet_number = find_str(layers, ("snmp.msgID",))
    # Hashcat's packet-number token is an eight-digit display/identity field;
    # some real agents emit nine- or ten-digit msgIDs.  The number is not part
    # of the cryptographic salt, so the capture frame number is the portable
    # fallback in that case.
    if not (packet_number and packet_number.isdigit() and len(packet_number) <= 8):
        packet_number = find_str(layers, ("frame.number",)) or str(frame)
    auth = find_hex(layers, ("snmp.msgAuthenticationParameters",))
    engine_id = find_hex(layers, ("snmp.msgAuthoritativeEngineID",))
    raw = first_raw_field(layers, "snmp_raw")
    if not (packet_number and packet_number.isdigit() and auth and engine_id and raw):
        return None
    if len(auth) != 24 or len(engine_id) < 26:
        return None
    try:
        auth_bytes = bytes.fromhex(auth)
    except ValueError:
        return None
    offset = raw.find(auth_bytes)
    if offset < 0:
        return None
    normalized_packet = raw[:offset] + (b"\x00" * 12) + raw[offset + 12 :]
    return f"$SNMPv3$0${packet_number}${normalized_packet.hex()}${engine_id}${auth}"


# ---------------------------------------------------------------------------
# Kerberos
# ---------------------------------------------------------------------------


def _path_keys(ancestors: tuple[tuple[str, dict[str, Any]], ...]) -> list[str]:
    return [key for key, _container in ancestors]


# Kerberos PA-ENC-TIMESTAMP is sometimes exposed by ``tshark -T fields`` but
# omitted from the JSON tree when a PA-DATA sequence contains repeated keys
# (JSON objects cannot represent two equal keys).  The raw ASN.1 bytes are
# still present in ``-T json -x``.  This small DER reader is not a pcap reader:
# it only recovers the already-dissected Kerberos value from Tshark's bytes.

def _der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int] | None:
    """Return (tag, content_start, content_end, next_offset) for one DER TLV."""

    if offset >= len(data):
        return None
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return None
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            return None
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        return None
    return tag, offset, end, end


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    children: list[tuple[int, int, int, int]] = []
    position = start
    while position < end:
        item = _der_tlv(data, position)
        if item is None or item[3] > end:
            break
        children.append(item)
        position = item[3]
    return children


def _der_integer(data: bytes, item: tuple[int, int, int, int]) -> int | None:
    tag, start, end, _next = item
    if tag != 0x02 or start >= end:
        return None
    return int.from_bytes(data[start:end], "big", signed=True)


def _der_context_child(
    data: bytes, item: tuple[int, int, int, int], wanted_tag: int
) -> tuple[int, int, int, int] | None:
    tag, start, end, _next = item
    if tag != wanted_tag:
        return None
    children = _der_children(data, start, end)
    return children[0] if children else None


def _der_octet_from_context(
    data: bytes, item: tuple[int, int, int, int], wanted_tag: int = 0xA2
) -> bytes | None:
    child = _der_context_child(data, item, wanted_tag)
    if child is None:
        return None
    tag, start, end, _next = child
    if tag != 0x04:
        return None
    return data[start:end]


def _der_pa_timestamp_ciphers(raw: bytes) -> list[tuple[int | None, str]]:
    """Recover (etype, cipher) from the AS-REQ's [3] PA-DATA field.

    It is important not to search every nested sequence for ``[1] INTEGER 2``:
    Kerberos request bodies contain many unrelated ASN.1 integers with that
    shape.  We first identify an AS-REQ sequence (pvno=5, msg-type=10), then
    inspect only its context tag [3], which is the PA-DATA sequence.
    """

    found: list[tuple[int | None, str]] = []
    seen: set[tuple[int | None, str]] = set()

    def inspect_asreq(data: bytes, start: int, end: int) -> None:
        for outer in _der_children(data, start, end):
            if outer[0] not in (0x30, 0x6A):  # SEQUENCE or [APPLICATION 10]
                continue
            children = _der_children(data, outer[1], outer[2])
            pvno: int | None = None
            msg_type: int | None = None
            padata_field: tuple[int, int, int, int] | None = None
            for child in children:
                if child[0] in (0xA0, 0xA1, 0xA2):
                    inner = _der_context_child(data, child, child[0])
                    if inner is not None:
                        integer_value = _der_integer(data, inner)
                        # KDC-REQ is seen both with explicit application
                        # wrappers and with the normal implicit [1]/[2]
                        # fields in Tshark raw exports.  Values are
                        # unambiguous here: pvno=5, AS-REQ msg-type=10.
                        if integer_value == 5:
                            pvno = integer_value
                        elif integer_value == 10:
                            msg_type = integer_value
                elif child[0] == 0xA3:
                    padata_field = child
            if pvno != 5 or msg_type != 10 or padata_field is None:
                continue

            padata_sequence = _der_context_child(data, padata_field, 0xA3)
            if padata_sequence is None or padata_sequence[0] != 0x30:
                continue
            for pa in _der_children(data, padata_sequence[1], padata_sequence[2]):
                if pa[0] != 0x30:
                    continue
                pa_children = _der_children(data, pa[1], pa[2])
                ptype: int | None = None
                pvalue: bytes | None = None
                for child in pa_children:
                    if child[0] == 0xA1:
                        integer_child = _der_context_child(data, child, 0xA1)
                        if integer_child is not None:
                            ptype = _der_integer(data, integer_child)
                    elif child[0] == 0xA2:
                        pvalue = _der_octet_from_context(data, child, 0xA2)
                if ptype != 2 or not pvalue:
                    continue

                # pvalue is EncTimestamp ::= EncryptedData.  Its [0]
                # integer is the enctype and its [2] OCTET STRING is the
                # ciphertext.
                etype: int | None = None
                cipher: bytes | None = None
                encrypted_outer = _der_tlv(pvalue, 0)
                encrypted_items: list[tuple[int, int, int, int]] = []
                if encrypted_outer and encrypted_outer[0] == 0x30:
                    encrypted_items = _der_children(
                        pvalue, encrypted_outer[1], encrypted_outer[2]
                    )
                for encrypted_field in encrypted_items:
                    if encrypted_field[0] == 0xA0:
                        integer_child = _der_context_child(
                            pvalue, encrypted_field, 0xA0
                        )
                        if integer_child is not None:
                            etype = _der_integer(pvalue, integer_child)
                    elif encrypted_field[0] == 0xA2:
                        cipher = _der_octet_from_context(
                            pvalue, encrypted_field, 0xA2
                        )
                if cipher:
                    candidate = (etype, cipher.hex())
                    if candidate not in seen:
                        seen.add(candidate)
                        found.append(candidate)

    # The raw field is normally exactly the AS-REQ element.  If it includes a
    # TCP record mark or an Ethernet/IP header, try every aligned DER TLV and
    # keep only an object that proves it is pvno 5 / msg-type 10.
    for offset in range(len(raw)):
        if raw[offset] not in (0x30, 0x6A):
            continue
        item = _der_tlv(raw, offset)
        if item is not None:
            inspect_asreq(raw, offset, item[3])
    return found


def _raw_asreq_ciphers(layers: dict[str, Any], frame_raw: bytes) -> list[tuple[int | None, str]]:
    candidates: list[bytes] = []
    for key in ("kerberos.as_req_element_raw", "kerberos_raw"):
        raw = first_raw_field(layers, key)
        if raw:
            candidates.append(raw)
    if not candidates and frame_raw:
        candidates.append(frame_raw)
    found: list[tuple[int | None, str]] = []
    seen: set[tuple[int | None, str]] = set()
    for raw in candidates:
        for item in _der_pa_timestamp_ciphers(raw):
            if item not in seen:
                seen.add(item)
                found.append(item)
    return found


def _nearest_container(
    ancestors: tuple[tuple[str, dict[str, Any]], ...], fragment: str
) -> dict[str, Any] | None:
    fragment = fragment.lower()
    for key, container in reversed(ancestors):
        if fragment in key.lower():
            return container
    return None


def _value_in_message(
    layers: dict[str, Any], root_key: str, keys: Sequence[str], exclude_ticket: bool = False
) -> str | None:
    """Get a value from one outer AS/TGS message, not a nested ticket."""

    for wanted in keys:
        for key, value, ancestors, _parent in walk_context(layers):
            if key != wanted:
                continue
            path = _path_keys(ancestors)
            if root_key not in path:
                continue
            if exclude_ticket and any("ticket_element" in item.lower() for item in path):
                continue
            result = clean_text(value)
            if result:
                return result
    return None


def _message_user_realm(layers: dict[str, Any], message_type: str) -> tuple[str | None, str | None]:
    root = {
        "10": "kerberos.as_req_element",
        "11": "kerberos.as_rep_element",
        "13": "kerberos.tgs_rep_element",
    }[message_type]

    user = _value_in_message(layers, root, KRB_USER_KEYS, exclude_ticket=True)

    # For AS-REP/TGS-REP, crealm is the client/user realm.  For AS-REQ the
    # request body uses kerberos.realm.
    if message_type == "10":
        realm = _value_in_message(layers, root, ("kerberos.realm",), exclude_ticket=True)
        if realm is None:
            realm = _value_in_message(layers, root, KRB_REALM_KEYS, exclude_ticket=True)
    else:
        realm = _value_in_message(layers, root, ("kerberos.crealm",), exclude_ticket=True)
        if realm is None:
            realm = _value_in_message(layers, root, KRB_REALM_KEYS, exclude_ticket=True)

    if user is None:
        user = find_str(layers, KRB_USER_KEYS)
    if realm is None:
        realm = find_str(layers, KRB_REALM_KEYS)
    return user, realm


def _der_sname_components(raw: bytes) -> list[str]:
    """Read the PrincipalName name-string sequence from raw DER."""

    components: list[str] = []
    # sname_element is a SEQUENCE with [1] name-string.  Accept an
    # application wrapper as well, since old Tshark versions expose both.
    roots = _der_children(raw, 0, len(raw))
    candidates = roots
    for root in roots:
        if root[0] & 0x20:
            nested = _der_children(raw, root[1], root[2])
            if nested and any(item[0] == 0xA1 for item in nested):
                candidates = nested
                break
    for item in candidates:
        if item[0] != 0xA1:
            continue
        sequence = _der_context_child(raw, item, 0xA1)
        if sequence is None or sequence[0] != 0x30:
            continue
        for part in _der_children(raw, sequence[1], sequence[2]):
            if part[0] not in (0x1B, 0x0C, 0x16):
                continue
            value = raw[part[1] : part[2]].decode("utf-8", "replace").strip()
            if value and value not in components:
                components.append(value)
    return components


def _spn_for_context(
    layers: dict[str, Any], ancestors: tuple[tuple[str, dict[str, Any]], ...]
) -> str | None:
    ticket = _nearest_container(ancestors, "ticket_element")
    if ticket is None:
        return None

    # JSON objects cannot retain repeated SNameString keys.  The raw field
    # inside this ticket still contains every PrincipalName component.
    raw_sname = first_raw_field(ticket, "kerberos.sname_element_raw")
    if raw_sname:
        components = _der_sname_components(raw_sname)
        if components:
            return "/".join(components)

    components: list[str] = []
    for item in find_all_str(ticket, KRB_SNAME_KEYS):
        # Avoid duplicated fields when an exporter represents the same ASN.1
        # value both at the tree and leaf level.
        if item not in components:
            components.append(item)
    return "/".join(components) if components else None


def _etype_from_context(
    layers: dict[str, Any], ancestors: tuple[tuple[str, dict[str, Any]], ...]
) -> int | None:
    # The nearest enc-part/PA-DATA dictionary is the authoritative context.
    for fragment in ("enc_part_element", "PA_DATA_element", "padata_value"):
        container = _nearest_container(ancestors, fragment)
        if container is not None:
            value = find_int(container, KRB_ETYPE_KEYS)
            if value is not None:
                return value
    # Old field names often put the etype directly beside the cipher.
    value = find_int(layers, KRB_ETYPE_KEYS)
    return value


def _pa_timestamp_context(
    ancestors: tuple[tuple[str, dict[str, Any]], ...], key: str
) -> bool:
    key_lower = key.lower()
    if key in KRB_PA_TIMESTAMP_CIPHER_KEYS or "enc_timestamp" in key_lower:
        return True

    # Modern Tshark exposes PA-ENC-TIMESTAMP as kerberos.cipher and keeps the
    # padata type (2) in the same PA_DATA element.
    for ancestor_key, container in reversed(ancestors):
        if "pa_data_element" not in ancestor_key.lower() and "padata" not in ancestor_key.lower():
            continue
        for candidate_key in ("kerberos.padata_type", "kerberos.padata.type"):
            value = find_int(container, (candidate_key,))
            if value == 2:
                return True
    return False


def _cipher_role(
    message_type: str,
    key: str,
    ancestors: tuple[tuple[str, dict[str, Any]], ...],
) -> str | None:
    key_lower = key.lower()
    path = [item.lower() for item in _path_keys(ancestors)]

    if message_type == "10":
        if key in KRB_PA_TIMESTAMP_CIPHER_KEYS or _pa_timestamp_context(ancestors, key):
            return "asreq"
        return None

    if message_type == "11":
        if key in KRB_ASREP_CIPHER_KEYS:
            return "asrep"
        if (
            key_lower == "kerberos.cipher"
            and any("as_rep_element" in item for item in path)
            and any("enc_part_element" in item for item in path)
            and not any("ticket_element" in item for item in path)
        ):
            return "asrep"
        return None

    if message_type == "13":
        if key in KRB_TGS_CIPHER_KEYS:
            return "tgs"
        if (
            key_lower == "kerberos.cipher"
            and any("tgs_rep_element" in item for item in path)
            and any("ticket_element" in item for item in path)
            and any("enc_part_element" in item for item in path)
        ):
            return "tgs"
        return None

    return None


def _kerberos_salts(layers: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in walk(layers):
        if key not in KRB_SALT_KEYS:
            continue
        for item in scalar_strings(value):
            item = item.strip()
            if not item:
                continue
            # INFO/INFO2 salts are OCTET STRINGs.  JSON may render those as
            # 44:45:... or as continuous hex; Hashcat needs the text salt.
            if re.fullmatch(r"[0-9a-fA-F][0-9a-fA-F: ]*", item):
                compact = re.sub(r"[^0-9a-fA-F]", "", item)
                if compact and len(compact) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(compact).decode("latin-1")
                        if decoded and all(32 <= ord(ch) < 127 for ch in decoded):
                            item = decoded
                    except (ValueError, UnicodeDecodeError):
                        pass
            if item not in values:
                values.append(item)
    return values


def _kerberos_etypes(layers: dict[str, Any]) -> list[int]:
    values: set[int] = set()
    for key, value in walk(layers):
        if key not in KRB_ETYPE_KEYS and key not in {
            "kerberos.kdc-req-body.etype",
            "kerberos.ENCTYPE",
        }:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            parsed = parse_int(item)
            if parsed is not None and parsed >= 0:
                values.add(parsed)
    return sorted(values)


def _has_pa_timestamp(layers: dict[str, Any]) -> bool:
    for key, value, ancestors, _parent in walk_context(layers):
        if key in KRB_PA_TIMESTAMP_CIPHER_KEYS and norm_hex(value):
            return True
        if key.lower() == "kerberos.cipher" and norm_hex(value) and _pa_timestamp_context(ancestors, key):
            return True
    for key, value in walk(layers):
        if key in {"kerberos.padata_type", "kerberos.padata.type"}:
            if parse_int(value) == 2:
                return True
    return False


def krb_asrep_line(etype: int, user: str, realm: str, cipher: str) -> tuple[int, str]:
    if etype == 23:
        principal = user if "@" in user else f"{user}@{realm}"
        return 18200, f"$krb5asrep$23${principal}:{cipher[:32]}${cipher[32:]}"
    return MODE_ASREP[etype], f"$krb5asrep${etype}${user}${realm}${cipher[-24:]}${cipher[:-24]}"


def krb_tgs_line(etype: int, user: str, realm: str, spn: str, cipher: str) -> tuple[int, str]:
    if etype == 23:
        if any("$" in value for value in (user, realm, spn)):
            # Hashcat mode 13100's compact syntax is the only unambiguous
            # representation when an account contains the '$' separator.
            return 13100, f"$krb5tgs$23${cipher[:32]}${cipher[32:]}"
        return 13100, f"$krb5tgs$23$*{user}${realm}${spn}*${cipher[:32]}${cipher[32:]}"
    # Hashcat 6.2.x and earlier use the compact AES TGS syntax.  The service
    # component is the account token; the complete SPN remains in the
    # Kerberos diagnostic section.
    service_account = spn.split("/", 1)[0] if spn else user
    return MODE_TGS[etype], f"$krb5tgs${etype}${service_account}${realm}${cipher[-24:]}${cipher[:-24]}"


def krb_asreq_line(
    etype: int,
    user: str,
    realm: str,
    cipher: str,
    salt: str | None = None,
) -> tuple[int, str]:
    if etype == 23:
        # Mode 7500 has an explicit salt token.  AD normally uses
        # REALM+username; ETYPE_INFO/ETYPE_INFO2, when present, is preferred
        # by the caller.
        salt = salt or f"{realm}{user}"
        return 7500, f"$krb5pa$23${user}${realm}${salt}${cipher}"
    return MODE_ASREQ[etype], f"$krb5pa${etype}${user}${realm}${cipher}"


def krb_packet(
    layers: dict[str, Any],
    frame: int,
    missing: list[str],
    preauth_users: set[str],
    diagnostics: list[tuple[int, str, str | None, str | None, str | None, list[str], list[int]]],
    raw_asreq_ciphers: Sequence[tuple[int | None, str]] = (),
) -> list[tuple[int, str]]:
    message_type_value = find_str(layers, ("kerberos.msg_type",))
    message_type_number = parse_int(message_type_value)
    message_type = str(message_type_number) if message_type_number is not None else None
    if message_type not in MT_NAMES:
        return []

    user, realm = _message_user_realm(layers, message_type)
    salts = _kerberos_salts(layers)
    etypes = _kerberos_etypes(layers)
    root_spn: str | None = None
    if message_type == "13":
        # The diagnostic SPN is taken from the first response ticket.
        for key, value, ancestors, _parent in walk_context(layers):
            if key in KRB_SNAME_KEYS and any(
                "tgs_rep_element" in path_key.lower() for path_key in _path_keys(ancestors)
            ):
                candidate = _spn_for_context(layers, ancestors)
                if candidate:
                    root_spn = candidate
                    break

    diagnostics.append(
        (frame, MT_NAMES[message_type], user, realm, root_spn, salts, etypes)
    )

    if message_type == "10" and (_has_pa_timestamp(layers) or raw_asreq_ciphers) and user:
        preauth_users.add(user)

    result: list[tuple[int, str]] = []
    seen_candidates: set[str] = set()

    for key, value, ancestors, _parent in walk_context(layers):
        cipher = norm_hex(value)
        if not cipher:
            continue
        role = _cipher_role(message_type, key, ancestors)
        if role is None:
            continue
        if cipher in seen_candidates:
            continue
        seen_candidates.add(cipher)

        etype = _etype_from_context(layers, ancestors)
        if role == "asreq":
            if not (user and realm):
                missing.append(f"Kerberos frame #{frame}: AS-REQ sans cname/realm -> ignoré")
                continue
            if etype in MODE_ASREQ:
                salt = salts[0] if salts else None
                result.append(krb_asreq_line(etype, user, realm, cipher, salt))
            else:
                missing.append(f"Kerberos frame #{frame}: AS-REQ etype inconnu ({etype}) -> ignoré")
        elif role == "asrep":
            if not (user and realm):
                missing.append(f"Kerberos frame #{frame}: AS-REP sans cname/realm -> ignoré")
                continue
            if etype in MODE_ASREP:
                result.append(krb_asrep_line(etype, user, realm, cipher))
            else:
                missing.append(f"Kerberos frame #{frame}: AS-REP etype inconnu ({etype}) -> ignoré")
        elif role == "tgs":
            spn = _spn_for_context(layers, ancestors)
            if spn and spn.lower().startswith("krbtgt"):
                continue
            if not (user and realm and spn):
                missing.append(
                    f"Kerberos frame #{frame}: TGS-REP sans cname/realm/spn -> ignoré "
                    f"(user={user}, realm={realm}, spn={spn})"
                )
                continue
            if etype in MODE_TGS:
                result.append(krb_tgs_line(etype, user, realm, spn, cipher))
            else:
                missing.append(f"Kerberos frame #{frame}: TGS-REP etype inconnu ({etype}) -> ignoré")

    # Repeated PA-DATA entries can be collapsed by the JSON exporter.  The
    # DER fallback above recovers the PA-ENC-TIMESTAMP ciphertext directly
    # from the raw bytes returned by Tshark.
    if message_type == "10":
        for raw_etype, cipher in raw_asreq_ciphers:
            if cipher in seen_candidates:
                continue
            seen_candidates.add(cipher)
            etype = raw_etype if raw_etype is not None else find_int(layers, KRB_ETYPE_KEYS)
            if not (user and realm):
                missing.append(f"Kerberos frame #{frame}: AS-REQ sans cname/realm -> ignoré")
            elif etype in MODE_ASREQ:
                salt = salts[0] if salts else None
                result.append(krb_asreq_line(etype, user, realm, cipher, salt))
            else:
                missing.append(f"Kerberos frame #{frame}: AS-REQ etype inconnu ({etype}) -> ignoré")

    return result


# ---------------------------------------------------------------------------
# Reassembly of application data from Tshark JSON
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadChunk:
    frame: int
    sequence: int | None
    data: bytes


def _payload_from_layers(layers: dict[str, Any]) -> bytes:
    """Get application bytes without a second packet-capture reader."""

    # These fields are supplied by ``-x`` and are already the payload after
    # the corresponding transport header.
    for key in (
        "tcp.payload_raw",
        "udp.payload_raw",
        "sctp.data_raw",
        "data.data_raw",
        "data_raw",
    ):
        raw = first_raw_field(layers, key)
        if raw:
            return raw

    # If a very old Tshark has no payload_raw field, strip the transport
    # header from tcp_raw/udp_raw.  The TCP data offset is in byte 12.
    tcp = first_raw_field(layers, "tcp_raw")
    if tcp and len(tcp) >= 20:
        header_length = ((tcp[12] >> 4) & 0xF) * 4
        if 20 <= header_length <= len(tcp):
            return tcp[header_length:]

    udp = first_raw_field(layers, "udp_raw")
    if udp and len(udp) >= 8:
        return udp[8:]

    return b""


def reassemble(chunks: Sequence[PayloadChunk]) -> bytes:
    """Reassemble one direction, removing exact TCP retransmissions."""

    if not chunks:
        return b""
    ordered = list(chunks)
    if any(item.sequence is not None for item in ordered):
        ordered.sort(key=lambda item: (item.sequence is None, item.sequence or 0, item.frame))

    output = bytearray()
    seen: set[tuple[int | None, bytes]] = set()
    cursor: int | None = None
    for chunk in ordered:
        if not chunk.data:
            continue
        fingerprint = (chunk.sequence, chunk.data)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        data = chunk.data
        if chunk.sequence is not None and cursor is not None:
            if chunk.sequence < cursor:
                overlap = cursor - chunk.sequence
                if overlap >= len(data):
                    continue
                data = data[overlap:]
            # Missing bytes are deliberately not synthesized.  Appending the
            # next captured segment still permits protocol line extraction.
            cursor = max(cursor, chunk.sequence + len(chunk.data))
        elif chunk.sequence is not None:
            cursor = chunk.sequence + len(chunk.data)
        output.extend(data)
    return bytes(output)


def find_tshark(cli_path: str | None) -> str | None:
    from shutil import which

    candidates = ([cli_path] if cli_path else []) + TSHARK_CANDIDATES
    for candidate in candidates:
        if candidate and (os.path.isfile(candidate) or which(candidate)):
            return which(candidate) or candidate
    return None


def iter_json_array(stream: Any, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    """Stream one top-level JSON array with the standard library only.

    A full ``-T json -x`` export can be several gigabytes even when the pcap
    itself is small.  ``json.load`` would make large, otherwise perfectly
    valid, Wireshark samples fail through memory exhaustion.  ``raw_decode``
    lets us release each packet after it has been processed.  The unconsumed
    text is kept at index zero after every packet; this avoids the subtle
    comma/compaction state bug that otherwise appears in very large exports.
    """

    decoder = json.JSONDecoder()
    buffer = ""
    eof = False

    def read_more() -> None:
        nonlocal buffer, eof
        if eof:
            return
        piece = stream.read(chunk_size)
        if piece == "":
            eof = True
        else:
            buffer += piece

    # Read the opening bracket, retaining any bytes after it.
    while True:
        buffer = buffer.lstrip()
        if buffer:
            if buffer[0] != "[":
                raise ValueError("l'export JSON ne commence pas par une liste")
            buffer = buffer[1:]
            break
        if eof:
            raise ValueError("JSON vide")
        read_more()

    while True:
        buffer = buffer.lstrip()
        if not buffer:
            if eof:
                raise ValueError("liste JSON incomplète")
            read_more()
            continue
        if buffer[0] == "]":
            return
        if buffer[0] == ",":
            buffer = buffer[1:]
            continue
        try:
            value, end = decoder.raw_decode(buffer, 0)
        except json.JSONDecodeError:
            if eof:
                raise ValueError("élément JSON incomplet")
            read_more()
            continue
        # Drop the complete object before yielding it.  The caller can now
        # release the packet while the JSON buffer stays bounded.
        buffer = buffer[end:]
        yield value


def iter_json_path(path: str | Path, remove_after: bool = False) -> Iterator[Any]:
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            yield from iter_json_array(stream)
    finally:
        if remove_after:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def run_tshark(
    tshark: str, capture: str, full_packets: bool = False
) -> Iterator[Any]:
    """Run Tshark exactly once and stream its JSON array.

    Tshark reads gzip captures itself.  It does not accept every bzip2/xz
    attachment in the Wireshark wiki, so those two compression wrappers are
    expanded to a temporary *capture* file before the same single Tshark call;
    packet decoding remains exclusively Tshark's job.
    """

    capture_for_tshark = capture
    decompressed_path: Path | None = None
    suffix = Path(capture).suffix.lower()
    if suffix in {".bz2", ".xz"}:
        fd, temporary_name = tempfile.mkstemp(
            prefix="tshark2hashcat-capture-", suffix=".pcap"
        )
        os.close(fd)
        decompressed_path = Path(temporary_name)
        opener = bz2.open if suffix == ".bz2" else lzma.open
        try:
            with opener(capture, "rb") as source, decompressed_path.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            capture_for_tshark = str(decompressed_path)
        except Exception:
            try:
                decompressed_path.unlink()
            except FileNotFoundError:
                pass
            raise

    # -2 enables the second pass used by Tshark for TCP/UDP reassembly while
    # -x keeps the raw bytes needed for malformed/unknown encapsulations.
    command = [
        tshark,
        "-n",
        "-2",
        "-r",
        capture_for_tshark,
    ]
    if not full_packets:
        command += ["-Y", INTEREST_FILTER]
    command += [
        "-T",
        "json",
        "-x",
        "-o",
        "tcp.desegment_tcp_streams:true",
    ]
    printable = subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
    print(f"[i] {printable}")

    def stream_packets() -> Iterator[Any]:
        # Keep Tshark's JSON off the Python heap and off the filesystem page
        # cache.  This matters for the multi-gigabyte ``-T json -x`` exports
        # produced by the larger Wireshark regression captures.
        error_file = tempfile.TemporaryFile(mode="w+b")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=error_file,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1024 * 1024,
        )
        packet_count = 0
        try:
            if process.stdout is None:
                raise RuntimeError("impossible d'ouvrir stdout de tshark")
            try:
                for packet in iter_json_array(process.stdout):
                    packet_count += 1
                    yield packet
            except Exception as exc:
                error_file.seek(0)
                error_text = error_file.read().decode("utf-8", "replace")
                detail = f"\n{error_text[:1000]}" if error_text else ""
                raise RuntimeError(f"JSON Tshark invalide ou vide : {exc}{detail}") from exc
            # Consume the final newline and close the pipe before wait().
            process.stdout.read()
            process.stdout.close()
            return_code = process.wait()
            error_file.seek(0)
            error_text = error_file.read().decode("utf-8", "replace")
            if return_code != 0 and packet_count == 0:
                # The wiki deliberately contains a few truncated regression
                # files.  Treat a capture-read failure as an empty capture so
                # the batch extractor remains usable across the whole sample
                # corpus; a missing tshark executable is still reported by
                # find_tshark before this point.
                print(
                    f"[!] capture ignorée par tshark (code {return_code}) : "
                    f"{error_text[:500].strip()}",
                    file=sys.stderr,
                )
                return
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None and not process.stdout.closed:
                process.stdout.close()
            error_file.close()
            if decompressed_path is not None:
                try:
                    decompressed_path.unlink()
                except FileNotFoundError:
                    pass

    return stream_packets()


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------


def _add_unique_missing(missing: list[str], value: str) -> None:
    if value not in missing:
        missing.append(value)


def _extract_packets(
    path: str, tshark: str | None, full_packets: bool = False
) -> Iterable[Any]:
    if path.lower().endswith(".json"):
        print(f"[i] lecture directe de l'export JSON : {path}")
        return iter_json_path(path)

    tshark_path = find_tshark(tshark)
    if not tshark_path:
        raise RuntimeError('tshark introuvable. Utilise --tshark "C:\\...\\tshark.exe"')
    print(f"[i] tshark : {tshark_path}")
    return run_tshark(tshark_path, path, full_packets=full_packets)


def _handle_ntlm_message(
    message_type: int,
    message: bytes,
    frame: int,
    flow: tuple[str, str, str, str] | None,
    challenges: list[Challenge],
    results: dict[int, list[str]],
    seen_lines: set[str],
    missing: list[str],
    raw_auth_keys: set[tuple[str, str, str, str]],
    verbose: bool = False,
) -> bool:
    """Handle one raw NTLM type 2/type 3 message.

    Return True for a successfully parsed type-3 message, even if its
    challenge is absent; this tells the caller that a dissection fallback is
    not needed for the same frame.
    """

    if message_type == 2:
        parsed = ntlm_parse_t2(message)
        if parsed:
            challenge, _target_domain = parsed
            item = Challenge(frame, flow, challenge)
            if item not in challenges:
                challenges.append(item)
        return False

    if message_type != 3:
        return False
    parsed = ntlm_parse_t3(message)
    if not parsed:
        return False
    lm, nt, domain, user = parsed
    auth_key = (user, domain, lm, nt)
    if auth_key in raw_auth_keys:
        return True
    raw_auth_keys.add(auth_key)

    challenge = choose_challenge(challenges, frame, flow)
    if challenge is None:
        _add_unique_missing(
            missing,
            f"NTLM frame #{frame}: challenge introuvable pour l'AUTH brut -> hash non généré",
        )
        return True

    for mode, line in ntlm_build(user, domain, challenge, lm, nt, frame, missing):
        if validate(mode, line) and line not in seen_lines:
            seen_lines.add(line)
            results[mode].append(line)
            if verbose:
                print(f"    [m{mode}] frame #{frame} NTLM brut ({user})")
    return True


def _push(
    mode: int,
    line: str,
    description: str,
    results: dict[int, list[str]],
    seen_lines: set[str],
    missing: list[str],
    verbose: bool,
) -> None:
    if not validate(mode, line):
        _add_unique_missing(missing, f"{description}: ligne rejetée par le validateur du mode {mode}")
        return
    if line in seen_lines:
        return
    seen_lines.add(line)
    results[mode].append(line)
    if verbose:
        print(f"    [m{mode}] {description}")


def extract_packets(
    packets: Iterable[Any], verbose: bool = False
) -> tuple[
    dict[int, list[str]],
    list[str],
    set[str],
    set[str],
    list[tuple[int, str, str | None, str | None, str | None, list[str], list[int]]],
    list[tuple[str, str, str]],
]:
    results: dict[int, list[str]] = defaultdict(list)
    missing: list[str] = []
    seen_lines: set[str] = set()
    proto_seen: set[str] = set()
    preauth_users: set[str] = set()
    diagnostics: list[tuple[int, str, str | None, str | None, str | None, list[str], list[int]]] = []

    challenges: list[Challenge] = []
    raw_auth_keys: set[tuple[str, str, str, str]] = set()
    stream_chunks: dict[tuple[Any, ...], list[PayloadChunk]] = defaultdict(list)
    payload_timeline: list[bytes] = []
    wpa_ssids: dict[str, str] = {}
    wpa_m1_nonces: dict[tuple[str, str, str], str] = {}
    snmp_clear_credentials: list[tuple[str, str, str]] = []

    for frame, packet in enumerate(packets, 1):
        layers = packet_layers(packet)
        if not layers:
            continue
        flow = tuple4(layers)
        frame_raw = frame_bytes(layers)
        payload = _payload_from_layers(layers)
        if payload:
            payload_timeline.append(payload)
            if flow is not None:
                sequence = find_int(layers, ("tcp.seq",))
                transport = "tcp" if find_str(layers, ("tcp.srcport",)) else "udp"
                stream_key = (transport,) + flow
                stream_chunks[stream_key].append(PayloadChunk(frame, sequence, payload))
            else:
                stream_key = ("frame", frame)
                stream_chunks[stream_key].append(PayloadChunk(frame, None, payload))

        # WPA/WPA2 4-way handshake (Hashcat 22000).
        if any(key.lower().startswith("wlan") for key, _value in walk(layers)):
            wlan_bssid = find_str(layers, ("wlan.bssid",))
            if wlan_bssid:
                wlan_bssid = wlan_bssid.replace(":", "").lower()
                raw_wlan = first_raw_field(layers, "wlan.mgt_raw")
                raw_ssid = _wlan_ssid_from_raw(raw_wlan or b"")
                if raw_ssid:
                    wpa_ssids[wlan_bssid] = raw_ssid
            wpa_pmkid = wpa_pmkid_line(layers, wpa_ssids)
            if wpa_pmkid:
                proto_seen.add("wpa/wpa2 pmkid")
                _push(
                    MODE_WPA,
                    wpa_pmkid,
                    f"frame #{frame} WPA/WPA2 PMKID",
                    results,
                    seen_lines,
                    missing,
                    verbose,
                )
            wpa_line = wpa_eapol_line(layers, wpa_ssids, wpa_m1_nonces)
            if wpa_line:
                proto_seen.add("wpa/wpa2 eapol")
                _push(
                    MODE_WPA,
                    wpa_line,
                    f"frame #{frame} WPA/WPA2 EAPOL",
                    results,
                    seen_lines,
                    missing,
                    verbose,
                )

        # SNMPv1/v2c community strings are clear text (report them, but do
        # not pretend they are a crackable password hash).
        snmp_version = find_int(layers, ("snmp.version", "snmp.msgVersion"))
        snmp_community = find_str(layers, ("snmp.community",))
        if (
            snmp_version in (0, 1)
            and snmp_community
            and 1 <= len(snmp_community) <= 32
            and all(32 <= ord(char) < 127 for char in snmp_community)
        ):
            item = ("SNMPv1/v2c community", "community", snmp_community)
            if item not in snmp_clear_credentials:
                snmp_clear_credentials.append(item)

        # SNMPv3 USM authentication (Hashcat 25000).
        if any(key.lower().startswith("snmp") for key, _value in walk(layers)):
            line = snmpv3_line(layers, frame)
            if line:
                proto_seen.add("snmpv3 usm")
                _push(
                    MODE_SNMP,
                    line,
                    f"frame #{frame} SNMPv3",
                    results,
                    seen_lines,
                    missing,
                    verbose,
                )

        # Kerberos fields have priority over the raw fallback.
        if any("kerberos" in key.lower() for key, _value in walk(layers)):
            proto_seen.add("kerberos")
            try:
                raw_asreq_ciphers = (
                    _raw_asreq_ciphers(layers, frame_raw)
                    if find_int(layers, ("kerberos.msg_type",)) == 10
                    else ()
                )
                for mode, line in krb_packet(
                    layers,
                    frame,
                    missing,
                    preauth_users,
                    diagnostics,
                    raw_asreq_ciphers,
                ):
                    _push(
                        mode,
                        line,
                        f"frame #{frame} Kerberos",
                        results,
                        seen_lines,
                        missing,
                        verbose,
                    )
            except Exception as exc:  # one malformed packet must not stop a capture
                _add_unique_missing(missing, f"Kerberos frame #{frame}: analyse impossible ({exc})")

        # First register a dissected type-2 challenge.  Raw messages below may
        # then use it even if the raw type-2 parser is incomplete.
        ntlm_present = any("ntlmssp" in key.lower() for key, _value in walk(layers))
        field_message_type = parse_int(find_str(layers, NTLM_MESSAGE_TYPE_KEYS))
        if ntlm_present:
            proto_seen.add("ntlmssp")
            if field_message_type == 2:
                field_challenge = find_hex(layers, NTLM_CHALLENGE_KEYS)
                if field_challenge and len(field_challenge) == 16:
                    candidate = Challenge(frame, flow, field_challenge)
                    if candidate not in challenges:
                        challenges.append(candidate)

        # Raw bytes are scanned per frame (including binary and base64 forms),
        # which handles NTLM hidden in HTTP/IMAP/SMTP even if the dissector did
        # not attach an ntlmssp layer.
        parsed_raw_auth = False
        if frame_raw:
            if NTLMSSP_MAGIC in frame_raw or BASE64_TOKEN_RE.search(frame_raw):
                for message_type, message in ntlm_messages(frame_raw):
                    if message_type in (2, 3):
                        proto_seen.add("ntlmssp (brut -x)")
                    parsed_raw_auth = (
                        _handle_ntlm_message(
                            message_type,
                            message,
                            frame,
                            flow,
                            challenges,
                            results,
                            seen_lines,
                            missing,
                            raw_auth_keys,
                            verbose,
                        )
                        or parsed_raw_auth
                    )

        # A field-only fallback is needed for captures where Tshark exposes the
        # NTLM fields but the frame is truncated before the complete message.
        if ntlm_present and field_message_type == 3 and not parsed_raw_auth:
            user = find_str(layers, NTLM_USER_KEYS)
            domain = find_str(layers, NTLM_DOMAIN_KEYS) or ""
            lm = find_hex(layers, NTLM_LM_KEYS)
            nt = find_hex(layers, NTLM_NT_KEYS)
            challenge = find_hex(layers, NTLM_CHALLENGE_KEYS)
            if challenge is None:
                challenge = choose_challenge(challenges, frame, flow)
            for mode, line in ntlm_build(user, domain, challenge, lm, nt, frame, missing):
                _push(
                    mode,
                    line,
                    f"frame #{frame} NTLM ({user or '?'})",
                    results,
                    seen_lines,
                    missing,
                    verbose,
                )

    # Reassembled streams catch NTLM whose binary or base64 representation
    # crosses a TCP segment boundary.  The local challenge list preserves the
    # order inside that direction; the global list is a fallback for captures
    # where challenge and AUTH are in opposite streams.
    for stream_key, chunks in stream_chunks.items():
        stream = reassemble(chunks)
        if not stream:
            continue
        flow = stream_key[1:] if stream_key and stream_key[0] in {"tcp", "udp"} else None
        local_challenges: list[Challenge] = []
        for message_type, message in ntlm_messages(stream):
            frame = chunks[-1].frame if chunks else 0
            if message_type == 2:
                parsed = ntlm_parse_t2(message)
                if parsed:
                    local_challenges.append(Challenge(frame, flow, parsed[0]))
            elif message_type == 3:
                # Prefer a local challenge only when this direction is the
                # server direction; otherwise choose from the global table.
                parsed = ntlm_parse_t3(message)
                if not parsed:
                    continue
                lm, nt, domain, user = parsed
                challenge = choose_challenge(local_challenges, frame, flow)
                if challenge is None:
                    challenge = choose_challenge(challenges, frame, flow)
                if challenge is None:
                    continue  # already reported by a complete frame, if any
                for mode, line in ntlm_build(user, domain, challenge, lm, nt, frame, missing):
                    _push(
                        mode,
                        line,
                        f"frame #{frame} NTLM réassemblé ({user})",
                        results,
                        seen_lines,
                        missing,
                        verbose,
                    )

    # APOP needs both directions (server banner then client command), so use
    # packet-order payload data.  Clear-text credentials are also checked in
    # each directionally reassembled stream and then in the timeline.
    timeline = b"".join(payload_timeline)
    if timeline and re.search(rb"(?i)\bAPOP\s+\S+\s+[0-9a-f]{32}\b", timeline):
        proto_seen.add("apop")
        for mode, line in apop_scan(timeline, missing):
            _push(mode, line, "APOP", results, seen_lines, missing, verbose)

    credentials: list[tuple[str, str, str]] = list(snmp_clear_credentials)
    credential_seen: set[tuple[str, str, str]] = set(credentials)
    for chunks in stream_chunks.values():
        stream = reassemble(chunks)
        if not stream:
            continue
        for credential in creds_scan(stream):
            if credential not in credential_seen:
                credential_seen.add(credential)
                credentials.append(credential)
    if timeline:
        for credential in creds_scan(timeline):
            if credential not in credential_seen:
                credential_seen.add(credential)
                credentials.append(credential)
    if credentials:
        proto_seen.add("identifiants en clair")

    return results, missing, proto_seen, preauth_users, diagnostics, credentials


def _mode_output_path(output: Path, mode: int) -> Path:
    return output.with_name(f"{output.stem}_m{mode}{output.suffix}")


def write_outputs(
    output_name: str,
    results: dict[int, list[str]],
    credentials: list[tuple[str, str, str]],
) -> int:
    output = Path(output_name)
    output.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for mode in sorted(results):
            for line in results[mode]:
                stream.write(line + "\n")
                total += 1

    for mode in sorted(results):
        path = _mode_output_path(output, mode)
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(results[mode]))
            stream.write("\n")

    if credentials:
        credential_path = output.with_name(f"{output.stem}_credentials.txt")
        with credential_path.open("w", encoding="utf-8", newline="\n") as stream:
            for protocol, user, password in credentials:
                stream.write(f"{protocol}\tuser={user}\tpass={password}\n")

    return total


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extraction de hashes Hashcat depuis un PCAP, via un seul appel Tshark."
    )
    parser.add_argument("pcap", help="fichier .pcap/.pcapng, ou export JSON Tshark")
    parser.add_argument(
        "-o",
        "--output",
        default="hashes.txt",
        help="fichier global de sortie (défaut : hashes.txt)",
    )
    parser.add_argument("--tshark", help="chemin complet vers tshark.exe")
    parser.add_argument(
        "--full-packets",
        action="store_true",
        help="désactive le filtre d'intérêt et transmet tous les paquets à Tshark",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        packets = _extract_packets(args.pcap, args.tshark, args.full_packets)
        (
            results,
            missing,
            proto_seen,
            preauth_users,
            diagnostics,
            credentials,
        ) = extract_packets(packets, verbose=args.verbose)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print("\n=== RÉSULTATS ===")
    print(f"[i] protocoles détectés : {', '.join(sorted(proto_seen)) or 'aucun'}")
    if preauth_users:
        print(
            "[i] comptes AVEC pré-auth Kerberos vus : "
            + ", ".join(sorted(preauth_users))
        )

    if diagnostics:
        print("\n=== IDENTITÉS KERBEROS VUES (diagnostic) ===")
        for frame, name, user, realm, spn, salts, etypes in diagnostics:
            print(
                f"    frame #{frame:<5} {name:<8} user={user or '?'} realm={realm or '?'} "
                f"spn={spn or '-'} salt={' + '.join(salts) or '-'} "
                f"etypes={','.join(map(str, etypes)) or '-'}"
            )

    total = write_outputs(args.output, results, credentials)
    for mode in sorted(results):
        path = _mode_output_path(Path(args.output), mode)
        print(f"[+] {len(results[mode]):3d} hash ({mode}) -> {path}")
        print(f"    hashcat -m {mode} {path} wordlist.txt")

    if credentials:
        credential_path = Path(args.output).with_name(
            f"{Path(args.output).stem}_credentials.txt"
        )
        print(f"\n[+] {len(credentials)} identifiant(s) en clair -> {credential_path}")
        print("=== IDENTIFIANTS EN CLAIR ===")
        for protocol, user, password in credentials:
            print(f"    {protocol:<22} {user} : {password}")

    if missing:
        print("\n[!] Données manquantes / éléments ignorés :")
        for item in sorted(set(missing)):
            print(f"    - {item}")

    if total == 0:
        print(
            "[-] aucun hash produit. La capture peut être valide mais ne pas contenir "
            "d'authentification NTLMSSP/Kerberos/APOP cassable."
        )
    else:
        print(f"\n[i] {total} hash(s) écrit(s) aussi dans ./{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
