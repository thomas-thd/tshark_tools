#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tshark2hashcat — hashes Hashcat et rapport d'audit depuis un pcap, via Tshark."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence, TypeVar
from urllib.parse import unquote_plus

__version__ = "1.0.0"
__author__ = "tshark2hashcat"
__license__ = "Apache-2.0"
__app_name__ = "tshark2hashcat"
__app_short__ = "t2h"
__url__ = "https://github.com/tshark2hashcat/tshark2hashcat"

SUPPORTED_HASHCAT_MODES: tuple[int, ...] = (
    20, 5500, 5600, 7500, 13100, 18200, 19600, 19700, 19800, 19900,
    22000, 32100, 32200, 11400, 16500, 4800,
)
EXPORT_FORMATS: tuple[str, ...] = (
    "txt", "csv", "json", "xlsx", "html", "md", "pcap", "pcapng",
)

HEX_ALPHABET = "0123456789abcdef"
HEX_RE = re.compile(r"^[0-9a-f]*$")

def norm_hex(v: Any) -> Optional[str]:
    """Normalise une valeur tshark en hex continu minuscule.

    Accepte ``'aa:bb'``, ``'AABB'``, ``['aabb']``, espaces, tirets.
    Retourne None si la chaîne n'est pas de l'hex de longueur paire.
    """
    if isinstance(v, list):
        v = next((x for x in v if isinstance(x, str)), None)
    if not isinstance(v, str):
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", v).lower()
    if not s or len(s) % 2 != 0:
        return None
    if any(c not in HEX_ALPHABET for c in s):
        return None
    return s

def is_hex(s: Optional[str], length: Optional[int] = None, minlen: int = 0, maxlen: Optional[int] = None) -> bool:
    """True si ``s`` est de l'hex minuscule de longueur paire (contraintes optionnelles)."""
    if not s or any(c not in HEX_ALPHABET for c in s):
        return False
    if length is not None and len(s) != length:
        return False
    if len(s) < minlen:
        return False
    if maxlen is not None and len(s) > maxlen:
        return False
    return len(s) % 2 == 0

def first_str(v: Any) -> Optional[str]:
    """Première chaîne non vide (récursif dans les listes JSON de tshark)."""
    if isinstance(v, list):
        for x in v:
            r = first_str(x)
            if r:
                return r
        return None
    return v if isinstance(v, str) and v else None

def first_int(v: Any) -> Optional[int]:
    s = first_str(v)
    if s is None:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None

def walk(node: Any) -> Iterator[tuple[str, Any]]:
    """Itère ``(clé, valeur)`` récursivement sur une structure JSON tshark."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from walk(v)
    elif isinstance(node, list):
        for it in node:
            yield from walk(it)

def walk_parent(node: Any, parent: Any = None) -> Iterator[tuple[str, Any, Any]]:
    """Comme :func:`walk` mais fournit aussi le dict parent."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v, node
            yield from walk_parent(v, node)
    elif isinstance(node, list):
        for it in node:
            yield from walk_parent(it, parent)

def find_str(layers: Any, keys: Sequence[str]) -> Optional[str]:
    """Première valeur texte trouvée pour une des clés (alias multiples)."""
    keyset = set(keys)
    for k, v in walk(layers):
        if k in keyset:
            r = first_str(v)
            if r:
                return r
    return None

def find_hex(layers: Any, keys: Sequence[str]) -> Optional[str]:
    keyset = set(keys)
    for k, v in walk(layers):
        if k in keyset:
            r = norm_hex(v)
            if r:
                return r
    return None

def find_all_str(layers: Any, keys: Sequence[str]) -> list[str]:
    keyset = set(keys)
    out: list[str] = []
    for k, v in walk(layers):
        if k in keyset:
            if isinstance(v, list):
                out.extend(x for x in v if isinstance(x, str) and x)
            elif isinstance(v, str) and v:
                out.append(v)
    return out

def index_layers(layers: Any) -> dict[str, list[str]]:
    """Une seule passe : clé tshark → valeurs texte (accélère 13k+ paquets)."""
    idx: dict[str, list[str]] = {}
    for k, v in walk(layers):
        if not isinstance(k, str):
            continue
        if isinstance(v, str) and v:
            idx.setdefault(k, []).append(v)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, str) and x:
                    idx.setdefault(k, []).append(x)
    return idx

def idx_all(idx: dict[str, list[str]], keys: Sequence[str]) -> list[str]:
    out: list[str] = []
    for k in keys:
        vs = idx.get(k)
        if vs:
            out.extend(vs)
    return out

def idx_one(idx: dict[str, list[str]], keys: Sequence[str]) -> Optional[str]:
    for k in keys:
        vs = idx.get(k)
        if vs:
            return vs[0]
    return None

def sibling_int(parent: dict, keys: Sequence[str]) -> Optional[int]:
    for k in keys:
        e = first_str(parent.get(k))
        if e and str(e).lstrip("-").isdigit():
            try:
                return int(e)
            except ValueError:
                continue
    return None

def tuple4(layers: Any) -> Optional[tuple[str, str, str, str]]:
    """``(src, dst, sport, dport)`` IP/TCP|UDP de la trame, pour appairer challenge/auth."""
    src = find_str(layers, ("ip.src", "ipv6.src"))
    dst = find_str(layers, ("ip.dst", "ipv6.dst"))
    sp = find_str(layers, ("tcp.srcport", "udp.srcport"))
    dp = find_str(layers, ("tcp.dstport", "udp.dstport"))
    return (src, dst, sp, dp) if all((src, dst, sp, dp)) else None

def frame_number(layers: Any, fallback: int) -> int:
    n = find_str(layers, ("frame.number",))
    if n and n.isdigit():
        return int(n)
    return fallback

def frame_time(layers: Any) -> Optional[str]:
    return find_str(layers, ("frame.time_epoch", "frame.time"))

def frame_protocols(layers: Any) -> list[str]:
    raw = find_str(layers, ("frame.protocols",))
    if not raw:
        return []
    return [p for p in raw.split(":") if p]

def _top_layer_str(layers: dict, key: str) -> Optional[str]:
    """Lecture O(1) d'un champ tshark au premier niveau de ``layers``."""
    if not isinstance(layers, dict):
        return None
    v = layers.get(key)
    if isinstance(v, list):
        for x in v:
            if isinstance(x, str) and x:
                return x
        return None
    return v if isinstance(v, str) and v else None

PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp", ".pcap.gz", ".pcapng.gz"}

def is_pcap_path(path: str | os.PathLike) -> bool:
    p = str(path).lower()
    return any(p.endswith(s) for s in (".pcap", ".pcapng", ".cap", ".dmp"))

def is_json_export(path: str | os.PathLike) -> bool:
    return str(path).lower().endswith(".json")

def ensure_parent(path: str | os.PathLike) -> Path:
    p = Path(path).expanduser()
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)
    return p

def stem_of(path: str | os.PathLike) -> str:
    p = Path(path)
    # hashes.txt -> hashes ; capture.pcapng -> capture
    return p.stem

def with_suffix(path: str | os.PathLike, suffix: str) -> Path:
    p = Path(path)
    if not suffix.startswith("."):
        suffix = "." + suffix
    return p.with_suffix(suffix)

def unique_path(path: str | os.PathLike) -> Path:
    """Si le fichier existe, ajoute _1, _2, …"""
    p = Path(path)
    if not p.exists():
        return p
    i = 1
    while True:
        cand = p.with_name(f"{p.stem}_{i}{p.suffix}")
        if not cand.exists():
            return cand
        i += 1

def human_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("o", "Kio", "Mio", "Gio", "Tio"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}" if unit != "o" else f"{int(n)} o"
        n /= 1024.0
    return f"{n:.1f} Pio"

def human_duration(seconds: float) -> str:
    if seconds is None:
        return "—"
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "—"
    if seconds < 0:
        return "—"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m} min {s:02d} s"
    h, m = divmod(m, 60)
    return f"{h} h {m:02d} min"

def human_bps(n: Optional[float]) -> str:
    if n is None:
        return "—"
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n < 0:
        return "—"
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"):
        if abs(n) < 1000.0:
            return f"{n:.1f} {unit}" if unit != "bit/s" else f"{int(n)} bit/s"
        n /= 1000.0
    return f"{n:.1f} Pbit/s"

def _fmt_epoch(ts: Optional[float]) -> str:
    if ts is None:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def file_sha256(path: str | os.PathLike, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def file_size(path: str | os.PathLike) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0

def split_csv(value: Optional[str]) -> list[str]:
    """Découpe 'csv,json,xlsx' → ['csv','json','xlsx']."""
    if not value:
        return []
    return [p.strip().lower() for p in value.split(",") if p.strip()]

def parse_int_list(value: Optional[str]) -> list[int]:
    if not value:
        return []
    out: list[int] = []
    for p in value.split(","):
        p = p.strip()
        if p.isdigit() or (p.startswith("-") and p[1:].isdigit()):
            out.append(int(p))
    return out

def which_python() -> str:
    return sys.executable or "python3"

class Timer:
    """Chronomètre simple ``with Timer() as t: ... ; t.seconds``."""

    def __init__(self) -> None:
        self.start = 0.0
        self.end = 0.0

    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc) -> None:
        self.end = time.perf_counter()

    @property
    def seconds(self) -> float:
        end = self.end or time.perf_counter()
        return max(0.0, end - self.start)

def safe_filename(name: str, fallback: str = "output") -> str:
    name = re.sub(r"[^\w.\-]+", "_", name, flags=re.UNICODE).strip("._")
    return name or fallback

def chunks(seq: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]

def dedupe_keep_order(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    out: list[Any] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out

_LANG = "fr"

MESSAGES: dict[str, dict[str, str]] = {
    # --- général ---
    "app.tagline": {
        "fr": "Extraction de hashes Hashcat depuis un PCAP, via Tshark",
        "en": "Extract Hashcat hashes from a PCAP, via Tshark",
    },
    "app.ready": {
        "fr": "Prêt. Choisissez un numéro dans le menu.",
        "en": "Ready. Pick a number from the menu.",
    },
    "err.tshark_missing": {
        "fr": "tshark introuvable. Installez Wireshark ou passez --tshark CHEMIN.",
        "en": "tshark not found. Install Wireshark or pass --tshark PATH.",
    },
    "err.pcap_missing": {
        "fr": "Fichier de capture introuvable : {path}",
        "en": "Capture file not found: {path}",
    },
    "err.pcap_empty": {
        "fr": "La capture ne contient aucun paquet (ou tshark n'a rien renvoyé).",
        "en": "The capture contains no packets (or tshark returned nothing).",
    },
    "err.invalid_format": {
        "fr": "Format d'export inconnu : {fmt}. Choix : {choices}",
        "en": "Unknown export format: {fmt}. Choices: {choices}",
    },
    "err.tshark_failed": {
        "fr": "tshark a échoué (code {code}) : {stderr}",
        "en": "tshark failed (code {code}): {stderr}",
    },
    "err.no_hashes": {
        "fr": "Aucun hash produit. Vérifiez que la capture contient de l'auth NTLMSSP / Kerberos / WPA.",
        "en": "No hash produced. Check that the capture contains NTLMSSP / Kerberos / WPA auth.",
    },
    "err.json_unexpected": {
        "fr": "Sortie tshark inattendue (pas une liste JSON).",
        "en": "Unexpected tshark output (not a JSON list).",
    },
    "err.write": {
        "fr": "Impossible d'écrire {path} : {exc}",
        "en": "Cannot write {path}: {exc}",
    },
    # --- étapes ---
    "stage.find_tshark": {
        "fr": "Recherche de tshark",
        "en": "Looking for tshark",
    },
    "stage.run_tshark": {
        "fr": "Appel tshark (dissection JSON + octets bruts)",
        "en": "Running tshark (JSON dissection + raw bytes)",
    },
    "stage.parse_json": {
        "fr": "Lecture de l'export JSON",
        "en": "Reading JSON export",
    },
    "stage.extract": {
        "fr": "Extraction des hashes et identifiants",
        "en": "Extracting hashes and credentials",
    },
    "stage.export": {
        "fr": "Écriture des exports",
        "en": "Writing exports",
    },
    "stage.report": {
        "fr": "Génération du rapport",
        "en": "Generating report",
    },
    "stage.analyze": {
        "fr": "Analyse de la capture",
        "en": "Analyzing capture",
    },
    "stage.packets": {
        "fr": "Export des paquets",
        "en": "Exporting packets",
    },
    "stage.objects": {
        "fr": "Export des objets",
        "en": "Exporting objects",
    },
    "stage.follow": {
        "fr": "Suivi de flux",
        "en": "Following stream",
    },
    "stage.filter": {
        "fr": "Filtrage / ré-export PCAP",
        "en": "Filtering / re-exporting PCAP",
    },
    # --- résultats ---
    "res.protocols": {
        "fr": "Protocoles détectés : {protos}",
        "en": "Detected protocols: {protos}",
    },
    "res.preauth": {
        "fr": "Comptes AVEC pré-auth Kerberos : {users}",
        "en": "Accounts WITH Kerberos pre-auth: {users}",
    },
    "res.hash_count": {
        "fr": "{n} hash ({mode}) → {path}",
        "en": "{n} hash(es) ({mode}) → {path}",
    },
    "res.total": {
        "fr": "{n} hash(es) écrit(s) dans {path}",
        "en": "{n} hash(es) written to {path}",
    },
    "res.creds": {
        "fr": "{n} identifiant(s) en clair → {path}",
        "en": "{n} cleartext credential(s) → {path}",
    },
    "res.missing": {
        "fr": "Données manquantes / éléments ignorés",
        "en": "Missing data / ignored items",
    },
    "res.none": {
        "fr": "aucun",
        "en": "none",
    },
    "res.packets": {
        "fr": "{n} paquet(s) lu(s)",
        "en": "{n} packet(s) read",
    },
    "res.elapsed": {
        "fr": "Durée : {sec:.2f} s",
        "en": "Elapsed: {sec:.2f} s",
    },
    "res.export_ok": {
        "fr": "Export {fmt} → {path}",
        "en": "Export {fmt} → {path}",
    },
    # --- kerberos diag ---
    "krb.section": {
        "fr": "IDENTITÉS KERBEROS VUES (diagnostic)",
        "en": "KERBEROS IDENTITIES SEEN (diagnostics)",
    },
    # --- wizard ---
    "wiz.title": {
        "fr": "Assistant interactif",
        "en": "Interactive wizard",
    },
    "wiz.ask_pcap": {
        "fr": "Chemin du fichier .pcap / .pcapng / .json",
        "en": "Path to .pcap / .pcapng / .json file",
    },
    "wiz.ask_action": {
        "fr": "Que souhaitez-vous faire ?",
        "en": "What would you like to do?",
    },
    "wiz.ask_formats": {
        "fr": "Formats d'export (csv,json,xlsx,txt,html,md) séparés par des virgules",
        "en": "Export formats (csv,json,xlsx,txt,html,md) comma-separated",
    },
    "wiz.ask_output": {
        "fr": "Préfixe des fichiers de sortie",
        "en": "Output file prefix",
    },
    # --- help ---
    "help.extract": {
        "fr": "Extraire les hashes cassables et identifiants depuis un PCAP",
        "en": "Extract crackable hashes and credentials from a PCAP",
    },
    "help.analyze": {
        "fr": "Analyser une capture (protocoles, conversations, endpoints, expert)",
        "en": "Analyze a capture (protocols, conversations, endpoints, expert)",
    },
    "help.stats": {
        "fr": "Statistiques tshark (-z) : io,phs, conv, endpoints, http, dns…",
        "en": "Tshark statistics (-z): io,phs, conv, endpoints, http, dns…",
    },
    "help.packets": {
        "fr": "Lister / exporter les paquets (filtre d'affichage, champs, CSV/JSON/XLSX)",
        "en": "List / export packets (display filter, fields, CSV/JSON/XLSX)",
    },
    "help.follow": {
        "fr": "Suivre un flux TCP / UDP / HTTP / TLS / SIP",
        "en": "Follow a TCP / UDP / HTTP / TLS / SIP stream",
    },
    "help.objects": {
        "fr": "Exporter les objets (HTTP, SMB, IMF, TFTP, DICOM…)",
        "en": "Export objects (HTTP, SMB, IMF, TFTP, DICOM…)",
    },
    "help.filter": {
        "fr": "Filtrer une capture et ré-écrire un .pcap / .pcapng",
        "en": "Filter a capture and rewrite a .pcap / .pcapng",
    },
    "help.report": {
        "fr": "Rapport HTML / Markdown de synthèse",
        "en": "HTML / Markdown summary report",
    },
    "help.wizard": {
        "fr": "Menu interactif guidé",
        "en": "Guided interactive menu",
    },
    "help.info": {
        "fr": "Métadonnées de la capture (capinfos)",
        "en": "Capture metadata (capinfos)",
    },
    "help.ifaces": {
        "fr": "Lister les interfaces de capture tshark",
        "en": "List tshark capture interfaces",
    },
    "help.protocols": {
        "fr": "Lister les protocoles / champs tshark",
        "en": "List tshark protocols / fields",
    },
    "help.hashcat": {
        "fr": "Générer / afficher la commande Hashcat adaptée",
        "en": "Generate / show the matching Hashcat command",
    },
    "help.creds": {
        "fr": "Extraire uniquement les identifiants en clair",
        "en": "Extract cleartext credentials only",
    },
    "help.convert": {
        "fr": "Convertir pcap ↔ pcapng / découper / fusionner",
        "en": "Convert pcap ↔ pcapng / split / merge",
    },
    "help.expert": {
        "fr": "Infos expert Wireshark (erreurs, warnings)",
        "en": "Wireshark expert info (errors, warnings)",
    },
    "help.hosts": {
        "fr": "Extraire les hôtes (DNS / IP)",
        "en": "Extract hosts (DNS / IP)",
    },
    "help.voip": {
        "fr": "Flux RTP / SIP / VoIP",
        "en": "RTP / SIP / VoIP streams",
    },
    "help.capture": {
        "fr": "Capture live (wrapper tshark -i)",
        "en": "Live capture (tshark -i wrapper)",
    },
    "help.decode": {
        "fr": "Forcer un décodage (decode-as)",
        "en": "Force a decode (decode-as)",
    },
    "help.fields": {
        "fr": "Extraire des champs tshark (-T fields -e …)",
        "en": "Extract tshark fields (-T fields -e …)",
    },
    "help.modes": {
        "fr": "Catalogue des modes Hashcat connus",
        "en": "Catalog of known Hashcat modes",
    },
    # --- ntlm / kerberos messages internes ---
    "miss.ntlm_field": {
        "fr": "NTLM frame #{frame}: '{name}' manquant → hash non généré",
        "en": "NTLM frame #{frame}: '{name}' missing → hash not generated",
    },
    "miss.ntlm_len": {
        "fr": "NTLM frame #{frame}: NT response de {nbytes} octets (ni v1=24o, ni v2>24o) → ignoré",
        "en": "NTLM frame #{frame}: NT response is {nbytes} bytes (neither v1=24B nor v2>24B) → ignored",
    },
    "miss.apop": {
        "fr": "APOP ({user}): challenge introuvable (pas de bannière '<...>') → ignoré",
        "en": "APOP ({user}): challenge not found (no '<...>' banner) → ignored",
    },
    "miss.krb_asreq": {
        "fr": "Kerberos frame #{frame}: AS-REQ sans cname/realm → ignoré",
        "en": "Kerberos frame #{frame}: AS-REQ without cname/realm → ignored",
    },
    "miss.krb_asreq_e": {
        "fr": "Kerberos frame #{frame}: AS-REQ etype inconnu ({e}) → ignoré",
        "en": "Kerberos frame #{frame}: AS-REQ unknown etype ({e}) → ignored",
    },
    "miss.krb_asrep": {
        "fr": "Kerberos frame #{frame}: AS-REP mais cname/realm manquant → ignoré",
        "en": "Kerberos frame #{frame}: AS-REP but cname/realm missing → ignored",
    },
    "miss.krb_asrep_e": {
        "fr": "Kerberos frame #{frame}: AS-REP etype inconnu ({e}) → ignoré",
        "en": "Kerberos frame #{frame}: AS-REP unknown etype ({e}) → ignored",
    },
    "miss.krb_tgs": {
        "fr": "Kerberos frame #{frame}: TGS-REP mais cname/realm/spn manquant (user={user}, realm={realm}, spn={spn}) → ignoré",
        "en": "Kerberos frame #{frame}: TGS-REP but cname/realm/spn missing (user={user}, realm={realm}, spn={spn}) → ignored",
    },
    "miss.krb_tgs_e": {
        "fr": "Kerberos frame #{frame}: TGS-REP etype inconnu ({e}) → ignoré",
        "en": "Kerberos frame #{frame}: TGS-REP unknown etype ({e}) → ignored",
    },
    "miss.validate": {
        "fr": "{src}: ligne rejetée par le validateur du mode {mode}",
        "en": "{src}: line rejected by mode {mode} validator",
    },
}

def set_lang(lang: str) -> None:
    """Définit la langue courante ('fr' ou 'en')."""
    global _LANG
    lang = (lang or "fr").lower()
    if lang.startswith("en"):
        _LANG = "en"
    else:
        _LANG = "fr"

def get_lang() -> str:
    return _LANG

def t(key: str, **kwargs: Any) -> str:
    """Traduit ``key`` dans la langue courante, avec formatage optionnel."""
    entry = MESSAGES.get(key)
    if not entry:
        return key.format(**kwargs) if kwargs else key
    tmpl = entry.get(_LANG) or entry.get("fr") or key
    if kwargs:
        try:
            return tmpl.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return tmpl
    return tmpl

def available_keys() -> list[str]:
    return sorted(MESSAGES.keys())

COLOR_CYAN = "#00d7ff"
COLOR_BLUE = "#5f87ff"
COLOR_MAGENTA = "#d75fff"
COLOR_GREEN = "#5fd75f"
COLOR_YELLOW = "#ffd75f"
COLOR_RED = "#ff5f5f"
COLOR_ORANGE = "#ffaf00"
COLOR_DIM = "#6c6c6c"
COLOR_WHITE = "#ffffff"
COLOR_PINK = "#ff87af"

# Dégradé du logo (haut -> bas)
_LOGO_GRADIENT = (
    "#00d7ff",
    "#00afff",
    "#0087ff",
    "#5f87ff",
    "#875fff",
    "#af5fff",
)

# Logo principal — tshark2hashcat (TSHARK2 + HASHCAT, figlet ANSI Shadow)
LOGO_LINES: tuple[str, ...] = (
    r"  ████████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗██████╗ ",
    r"  ╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝╚════██╗",
    r"     ██║   ███████╗███████║███████║██████╔╝█████╔╝  █████╔╝",
    r"     ██║   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██╔═══╝ ",
    r"     ██║   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗",
    r"     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
    r"  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ █████╗ ████████╗",
    r"  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝",
    r"  ███████║███████║███████╗███████║██║     ███████║   ██║   ",
    r"  ██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██║   ██║   ",
    r"  ██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║   ██║   ",
    r"  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ",
)

LOGO_SMALL: tuple[str, ...] = (
    r"  ╔╦╗╔═╗╦ ╦╔═╗╦═╗╦╔═  ╔═╗",
    r"   ║ ╚═╗╠═╣╠═╣╠╦╝╠╩╗  ╔═╝",
    r"   ╩ ╚═╝╩ ╩╩ ╩╩╚═╩ ╩  ╚═╝  HASHCAT",
)

TAGLINE_FR = "un fichier ou un dossier · tout dans Excel"
TAGLINE_EN = "one file or one folder · everything in Excel"

SUBTITLE_FR = "tshark2hashcat  ·  tous les protocoles, sécurisés ou non"
SUBTITLE_EN = "tshark2hashcat  ·  every protocol, cleartext or encrypted"

# Mini-logo pour les en-têtes de section
MINI_MARK = "◆ tshark2hashcat"

def _have_rich() -> bool:
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        return False

def terminal_width(fallback: int = 88) -> int:
    """Largeur du terminal, avec plancher / plafond raisonnables."""
    try:
        w = shutil.get_terminal_size(fallback=(fallback, 24)).columns
    except Exception:
        w = fallback
    return max(60, min(w, 140))

def print_logo(
    lang: str = "fr",
    compact: bool = False,
    no_color: bool = False,
    file=None,
) -> None:
    """Affiche le splash (logo + version + tagline)."""
    file = file or sys.stdout
    if no_color or not _have_rich() or not getattr(file, "isatty", lambda: False)():
        _print_logo_plain(lang, compact, file)
        return
    _print_logo_rich(lang, compact)

def _print_logo_plain(lang: str, compact: bool, file) -> None:
    lines = LOGO_SMALL if compact else LOGO_LINES
    for line in lines:
        print(line, file=file)
    tag = TAGLINE_FR if lang == "fr" else TAGLINE_EN
    print(f"  {__app_name__}  v{__version__}", file=file)
    print(f"  {tag}", file=file)
    print(file=file)

def _print_logo_rich(lang: str, compact: bool) -> None:
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule

    console = Console(highlight=False)
    lines = LOGO_SMALL if compact else LOGO_LINES
    art = Text()
    for i, line in enumerate(lines):
        color = _LOGO_GRADIENT[i % len(_LOGO_GRADIENT)]
        art.append(line + "\n", style=f"bold {color}")

    tag = TAGLINE_FR if lang == "fr" else TAGLINE_EN
    sub = SUBTITLE_FR if lang == "fr" else SUBTITLE_EN
    meta = Text()
    meta.append("  ", style="dim")
    meta.append(__app_name__, style=f"bold {COLOR_CYAN}")
    meta.append("  ·  ", style="dim")
    meta.append(f"v{__version__}", style=f"bold {COLOR_YELLOW}")
    meta.append("  ·  ", style="dim")
    meta.append(tag, style=COLOR_DIM)
    meta.append("\n  ")
    meta.append(sub, style=f"italic {COLOR_MAGENTA}")

    body = Group(Align.center(art), Text(""), Align.center(meta))
    panel = Panel(
        body,
        border_style=COLOR_BLUE,
        padding=(0, 1),
        title=f"[bold {COLOR_CYAN}]◆ tshark2hashcat[/]",
        subtitle=f"[dim]hashcat · tshark · pcap/pcapng[/]",
        subtitle_align="right",
    )
    console.print(panel)
    console.print(Rule(style=COLOR_DIM))

def section_title(title: str, icon: str = "▸") -> None:
    """Titre de section coloré (Rich si possible)."""
    if _have_rich():
        from rich.console import Console
        from rich.rule import Rule
        console = Console(highlight=False)
        console.print(Rule(f"[bold {COLOR_CYAN}]{icon} {title}[/]", style=COLOR_BLUE))
    else:
        print(f"\n=== {title} ===")

def ok(msg: str) -> None:
    _styled(msg, "✓", COLOR_GREEN)

def warn(msg: str) -> None:
    _styled(msg, "!", COLOR_YELLOW)

def err(msg: str) -> None:
    _styled(msg, "✗", COLOR_RED)

def info(msg: str) -> None:
    _styled(msg, "i", COLOR_CYAN)

def step(msg: str) -> None:
    _styled(msg, "→", COLOR_MAGENTA)

def _styled(msg: str, glyph: str, color: str) -> None:
    if _have_rich():
        from rich.console import Console
        Console(highlight=False).print(f"[{color}]{glyph}[/{color}] {msg}")
    else:
        print(f"[{glyph}] {msg}")

def kv(key: str, value: str, key_width: int = 22) -> None:
    """Affiche une paire clé / valeur alignée."""
    if _have_rich():
        from rich.console import Console
        Console(highlight=False).print(
            f"  [{COLOR_DIM}]{key:<{key_width}}[/{COLOR_DIM}] [{COLOR_WHITE}]{value}[/{COLOR_WHITE}]"
        )
    else:
        print(f"  {key:<{key_width}} {value}")

def tip(msg: str) -> None:
    if _have_rich():
        from rich.console import Console
        Console(highlight=False).print(f"  [{COLOR_YELLOW}]💡[/{COLOR_YELLOW}] [italic]{msg}[/italic]")
    else:
        print(f"  Astuce : {msg}")

def hashcat_hint(mode: int, path: str, wordlist: str = "wordlist.txt") -> None:
    """Affiche la commande Hashcat recommandée."""
    cmd = f"hashcat -m {mode} {path} {wordlist}"
    if _have_rich():
        from rich.console import Console
        from rich.syntax import Syntax
        Console(highlight=False).print(
            f"  [{COLOR_DIM}]lancer :[/{COLOR_DIM}] [{COLOR_GREEN}]{cmd}[/{COLOR_GREEN}]"
        )
    else:
        print(f"    {cmd}")

def print_examples(lang: str = "fr") -> None:
    """Bloc d'exemples d'utilisation (splash / --help étendu)."""
    examples_fr = [
        ("Extraire les hashes", "tshark2hashcat extract capture.pcapng"),
        ("Export multi-formats", "tshark2hashcat extract dump.pcap -f csv,json,xlsx"),
        ("Analyse complète", "tshark2hashcat analyze capture.pcapng --report"),
        ("Statistiques tshark", "tshark2hashcat stats capture.pcapng -z io,phs"),
        ("Paquets → Excel", "tshark2hashcat packets dump.pcap --filter http -o http.xlsx"),
        ("Objets HTTP", "tshark2hashcat objects capture.pcapng --proto http"),
        ("Follow TCP", "tshark2hashcat follow capture.pcapng --tcp 0"),
        ("Menu interactif", "tshark2hashcat wizard"),
    ]
    examples_en = [
        ("Extract hashes", "tshark2hashcat extract capture.pcapng"),
        ("Multi-format export", "tshark2hashcat extract dump.pcap -f csv,json,xlsx"),
        ("Full analysis", "tshark2hashcat analyze capture.pcapng --report"),
        ("Tshark statistics", "tshark2hashcat stats capture.pcapng -z io,phs"),
        ("Packets to Excel", "tshark2hashcat packets dump.pcap --filter http -o http.xlsx"),
        ("HTTP objects", "tshark2hashcat objects capture.pcapng --proto http"),
        ("Follow TCP", "tshark2hashcat follow capture.pcapng --tcp 0"),
        ("Interactive menu", "tshark2hashcat wizard"),
    ]
    rows = examples_fr if lang == "fr" else examples_en
    if _have_rich():
        from rich.console import Console
        from rich.table import Table
        table = Table(show_header=True, header_style=f"bold {COLOR_CYAN}", box=None, pad_edge=False)
        table.add_column("Action" if lang != "fr" else "Action", style=COLOR_DIM)
        table.add_column("Commande" if lang == "fr" else "Command", style=COLOR_GREEN)
        for label, cmd in rows:
            table.add_row(label, cmd)
        Console(highlight=False).print(table)
    else:
        for label, cmd in rows:
            print(f"  {label:<24} {cmd}")

def spinner_status(message: str):
    """Context manager : spinner Rich, ou no-op."""
    if _have_rich():
        from rich.console import Console
        return Console().status(f"[{COLOR_CYAN}]{message}[/]", spinner="dots")

    class _Dummy:
        def __enter__(self):
            print(f"[…] {message}")
            return self

        def __exit__(self, *a):
            return False

    return _Dummy()

T = TypeVar("T")

def _have_rich() -> bool:
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        return False

def _have_tqdm() -> bool:
    try:
        import tqdm  # noqa: F401
        return True
    except ImportError:
        return False

class ProgressHandle:
    """Interface minimale d'une barre (advance / update / set_desc)."""

    def __init__(self) -> None:
        self.n = 0
        self.total: Optional[int] = None
        self.description = ""

    def advance(self, step: int = 1) -> None:
        self.n += step

    def update(self, n: int) -> None:
        self.n = n

    def set_desc(self, desc: str) -> None:
        self.description = desc

    def set_total(self, total: int) -> None:
        self.total = total

    def close(self) -> None:
        pass

class _RichHandle(ProgressHandle):
    def __init__(self, progress, task_id) -> None:
        super().__init__()
        self._progress = progress
        self._task_id = task_id

    def advance(self, step: int = 1) -> None:
        super().advance(step)
        self._progress.advance(self._task_id, step)

    def update(self, n: int) -> None:
        delta = n - self.n
        super().update(n)
        if delta:
            self._progress.advance(self._task_id, delta)

    def set_desc(self, desc: str) -> None:
        super().set_desc(desc)
        self._progress.update(self._task_id, description=desc)

    def set_total(self, total: int) -> None:
        super().set_total(total)
        self._progress.update(self._task_id, total=total)

    def close(self) -> None:
        pass

class _TqdmHandle(ProgressHandle):
    def __init__(self, bar) -> None:
        super().__init__()
        self._bar = bar

    def advance(self, step: int = 1) -> None:
        super().advance(step)
        self._bar.update(step)

    def update(self, n: int) -> None:
        delta = n - self.n
        super().update(n)
        if delta:
            self._bar.update(delta)

    def set_desc(self, desc: str) -> None:
        super().set_desc(desc)
        self._bar.set_description(desc)

    def set_total(self, total: int) -> None:
        super().set_total(total)
        self._bar.total = total

    def close(self) -> None:
        self._bar.close()

class _PlainHandle(ProgressHandle):
    def __init__(self, desc: str, total: Optional[int], file) -> None:
        super().__init__()
        self.description = desc
        self.total = total
        self._file = file
        self._last_print = 0.0
        self._start = time.time()
        self._print(force=True)

    def _print(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_print < 0.15:
            return
        self._last_print = now
        if self.total:
            pct = min(100.0, 100.0 * self.n / max(self.total, 1))
            filled = int(28 * pct / 100)
            bar = "█" * filled + "░" * (28 - filled)
            msg = f"\r  {self.description:<28} |{bar}| {pct:5.1f}%  {self.n}/{self.total}"
        else:
            elapsed = now - self._start
            msg = f"\r  {self.description:<28} … {self.n}  ({elapsed:.1f}s)"
        try:
            self._file.write(msg)
            self._file.flush()
        except Exception:
            pass

    def advance(self, step: int = 1) -> None:
        super().advance(step)
        self._print()

    def update(self, n: int) -> None:
        super().update(n)
        self._print()

    def set_desc(self, desc: str) -> None:
        super().set_desc(desc)
        self._print(force=True)

    def close(self) -> None:
        self._print(force=True)
        try:
            self._file.write("\n")
            self._file.flush()
        except Exception:
            pass

@contextmanager
def progress_bar(
    description: str,
    total: Optional[int] = None,
    transient: bool = False,
    disable: bool = False,
) -> Iterator[ProgressHandle]:
    """Barre de progression contextuelle.

    Parameters
    ----------
    description : str
        Libellé affiché à gauche.
    total : int | None
        Nombre d'étapes. None = barre indéterminée.
    transient : bool
        Si True, la barre disparaît à la fin (Rich uniquement).
    disable : bool
        Désactive tout affichage (scripts batch / --quiet).
    """
    if disable:
        handle: ProgressHandle = ProgressHandle()
        handle.total = total
        handle.description = description
        yield handle
        return

    if _have_rich():
        from rich.console import Console
        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            SpinnerColumn,
            TaskProgressColumn,
            TextColumn,
            TimeElapsedColumn,
            TimeRemainingColumn,
        )

        columns = [
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[bold cyan]{task.description}[/]"),
            BarColumn(bar_width=32, style="blue", complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ]
        with Progress(*columns, console=Console(highlight=False), transient=transient) as prog:
            task_id = prog.add_task(description, total=total)
            handle = _RichHandle(prog, task_id)
            handle.total = total
            handle.description = description
            yield handle
        return

    if _have_tqdm():
        from tqdm import tqdm

        bar = tqdm(
            total=total,
            desc=description,
            unit="pkt",
            ncols=88,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        )
        handle = _TqdmHandle(bar)
        handle.total = total
        try:
            yield handle
        finally:
            handle.close()
        return

    handle = _PlainHandle(description, total, sys.stderr)
    try:
        yield handle
    finally:
        handle.close()

def track(
    iterable: Iterable[T],
    description: str,
    total: Optional[int] = None,
    disable: bool = False,
) -> Iterator[T]:
    """Itère en affichant une barre. Équivalent de ``rich.progress.track``."""
    if total is None:
        try:
            total = len(iterable)  # type: ignore[arg-type]
        except TypeError:
            total = None
    with progress_bar(description, total=total, disable=disable) as bar:
        for item in iterable:
            yield item
            bar.advance()

@contextmanager
def indeterminate(description: str, disable: bool = False) -> Iterator[ProgressHandle]:
    """Barre / spinner sans total connu (appel tshark, I/O réseau…)."""
    with progress_bar(description, total=None, disable=disable) as bar:
        yield bar

def stage_printer(quiet: bool = False) -> Callable[[str], None]:
    """Retourne une fonction ``print_stage("…")`` respectant --quiet."""

    def _print(msg: str) -> None:
        if quiet:
            return
        if _have_rich():
            from rich.console import Console
            Console(highlight=False).print(f"[bold magenta]▸[/] {msg}")
        else:
            print(f"▸ {msg}")

    return _print

class MultiStage:
    """Enchaîne plusieurs étapes nommées avec une barre globale.

    Example
    -------
        stages = MultiStage([
            ("tshark", "Appel Tshark"),
            ("parse",  "Parsing JSON"),
            ("extract","Extraction des hashes"),
            ("export", "Exports"),
        ])
        with stages:
            stages.start("tshark")
            ...
            stages.done("tshark")
    """

    def __init__(self, stages: list[tuple[str, str]], disable: bool = False) -> None:
        self.stages = stages
        self.disable = disable
        self._index = {k: i for i, (k, _) in enumerate(stages)}
        self._bar: Optional[ProgressHandle] = None
        self._cm = None

    def __enter__(self) -> "MultiStage":
        self._cm = progress_bar("Pipeline", total=len(self.stages), disable=self.disable)
        self._bar = self._cm.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._cm is not None:
            self._cm.__exit__(*exc)

    def start(self, key: str) -> None:
        if self._bar is None:
            return
        label = self.stages[self._index[key]][1]
        self._bar.set_desc(label)

    def done(self, key: str) -> None:
        if self._bar is None:
            return
        self._bar.advance()

DEFAULT_OUTPUT = "hashes.txt"
DEFAULT_FORMATS = ("txt",)
DEFAULT_LANG = "fr"
ENV_PREFIX = "T2H_"

CONFIG_FILENAMES = (
    "tshark2hashcat.toml",
    "tshark2hashcat.json",
    ".tshark2hashcat.toml",
    ".tshark2hashcat.json",
)

@dataclass
class AppConfig:
    """Options persistantes / surchargeables."""

    # I/O
    output: str = DEFAULT_OUTPUT
    formats: list[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    overwrite: bool = True
    out_dir: str = ""

    # tshark
    tshark_path: str = ""
    tshark_timeout: int = 0          # 0 = pas de timeout
    tshark_extra_args: list[str] = field(default_factory=list)
    display_filter: str = ""
    read_filter: str = ""
    decode_as: list[str] = field(default_factory=list)
    disable_names: bool = False      # -n
    two_pass: bool = False           # -2

    # UI
    lang: str = DEFAULT_LANG
    no_color: bool = False
    no_banner: bool = False
    quiet: bool = False
    verbose: bool = False
    no_progress: bool = False

    # extraction
    include_wpa: bool = True
    include_apop: bool = True
    include_creds: bool = True
    include_ntlm: bool = True
    include_kerberos: bool = True
    raw_scan: bool = True            # scan binaire NTLMSSP / APOP / creds

    # hashcat
    wordlist: str = "wordlist.txt"
    hashcat_bin: str = "hashcat"
    show_commands: bool = True

    # exports paquets
    packet_limit: int = 0            # 0 = tous
    packet_fields: list[str] = field(default_factory=list)

    def merged(self, **overrides: Any) -> "AppConfig":
        data = asdict(self)
        for k, v in overrides.items():
            if v is None:
                continue
            if k in data:
                data[k] = v
        return AppConfig(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def _parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "yes", "on", "oui", "y", "o"}

def _parse_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [p.strip() for p in str(v).split(",") if p.strip()]

def _load_toml(path: Path) -> dict[str, Any]:
    try:
        import tomllib  # py3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    if isinstance(data.get("t2h"), dict):
        return data["t2h"]
    return data

def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data.get("t2h"), dict):
        return data["t2h"]
    return data if isinstance(data, dict) else {}

def discover_config_file(explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    candidates: list[Path] = []
    cwd = Path.cwd()
    home = Path.home()
    for name in CONFIG_FILENAMES:
        candidates.append(cwd / name)
        candidates.append(home / name)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / "tshark2hashcat" / "config.toml")
        candidates.append(Path(xdg) / "tshark2hashcat" / "config.json")
    else:
        candidates.append(home / ".config" / "tshark2hashcat" / "config.toml")
    for c in candidates:
        if c.is_file():
            return c
    return None

def load_file_config(path: Optional[Path]) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            return _load_toml(path)
        if suffix == ".json":
            return _load_json(path)
    except Exception:
        return {}
    return {}

def load_env_config() -> dict[str, Any]:
    """Lit les variables ``T2H_OUTPUT``, ``T2H_LANG``, ``T2H_TSHARK_PATH``, …"""
    known = {f.name for f in fields(AppConfig)}
    out: dict[str, Any] = {}
    for key, val in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        name = key[len(ENV_PREFIX):].lower()
        if name not in known:
            continue
        out[name] = val
    return out

def _coerce(cfg: dict[str, Any]) -> dict[str, Any]:
    bool_fields = {
        "overwrite", "disable_names", "two_pass", "no_color", "no_banner",
        "quiet", "verbose", "no_progress", "include_wpa", "include_apop",
        "include_creds", "include_ntlm", "include_kerberos", "raw_scan",
        "show_commands",
    }
    list_fields = {"formats", "tshark_extra_args", "decode_as", "packet_fields"}
    int_fields = {"tshark_timeout", "packet_limit"}
    out = dict(cfg)
    for k in list(out):
        if k in bool_fields:
            out[k] = _parse_bool(out[k])
        elif k in list_fields:
            out[k] = _parse_list(out[k])
        elif k in int_fields:
            try:
                out[k] = int(out[k])
            except (TypeError, ValueError):
                out[k] = 0
    return out

def load_config(explicit_path: Optional[str] = None, cli_overrides: Optional[dict[str, Any]] = None) -> AppConfig:
    """Charge la config fusionnée (fichier + env + CLI)."""
    file_cfg = load_file_config(discover_config_file(explicit_path))
    env_cfg = load_env_config()
    merged: dict[str, Any] = {}
    merged.update(_coerce(file_cfg))
    merged.update(_coerce(env_cfg))
    if cli_overrides:
        # ignore None pour ne pas écraser
        cleaned = {k: v for k, v in cli_overrides.items() if v is not None and k in {f.name for f in fields(AppConfig)}}
        merged.update(_coerce(cleaned))
    known = {f.name for f in fields(AppConfig)}
    merged = {k: v for k, v in merged.items() if k in known}
    return AppConfig(**merged)

def write_example_config(path: str | os.PathLike) -> Path:
    """Écrit un fichier d'exemple JSON commenté via clés documentées."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    example = {
        "_comment": "Configuration tshark2hashcat — toutes les clés sont optionnelles.",
        "output": "hashes.txt",
        "formats": ["txt", "csv", "json", "xlsx"],
        "lang": "fr",
        "tshark_path": "",
        "wordlist": "wordlist.txt",
        "include_wpa": True,
        "include_creds": True,
        "show_commands": True,
        "no_banner": False,
        "verbose": False,
    }
    p.write_text(json.dumps(example, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return p

HEX = "0123456789abcdef"

def is_hex(s: Optional[str], length: Optional[int] = None, minlen: int = 0, maxlen: Optional[int] = None) -> bool:
    if not s or any(c not in HEX for c in s):
        return False
    if length is not None and len(s) != length:
        return False
    if len(s) < minlen:
        return False
    if maxlen is not None and len(s) > maxlen:
        return False
    return len(s) % 2 == 0

def validate(mode: int, line: str) -> bool:
    """True si la ligne respecte EXACTEMENT la syntaxe attendue par hashcat ``<mode>``."""
    if not line or not isinstance(line, str):
        return False
    line = line.strip()
    if not line or line.startswith("#"):
        return False

    p = line.split(":") if mode in (5500, 5600) else None

    if mode == 5600:  # user::domain:chal:NTProofStr:blob
        return (
            p is not None
            and len(p) == 6
            and 1 <= len(p[0]) <= 60
            and len(p[1]) == 0
            and len(p[2]) <= 45
            and is_hex(p[3], 16)
            and is_hex(p[4], 32)
            and is_hex(p[5], minlen=2, maxlen=1024)
        )

    if mode == 5500:  # user::domain:chal:LM(24o):NT(24o)
        return (
            p is not None
            and len(p) == 6
            and 1 <= len(p[0]) <= 60
            and len(p[1]) == 0
            and len(p[2]) <= 45
            and is_hex(p[3], 16)
            and is_hex(p[4], 48)
            and is_hex(p[5], 48)
        )

    if mode == 18200:  # $krb5asrep$23$user@dom:$chk(16o)$edata2
        m = re.fullmatch(
            r"\$krb5asrep\$23\$([^@$]+)@([^:$]+):([0-9a-f]{32})\$([0-9a-f]+)",
            line,
        )
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0

    if mode in (32100, 32200):  # $krb5asrep$17|18$user$realm$chk24$edata2
        e = 17 if mode == 32100 else 18
        m = re.fullmatch(
            rf"\$krb5asrep\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)",
            line,
        )
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0

    if mode in (19800, 19900):  # $krb5pa$17|18$user$realm$cipher(104..112)
        e = 17 if mode == 19800 else 18
        m = re.fullmatch(rf"\$krb5pa\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]+)", line)
        return bool(m) and 104 <= len(m.group(3)) <= 112

    if mode == 7500:  # $krb5pa$23$user$realm$cipher (RC4)
        return bool(re.fullmatch(r"\$krb5pa\$23\$([^$]+)\$([^$]+)\$([0-9a-f]+)", line))

    if mode == 13100:  # $krb5tgs$23$*user$dom$spn*$chk32$edata2
        m = re.fullmatch(
            r"\$krb5tgs\$23\$\*([^$]+)\$([^$]+)\$([^$]+)\*\$([0-9a-f]{32})\$([0-9a-f]+)",
            line,
        )
        return bool(m) and 64 <= len(m.group(5)) <= 40960 and len(m.group(5)) % 2 == 0

    if mode in (19600, 19700):  # $krb5tgs$17|18$user$realm$chk24$edata2
        e = 17 if mode == 19600 else 18
        m = re.fullmatch(
            rf"\$krb5tgs\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)",
            line,
        )
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0

    if mode == 20:  # md5($salt.$pass) -> hash:salt  (APOP : digest:challenge)
        if ":" in line:
            h, salt = line.split(":", 1)
            return is_hex(h, 32) and 0 < len(salt) <= 256
        return False

    if mode == 22000:  # WPA*01/02*...
        # WPA*01*PMKID*MACAP*MACSTA*ESSID
        # WPA*02*MIC*MACAP*MACSTA*ESSID*NONCEAP*EAPOL*MESSAGEPAIR
        if line.startswith("WPA*01*"):
            parts = line.split("*")
            return len(parts) >= 6 and is_hex(parts[2], 32) and is_hex(parts[3], 12) and is_hex(parts[4], 12)
        if line.startswith("WPA*02*"):
            parts = line.split("*")
            return len(parts) >= 9 and is_hex(parts[2], 32)
        return False

    if mode == 16800:  # WPA-PMKID-PBKDF2 (legacy)
        # macap:macsta:essid:pmkid
        parts = line.split(":")
        return len(parts) == 4 and is_hex(parts[0], 12) and is_hex(parts[1], 12) and is_hex(parts[3], 32)

    if mode == 2500:  # WPA/WPA2 legacy hccapx — binaire, on n'émet pas de ligne texte
        return False

    if mode == 11400:  # SIP digest
        return line.startswith("$sip$") and line.count("*") >= 8

    if mode == 4800:  # iSCSI CHAP / MD5(CHAP)
        parts = line.split(":")
        return len(parts) == 3 and is_hex(parts[0], 32) and is_hex(parts[1]) and parts[2].isdigit()

    if mode == 23:  # Skype MD5
        return is_hex(line, 32)

    if mode == 1100:  # Domain Cached Credentials (DCC)
        parts = line.split(":")
        return len(parts) == 2 and is_hex(parts[0], 32) and 0 < len(parts[1]) <= 256

    if mode == 2100:  # DCC2
        return line.startswith("$DCC2$") and line.count("#") >= 2

    if mode == 5300:  # IKE-PSK MD5
        parts = line.split(":")
        return len(parts) >= 9 and all(is_hex(x) or x == "" for x in parts[:9])

    if mode == 5400:  # IKE-PSK SHA1
        parts = line.split(":")
        return len(parts) >= 9

    if mode == 4800:
        parts = line.split(":")
        return len(parts) == 3 and is_hex(parts[0], 32)

    if mode == 16100:  # TACACS+
        return line.startswith("$tacacs-plus$") 

    if mode == 16500:  # JWT
        return line.count(".") == 2

    if mode == 7300:  # IPMI2 RAKP HMAC-SHA1
        parts = line.split(":")
        return len(parts) == 2 and is_hex(parts[0]) and is_hex(parts[1], 40)

    if mode == 11600:  # 7-Zip
        return line.startswith("$7z$")

    if mode == 0:  # raw MD5
        return is_hex(line, 32)

    if mode == 100:  # raw SHA1
        return is_hex(line, 40)

    if mode == 1400:  # raw SHA256
        return is_hex(line, 64)

    if mode == 1700:  # raw SHA512
        return is_hex(line, 128)

    # Par défaut : on refuse (mieux vaut rater un hash que d'écrire une ligne invalide).
    return False

def describe_expected(mode: int) -> str:
    """Rappel du format attendu (aide / messages d'erreur)."""
    hints = {
        20: "<md5hex>:<challenge>",
        5500: "USER::DOMAIN:CHALLENGE:LMRESPONSE:NTRESPONSE",
        5600: "USER::DOMAIN:CHALLENGE:NTPROOFSTR:BLOB",
        7500: "$krb5pa$23$USER$REALM$CIPHER",
        13100: "$krb5tgs$23$*USER$REALM$SPN*$CHECKSUM$EDATA2",
        18200: "$krb5asrep$23$USER@REALM:CHECKSUM$EDATA2",
        19600: "$krb5tgs$17$USER$REALM$CHECKSUM$EDATA2",
        19700: "$krb5tgs$18$USER$REALM$CHECKSUM$EDATA2",
        19800: "$krb5pa$17$USER$REALM$CIPHER",
        19900: "$krb5pa$18$USER$REALM$CIPHER",
        22000: "WPA*01*PMKID*MACAP*MACSTA*ESSID   ou   WPA*02*MIC*…",
        32100: "$krb5asrep$17$USER$REALM$CHECKSUM$EDATA2",
        32200: "$krb5asrep$18$USER$REALM$CHECKSUM$EDATA2",
        11400: "$sip$*…",
        16800: "MACAP:MACSTA:ESSID:PMKID",
        7300: "SALT:HMACSHA1",
        16100: "$tacacs-plus$0$…",
    }
    return hints.get(mode, f"(format du mode {mode})")

# Catégories
CAT_RAW = "raw"
CAT_NET = "network"
CAT_OS = "os"
CAT_FORUM = "forum"
CAT_DB = "database"
CAT_KRB = "kerberos"
CAT_WIFI = "wifi"
CAT_DOC = "document"
CAT_ARCHIVE = "archive"
CAT_FDE = "full-disk"
CAT_FW = "framework"
CAT_ENTERPRISE = "enterprise"
CAT_CRYPTO = "crypto-currency"
CAT_OTHER = "other"

MODE_CATALOG: dict[int, dict[str, Any]] = {}

def _m(
    mode: int,
    name: str,
    category: str,
    *,
    from_pcap: bool = False,
    protocol: Optional[str] = None,
    example: str = "",
    notes: str = "",
    speed: str = "",
) -> None:
    MODE_CATALOG[mode] = {
        "mode": mode,
        "name": name,
        "category": category,
        "from_pcap": from_pcap,
        "protocol": protocol,
        "example": example,
        "notes": notes,
        "speed": speed,
        "hashcat": f"hashcat -m {mode} hashes_m{mode}.txt wordlist.txt",
    }

_m(0, "MD5", CAT_RAW, example="8743b52063cd84097a65d1633f5c74f5")
_m(10, "md5($pass.$salt)", CAT_RAW, example="01dfae6e5d4d90d9892622325959afbe:7050461")
_m(20, "md5($salt.$pass)", CAT_RAW, from_pcap=True, protocol="APOP",
   example="3d63db1e1b93b3894fe9f56e1f02334d:<1895122944.10526@mail.example>",
   notes="APOP POP3 : digest = MD5(challenge || password). Format hash:challenge.")
_m(30, "md5(utf16le($pass).$salt)", CAT_RAW)
_m(40, "md5($salt.utf16le($pass))", CAT_RAW)
_m(50, "HMAC-MD5 (key = $pass)", CAT_RAW)
_m(60, "HMAC-MD5 (key = $salt)", CAT_RAW)
_m(100, "SHA1", CAT_RAW, example="b89eaac7e61417341b710b727768294d0e6a277b")
_m(110, "sha1($pass.$salt)", CAT_RAW)
_m(120, "sha1($salt.$pass)", CAT_RAW)
_m(130, "sha1(utf16le($pass).$salt)", CAT_RAW)
_m(140, "sha1($salt.utf16le($pass))", CAT_RAW)
_m(150, "HMAC-SHA1 (key = $pass)", CAT_RAW)
_m(160, "HMAC-SHA1 (key = $salt)", CAT_RAW)
_m(200, "MySQL323", CAT_DB)
_m(300, "MySQL4.1/MySQL5", CAT_DB)
_m(400, "phpass, WordPress, Joomla, phpBB3", CAT_FORUM)
_m(500, "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)", CAT_OS)
_m(900, "MD4", CAT_RAW)
_m(1000, "NTLM", CAT_OS, notes="Hash NT Windows (pas NetNTLM).")
_m(1100, "Domain Cached Credentials (DCC), MS Cache", CAT_OS)
_m(1300, "SHA-224", CAT_RAW)
_m(1400, "SHA-256", CAT_RAW)
_m(1410, "sha256($pass.$salt)", CAT_RAW)
_m(1420, "sha256($salt.$pass)", CAT_RAW)
_m(1450, "HMAC-SHA256 (key = $pass)", CAT_RAW)
_m(1460, "HMAC-SHA256 (key = $salt)", CAT_RAW)
_m(1500, "descrypt, DES (Unix), Traditional DES", CAT_OS)
_m(1600, "Apache $apr1$ MD5, md5apr1, MD5 (APR)", CAT_OS)
_m(1700, "SHA-512", CAT_RAW)
_m(1710, "sha512($pass.$salt)", CAT_RAW)
_m(1720, "sha512($salt.$pass)", CAT_RAW)
_m(1750, "HMAC-SHA512 (key = $pass)", CAT_RAW)
_m(1760, "HMAC-SHA512 (key = $salt)", CAT_RAW)
_m(1800, "sha512crypt $6$, SHA512 (Unix)", CAT_OS)
_m(2100, "Domain Cached Credentials 2 (DCC2), MS Cache 2", CAT_OS)
_m(2400, "Cisco-PIX MD5", CAT_OS)
_m(2410, "Cisco-ASA MD5", CAT_OS)
_m(2500, "WPA-EAPOL-PBKDF2 (legacy hccapx)", CAT_WIFI, from_pcap=True, protocol="EAPOL",
   notes="Remplacé par 22000. Conservé pour compat.")
_m(2600, "md5(md5($pass))", CAT_RAW)
_m(3000, "LM", CAT_OS)
_m(3100, "Oracle H: Type (Oracle 7+)", CAT_DB)
_m(3200, "bcrypt $2*$, Blowfish (Unix)", CAT_OS)
_m(3710, "md5($salt.md5($pass))", CAT_RAW)
_m(3800, "md5($salt.$pass.$salt)", CAT_RAW)
_m(4300, "md5(strtoupper(md5($pass)))", CAT_RAW)
_m(4400, "md5(sha1($pass))", CAT_RAW)
_m(4500, "sha1(sha1($pass))", CAT_RAW)
_m(4700, "sha1(md5($pass))", CAT_RAW)
_m(4800, "iSCSI CHAP authentication, MD5(CHAP)", CAT_NET, from_pcap=True, protocol="iSCSI/CHAP",
   example="cc7e033c2593c43358582e209db1ec5e:0123456789abcdef:00")
_m(4900, "sha1($salt.$pass.$salt)", CAT_RAW)
_m(5100, "Half MD5", CAT_RAW)
_m(5200, "Password Safe v3", CAT_OTHER)
_m(5300, "IKE-PSK MD5", CAT_NET, from_pcap=True, protocol="ISAKMP/IKE",
   notes="Clé pré-partagée IKE v1 (hash MD5).")
_m(5400, "IKE-PSK SHA1", CAT_NET, from_pcap=True, protocol="ISAKMP/IKE")
_m(5500, "NetNTLMv1 / NetNTLMv1+ESS", CAT_NET, from_pcap=True, protocol="NTLMSSP",
   example="u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
   notes="NT response = 24 octets. Challenge serveur 8 octets.")
_m(5600, "NetNTLMv2", CAT_NET, from_pcap=True, protocol="NTLMSSP",
   example="admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
   notes="NT response > 24 octets. NTProofStr = 16 premiers octets, blob = reste.")
_m(5700, "Cisco-IOS type 4 (SHA256)", CAT_OS)
_m(5800, "Samsung Android Password/PIN", CAT_OS)
_m(6000, "RIPEMD-160", CAT_RAW)
_m(6100, "Whirlpool", CAT_RAW)
_m(6211, "TrueCrypt RIPEMD160 + XTS 512 bit", CAT_FDE)
_m(6221, "TrueCrypt SHA512 + XTS 512 bit", CAT_FDE)
_m(6231, "TrueCrypt Whirlpool + XTS 512 bit", CAT_FDE)
_m(6300, "AIX {smd5}", CAT_OS)
_m(6400, "AIX {ssha256}", CAT_OS)
_m(6500, "AIX {ssha512}", CAT_OS)
_m(6600, "1Password, agilekeychain", CAT_OTHER)
_m(6700, "AIX {ssha1}", CAT_OS)
_m(6800, "LastPass + LastPass sniffed", CAT_NET, from_pcap=True, protocol="HTTPS/LastPass")
_m(6900, "GOST R 34.11-94", CAT_RAW)
_m(7000, "FortiGate (FortiOS)", CAT_OS)
_m(7100, "macOS v10.8+ (PBKDF2-SHA512)", CAT_OS)
_m(7200, "GRUB 2", CAT_OS)
_m(7300, "IPMI2 RAKP HMAC-SHA1", CAT_NET, from_pcap=True, protocol="IPMI",
   notes="Remote Management : hash HMAC-SHA1 de la session RAKP.")
_m(7400, "sha256crypt $5$, SHA256 (Unix)", CAT_OS)
_m(7500, "Kerberos 5, etype 23, AS-REQ Pre-Auth", CAT_KRB, from_pcap=True, protocol="Kerberos",
   example="$krb5pa$23$user$realm$22a0f7840c4b41f26fc67778165cd587...",
   notes="PA-ENC-TIMESTAMP RC4-HMAC. AS-REQ msg-type 10.")
_m(7700, "SAP CODVN B (BCODE)", CAT_ENTERPRISE)
_m(7800, "SAP CODVN F/G (PASSCODE)", CAT_ENTERPRISE)
_m(7900, "Drupal7", CAT_FORUM)
_m(8000, "Sybase ASE", CAT_DB)
_m(8100, "Citrix NetScaler (SHA1)", CAT_ENTERPRISE)
_m(8200, "1Password, cloudkeychain", CAT_OTHER)
_m(8300, "DNSSEC (NSEC3)", CAT_NET, from_pcap=True, protocol="DNS")
_m(8400, "WBB3 (Woltlab Burning Board)", CAT_FORUM)
_m(8500, "RACF", CAT_ENTERPRISE)
_m(8600, "Lotus Notes/Domino 5", CAT_ENTERPRISE)
_m(8700, "Lotus Notes/Domino 6", CAT_ENTERPRISE)
_m(8900, "scrypt", CAT_RAW)
_m(9000, "Password Safe v2", CAT_OTHER)
_m(9100, "Lotus Notes/Domino 8", CAT_ENTERPRISE)
_m(9200, "Cisco-IOS $8$ (PBKDF2-SHA256)", CAT_OS)
_m(9300, "Cisco-IOS $9$ (scrypt)", CAT_OS)
_m(9400, "MS Office 2007", CAT_DOC)
_m(9500, "MS Office 2010", CAT_DOC)
_m(9600, "MS Office 2013", CAT_DOC)
_m(9700, "MS Office <= 2003 $0/$1, MD5 + RC4", CAT_DOC)
_m(9800, "MS Office <= 2003 $3/$4, SHA1 + RC4", CAT_DOC)
_m(9900, "Radmin2", CAT_NET)
_m(10000, "Django (PBKDF2-SHA256)", CAT_FW)
_m(10100, "SipHash", CAT_RAW)
_m(10200, "CRAM-MD5", CAT_NET, from_pcap=True, protocol="IMAP/SMTP")
_m(10300, "SAP CODVN H (PWDSALTEDHASH) iSSHA-1", CAT_ENTERPRISE)
_m(10400, "PDF 1.1 - 1.3 (Acrobat 2 - 4)", CAT_DOC)
_m(10500, "PDF 1.4 - 1.6 (Acrobat 5 - 8)", CAT_DOC)
_m(10600, "PDF 1.7 Level 3 (Acrobat 9)", CAT_DOC)
_m(10700, "PDF 1.7 Level 8 (Acrobat 10 - 11)", CAT_DOC)
_m(10800, "SHA-384", CAT_RAW)
_m(10900, "PBKDF2-HMAC-SHA256", CAT_RAW)
_m(11000, "PrestaShop", CAT_FW)
_m(11100, "PostgreSQL CRAM (MD5)", CAT_DB, from_pcap=True, protocol="PostgreSQL")
_m(11200, "MySQL CRAM (SHA1)", CAT_DB, from_pcap=True, protocol="MySQL")
_m(11300, "Bitcoin/Litecoin wallet.dat", CAT_CRYPTO)
_m(11400, "SIP digest authentication (MD5)", CAT_NET, from_pcap=True, protocol="SIP",
   example="$sip$*caller*realm*method*uri*nonce*cnonce*nc*qop*md5hash")
_m(11500, "CRC32", CAT_RAW)
_m(11600, "7-Zip", CAT_ARCHIVE)
_m(11700, "GOST R 34.11-2012 (Streebog) 256-bit, big-endian", CAT_RAW)
_m(11800, "GOST R 34.11-2012 (Streebog) 512-bit, big-endian", CAT_RAW)
_m(11900, "PBKDF2-HMAC-MD5", CAT_RAW)
_m(12000, "PBKDF2-HMAC-SHA1", CAT_RAW)
_m(12100, "PBKDF2-HMAC-SHA512", CAT_RAW)
_m(12200, "eCryptfs", CAT_FDE)
_m(12300, "Oracle T: Type (Oracle 12+)", CAT_DB)
_m(12400, "BSDi Crypt, Extended DES", CAT_OS)
_m(12500, "RAR3-hp", CAT_ARCHIVE)
_m(12600, "ColdFusion 10+", CAT_FW)
_m(12700, "Blockchain, My Wallet", CAT_CRYPTO)
_m(12800, "MS-AzureSync PBKDF2-HMAC-SHA256", CAT_ENTERPRISE)
_m(12900, "Android FDE (Samsung DEK)", CAT_FDE)
_m(13000, "RAR5", CAT_ARCHIVE)
_m(13100, "Kerberos 5, etype 23, TGS-REP", CAT_KRB, from_pcap=True, protocol="Kerberos",
   example="$krb5tgs$23$*user$realm$spn*$checksum$edata2",
   notes="Kerberoasting RC4. Ticket etype 23, msg-type 13. Skip krbtgt.")
_m(13200, "AxCrypt 1", CAT_ARCHIVE)
_m(13300, "AxCrypt 1 in-memory SHA1", CAT_ARCHIVE)
_m(13400, "KeePass 1 (AES/Twofish) and KeePass 2 (AES)", CAT_OTHER)
_m(13500, "PeopleSoft PS_TOKEN", CAT_ENTERPRISE)
_m(13600, "WinZip", CAT_ARCHIVE)
_m(13711, "VeraCrypt RIPEMD160 + XTS 512 bit", CAT_FDE)
_m(13721, "VeraCrypt SHA512 + XTS 512 bit", CAT_FDE)
_m(13731, "VeraCrypt Whirlpool + XTS 512 bit", CAT_FDE)
_m(13741, "VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode", CAT_FDE)
_m(13751, "VeraCrypt SHA256 + XTS 512 bit", CAT_FDE)
_m(13761, "VeraCrypt SHA256 + XTS 512 bit + boot-mode", CAT_FDE)
_m(13771, "VeraCrypt Streebog-512 + XTS 512 bit", CAT_FDE)
_m(13800, "Windows Phone 8+ PIN/password", CAT_OS)
_m(13900, "OpenCart", CAT_FW)
_m(14000, "DES (PT = $salt, key = $pass)", CAT_RAW)
_m(14100, "3DES (PT = $salt, key = $pass)", CAT_RAW)
_m(14400, "sha1(CX)", CAT_RAW)
_m(14600, "LUKS", CAT_FDE)
_m(14700, "iTunes backup < 10.0", CAT_OTHER)
_m(14800, "iTunes backup >= 10.0", CAT_OTHER)
_m(14900, "Skip32 (PT = $salt, key = $pass)", CAT_RAW)
_m(15000, "FileZilla Server >= 0.9.55", CAT_NET)
_m(15100, "Juniper/NetBSD sha1crypt", CAT_OS)
_m(15200, "Blockchain, My Wallet, V2", CAT_CRYPTO)
_m(15300, "DPAPI masterkey file v1 (context 1 and 2)", CAT_OS)
_m(15400, "ChaCha20", CAT_RAW)
_m(15500, "JKS Java Key Store SHA1", CAT_OTHER)
_m(15600, "Ethereum Wallet, PBKDF2-HMAC-SHA256", CAT_CRYPTO)
_m(15700, "Ethereum Wallet, SCRYPT", CAT_CRYPTO)
_m(15900, "DPAPI masterkey file v2 (context 1 and 2)", CAT_OS)
_m(16000, "Tripcode", CAT_FORUM)
_m(16100, "TACACS+", CAT_NET, from_pcap=True, protocol="TACACS+",
   notes="Pas de mode OSPF natif. TACACS+ est cassable si la clé est faible.")
_m(16200, "Apple Secure Notes", CAT_OTHER)
_m(16300, "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256", CAT_CRYPTO)
_m(16400, "CRAM-MD5 Dovecot", CAT_NET, from_pcap=True, protocol="IMAP")
_m(16500, "JWT (JSON Web Token)", CAT_NET, from_pcap=True, protocol="HTTP")
_m(16600, "Electrum Wallet (Salt-Type 1-3)", CAT_CRYPTO)
_m(16700, "FileVault 2", CAT_FDE)
_m(16800, "WPA-PMKID-PBKDF2 (legacy)", CAT_WIFI, from_pcap=True, protocol="EAPOL/RSN",
   notes="Remplacé par 22000 (WPA*01*).")
_m(16801, "WPA-PMKID-PMK", CAT_WIFI, from_pcap=True, protocol="EAPOL/RSN")
_m(16900, "Ansible Vault", CAT_OTHER)
_m(17200, "PKZIP (Compressed)", CAT_ARCHIVE)
_m(17210, "PKZIP (Uncompressed)", CAT_ARCHIVE)
_m(17220, "PKZIP (Compressed Multi-File)", CAT_ARCHIVE)
_m(17225, "PKZIP (Mixed Multi-File)", CAT_ARCHIVE)
_m(17230, "PKZIP (Compressed Multi-File Checksum-Only)", CAT_ARCHIVE)
_m(17300, "SHA3-224", CAT_RAW)
_m(17400, "SHA3-256", CAT_RAW)
_m(17500, "SHA3-384", CAT_RAW)
_m(17600, "SHA3-512", CAT_RAW)
_m(17700, "Keccak-224", CAT_RAW)
_m(17800, "Keccak-256", CAT_RAW)
_m(17900, "Keccak-384", CAT_RAW)
_m(18000, "Keccak-512", CAT_RAW)
_m(18100, "TOTP (HMAC-SHA1)", CAT_OTHER)
_m(18200, "Kerberos 5, etype 23, AS-REP", CAT_KRB, from_pcap=True, protocol="Kerberos",
   example="$krb5asrep$23$user@realm:checksum$edata2",
   notes="AS-REP roasting RC4. msg-type 11, enc-part etype 23. Compte SANS pré-auth.")
_m(18300, "Apple File System (APFS)", CAT_FDE)
_m(18400, "Open Document Format (ODF) 1.2 (SHA-256, AES)", CAT_DOC)
_m(18500, "sha1(md5(md5($pass)))", CAT_RAW)
_m(18600, "Open Document Format (ODF) 1.1 (SHA-1, Blowfish)", CAT_DOC)
_m(18700, "Java Object hashCode()", CAT_RAW)
_m(18800, "Blockchain, My Wallet, Second Password (SHA256)", CAT_CRYPTO)
_m(18900, "Android Backup", CAT_OTHER)
_m(19000, "QNX /etc/shadow (MD5)", CAT_OS)
_m(19100, "QNX /etc/shadow (SHA256)", CAT_OS)
_m(19200, "QNX /etc/shadow (SHA512)", CAT_OS)
_m(19300, "sha1($salt1.$pass.$salt2)", CAT_RAW)
_m(19500, "Ruby on Rails Restful-Authentication", CAT_FW)
_m(19600, "Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96)", CAT_KRB,
   from_pcap=True, protocol="Kerberos",
   notes="Kerberoasting AES128. Checksum = 12 derniers octets.")
_m(19700, "Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)", CAT_KRB,
   from_pcap=True, protocol="Kerberos",
   notes="Kerberoasting AES256. Checksum = 12 derniers octets.")
_m(19800, "Kerberos 5, etype 17, Pre-Auth", CAT_KRB, from_pcap=True, protocol="Kerberos",
   notes="AS-REQ PA-ENC-TIMESTAMP AES128. Cipher 52-56 octets (104-112 hex).")
_m(19900, "Kerberos 5, etype 18, Pre-Auth", CAT_KRB, from_pcap=True, protocol="Kerberos",
   notes="AS-REQ PA-ENC-TIMESTAMP AES256.")
_m(20011, "DiskCryptor SHA512 + XTS 512 bit", CAT_FDE)
_m(20012, "DiskCryptor SHA512 + XTS 1024 bit", CAT_FDE)
_m(20013, "DiskCryptor SHA512 + XTS 1536 bit", CAT_FDE)
_m(20200, "Python passlib pbkdf2-sha512", CAT_FW)
_m(20300, "Python passlib pbkdf2-sha256", CAT_FW)
_m(20400, "Python passlib pbkdf2-sha1", CAT_FW)
_m(20500, "PKZIP Master Key", CAT_ARCHIVE)
_m(20510, "PKZIP Master Key (6 byte)", CAT_ARCHIVE)
_m(20600, "Oracle Transportation Management (SHA256)", CAT_ENTERPRISE)
_m(20710, "sha256(sha256($pass).$salt)", CAT_RAW)
_m(20711, "AuthMe sha256", CAT_FW)
_m(20800, "sha256(md5($pass))", CAT_RAW)
_m(20900, "md5(sha1($pass).md5($pass).sha1($pass))", CAT_RAW)
_m(21000, "BitShares v0.x", CAT_CRYPTO)
_m(21100, "sha1(md5($pass.$salt))", CAT_RAW)
_m(21200, "md5(sha1($salt).md5($pass))", CAT_RAW)
_m(21300, "md5($salt.sha1($salt.$pass))", CAT_RAW)
_m(21400, "sha256(sha256_bin($pass))", CAT_RAW)
_m(21500, "SolarWinds Orion", CAT_ENTERPRISE)
_m(21501, "SolarWinds Orion v2", CAT_ENTERPRISE)
_m(21600, "Web2py pbkdf2-sha512", CAT_FW)
_m(21700, "Electrum Wallet (Salt-Type 4)", CAT_CRYPTO)
_m(21800, "Electrum Wallet (Salt-Type 5)", CAT_CRYPTO)
_m(22000, "WPA-PBKDF2-PMKID+EAPOL", CAT_WIFI, from_pcap=True, protocol="EAPOL/RSN",
   example="WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***",
   notes="Format unifié PMKID (WPA*01*) + handshake EAPOL (WPA*02*). Remplace 2500 et 16800.")
_m(22001, "WPA-PMK-PMKID+EAPOL", CAT_WIFI, from_pcap=True, protocol="EAPOL/RSN")
_m(22100, "BitLocker", CAT_FDE)
_m(22200, "Citrix NetScaler (SHA512)", CAT_ENTERPRISE)
_m(22300, "sha256($salt.$pass.$salt)", CAT_RAW)
_m(22400, "AES Crypt (SHA256)", CAT_OTHER)
_m(22500, "MultiBit Classic .key (MD5)", CAT_CRYPTO)
_m(22600, "Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)", CAT_OTHER)
_m(22700, "MultiBit HD (scrypt)", CAT_CRYPTO)
_m(22911, "RSA/DSA/EC/OpenSSH Private Keys ($0$)", CAT_OTHER)
_m(22921, "RSA/DSA/EC/OpenSSH Private Keys ($6$)", CAT_OTHER)
_m(22931, "RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)", CAT_OTHER)
_m(22941, "RSA/DSA/EC/OpenSSH Private Keys ($4$)", CAT_OTHER)
_m(22951, "RSA/DSA/EC/OpenSSH Private Keys ($5$)", CAT_OTHER)
_m(23001, "SecureZIP AES-128", CAT_ARCHIVE)
_m(23002, "SecureZIP AES-192", CAT_ARCHIVE)
_m(23003, "SecureZIP AES-256", CAT_ARCHIVE)
_m(23100, "Apple Keychain", CAT_OTHER)
_m(23200, "XMPP SCRAM PBKDF2-SHA1", CAT_NET, from_pcap=True, protocol="XMPP")
_m(23300, "Apple iWork", CAT_DOC)
_m(23400, "Bitwarden", CAT_OTHER)
_m(23500, "AxCrypt 2 AES-128", CAT_ARCHIVE)
_m(23600, "AxCrypt 2 AES-256", CAT_ARCHIVE)
_m(23700, "RAR3-p (Uncompressed)", CAT_ARCHIVE)
_m(23800, "RAR3-p (Compressed)", CAT_ARCHIVE)
_m(23900, "BestCrypt v3 Volume Encryption", CAT_FDE)
_m(24100, "MongoDB ServerKey SCRAM-SHA-1", CAT_DB)
_m(24200, "MongoDB ServerKey SCRAM-SHA-256", CAT_DB)
_m(24300, "sha1($salt.sha1($pass.$salt))", CAT_RAW)
_m(24410, "PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)", CAT_OTHER)
_m(24420, "PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)", CAT_OTHER)
_m(24500, "Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)", CAT_OTHER)
_m(24600, "SQLCipher", CAT_DB)
_m(24700, "Stuffit5", CAT_ARCHIVE)
_m(24800, "Umbraco HMAC-SHA1", CAT_FW)
_m(24900, "Dahua Authentication MD5", CAT_NET, from_pcap=True, protocol="Dahua")
_m(25000, "SNMPv3 HMAC-MD5-96/HMAC-SHA1-96", CAT_NET, from_pcap=True, protocol="SNMP",
   notes="authPassword SNMPv3 USM.")
_m(25100, "SNMPv3 HMAC-MD5-96", CAT_NET, from_pcap=True, protocol="SNMP")
_m(25200, "SNMPv3 HMAC-SHA1-96", CAT_NET, from_pcap=True, protocol="SNMP")
_m(25300, "MS Office 2016 - SheetProtection", CAT_DOC)
_m(25400, "PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass", CAT_DOC)
_m(25500, "Stargazer Stellar Wallet XLM", CAT_CRYPTO)
_m(25600, "bcrypt(md5($pass)) / bcryptmd5", CAT_OS)
_m(25700, "MurmurHash", CAT_RAW)
_m(25800, "bcrypt(sha1($pass)) / bcryptsha1", CAT_OS)
_m(25900, "KNX IP Secure - Device Authentication Code", CAT_NET)
_m(26000, "Mozilla key3.db", CAT_OTHER)
_m(26100, "Mozilla key4.db", CAT_OTHER)
_m(26200, "OpenEdge Progress Encode", CAT_ENTERPRISE)
_m(26300, "FortiGate256 (FortiOS256)", CAT_OS)
_m(26401, "AES-128-ECB NOKDF (PT = $salt, key = $pass)", CAT_RAW)
_m(26402, "AES-192-ECB NOKDF (PT = $salt, key = $pass)", CAT_RAW)
_m(26403, "AES-256-ECB NOKDF (PT = $salt, key = $pass)", CAT_RAW)
_m(26500, "iPhone passcode (UID key + System Keybag)", CAT_OS)
_m(26600, "MetaMask Wallet", CAT_CRYPTO)
_m(26700, "SNMPv3 HMAC-SHA224-128", CAT_NET, from_pcap=True, protocol="SNMP")
_m(26800, "SNMPv3 HMAC-SHA256-192", CAT_NET, from_pcap=True, protocol="SNMP")
_m(26900, "SNMPv3 HMAC-SHA384-256", CAT_NET, from_pcap=True, protocol="SNMP")
_m(27000, "NetNTLMv1 / NetNTLMv1+ESS (NT)", CAT_NET, protocol="NTLMSSP")
_m(27100, "NetNTLMv2 (NT)", CAT_NET, protocol="NTLMSSP")
_m(27200, "Ruby on Rails Restful Auth (one round, no sitekey)", CAT_FW)
_m(27300, "SNMPv3 HMAC-SHA512-384", CAT_NET, from_pcap=True, protocol="SNMP")
_m(27400, "VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)", CAT_OTHER)
_m(27500, "VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)", CAT_OTHER)
_m(27600, "VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)", CAT_OTHER)
_m(27700, "MultiBit Classic .wallet (scrypt)", CAT_CRYPTO)
_m(27800, "MurmurHash3", CAT_RAW)
_m(27900, "CRC32C", CAT_RAW)
_m(28000, "CRC64Jones", CAT_RAW)
_m(28100, "Windows Hello PIN/Password", CAT_OS)
_m(28200, "Exodus Desktop Wallet (scrypt)", CAT_CRYPTO)
_m(28300, "Teamspeak 3 (channel hash)", CAT_NET)
_m(28400, "bcrypt(sha512($pass)) / bcryptsha512", CAT_OS)
_m(28600, "PostgreSQL SCRAM-SHA-256", CAT_DB)
_m(28700, "Amazon AWS4-HMAC-SHA256", CAT_NET, from_pcap=True, protocol="HTTP/AWS")
_m(28800, "Kerberos 5, etype 17, DB", CAT_KRB, protocol="Kerberos")
_m(28900, "Kerberos 5, etype 18, DB", CAT_KRB, protocol="Kerberos")
_m(29000, "sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))", CAT_RAW)
_m(29100, "Flask Session Cookie ($salt.$salt.$pass)", CAT_FW)
_m(29200, "Radmin3", CAT_NET)
_m(29311, "TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)", CAT_FDE)
_m(29411, "VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)", CAT_FDE)
_m(29511, "LUKS v1 SHA-1 + AES", CAT_FDE)
_m(29512, "LUKS v1 SHA-1 + Serpent", CAT_FDE)
_m(29513, "LUKS v1 SHA-1 + Twofish", CAT_FDE)
_m(29521, "LUKS v1 SHA-256 + AES", CAT_FDE)
_m(29531, "LUKS v1 SHA-512 + AES", CAT_FDE)
_m(29541, "LUKS v1 RIPEMD-160 + AES", CAT_FDE)
_m(29600, "Terra Station Wallet (AES256-CTR + HMAC-SHA256 + SHA256x2)", CAT_CRYPTO)
_m(29700, "KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only hash", CAT_OTHER)
_m(30000, "Python Werkzeug MD5 (HMAC-MD5 (key = $salt))", CAT_FW)
_m(30120, "Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))", CAT_FW)
_m(30600, "bcrypt(sha256($pass)) / bcryptsha256", CAT_OS)
_m(30700, "Anope IRC Services (enc_sha256)", CAT_NET)
_m(30901, "Bitcoin raw private key (P2PKH), compressed", CAT_CRYPTO)
_m(30902, "Bitcoin raw private key (P2PKH), uncompressed", CAT_CRYPTO)
_m(30903, "Bitcoin raw private key (P2WPKH, Bech32), compressed", CAT_CRYPTO)
_m(30904, "Bitcoin raw private key (P2WPKH, Bech32), uncompressed", CAT_CRYPTO)
_m(30905, "Bitcoin raw private key (P2SH(P2WPKH)), compressed", CAT_CRYPTO)
_m(30906, "Bitcoin raw private key (P2SH(P2WPKH)), uncompressed", CAT_CRYPTO)
_m(31200, "Veeam VBK", CAT_ENTERPRISE)
_m(31300, "MS SNTP", CAT_NET, from_pcap=True, protocol="NTP")
_m(31400, "SecureCRT", CAT_OTHER)
_m(31600, "Domain Cached Credentials (DCC), MS Cache (NT)", CAT_OS)
_m(31700, "md5(md5(md5($pass).$salt1).$salt2)", CAT_RAW)
_m(31800, "MySQL $A$ (sha256crypt)", CAT_DB)
_m(31900, "MetaMask Wallet (short hash, plaintext check)", CAT_CRYPTO)
_m(32000, "NetIQ SSPR (MD5)", CAT_ENTERPRISE)
_m(32010, "NetIQ SSPR (SHA1)", CAT_ENTERPRISE)
_m(32020, "NetIQ SSPR (SHA-1 with Salt)", CAT_ENTERPRISE)
_m(32030, "NetIQ SSPR (SHA-256 with Salt)", CAT_ENTERPRISE)
_m(32040, "NetIQ SSPR (SHA-512 with Salt)", CAT_ENTERPRISE)
_m(32100, "Kerberos 5, etype 17, AS-REP", CAT_KRB, from_pcap=True, protocol="Kerberos",
   notes="AS-REP roasting AES128. Checksum = 12 derniers octets.")
_m(32200, "Kerberos 5, etype 18, AS-REP", CAT_KRB, from_pcap=True, protocol="Kerberos",
   notes="AS-REP roasting AES256. Checksum = 12 derniers octets.")
_m(32300, "Empire CMS (admin password)", CAT_FW)
_m(32410, "sha512(sha512($pass).$salt)", CAT_RAW)
_m(32420, "sha512($salt.sha512($pass))", CAT_RAW)
_m(32500, "Dogecoin Wallet", CAT_CRYPTO)
_m(32600, "CubeCart (md5(md5($salt).md5($pass)))", CAT_FW)
_m(32700, "KNX IP Secure - Device Authentication Code, HMAC-SHA256", CAT_NET)
_m(32900, "MD5(UTF-16LE($pass))", CAT_RAW)
_m(33000, "MD4(UTF-16LE($pass))", CAT_RAW)
_m(33100, "md5($salt.sha1($salt.$pass))", CAT_RAW)
_m(33200, "Veeam VBM", CAT_ENTERPRISE)
_m(33300, "RFC 2144 MD5 (MD5(MD5($pass.$salt).$salt))", CAT_RAW)
_m(33400, "RFC 1321 MD5 (MD5($pass.$salt))", CAT_RAW)

def mode_info(mode: int) -> Optional[dict[str, Any]]:
    return MODE_CATALOG.get(int(mode))

def modes_for_protocol(protocol: str) -> list[dict[str, Any]]:
    proto = protocol.lower()
    return [v for v in MODE_CATALOG.values() if (v.get("protocol") or "").lower().find(proto) >= 0]

def pcap_modes() -> list[dict[str, Any]]:
    return [v for v in MODE_CATALOG.values() if v.get("from_pcap")]

def search_modes(query: str) -> list[dict[str, Any]]:
    q = query.lower().strip()
    if not q:
        return []
    if q.isdigit():
        info = mode_info(int(q))
        return [info] if info else []
    out = []
    for v in MODE_CATALOG.values():
        blob = " ".join(
            str(v.get(k, "") or "")
            for k in ("name", "category", "protocol", "notes")
        ).lower()
        if q in blob:
            out.append(v)
    return out

def format_mode_row(info: dict[str, Any]) -> tuple[str, str, str, str, str]:
    flag = "oui" if info.get("from_pcap") else "—"
    return (
        str(info["mode"]),
        info.get("name") or "",
        info.get("category") or "",
        info.get("protocol") or "—",
        flag,
    )

def categories() -> list[str]:
    return sorted({v["category"] for v in MODE_CATALOG.values()})

def all_modes() -> list[int]:
    return sorted(MODE_CATALOG.keys())

def hashcat_command(
    mode: int,
    hashfile: str,
    wordlist: str = "wordlist.txt",
    *,
    extra: Optional[list[str]] = None,
    workload: int = 3,
    optimized: bool = True,
    outfile: Optional[str] = None,
    session: Optional[str] = None,
    rules: Optional[str] = None,
    potfile: Optional[str] = None,
    force: bool = False,
    username: bool = False,
    binary: str = "hashcat",
) -> str:
    """Construit une ligne de commande Hashcat idiomatique."""
    parts = [binary, "-m", str(mode), "-a", "0"]
    if optimized:
        parts.append("-O")
    parts.extend(["-w", str(workload)])
    if session:
        parts.extend(["--session", session])
    if outfile:
        parts.extend(["-o", outfile])
    if potfile:
        parts.extend(["--potfile-path", potfile])
    if username:
        parts.append("--username")
    if force:
        parts.append("--force")
    parts.append(hashfile)
    parts.append(wordlist)
    if rules:
        parts.extend(["-r", rules])
    if extra:
        parts.extend(extra)
    return " ".join(_quote(p) for p in parts)

def _quote(s: str) -> str:
    if not s:
        return '""'
    if any(c.isspace() or c in ";&|<>()" for c in s):
        return '"' + s.replace('"', '\\"') + '"'
    return s

def attack_presets(mode: int, hashfile: str, wordlist: str = "wordlist.txt") -> list[dict[str, str]]:
    """Quelques recettes d'attaque prêtes à copier-coller."""
    info = mode_info(mode)
    name = (info or {}).get("name", f"mode {mode}")
    base = {
        "straight": {
            "title": f"Dictionnaire ({name})",
            "cmd": hashcat_command(mode, hashfile, wordlist),
        },
        "rules_best64": {
            "title": "Dictionnaire + best64",
            "cmd": hashcat_command(mode, hashfile, wordlist, rules="rules/best64.rule"),
        },
        "rules_rockyou3600": {
            "title": "Dictionnaire + rockyou-30000",
            "cmd": hashcat_command(mode, hashfile, wordlist, rules="rules/rockyou-30000.rule"),
        },
        "combinator": {
            "title": "Combinator (wordlist x wordlist)",
            "cmd": f"hashcat -m {mode} -a 1 -O -w 3 {hashfile} {wordlist} {wordlist}",
        },
        "mask_8lower": {
            "title": "Brute-force 8 minuscules",
            "cmd": f"hashcat -m {mode} -a 3 -O -w 3 {hashfile} ?l?l?l?l?l?l?l?l",
        },
        "mask_8mixed": {
            "title": "Brute-force 8 (minuscule + chiffre)",
            "cmd": f"hashcat -m {mode} -a 3 -O -w 3 {hashfile} -1 ?l?d ?1?1?1?1?1?1?1?1",
        },
        "hybrid_word_mask": {
            "title": "Hybride wordlist + ?d?d?d?d",
            "cmd": f"hashcat -m {mode} -a 6 -O -w 3 {hashfile} {wordlist} ?d?d?d?d",
        },
        "hybrid_mask_word": {
            "title": "Hybride ?d?d + wordlist",
            "cmd": f"hashcat -m {mode} -a 7 -O -w 3 {hashfile} ?d?d {wordlist}",
        },
        "show": {
            "title": "Afficher les hashes cassés",
            "cmd": f"hashcat -m {mode} --show {hashfile}",
        },
        "left": {
            "title": "Hashes encore non cassés",
            "cmd": f"hashcat -m {mode} --left {hashfile}",
        },
    }
    # Recettes spécifiques selon le proto
    proto = ((info or {}).get("protocol") or "").lower()
    if "ntlm" in proto:
        base["ntlm_user_as_pass"] = {
            "title": "Username = password (loopback)",
            "cmd": f"hashcat -m {mode} -a 0 -O {hashfile} --username userlist.txt",
        }
    if "kerberos" in proto:
        base["krb_notes"] = {
            "title": "Rappel Kerberos",
            "cmd": f"# AS-REP (18200/32100/32200) : comptes SANS pré-auth. TGS (13100/19600/19700) : Kerberoast. PA (7500/19800/19900) : timestamp AS-REQ.",
        }
    if "wpa" in proto or "eapol" in proto:
        base["wpa_hcx"] = {
            "title": "Conversion recommandée (hcxpcapngtool)",
            "cmd": f"hcxpcapngtool -o {hashfile} capture.pcapng",
        }
    return list(base.values())

def suggest_for_file(path: str, wordlist: str = "wordlist.txt") -> list[dict[str, str]]:
    """Devine le mode d'après le nom ``*_m5600.txt`` ou le contenu."""
    p = Path(path)
    mode: Optional[int] = None
    name = p.stem
    # hashes_m5600 / m5600
    for token in name.replace("-", "_").split("_"):
        if token.startswith("m") and token[1:].isdigit():
            mode = int(token[1:])
            break
    if mode is None:
        try:
            sample = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            sample = []
        mode = _guess_mode_from_lines(sample)
    if mode is None:
        return [{"title": "Mode inconnu", "cmd": f"hashcat {path} {wordlist}"}]
    return attack_presets(mode, str(p), wordlist)

def _guess_mode_from_lines(lines: list[str]) -> Optional[int]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("$krb5asrep$23$"):
            return 18200
        if line.startswith("$krb5asrep$17$"):
            return 32100
        if line.startswith("$krb5asrep$18$"):
            return 32200
        if line.startswith("$krb5tgs$23$"):
            return 13100
        if line.startswith("$krb5tgs$17$"):
            return 19600
        if line.startswith("$krb5tgs$18$"):
            return 19700
        if line.startswith("$krb5pa$23$"):
            return 7500
        if line.startswith("$krb5pa$17$"):
            return 19800
        if line.startswith("$krb5pa$18$"):
            return 19900
        if line.startswith("WPA*"):
            return 22000
        if line.startswith("$sip$"):
            return 11400
        if line.startswith("$tacacs-plus$"):
            return 16100
        parts = line.split(":")
        if len(parts) == 6 and parts[1] == "":
            # NetNTLM
            if len(parts[4]) == 32:
                return 5600
            if len(parts[4]) == 48:
                return 5500
        if len(parts) == 2 and len(parts[0]) == 32:
            return 20
    return None

@dataclass
class HashHit:
    """Un hash prêt à être écrit, déjà validé (ou en attente de validation)."""

    mode: int
    line: str
    source: str                      # "frame #12 NTLM (alice)"
    protocol: str
    frame: Optional[int] = None
    user: Optional[str] = None
    domain: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

@dataclass
class CredentialHit:
    protocol: str
    username: str
    password: str
    frame: Optional[int] = None
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

@dataclass
class KerberosIdentity:
    frame: int
    msg: str
    user: Optional[str]
    realm: Optional[str]
    spn: Optional[str]
    salts: list[str]
    etypes: list[int]

@dataclass
class MissingItem:
    message: str
    frame: Optional[int] = None
    protocol: str = ""

@dataclass
class ExtractContext:
    """État partagé pendant le parcours des paquets."""

    missing: list[str] = field(default_factory=list)
    preauth_users: set[str] = field(default_factory=set)
    diag: list[KerberosIdentity] = field(default_factory=list)
    ntlm_chals: list[tuple[int, Optional[tuple], str]] = field(default_factory=list)
    proto_seen: set[str] = field(default_factory=set)
    proto_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    raw_chunks: list[bytes] = field(default_factory=list)
    wpa_handshakes: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    bytes_min: Optional[int] = None
    bytes_max: int = 0
    bytes_sum: int = 0
    t_first: Optional[float] = None
    t_last: Optional[float] = None
    ips: set[str] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)

    def miss(self, msg: str) -> None:
        self.missing.append(msg)

NTLMSSP_MAGIC = b"NTLMSSP\x00"

def ntlm_build(
    user: Optional[str],
    dom: Optional[str],
    chal: Optional[str],
    lm: Optional[str],
    nt: Optional[str],
    frame,
    ctx: ExtractContext,
) -> list[HashHit]:
    """Construit les lignes 5500/5600 si tout est présent."""
    for name, val in (("username", user), ("server_challenge", chal), ("nt_response", nt)):
        if not val:
            ctx.miss(f"NTLM frame #{frame}: '{name}' manquant -> hash non généré")
            return []
    assert user and chal and nt
    dom = dom or ""
    if len(nt) == 48 and lm and len(lm) == 48:  # NetNTLMv1 / +ESS
        return [
            HashHit(
                mode=5500,
                line=f"{user}::{dom}:{chal}:{lm}:{nt}",
                source=f"frame #{frame} NTLM ({user})",
                protocol="ntlmssp",
                frame=_as_int(frame),
                user=user,
                domain=dom,
                extra={"variant": "v1", "challenge": chal},
            )
        ]
    if len(nt) > 48:  # NetNTLMv2
        return [
            HashHit(
                mode=5600,
                line=f"{user}::{dom}:{chal}:{nt[:32]}:{nt[32:]}",
                source=f"frame #{frame} NTLM ({user})",
                protocol="ntlmssp",
                frame=_as_int(frame),
                user=user,
                domain=dom,
                extra={"variant": "v2", "challenge": chal, "ntproof": nt[:32]},
            )
        ]
    ctx.miss(
        f"NTLM frame #{frame}: NT response de {len(nt)//2} octets "
        f"(ni v1=24o, ni v2>24o) -> ignoré"
    )
    return []

def _as_int(frame) -> Optional[int]:
    try:
        return int(frame)
    except (TypeError, ValueError):
        return None

def ntlm_secbuf(msg: bytes, off: int) -> bytes:
    """Security buffer NTLMSSP : <uint16 len><uint16 max><uint32 offset>."""
    ln, _mx, rel = struct.unpack_from("<HHI", msg, off)
    if rel < 0 or ln < 0 or rel + ln > len(msg):
        return b""
    return msg[rel : rel + ln]

def ntlm_parse_t2(msg: bytes) -> tuple[str, str]:
    """NTLMSSP_CHALLENGE : challenge @ +24 (8 o), target name en secbuf +12."""
    flags = struct.unpack_from("<I", msg, 20)[0]
    uni = bool(flags & 0x1)
    dom = ntlm_secbuf(msg, 12).decode("utf-16-le" if uni else "latin-1", "replace")
    return msg[24:32].hex(), dom

def ntlm_parse_t3(msg: bytes) -> tuple[str, str, str, str]:
    """NTLMSSP_AUTH : LM@12, NT@20, domain@28, user@36 (secbufs)."""
    lm = ntlm_secbuf(msg, 12).hex()
    nt = ntlm_secbuf(msg, 20).hex()
    flags = struct.unpack_from("<I", msg, 60)[0] if len(msg) >= 64 else 0x1
    enc = "utf-16-le" if flags & 0x1 else "latin-1"
    return (
        lm,
        nt,
        ntlm_secbuf(msg, 28).decode(enc, "replace"),
        ntlm_secbuf(msg, 36).decode(enc, "replace"),
    )

def ntlm_raw_scan(raw: bytes, frame, ctx: ExtractContext) -> list[HashHit]:
    """Retrouve les NTLMSSP type2/type3 dans les octets bruts (clair + base64)."""
    blobs = [raw]
    for m in re.finditer(rb"[A-Za-z0-9+/]{40,}={0,2}", raw):
        try:
            d = base64.b64decode(m.group(0), validate=True)
        except Exception:
            continue
        if d.startswith(NTLMSSP_MAGIC):
            blobs.append(d)
    chals: list[tuple[str, str]] = []
    auths: list[tuple[str, str, str, str]] = []
    for blob in blobs:
        pos = 0
        while True:
            i = blob.find(NTLMSSP_MAGIC, pos)
            if i < 0 or i + 12 > len(blob):
                break
            pos = i + 1
            try:
                t = struct.unpack_from("<I", blob, i + 8)[0]
                if t == 2:
                    chals.append(ntlm_parse_t2(blob[i : i + 2048]))
                elif t == 3:
                    auths.append(ntlm_parse_t3(blob[i : i + 8192]))
            except (struct.error, UnicodeDecodeError, ValueError):
                pass
    res: list[HashHit] = []
    for lm, nt, dom, usr in auths:
        chal, cdom = (chals[-1] if chals else (None, None))
        res.extend(ntlm_build(usr, dom or cdom or "", chal, lm, nt, frame, ctx))
    return res

def extract_dissected(layers: dict, frame: int, ctx: ExtractContext) -> list[HashHit]:
    """Extraction via les champs tshark ntlmssp.*."""
    ntlm = {k: v for k, v in layers.items() if "ntlm" in k.lower()}
    if not ntlm:
        # parfois les champs sont imbriqués : on cherche quand même
        if not any("ntlmssp" in k.lower() for k, _ in _walk_keys(layers)):
            return []
        ntlm = layers

    ctx.proto_seen.add("ntlmssp")
    mt_raw = find_str(ntlm, ("ntlmssp.messagetype",))
    try:
        mtype = int(mt_raw, 0) if mt_raw else None
    except (TypeError, ValueError):
        mtype = None
    t4 = tuple4(layers)
    hits: list[HashHit] = []

    if mtype == 2:  # CHALLENGE (srv->cli)
        chal = find_hex(ntlm, ("ntlmssp.ntlmserverchallenge",))
        if chal and len(chal) == 16:
            ctx.ntlm_chals.append((frame, t4, chal))
    elif mtype == 3:  # AUTH (cli->srv)
        user = find_str(ntlm, ("ntlmssp.auth.username",))
        dom = find_str(ntlm, ("ntlmssp.auth.domain",)) or ""
        lm = find_hex(ntlm, ("ntlmssp.auth.lmresponse", "ntlmssp.lmresponse"))
        nt = find_hex(ntlm, ("ntlmssp.auth.ntresponse", "ntlmssp.ntresponse"))
        chal = find_hex(ntlm, ("ntlmssp.ntlmserverchallenge",))
        if not chal:
            want = (t4[1], t4[0], t4[3], t4[2]) if t4 else None
            chal = next(
                (c for _f, t, c in reversed(ctx.ntlm_chals) if want and t == want),
                ctx.ntlm_chals[-1][2] if ctx.ntlm_chals else None,
            )
        hits.extend(ntlm_build(user, dom, chal, lm, nt, frame, ctx))
    return hits

def _walk_keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from _walk_keys(v)
    elif isinstance(node, list):
        for it in node:
            yield from _walk_keys(it)

MODE_ASREP = {17: 32100, 18: 32200, 23: 18200}
MODE_TGS = {17: 19600, 18: 19700, 23: 13100}
MODE_ASREQ = {17: 19800, 18: 19900, 23: 7500}
MT_NAMES = {"10": "AS-REQ", "11": "AS-REP", "13": "TGS-REP"}

# Alias tshark (selon versions Wireshark les noms varient légèrement)
CNAME_KEYS = ("kerberos.CNameString", "kerberos.cname-string", "kerberos.cname")
REALM_KEYS = ("kerberos.crealm", "kerberos.realm", "kerberos.realm_string")
SNAME_KEYS = ("kerberos.SNameString", "kerberos.sname-string", "kerberos.sname")
MSG_KEYS = ("kerberos.msg_type", "kerberos.msg-type")

def sibling_etype(parent: dict, layers: dict) -> Optional[int]:
    """etype posé à côté d'un champ *_cipher (même dict), sinon etype du paquet."""
    for k in ("kerberos.PA_ENC_TIMESTAMP_etype", "kerberos.etype", "kerberos.enctype"):
        e = first_str(parent.get(k)) if isinstance(parent, dict) else None
        if e and str(e).lstrip("-").isdigit():
            return int(e)
    e = find_str(layers, ("kerberos.etype", "kerberos.PA_ENC_TIMESTAMP_etype", "kerberos.enctype"))
    return int(e) if e and str(e).lstrip("-").isdigit() else None

def krb_asrep_line(e: int, user: str, realm: str, h: str) -> tuple[int, str]:
    if e == 23:  # RC4 : chk = 16 premiers octets
        return 18200, f"$krb5asrep$23${user}@{realm}:{h[:32]}${h[32:]}"
    return MODE_ASREP[e], f"$krb5asrep${e}${user}${realm}${h[-24:]}${h[:-24]}"

def krb_tgs_line(e: int, user: str, realm: str, spn: str, h: str) -> tuple[int, str]:
    if e == 23:
        return 13100, f"$krb5tgs$23$*{user}${realm}${spn}*${h[:32]}${h[32:]}"
    svc = spn.split("/", 1)[0] if spn else user
    return MODE_TGS[e], f"$krb5tgs${e}${svc}${realm}${h[-24:]}${h[:-24]}"

def krb_asreq_line(e: int, user: str, realm: str, h: str) -> tuple[int, str]:
    return MODE_ASREQ[e], f"$krb5pa${e}${user}${realm}${h}"

def _spn_from_layers(layers: dict) -> Optional[str]:
    parts: list[str] = []
    for k, v in walk(layers):
        if k in SNAME_KEYS:
            if isinstance(v, list):
                parts += [x for x in v if isinstance(x, str) and x]
            elif isinstance(v, str) and v:
                parts.append(v)
    return "/".join(parts) if parts else None

def extract_kerberos(layers: dict, frame: int, ctx: ExtractContext) -> list[HashHit]:
    if not any("kerb" in str(k).lower() for k in layers):
        return []

    mt = first_str(find_str(layers, MSG_KEYS))
    # find_str already returns a string; keep both paths
    if mt is None:
        mt = find_str(layers, MSG_KEYS)
    if mt not in MT_NAMES:
        return []

    ctx.proto_seen.add("kerberos")
    user = find_str(layers, CNAME_KEYS)
    realm = find_str(layers, REALM_KEYS)
    hits: list[HashHit] = []

    salts: set[str] = set()
    etypes: set[int] = set()
    for k, v in walk(layers):
        if k == "kerberos.salt":
            salts.update(x for x in (v if isinstance(v, list) else [v]) if isinstance(x, str))
        elif k in ("kerberos.etype", "kerberos.enctype", "kerberos.PA_ENC_TIMESTAMP_etype"):
            for x in v if isinstance(v, list) else [v]:
                if isinstance(x, str) and x.lstrip("-").isdigit():
                    etypes.add(int(x))

    if mt == "10" and any(k == "kerberos.PA_ENC_TIMESTAMP_cipher" for k, _ in walk(layers)):
        if user:
            ctx.preauth_users.add(user)

    spn = _spn_from_layers(layers)
    ctx.diag.append(
        KerberosIdentity(
            frame=frame,
            msg=MT_NAMES[mt],
            user=user,
            realm=realm,
            spn=spn,
            salts=sorted(salts),
            etypes=sorted(etypes),
        )
    )

    for k, v, parent in walk_parent(layers):
        h = norm_hex(v)
        if not h:
            continue

        if k == "kerberos.PA_ENC_TIMESTAMP_cipher" and mt == "10":
            if not (user and realm):
                ctx.miss(f"Kerberos frame #{frame}: AS-REQ sans cname/realm -> ignoré")
                continue
            e = sibling_etype(parent if isinstance(parent, dict) else {}, layers)
            if e in MODE_ASREQ:
                mode, line = krb_asreq_line(e, user, realm, h)
                hits.append(
                    HashHit(
                        mode=mode,
                        line=line,
                        source=f"frame #{frame} Kerberos AS-REQ",
                        protocol="kerberos",
                        frame=frame,
                        user=user,
                        domain=realm,
                        extra={"msg": "AS-REQ", "etype": e},
                    )
                )
            else:
                ctx.miss(f"Kerberos frame #{frame}: AS-REQ etype inconnu ({e}) -> ignoré")

        elif k in ("kerberos.encryptedKDCREPData_cipher", "kerberos.enc-part") and mt == "11":
            # enc-part seul n'est pas forcément hex du cipher ; on exige *_cipher
            if k != "kerberos.encryptedKDCREPData_cipher":
                continue
            if not (user and realm):
                ctx.miss(f"Kerberos frame #{frame}: AS-REP mais cname/realm manquant -> ignoré")
                continue
            e = sibling_etype(parent if isinstance(parent, dict) else {}, layers)
            if e in MODE_ASREP:
                mode, line = krb_asrep_line(e, user, realm, h)
                hits.append(
                    HashHit(
                        mode=mode,
                        line=line,
                        source=f"frame #{frame} Kerberos AS-REP",
                        protocol="kerberos",
                        frame=frame,
                        user=user,
                        domain=realm,
                        extra={"msg": "AS-REP", "etype": e},
                    )
                )
            else:
                ctx.miss(f"Kerberos frame #{frame}: AS-REP etype inconnu ({e}) -> ignoré")

        elif k == "kerberos.encryptedTicketData_cipher" and mt == "13":
            if spn and spn.lower().startswith("krbtgt"):
                continue
            if not (user and realm and spn):
                ctx.miss(
                    f"Kerberos frame #{frame}: TGS-REP mais cname/realm/spn manquant "
                    f"(user={user}, realm={realm}, spn={spn}) -> ignoré"
                )
                continue
            e = sibling_etype(parent if isinstance(parent, dict) else {}, layers)
            if e in MODE_TGS:
                mode, line = krb_tgs_line(e, user, realm, spn, h)
                hits.append(
                    HashHit(
                        mode=mode,
                        line=line,
                        source=f"frame #{frame} Kerberos TGS-REP",
                        protocol="kerberos",
                        frame=frame,
                        user=user,
                        domain=realm,
                        extra={"msg": "TGS-REP", "etype": e, "spn": spn},
                    )
                )
            else:
                ctx.miss(f"Kerberos frame #{frame}: TGS-REP etype inconnu ({e}) -> ignoré")

    return hits

def apop_scan(raw: bytes, ctx: ExtractContext) -> list[HashHit]:
    """Authentification APOP : digest = MD5(challenge + password).

    Format hashcat -m 20 : <md5>:<challenge>.
    La bannière '+OK ... <ts>' fournit le challenge ;
    la commande 'APOP user digest' le digest.
    """
    text = raw.decode("latin-1", "replace")
    events: list[tuple] = []
    for m in re.finditer(r"\+OK[^\n]*((?:<[^>\r\n]+>))", text):
        events.append((m.start(), "chal", m.group(1), None))
    for m in re.finditer(r"\bAPOP\s+(\S+)\s+([0-9a-f]{32})\b", text, re.I):
        events.append((m.start(), "apop", m.group(1), m.group(2).lower()))
    events.sort(key=lambda x: x[0])
    current = None
    res: list[HashHit] = []
    for _pos, kind, a, b in events:
        if kind == "chal":
            current = a
        else:
            user, digest = a, b
            if current:
                res.append(
                    HashHit(
                        mode=20,
                        line=f"{digest}:{current}",
                        source=f"APOP ({user})",
                        protocol="apop",
                        user=user,
                        extra={"challenge": current},
                    )
                )
            else:
                ctx.miss(f"APOP ({user}): challenge introuvable (pas de bannière '<...>') -> ignoré")
    return res

def _b64d(s: str):
    try:
        return base64.b64decode(s, validate=True).decode("latin-1", "replace")
    except Exception:
        return None

def _is_sane(s: str, maxlen: int = 256) -> bool:
    """Rejette les « identifiants » qui sont clairement de l'octet-stream."""
    if not s or len(s) > maxlen:
        return False
    # pas de caractères de contrôle (sauf TAB)
    if any(ord(c) < 32 and c not in "\t" for c in s):
        return False
    # au moins un caractère imprimable « mot »
    return any(c.isalnum() for c in s)

def creds_scan(raw: bytes) -> list[CredentialHit]:
    """Extrait les identifiants transmis en clair."""
    text = raw.decode("latin-1", "replace")
    found: list[CredentialHit] = []

    # --- FTP / Telnet : USER ... puis PASS ... ---
    events: list[tuple] = []
    for m in re.finditer(r"(?im)^USER\s+(\S+)\s*$", text):
        events.append((m.start(), "u", m.group(1)))
    for m in re.finditer(r"(?im)^PASS\s+(\S+)\s*$", text):
        events.append((m.start(), "p", m.group(1)))
    events.sort(key=lambda x: x[0])
    u = None
    for _pos, kind, val in events:
        if kind == "u":
            u = val
        elif u is not None:
            found.append(CredentialHit("FTP/Telnet USER/PASS", u, val, source="USER/PASS"))
            u = None

    # --- HTTP Basic ---
    for m in re.finditer(r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text):
        cred = _b64d(m.group(1))
        if cred and ":" in cred:
            us, ps = cred.split(":", 1)
            found.append(CredentialHit("HTTP Basic", us, ps, source="Authorization: Basic"))

    # Proxy-Authorization Basic
    for m in re.finditer(r"(?i)Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text):
        cred = _b64d(m.group(1))
        if cred and ":" in cred:
            us, ps = cred.split(":", 1)
            found.append(CredentialHit("HTTP Proxy-Basic", us, ps, source="Proxy-Authorization"))

    # --- AUTH PLAIN (SMTP/IMAP/POP) : b64(\0user\0pass) ---
    for m in re.finditer(r"(?i)AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", text):
        rb = _b64d(m.group(1))
        if rb is None:
            continue
        parts = rb.split("\x00")
        if len(parts) >= 3:
            found.append(CredentialHit("AUTH PLAIN", parts[-2], parts[-1], source="AUTH PLAIN"))
        elif len(parts) == 2:
            found.append(CredentialHit("AUTH PLAIN", parts[0], parts[1], source="AUTH PLAIN"))

    # --- AUTH LOGIN : b64(user)\r\nb64(pass) ---
    for m in re.finditer(
        r"(?i)AUTH\s+LOGIN\s*\r?\n\s*([A-Za-z0-9+/=]+)\s*\r?\n\s*([A-Za-z0-9+/=]+)",
        text,
    ):
        us, ps = _b64d(m.group(1)), _b64d(m.group(2))
        if us is not None and ps is not None:
            found.append(CredentialHit("AUTH LOGIN", us, ps, source="AUTH LOGIN"))

    # --- HTTP form (GET/POST) user=...&pass=... ---
    # charset restreint : évite d'avaler l'octet-stream des paquets suivants
    _tok = r"[\w.~%+\-@!*()$]+"
    for m in re.finditer(
        rf"(?i)(?:user(?:name)?|login|email)\s*=\s*({_tok})\s*&\s*(?:pass(?:word)?|pwd|passwd)\s*=\s*({_tok})",
        text,
    ):
        us = unquote_plus(m.group(1))
        ps = unquote_plus(m.group(2))
        if _is_sane(us) and _is_sane(ps):
            found.append(CredentialHit("HTTP form", us, ps, source="form"))

    # --- Authorization: Bearer (on note le token, pas un mot de passe) ---
    for m in re.finditer(r"(?i)Authorization:\s*Bearer\s+(\S+)", text):
        tok = m.group(1).strip()
        if 8 <= len(tok) <= 4096:
            found.append(CredentialHit("HTTP Bearer", "(token)", tok, source="Authorization: Bearer"))

    # --- MQTT CONNECT user/pass (texte approximatif via dissection brute) ---
    for m in re.finditer(r"(?i)mqtt\.passwd\s*[:=]\s*(\S+)", text):
        found.append(CredentialHit("MQTT", "?", m.group(1), source="mqtt.passwd"))

    # dédoublonnage
    seen: set[tuple] = set()
    out: list[CredentialHit] = []
    for c in found:
        k = (c.protocol, c.username, c.password)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out

def _mac_hex(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    s = "".join(c for c in v.lower() if c in "0123456789abcdef")
    return s if len(s) == 12 else None

def _ssid_hex(ssid: Optional[str]) -> Optional[str]:
    if ssid is None:
        return None
    # tshark peut donner le SSID en clair ou déjà en hex
    hx = norm_hex(ssid)
    if hx and len(hx) % 2 == 0 and len(hx) <= 64:
        # heuristique : si ça ne décode pas en ascii imprimable, on garde l'hex
        try:
            raw = bytes.fromhex(hx)
            if all(32 <= b < 127 for b in raw) and len(raw) == len(ssid) // 2:
                return hx
        except ValueError:
            pass
    return ssid.encode("utf-8", "replace").hex()

def extract_pmkid(layers: dict, frame: int, ctx: ExtractContext) -> list[HashHit]:
    """PMKID dans RSN IE / EAPOL M1 → WPA*01*."""
    pmkid = find_hex(
        layers,
        (
            "wlan.rsn.ie.pmkid",
            "wlan_rsna_eapol.keydes.pmkid",
            "eapol.keydes.msgnr",  # pas un pmkid
        ),
    )
    # chercher plus largement
    if not pmkid or len(pmkid) != 32:
        for k, v in walk(layers):
            if "pmkid" in k.lower():
                pmkid = norm_hex(v)
                if pmkid and len(pmkid) == 32:
                    break
        else:
            pmkid = None
    if not pmkid or len(pmkid) != 32:
        return []

    mac_ap = _mac_hex(find_str(layers, ("wlan.bssid", "wlan.sa", "wlan.ta")))
    mac_sta = _mac_hex(find_str(layers, ("wlan.da", "wlan.ra", "wlan.sa")))
    ssid = find_str(layers, ("wlan.ssid", "wlan_mgt.ssid"))
    essid_hex = _ssid_hex(ssid) or ""
    if not (mac_ap and mac_sta):
        ctx.miss(f"WPA frame #{frame}: PMKID sans MAC AP/STA -> ignoré")
        return []
    # éviter AP == STA
    if mac_ap == mac_sta:
        # essayer l'autre combinaison
        alt = _mac_hex(find_str(layers, ("wlan.da",)))
        if alt and alt != mac_ap:
            mac_sta = alt
    line = f"WPA*01*{pmkid}*{mac_ap}*{mac_sta}*{essid_hex}***"
    ctx.proto_seen.add("wpa-pmkid")
    return [
        HashHit(
            mode=22000,
            line=line,
            source=f"frame #{frame} WPA-PMKID",
            protocol="wpa",
            frame=frame,
            extra={"kind": "pmkid", "ssid": ssid, "ap": mac_ap, "sta": mac_sta},
        )
    ]

def extract_eapol_hint(layers: dict, frame: int, ctx: ExtractContext) -> None:
    """Mémorise les messages EAPOL pour un éventuel assemblage 22000 WPA*02*."""
    if not any("eapol" in str(k).lower() for k in layers) and not any(
        "eapol" in k.lower() for k, _ in walk(layers)
    ):
        return
    info: dict = {
        "frame": frame,
        "mic": find_hex(layers, ("eapol.keydes.mic", "wlan_rsna_eapol.keydes.mic")),
        "nonce": find_hex(layers, ("eapol.keydes.nonce", "wlan_rsna_eapol.keydes.nonce")),
        "replay": find_str(layers, ("eapol.keydes.replay_counter",)),
        "keyinfo": find_str(layers, ("eapol.keydes.key_info", "eapol.keydes.keyinfo")),
        "mac_ap": _mac_hex(find_str(layers, ("wlan.bssid", "wlan.sa"))),
        "mac_sta": _mac_hex(find_str(layers, ("wlan.da", "wlan.sa"))),
        "ssid": find_str(layers, ("wlan.ssid", "wlan_mgt.ssid")),
    }
    if info["mic"] or info["nonce"]:
        ctx.wpa_handshakes.append(info)
        ctx.proto_seen.add("eapol")

def finalize_eapol(ctx: ExtractContext) -> list[HashHit]:
    """Essaie d'assembler un WPA*02* si on a MIC + anonce + snonce + SSID.

    Sans l'EAPOL frame entière (octets), Hashcat 22000 ne peut pas vérifier
    le MIC. On émet donc uniquement un *rappel* dans missing, sauf si les
    octets EAPOL bruts sont présents dans extra (non garanti via -T json -x
    selon versions). On documente clairement la limite.
    """
    if not ctx.wpa_handshakes:
        return []
    # On ne fabrique pas de faux WPA*02* (inutile / invalide sans EAPOL raw).
    n = len(ctx.wpa_handshakes)
    ctx.notes.append(
        f"{n} message(s) EAPOL vu(s). Pour un handshake 22000 WPA*02* fiable, "
        f"utilisez : hcxpcapngtool -o handshake.22000 capture.pcapng"
    )
    return []

_DIGEST_RE = re.compile(
    r"(?is)Authorization:\s*Digest\s+([^\r\n]+)"
)
_KV_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^\s,]+))')

def _parse_digest(blob: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _KV_RE.finditer(blob):
        out[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return out

def http_digest_scan(raw: bytes, ctx: ExtractContext) -> list[HashHit]:
    text = raw.decode("latin-1", "replace")
    hits: list[HashHit] = []
    # challenges
    challenges: list[dict] = []
    for m in re.finditer(r"(?is)WWW-Authenticate:\s*Digest\s+([^\r\n]+)", text):
        challenges.append(_parse_digest(m.group(1)))
    for m in _DIGEST_RE.finditer(text):
        d = _parse_digest(m.group(1))
        user = d.get("username") or ""
        realm = d.get("realm") or ""
        nonce = d.get("nonce") or ""
        uri = d.get("uri") or "/"
        response = (d.get("response") or "").lower()
        qop = d.get("qop") or ""
        nc = d.get("nc") or ""
        cnonce = d.get("cnonce") or ""
        algo = (d.get("algorithm") or "MD5").upper()
        method = "GET"
        if not (user and response and nonce):
            ctx.miss("HTTP Digest: username/nonce/response manquant -> ignoré")
            continue
        ctx.proto_seen.add("http-digest")
        # Ici : on stocke une note + un hash « documentaire » rejeté par le validateur
        ctx.notes.append(
            f"HTTP Digest vu user={user!r} realm={realm!r} algo={algo} "
            f"response={response} nonce={nonce} uri={uri} qop={qop} nc={nc} cnonce={cnonce} method={method}"
        )
    return hits

# SIP Digest -> hashcat -m 11400
# $sip$*[server IP]*[client IP]*[username]*[realm]*[method]*[uri]*[nonce]*[cnonce]*[noncecount]*[qop]*[md5 hash]
# (variantes selon versions hashcat — on vise le format le plus courant)

def sip_scan(raw: bytes, ctx: ExtractContext) -> list[HashHit]:
    text = raw.decode("latin-1", "replace")
    hits: list[HashHit] = []
    # Requête SIP pour récupérer la méthode / URI
    req = re.search(r"(?im)^(INVITE|REGISTER|SUBSCRIBE|OPTIONS|BYE|ACK|CANCEL|MESSAGE|PUBLISH|INFO|PRACK|UPDATE|REFER)\s+(\S+)\s+SIP/2\.0", text)
    method = req.group(1) if req else "REGISTER"
    uri = req.group(2) if req else "sip:example"
    for m in re.finditer(r"(?is)Authorization:\s*Digest\s+([^\r\n]+)", text):
        # ne garder que le contexte SIP
        start = max(0, m.start() - 400)
        window = text[start : m.start()]
        if "SIP/2.0" not in window and "sip:" not in window.lower():
            continue
        d = _parse_digest(m.group(1))
        user = d.get("username") or ""
        realm = d.get("realm") or ""
        nonce = d.get("nonce") or ""
        cnonce = d.get("cnonce") or ""
        nc = d.get("nc") or ""
        qop = d.get("qop") or ""
        response = (d.get("response") or "").lower()
        duri = d.get("uri") or uri
        if not (user and realm and nonce and response):
            ctx.miss("SIP Digest: champs manquants -> ignoré")
            continue
        line = f"$sip$*{user}*{realm}*{method}*{duri}*{nonce}*{cnonce}*{nc}*{qop}*{response}"
        ctx.proto_seen.add("sip")
        hits.append(
            HashHit(
                mode=11400,
                line=line,
                source=f"SIP Digest ({user})",
                protocol="sip",
                user=user,
                domain=realm,
                extra={"method": method, "uri": duri},
            )
        )
    return hits

# CRAM-MD5 (SMTP/IMAP/POP AUTH) -> hashcat -m 10200
# challenge base64, response base64(user + " " + hexhmac)
# Format hashcat : $cram_md5$challenge$digest   (challenge/digest en hex ou b64 selon module)

def cram_md5_scan(raw: bytes, ctx: ExtractContext) -> list[HashHit]:
    text = raw.decode("latin-1", "replace")
    hits: list[HashHit] = []
    # On cherche AUTH CRAM-MD5 puis une ligne serveur (challenge) puis une ligne client
    if not re.search(r"(?i)AUTH\s+CRAM-MD5", text):
        return hits
    ctx.proto_seen.add("cram-md5")
    ctx.notes.append(
        "AUTH CRAM-MD5 détecté. Export hashcat -m 10200 : "
        "utilisez un parseur dédié (challenge serveur + réponse client en base64). "
        "Les lignes brutes sont dans le follow-stream SMTP/IMAP."
    )
    return hits

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

def jwt_scan(raw: bytes, ctx: ExtractContext) -> list[HashHit]:
    text = raw.decode("latin-1", "replace")
    hits: list[HashHit] = []
    seen: set[str] = set()
    for m in _JWT_RE.finditer(text):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        ctx.proto_seen.add("jwt")
        hits.append(
            HashHit(
                mode=16500,
                line=tok,
                source="JWT",
                protocol="jwt",
                extra={"alg": "from-header"},
            )
        )
    return hits

def chap_from_layers(layers: dict, frame: int, ctx: ExtractContext) -> list[HashHit]:
    ident = find_str(layers, ("chap.identifier", "eap.md5.value_size"))
    chal = None
    resp = None
    for k, v in walk(layers):
        kl = k.lower()
        if "chap.value" in kl or "chap.challenge" in kl:
            chal = norm_hex(v) or chal
        if "chap.response" in kl or (kl.endswith("md5") and "eap" in kl):
            resp = norm_hex(v) or resp
    if resp and chal and len(resp) == 32:
        ident_i = "00"
        if ident and str(ident).isdigit():
            ident_i = f"{int(ident):02x}"
        ctx.proto_seen.add("chap")
        return [
            HashHit(
                mode=4800,
                line=f"{resp}:{chal}:{ident_i}",
                source=f"frame #{frame} CHAP",
                protocol="chap",
                frame=frame,
            )
        ]
    return []

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_API_KEY_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|x-api-key)\s*[:=]\s*([A-Za-z0-9_\-./+]{8,})"
)
_SNMP_COMM_RE = re.compile(
    r"(?i)(?:community|snmp\.community)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./@+]{1,64})"
)

def _cred(protocol: str, user: str, secret: str, frame=None, source: str = "") -> CredentialHit:
    return CredentialHit(protocol, user or "", secret or "", frame=_as_int(frame), source=source)

def secrets_from_layers(layers: dict, frame: int) -> list[CredentialHit]:
    """Secrets issus des champs disséqués tshark (un paquet)."""
    out: list[CredentialHit] = []
    idx = index_layers(layers)

    for comm in idx_all(idx, ("snmp.community", "snmp.community_name")):
        if comm and _is_sane(comm, 128):
            out.append(_cred("SNMPv1/v2c community", "(community)", comm, frame, "snmp.community"))
    for user in idx_all(idx, ("snmp.msgUserName", "snmp.user")):
        if user and _is_sane(user, 128):
            out.append(_cred("SNMPv3 user", user, "", frame, "snmp.msgUserName"))

    ldap_dn = idx_one(idx, ("ldap.name", "ldap.objectName"))
    ldap_pw = idx_one(idx, ("ldap.simple", "ldap.simple_bind"))
    if ldap_pw:
        out.append(_cred("LDAP simple bind", ldap_dn or "", ldap_pw, frame, "ldap.simple"))

    for cookie in idx_all(idx, ("http.cookie", "http.cookie_pair")):
        if cookie and 3 <= len(cookie) <= 4096:
            out.append(_cred("HTTP Cookie", "(cookie)", cookie[:2000], frame, "http.cookie"))
    for auth in idx_all(idx, ("http.authorization", "http.proxy_authorization")):
        if auth:
            out.append(_cred("HTTP Authorization", "(header)", auth[:2000], frame, "http.authorization"))
    for sc in idx_all(idx, ("http.set_cookie", "http.set-cookie")):
        if sc and 3 <= len(sc) <= 2000:
            out.append(_cred("HTTP Set-Cookie", "(cookie)", sc[:500], frame, "http.set_cookie"))

    cmd = idx_one(idx, ("ftp.request.command",))
    arg = idx_one(idx, ("ftp.request.arg",))
    if cmd and arg:
        cu = cmd.upper()
        if cu == "USER":
            out.append(_cred("FTP USER", arg, "", frame, "ftp.request"))
        elif cu == "PASS":
            out.append(_cred("FTP PASS", "", arg, frame, "ftp.request"))

    pop_cmd = idx_one(idx, ("pop.request.command",))
    pop_arg = idx_one(idx, ("pop.request.parameter",))
    if pop_cmd and pop_arg and pop_cmd.upper() in {"USER", "PASS", "APOP"}:
        out.append(_cred(f"POP {pop_cmd.upper()}", pop_arg if pop_cmd.upper() == "USER" else "",
                         pop_arg if pop_cmd.upper() != "USER" else "", frame, "pop"))

    pap_user = idx_one(idx, ("pap.peer_id", "ppp.pap.peer_id"))
    pap_pass = idx_one(idx, ("pap.password", "ppp.pap.password"))
    if pap_user or pap_pass:
        out.append(_cred("PAP", pap_user or "", pap_pass or "", frame, "pap"))

    rad_user = idx_one(idx, ("radius.User_Name", "radius.User-Name"))
    if rad_user:
        out.append(_cred("RADIUS", rad_user, "", frame, "radius.User_Name"))

    tac_user = idx_one(idx, ("tacacs.username",))
    tac_pass = idx_one(idx, ("tacacs.password",))
    if tac_user or tac_pass:
        out.append(_cred("TACACS+", tac_user or "", tac_pass or "", frame, "tacacs"))

    host = idx_one(idx, ("dhcp.option.hostname", "bootp.option.hostname"))
    if host and _is_sane(host, 128):
        out.append(_cred("DHCP hostname", host, "", frame, "dhcp.option.hostname"))

    sni = idx_one(idx, ("tls.handshake.extensions_server_name",))
    if sni and _is_sane(sni, 253):
        out.append(_cred("TLS SNI", sni, "", frame, "tls.sni"))

    out.extend(_intel_from_idx(idx, frame))
    return out

# Champs tshark à récolter sur TOUS les protocoles (sécurisés ou non).
# (clés, libellé, rôle)  rôle = secret | id | meta
_INTEL_SPEC: list[tuple[tuple[str, ...], str, str]] = [
    # Web / HTTP / HTTP2
    (("http.host", "http2.headers.authority"), "HTTP Host", "id"),
    (("http.request.uri", "http.request.full_uri", "http2.headers.path"), "HTTP URI", "id"),
    (("http.user_agent",), "HTTP User-Agent", "meta"),
    (("http.x_forwarded_for",), "HTTP X-Forwarded-For", "id"),
    (("http.file_data",), "HTTP body", "secret"),
    # TLS / QUIC (métadonnées malgré le chiffrement)
    (("tls.handshake.certificate",), "TLS certificat", "meta"),
    (("x509sat.uTF8String", "x509af.printableString", "x509ce.dNSName"), "TLS cert CN/SAN", "id"),
    (("tls.handshake.version",), "TLS version", "meta"),
    (("tls.handshake.ciphersuite",), "TLS cipher", "meta"),
    (("tls.handshake.ja3",), "JA3", "meta"),
    (("quic.connection.number",), "QUIC conn", "meta"),
    # SSH (bannière en clair même si la session est chiffrée ensuite)
    (("ssh.protocol", "ssh.kex.protocols", "ssh.host_key.type"), "SSH bannière", "meta"),
    # DNS / résolution
    (("dns.qry.name", "mdns.qry.name", "llmnr.qry.name", "nbns.name"), "DNS / nom", "id"),
    (("dns.a", "dns.aaaa", "dns.cname", "dns.txt"), "DNS réponse", "id"),
    # Mail
    (("imf.from", "smtp.req.parameter"), "Mail From", "id"),
    (("imf.to",), "Mail To", "id"),
    (("imf.subject",), "Mail Subject", "id"),
    (("imap.request", "imap.request.command"), "IMAP", "secret"),
    (("smtp.req.command",), "SMTP cmd", "meta"),
    # SMB / Windows
    (("smb2.filename", "smb.file", "smb.path"), "SMB fichier", "id"),
    (("smb2.tree", "smb.path"), "SMB share", "id"),
    (("smb.auth.username",), "SMB user", "id"),
    # Bases de données
    (("mysql.user",), "MySQL user", "id"),
    (("pgsql.user", "pgsql.password"), "PostgreSQL", "secret"),
    (("tds.username",), "MSSQL user", "id"),
    (("redis.bulk", "redis.request"), "Redis", "secret"),
    (("mongodb.user", "mongo.user"), "MongoDB user", "id"),
    # Télémétrie / IoT / OT
    (("mqtt.username", "mqtt.passwd", "mqtt.clientid"), "MQTT", "secret"),
    (("modbus.func_code",), "Modbus", "meta"),
    (("s7comm.param.func",), "Siemens S7", "meta"),
    (("bacnet.vendor_name", "bacnet.object_name"), "BACnet", "id"),
    (("dnp3.src", "dnp3.dst"), "DNP3", "meta"),
    # Remote
    (("vnc.auth_challenge", "vnc.security_type"), "VNC", "meta"),
    (("rdp.client.name", "rdp.client.address"), "RDP client", "id"),
    (("telnet.data",), "Telnet data", "secret"),
    # VoIP
    (("sip.From", "sip.To", "sip.Contact"), "SIP identité", "id"),
    (("sip.User-Agent",), "SIP UA", "meta"),
    # Infra
    (("dhcp.option.domain_name", "dhcp.hw.mac_addr"), "DHCP", "id"),
    (("ntp.refid",), "NTP", "meta"),
    (("ospf.auth.type", "ospf.auth.none"), "OSPF auth", "meta"),
    (("bgp.open.version",), "BGP", "meta"),
    (("cdp.deviceid", "lldp.tlv.system.name"), "CDP/LLDP nom", "id"),
    # Wi-Fi
    (("wlan.ssid",), "SSID Wi-Fi", "id"),
    (("wlan.bssid",), "BSSID", "id"),
    # Divers auth
    (("ike.initiator_spi", "isakmp.ispi"), "IKE SPI", "meta"),
    (("ipmi.session.id",), "IPMI", "meta"),
    (("diameter.Session-Id", "diameter.User-Name"), "Diameter", "id"),
    # Autres protocoles (clair ou métadonnées chiffrées)
    (("ftp.request.command", "ftp.request.arg"), "FTP", "meta"),
    (("tftp.destination_file", "tftp.source_file"), "TFTP fichier", "id"),
    (("ldap.name", "ldap.baseObject"), "LDAP DN", "id"),
    (("kerberos.CNameString", "kerberos.crealm"), "Kerberos id", "id"),
    (("ntlmssp.auth.username", "ntlmssp.auth.domain"), "NTLM id", "id"),
    (("http2.headers.user_agent",), "HTTP2 UA", "meta"),
    (("http2.headers.cookie",), "HTTP2 Cookie", "secret"),
    (("quic.tls.handshake.extensions_server_name", "tls.handshake.extensions_server_name"), "QUIC/TLS SNI", "id"),
    (("dtls.handshake.extensions_server_name",), "DTLS SNI", "id"),
    (("gquic.tag.sni",), "GQUIC SNI", "id"),
    (("ssdp.http.location", "http.location"), "SSDP / Location", "id"),
    (("llmnr.qry.name",), "LLMNR", "id"),
    (("nbns.name",), "NetBIOS", "id"),
    (("eigrp.as", "eigrp.opcode"), "EIGRP", "meta"),
    (("hsrp.virt_ip", "vrrp.ip_addr"), "HSRP/VRRP VIP", "id"),
    (("iec104.asdu.addr",), "IEC-104", "meta"),
    (("opcua.security.policyuri", "opcua.username"), "OPC UA", "id"),
    (("enip.command",), "EtherNet/IP", "meta"),
    (("coap.opt.uri_path", "coap.code"), "CoAP", "id"),
    (("amqp.method.arguments.mechanism",), "AMQP", "meta"),
    (("kafka.client_id",), "Kafka", "id"),
    (("dns.srv.target", "dns.mx.mail_exchange"), "DNS SRV/MX", "id"),
    (("tls.handshake.ja3s",), "JA3S", "meta"),
    (("x509ce.dNSName",), "Cert SAN", "id"),
    # Couverture large — tous les protocoles réseau courants
    (("arp.src.proto_ipv4", "arp.dst.proto_ipv4"), "ARP IP", "id"),
    (("icmp.type", "icmpv6.type"), "ICMP", "meta"),
    (("stun.att.username", "stun.att.realm"), "STUN / WebRTC", "id"),
    (("gtp.teid", "gtpv2.teid"), "GTP TEID", "meta"),
    (("sctp.srcport", "sctp.dstport"), "SCTP", "meta"),
    (("syslog.msg", "syslog.hostname"), "Syslog", "id"),
    (("nfs.fh.hash", "nfs.name"), "NFS", "id"),
    (("dcerpc.cn_bind_to_uuid", "dcerpc.opnum"), "DCERPC", "meta"),
    (("spoolss.opnum",), "Print Spooler", "meta"),
    (("winreg.opnum",), "Remote Registry", "meta"),
    (("lsarpc.op",), "LSARPC", "meta"),
    (("samr.opnum",), "SAMR", "meta"),
    (("drsuapi.opnum",), "DRSUAPI", "meta"),
    (("gss-api.OID", "spnego.mechtypes"), "GSS-API / SPNEGO", "meta"),
    (("tls.handshake.extensions_alpn_str",), "ALPN", "meta"),
    (("http2.headers.method", "http3.frame_type"), "HTTP/2-3", "meta"),
    (("websocket.payload", "websocket.payload.text"), "WebSocket", "secret"),
    (("grpc.message_length",), "gRPC", "meta"),
    (("dhcpv6.duid.bytes", "dhcpv6.client_fqdn"), "DHCPv6", "id"),
    (("netflow.version", "cflow.srcaddr"), "NetFlow / IPFIX", "id"),
    (("syslog.level",), "Syslog level", "meta"),
    (("rip.ip",), "RIP", "id"),
    (("eigrp.as",), "EIGRP AS", "meta"),
    (("isis.sys_id",), "IS-IS", "id"),
    (("ldp.id",), "LDP", "id"),
    (("gre.proto",), "GRE", "meta"),
    (("l2tp.session_id",), "L2TP", "meta"),
    (("wireguard.receiver",), "WireGuard", "meta"),
    (("openvpn.opcode",), "OpenVPN", "meta"),
    (("esp.spi",), "IPsec ESP SPI", "meta"),
    (("socks.dst", "socks.user"), "SOCKS", "id"),
    (("iscsi.lun",), "iSCSI", "meta"),
    (("afp.command",), "AFP", "meta"),
    (("rsync.command",), "Rsync", "meta"),
    (("bittorrent.info_hash",), "BitTorrent", "id"),
    (("ssdp.http.server",), "SSDP server", "id"),
    (("wsdd.types",), "WS-Discovery", "id"),
    (("browser.server",), "Browser / NetBIOS", "id"),
    (("rtp.ssrc", "rtp.p_type"), "RTP", "meta"),
    (("rtcp.ssrc.identifier",), "RTCP", "meta"),
    (("h225.CallingPartyNumber", "h225.CalledPartyNumber"), "H.323", "id"),
    (("mgcp.req.endpoint",), "MGCP", "id"),
    (("iax2.username",), "IAX2", "id"),
    (("skinny.stationName",), "Skinny", "id"),
    (("opcua.security.username",), "OPC UA user", "id"),
    (("enip.sendercontext",), "EtherNet/IP", "meta"),
    (("iec104.asdu.typeid",), "IEC-104", "meta"),
    (("dnp3.al.func",), "DNP3", "meta"),
    (("s7comm.param.itemcount",), "S7", "meta"),
    (("modbus.unit_id",), "Modbus unit", "meta"),
    (("bacnet.sadr_eth",), "BACnet", "id"),
    (("coap.mid",), "CoAP", "meta"),
    (("zwave.src",), "Z-Wave", "id"),
    (("zigbee.nwk.src",), "ZigBee", "id"),
    (("btatt.handle", "bthci_evt.bd_addr"), "Bluetooth", "id"),
    (("usb.device_address",), "USB", "id"),
    (("llmnr.resp.name",), "LLMNR resp", "id"),
    (("nbns.addr",), "NBNS IP", "id"),
    (("mdns.resp.name",), "mDNS resp", "id"),
    (("kerberos.error_code",), "Kerberos erreur", "meta"),
    (("ldap.AttributeValue",), "LDAP valeur", "secret"),
    (("http.location",), "HTTP Location", "id"),
    (("http.referer",), "HTTP Referer", "id"),
    (("http.server",), "HTTP Server", "meta"),
    (("http.content_type",), "HTTP Content-Type", "meta"),
    (("tls.handshake.ja3s",), "JA3S", "meta"),
    (("ssh.host_key.type",), "SSH host key", "meta"),
    (("ftp.response.code",), "FTP code", "meta"),
    (("smtp.response.code",), "SMTP code", "meta"),
]

def _intel_from_layers(layers: dict, frame: int) -> list[CredentialHit]:
    return _intel_from_idx(index_layers(layers), frame)

def _intel_from_idx(idx: dict[str, list[str]], frame: int) -> list[CredentialHit]:
    """Récolte générique via index (une passe)."""
    out: list[CredentialHit] = []
    seen_local: set[tuple] = set()
    for keys, label, role in _INTEL_SPEC:
        vals = idx_all(idx, keys)
        for val in vals[:4]:
            if not val or not _is_sane(val, 512):
                continue
            # corps HTTP trop long / binaire
            if role == "secret" and len(val) > 400:
                val = val[:400] + "…"
            k = (label, val[:120])
            if k in seen_local:
                continue
            seen_local.add(k)
            if role == "secret":
                out.append(_cred(label, "", val, frame, keys[0]))
            else:
                out.append(_cred(label, val, "", frame, keys[0]))
    return out

def snmp_communities_from_bytes(raw: bytes) -> list[str]:
    """Community SNMPv1/v2c dans le BER (INTEGER version + OCTET STRING)."""
    out: list[str] = []
    n = len(raw)
    i = 0
    while i + 6 < n:
        if raw[i] == 0x02 and raw[i + 1] == 0x01 and raw[i + 2] in (0x00, 0x01):
            if raw[i + 3] == 0x04:
                ln = raw[i + 4]
                if not (ln & 0x80) and 1 <= ln <= 64:
                    chunk = raw[i + 5 : i + 5 + ln]
                    if len(chunk) == ln and all(32 <= b < 127 for b in chunk):
                        s = chunk.decode("ascii")
                        if any(c.isalnum() for c in s):
                            out.append(s)
        i += 1
    return list(dict.fromkeys(out))

def secrets_from_raw(raw: bytes) -> list[CredentialHit]:
    """Secrets dans le flux texte reconstruit (octets -x)."""
    text = raw.decode("latin-1", "replace")
    out: list[CredentialHit] = []

    # community SNMP dans le texte (Wireshark / dumps)
    for m in _SNMP_COMM_RE.finditer(text):
        comm = m.group(1)
        if _is_sane(comm, 64) and comm.lower() not in {"community", "publicpublic"}:
            out.append(_cred("SNMP community (brut)", "(community)", comm, source="raw"))

    # e-mails
    seen_mail: set[str] = set()
    for m in _EMAIL_RE.finditer(text):
        mail = m.group(0)
        if mail.lower() in seen_mail or len(mail) > 80:
            continue
        # bannière APOP : <timestamp@host> n'est pas un e-mail utile
        if re.match(r"^\d+\.\d+@", mail):
            continue
        seen_mail.add(mail.lower())
        if len(seen_mail) > 40:
            break
        out.append(_cred("E-mail", mail, "", source="raw"))

    # AWS access keys
    for m in _AWS_KEY_RE.finditer(text):
        out.append(_cred("AWS Access Key", m.group(0), "", source="raw"))

    # API keys dans query / headers
    for m in _API_KEY_RE.finditer(text):
        out.append(_cred("API key", m.group(1), m.group(2)[:200], source="raw"))

    # Cookie: ...
    for m in re.finditer(r"(?im)^Cookie:\s*(.+)$", text):
        val = m.group(1).strip()
        if 3 <= len(val) <= 2000:
            out.append(_cred("HTTP Cookie", "(cookie)", val[:2000], source="Cookie:"))

    # Set-Cookie
    for m in re.finditer(r"(?im)^Set-Cookie:\s*([^;\r\n]+)", text):
        out.append(_cred("HTTP Set-Cookie", "(cookie)", m.group(1).strip()[:500], source="Set-Cookie:"))

    seen_tel: set[str] = set()
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        norm = _norm_phone(raw)
        if not norm or norm in seen_tel:
            continue
        seen_tel.add(norm)
        if len(seen_tel) > 20:
            break
        out.append(_cred("Téléphone", norm, raw.strip(), source="raw"))

    return out

def dedupe_creds(items: Iterable[CredentialHit]) -> list[CredentialHit]:
    seen: set[tuple] = set()
    out: list[CredentialHit] = []
    for c in items:
        k = (c.protocol, c.username, c.password)
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out

_FAKE_MAIL_DOMAINS = (
    "openssh.com",
    "libssh.org",
    "openssl.org",
    "example.com",
    "example.org",
    "example.net",
    "invalid",
    "localhost",
    "localdomain",
    "iana.org",
)
_FAKE_MAIL_TOKENS = (
    "curve25519",
    "poly1305",
    "chacha20",
    "cert-v01",
    "sk-ssh",
    "rsa-sha2",
    "ecdsa-sha2",
    "ssh-ed25519",
    "ssh-rsa",
    "sk-ecdsa",
    "webauthn",
)
_KNOWN_COMMUNITIES = {
    "public",
    "private",
    "secret",
    "monitor",
    "admin",
    "manager",
    "read",
    "write",
    "community",
    "snmp",
    "cisco",
    "default",
    "internal",
    "guest",
    "ro",
    "rw",
}
_FUZZ_TOKS = ("%s", "%n", "%x", "%d", "%p", "%.", "%*", "\\x", "\\a", "%n$")

_WIFI_LABELS = {"SSID Wi-Fi", "BSSID"}
_FILE_LABELS = {"SMB fichier", "SMB share", "TFTP fichier"}
_HOST_LABELS = {
    "TLS SNI",
    "QUIC/TLS SNI",
    "DTLS SNI",
    "GQUIC SNI",
    "HTTP Host",
    "DNS / nom",
    "DNS réponse",
    "DNS SRV/MX",
    "DHCP hostname",
    "CDP/LLDP nom",
    "SSDP / Location",
    "HTTP Location",
    "Cert SAN",
    "TLS cert CN/SAN",
}
_ID_LABELS = {
    "Kerberos id",
    "NTLM id",
    "SMB user",
    "RADIUS",
    "SNMPv3 user",
    "E-mail",
    "Mail From",
    "Mail To",
    "SIP identité",
    "RDP client",
    "LDAP DN",
    "DHCP",
    "MySQL user",
    "MSSQL user",
    "MongoDB user",
    "FTP USER",
    "POP USER",
    "HTTP X-Forwarded-For",
}
_SECRET_LABELS = {
    "SNMPv1/v2c community",
    "SNMP community (brut)",
    "HTTP Cookie",
    "HTTP Set-Cookie",
    "HTTP Authorization",
    "HTTP2 Cookie",
    "HTTP Basic",
    "HTTP Proxy-Basic",
    "HTTP Bearer",
    "HTTP form",
    "FTP/Telnet USER/PASS",
    "FTP PASS",
    "LDAP simple bind",
    "PAP",
    "TACACS+",
    "AWS Access Key",
    "API key",
    "AUTH PLAIN",
    "AUTH LOGIN",
    "POP PASS",
    "POP APOP",
}
_META_LABELS = {
    "TLS version",
    "TLS cipher",
    "JA3",
    "JA3S",
    "ALPN",
    "SSH bannière",
    "SSH host key",
    "ICMP",
    "ARP IP",
    "HTTP User-Agent",
    "HTTP Server",
    "HTTP Content-Type",
    "QUIC conn",
    "Modbus",
    "Siemens S7",
    "TLS certificat",
    "SMTP cmd",
    "FTP code",
    "SMTP code",
    "HTTP/2-3",
    "OSPF auth",
    "BGP",
    "NTP",
    "IKE SPI",
    "IPMI",
    "VNC",
    "Kerberos erreur",
    "GSS-API / SPNEGO",
    "DCERPC",
    "Print Spooler",
    "Remote Registry",
    "LSARPC",
    "SAMR",
    "DRSUAPI",
    "NFS",
    "GRE",
    "L2TP",
    "WireGuard",
    "OpenVPN",
    "IPsec ESP SPI",
    "RTP",
    "RTCP",
    "SCTP",
    "GTP TEID",
    "Syslog level",
    "HTTP URI",
}

def _looks_like_mac(val: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", val or ""))

def decode_maybe_hex(val: str) -> str:
    """Décode un SSID hex ``47:72:65:48…`` → ASCII si imprimable."""
    if not val or _looks_like_mac(val):
        return val
    cleaned = val.replace(":", "").replace("-", "").replace(" ", "")
    if len(cleaned) < 4 or len(cleaned) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return val
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return val
    if not raw or not all(32 <= b < 127 for b in raw):
        return val
    txt = raw.decode("ascii")
    if len(raw) == 6 and not any(c.isalpha() for c in txt):
        return val
    return txt

def _is_fuzz_payload(s: str) -> bool:
    if not s:
        return False
    if any(tok in s for tok in _FUZZ_TOKS):
        return True
    if re.search(r"(.)\1{3,}", s):  # aaaa, 0000, AAAA@AAAA
        return True
    compact = re.sub(r"[\s@:._/\-]", "", s)
    if len(compact) >= 4 and len(set(compact.lower())) <= 2:
        return True
    if re.fullmatch(r"[A@a0\-9 ]{6,}", s) and len(set(s.replace(" ", "").lower())) <= 3:
        return True
    # public@aaaa / private%s — community connue + suffixe poubelle
    low = s.lower()
    for comm in _KNOWN_COMMUNITIES:
        if low.startswith(comm) and len(s) > len(comm) + 1 and s[len(comm)] in "@._-+%":
            return True
    return False

def _is_fake_email(mail: str) -> bool:
    low = (mail or "").lower()
    if not low or "@" not in low:
        return False
    if re.match(r"^\d+\.\d+@", low):
        return True
    domain = low.rsplit("@", 1)[-1]
    if domain in _FAKE_MAIL_DOMAINS or any(domain.endswith("." + d) for d in _FAKE_MAIL_DOMAINS):
        return True
    if any(tok in low for tok in _FAKE_MAIL_TOKENS):
        return True
    return False

def _is_real_community(s: str) -> bool:
    if not s or _is_fuzz_payload(s):
        return False
    if s.lower() in _KNOWN_COMMUNITIES:
        return True
    if len(set(s.lower())) <= 2:
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-.]{1,31}", s))

def _hit_file(obj: Any) -> str:
    extra = getattr(obj, "extra", None) or {}
    return str(extra.get("fichier") or "")

def _hit_value(c: "CredentialHit") -> str:
    return (c.password or c.username or "").strip()

def classify_hit(c: "CredentialHit") -> str:
    """Classe un hit : secret | identity | host | wifi | file | meta | noise."""
    proto = (c.protocol or "").strip()
    user = c.username or ""
    secret = c.password or ""
    val = secret or user

    if proto in _WIFI_LABELS:
        return "wifi"
    if proto in ("FTP code",) or proto.startswith("FTP ") and proto not in {"FTP PASS", "FTP USER", "FTP/Telnet USER/PASS"}:
        if proto in _FILE_LABELS:
            return "file"
        return "meta"
    if proto in _FILE_LABELS:
        return "file"
    if proto in ("E-mail", "Mail From", "Mail To") and _is_fake_email(user or secret):
        return "noise"
    if "snmp" in proto.lower() and "user" not in proto.lower():
        return "secret" if _is_real_community(secret or user) else "noise"
    if proto in _SECRET_LABELS:
        if secret and (_is_fuzz_payload(secret) or _is_cf_cookie(secret)):
            return "noise"
        if proto == "HTTP body" and not any(
            k in (secret or "").lower() for k in ("password", "passwd", "token", "secret", "api_key", "authorization")
        ):
            return "meta"
        return "secret"
    if proto in _HOST_LABELS:
        return "host"
    if proto in _ID_LABELS:
        if proto == "E-mail" and _is_fake_email(user or secret):
            return "noise"
        if (user or secret).strip().lower() in {"null", "none", "(null)", "nil"}:
            return "noise"
        if _is_realm_not_person(user or secret) and proto in {"Kerberos id", "NTLM id"}:
            return "meta"
        return "identity"
    if proto in _META_LABELS or proto.startswith("SSH"):
        return "meta"
    if proto in ("HTTP URI",) and val.startswith("/") and len(val) < 4:
        return "meta"
    if secret and proto not in _META_LABELS:
        if _is_fuzz_payload(secret):
            return "noise"
        if proto in _SECRET_LABELS or "PASS" in proto or "Cookie" in proto or "token" in proto.lower():
            return "secret"
    if user and not secret:
        return "identity" if proto in _ID_LABELS or proto in _HOST_LABELS else "meta"
    return "meta"

def dedupe_kerberos(items: Iterable["KerberosIdentity"]) -> list["KerberosIdentity"]:
    seen: set[tuple] = set()
    out: list[KerberosIdentity] = []
    for d in items:
        k = (d.msg, d.user or "", d.realm or "", d.spn or "", tuple(d.etypes or []))
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out

def dedupe_hash_map(hashes: dict[int, list["HashHit"]]) -> dict[int, list["HashHit"]]:
    out: dict[int, list[HashHit]] = {}
    for mode, hits in hashes.items():
        seen: set[str] = set()
        uniq: list[HashHit] = []
        for h in hits:
            if h.line in seen:
                continue
            seen.add(h.line)
            uniq.append(h)
        if uniq:
            out[mode] = uniq
    return out

def _wpa_essid_from_line(line: str) -> str:
    parts = (line or "").split("*")
    if len(parts) >= 6 and parts[0] == "WPA":
        return decode_maybe_hex(parts[5]) or parts[5]
    return ""

def hash_context(h: "HashHit") -> str:
    bits: list[str] = []
    extra = h.extra or {}
    if h.user:
        bits.append(str(h.user))
    if h.domain and str(h.domain) not in bits:
        bits.append(str(h.domain))
    if extra.get("spn"):
        bits.append(str(extra["spn"]))
    if extra.get("ssid"):
        ss = decode_maybe_hex(str(extra["ssid"]))
        if ss and ss not in bits:
            bits.append(ss)
    if extra.get("kind") and extra["kind"] not in bits:
        bits.append(str(extra["kind"]))
    if h.mode == 22000:
        essid = _wpa_essid_from_line(h.line)
        if essid and essid not in bits:
            bits.append(essid)
        if h.line.startswith("WPA*01*") and "PMKID" not in bits:
            bits.append("PMKID")
        elif h.line.startswith("WPA*02*") and "EAPOL" not in bits:
            bits.append("EAPOL")
    if extra.get("msg") and str(extra["msg"]) not in bits:
        bits.append(str(extra["msg"]))
    if extra.get("etype") is not None:
        bits.append(f"etype {extra['etype']}")
    return " · ".join(bits)

def _unique_rows(rows: list[dict[str, Any]], key: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        k = tuple(str(r.get(x) or "") for x in key)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out

def build_network_report(result: "ExtractResult") -> dict[str, Any]:
    """Vue filtrée : faits importants, identités, hôtes, secrets utiles, bruit compté."""
    hashes = dedupe_hash_map(dict(result.hashes))
    kerberos = dedupe_kerberos(result.diag)
    buckets: dict[str, list[CredentialHit]] = defaultdict(list)
    noise_counts: dict[str, int] = defaultdict(int)
    for c in result.credentials:
        kind = classify_hit(c)
        if kind == "noise":
            proto = c.protocol or "autre"
            if "snmp" in proto.lower():
                noise_counts["SNMP fuzz"] += 1
            elif proto in ("E-mail", "Mail From", "Mail To"):
                noise_counts["e-mail / bannière SSH"] += 1
            else:
                noise_counts[proto] += 1
            continue
        buckets[kind].append(c)

    snmp_real = sorted(
        {
            (c.password or c.username or "").strip()
            for c in buckets.get("secret", [])
            if "snmp" in (c.protocol or "").lower() and (c.password or c.username)
        }
    )
    snmp_fuzz_n = int(noise_counts.get("SNMP fuzz", 0))

    identities: list[dict[str, Any]] = []
    for d in kerberos:
        if not (d.user or d.realm):
            continue
        upn = f"{d.user}@{d.realm}" if d.user and d.realm else (d.user or d.realm or "")
        identities.append(
            {
                "type": f"Kerberos {d.msg}",
                "valeur": upn,
                "detail": d.spn or "",
                "kind": "kerberos",
                "fichier": "",
            }
        )
    for mode, hits in hashes.items():
        for h in hits:
            if not h.user:
                continue
            # Kerberos : l'identité vient déjà de result.diag (évite 9× le même UPN)
            if "kerb" in (h.protocol or "").lower() and kerberos:
                continue
            kind = "ntlm" if mode in (5500, 5600) else "hash"
            val = f"{h.user}@{h.domain}" if h.domain else str(h.user)
            identities.append(
                {
                    "type": (mode_info(mode) or {}).get("name") or f"m{mode}",
                    "valeur": val,
                    "detail": hash_context(h),
                    "kind": kind,
                    "fichier": _hit_file(h),
                }
            )
    for c in buckets.get("identity", []):
        val = (c.username or c.password or "").strip()
        if not val or val.startswith("("):
            continue
        identities.append(
            {
                "type": c.protocol,
                "valeur": val,
                "detail": c.source or "",
                "kind": "id",
                "fichier": _hit_file(c),
            }
        )
    identities = _unique_rows(identities, ("type", "valeur", "detail"))
    # un même compte AD ne doit pas apparaître 4 fois (diag + chaque mode hash)
    prefer = {"kerberos": 0, "ntlm": 1, "ad": 2, "id": 3, "hash": 4}
    identities.sort(key=lambda r: (prefer.get(r.get("kind"), 9), r.get("type") or "", r.get("valeur") or ""))
    compact_ids: list[dict[str, Any]] = []
    seen_val: set[str] = set()
    for row in identities:
        key = (row.get("valeur") or "").lower()
        kind = row.get("kind") or ""
        if key and kind in {"kerberos", "ntlm", "ad", "hash"} and key in seen_val:
            for prev in compact_ids:
                if (prev.get("valeur") or "").lower() != key:
                    continue
                if row.get("detail") and row["detail"] not in (prev.get("detail") or ""):
                    prev["detail"] = " · ".join(x for x in (prev.get("detail"), row["detail"]) if x)
                if kind == "kerberos" and prev.get("kind") == "kerberos":
                    t1 = (prev.get("type") or "").replace("Kerberos ", "")
                    t2 = (row.get("type") or "").replace("Kerberos ", "")
                    merged = ", ".join(dict.fromkeys(x for x in (t1, t2) if x))
                    prev["type"] = "Kerberos " + merged if merged else prev.get("type")
                break
            continue
        if key and kind in {"kerberos", "ntlm", "ad", "hash"}:
            seen_val.add(key)
        compact_ids.append(row)
    identities = compact_ids

    hosts: list[dict[str, Any]] = []
    for c in buckets.get("host", []):
        nom = decode_maybe_hex((c.username or c.password or "").strip())
        if not nom or nom in {".", "*"}:
            continue
        hosts.append({"type": c.protocol, "nom": nom, "fichier": _hit_file(c), "source": c.source})
    hosts = _unique_rows(hosts, ("type", "nom"))

    wifi: list[dict[str, Any]] = []
    for c in buckets.get("wifi", []):
        raw = (c.username or c.password or "").strip()
        if "SSID" in (c.protocol or ""):
            decoded = decode_maybe_hex(raw)
            if _looks_like_mac(decoded):
                wifi.append({"type": "BSSID", "valeur": decoded.lower(), "brut": "", "fichier": _hit_file(c)})
            else:
                wifi.append(
                    {
                        "type": "SSID",
                        "valeur": decoded,
                        "brut": raw if decoded != raw else "",
                        "fichier": _hit_file(c),
                    }
                )
        else:
            wifi.append({"type": "BSSID", "valeur": raw, "brut": "", "fichier": _hit_file(c)})
    for hits in hashes.values():
        for h in hits:
            if h.mode != 22000:
                continue
            essid = decode_maybe_hex(str((h.extra or {}).get("ssid") or "")) or _wpa_essid_from_line(h.line)
            if essid:
                kind = "PMKID" if h.line.startswith("WPA*01*") else "EAPOL"
                wifi.append(
                    {
                        "type": f"SSID ({kind})",
                        "valeur": essid,
                        "brut": "",
                        "fichier": _hit_file(h),
                    }
                )
    wifi = _unique_rows(wifi, ("type", "valeur"))

    files: list[dict[str, Any]] = []
    for c in buckets.get("file", []):
        path = (c.username or c.password or "").strip()
        if not path:
            continue
        files.append({"type": c.protocol, "chemin": path, "fichier": _hit_file(c)})
    files = _unique_rows(files, ("type", "chemin"))

    secrets = buckets.get("secret", [])
    secrets = dedupe_creds(secrets)

    facts: list[dict[str, str]] = []

    ad = []
    for ident in identities:
        if ident.get("kind") in ("kerberos", "ntlm", "ad"):
            ad.append(ident["valeur"])
    ad = list(dict.fromkeys(ad))
    if ad:
        facts.append(
            {
                "sev": "ÉLEVÉ",
                "titre": "Comptes Active Directory",
                "detail": ", ".join(ad[:8]) + (f"  (+{len(ad) - 8})" if len(ad) > 8 else ""),
            }
        )

    spns = sorted({d.spn for d in kerberos if d.spn})
    if spns:
        facts.append({"sev": "ÉLEVÉ", "titre": "SPN Kerberos (Kerberoast)", "detail": ", ".join(spns[:8])})

    if any(m in hashes for m in (5500, 5600)):
        users = sorted(
            {
                f"{h.user}@{h.domain}" if h.domain else str(h.user)
                for m in (5500, 5600)
                for h in hashes.get(m, [])
                if h.user
            }
        )
        facts.append({"sev": "ÉLEVÉ", "titre": "Hash NetNTLM capturé", "detail": ", ".join(users) or "compte Windows"})

    ssids = sorted({w["valeur"] for w in wifi if w["type"].startswith("SSID") and w["valeur"]})
    if ssids:
        facts.append({"sev": "MOYEN", "titre": "Réseau Wi-Fi", "detail": ", ".join(ssids[:8])})

    if snmp_real:
        extra = f"  (+ {snmp_fuzz_n} payload(s) de fuzzing ignoré(s))" if snmp_fuzz_n else ""
        facts.append(
            {
                "sev": "CRITIQUE",
                "titre": "Community SNMP en clair",
                "detail": ", ".join(snmp_real) + extra,
            }
        )
    elif snmp_fuzz_n:
        facts.append(
            {
                "sev": "FAIBLE",
                "titre": "Scan / fuzzing SNMP",
                "detail": f"{snmp_fuzz_n} community factices (aaaa, %s%s…) — pas des secrets réels",
            }
        )

    if files:
        facts.append(
            {
                "sev": "MOYEN",
                "titre": "Fichiers / partages vus",
                "detail": ", ".join(f["chemin"] for f in files[:10]),
            }
        )

    sni = [h["nom"] for h in hosts if "SNI" in h["type"] or h["type"] == "HTTP Host"]
    sni = list(dict.fromkeys(sni))
    if sni:
        facts.append({"sev": "FAIBLE", "titre": "Hôtes TLS / HTTP", "detail": ", ".join(sni[:12])})

    if 20 in hashes:
        facts.append(
            {
                "sev": "ÉLEVÉ",
                "titre": "Hash MD5(salt+pass)  (APOP / OSPF-like)",
                "detail": f"{len(hashes[20])} ligne(s) → hashcat -m 20",
            }
        )

    n_files = len(
        {
            _hit_file(h)
            for hits in hashes.values()
            for h in hits
            if _hit_file(h)
        }
        | {_hit_file(c) for c in result.credentials if _hit_file(c)}
    )

    return {
        "facts": facts,
        "identities": identities,
        "hosts": hosts,
        "wifi": wifi,
        "files": files,
        "secrets": secrets,
        "kerberos": kerberos,
        "hashes": hashes,
        "snmp_real": snmp_real,
        "snmp_fuzz_n": snmp_fuzz_n,
        "noise_counts": dict(sorted(noise_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "n_secrets_raw": len(result.credentials),
        "n_secrets_useful": len(secrets),
        "n_hashes": sum(len(v) for v in hashes.values()),
        "hash_modes": sorted(hashes.keys()),
        "n_files": n_files,
        "n_identities": len(identities),
        "n_hosts": len(hosts),
        "n_wifi": len(ssids) if ssids else len([w for w in wifi if w["type"].startswith("SSID")]),
        "n_noise": sum(noise_counts.values()),
    }

def finalize_extract_result(result: "ExtractResult") -> "ExtractResult":
    """Dédoublonne hashes / Kerberos / credentials après fusion de chunks."""
    result.hashes = defaultdict(list, dedupe_hash_map(dict(result.hashes)))
    result.diag = dedupe_kerberos(result.diag)
    result.credentials = dedupe_creds(result.credentials)
    result.notes = list(dict.fromkeys(result.notes))
    return result

_PROTO_FAMILIES: list[tuple[str, tuple[str, ...]]] = [
    ("Wi-Fi", ("wlan", "radiotap", "wlan_radio", "eapol", "wep")),
    ("Auth / AD", ("kerberos", "ntlmssp", "ldap", "cldap", "smb", "smb2", "gss-api", "spnego", "samr", "netlogon", "kpasswd", "lsarpc", "drsuapi")),
    ("Web / TLS", ("http", "http2", "http3", "tls", "ssl", "quic")),
    ("Noms / DHCP", ("dns", "mdns", "llmnr", "nbns", "ssdp", "dhcp", "dhcpv6", "bootp")),
    ("Mail", ("smtp", "imap", "pop", "imf")),
    ("VoIP", ("sip", "rtp", "rtcp", "sdp", "skinny", "h225", "mgcp")),
    ("Infra", ("snmp", "ospf", "bgp", "cdp", "lldp", "stp", "hsrp", "vrrp", "ntp", "icmp", "icmpv6")),
    ("Fichiers", ("ftp", "tftp", "nfs", "smb", "smb2")),
    ("OT / IoT", ("modbus", "s7comm", "dnp3", "bacnet", "enip", "opcua", "mqtt", "coap")),
    ("Remote", ("ssh", "telnet", "rdp", "vnc", "rfb")),
    ("Transport", ("tcp", "udp", "sctp")),
    ("Réseau", ("ip", "ipv6", "igmp", "gre", "esp")),
    ("Liaison", ("eth", "ethertype", "llc", "sll", "vlan", "pppoe", "arp")),
]
_CLEARTEXT_PROTOS = {
    "ftp", "telnet", "http", "snmp", "ldap", "pop", "imap", "smtp", "tftp",
    "redis", "mqtt", "nbns", "llmnr", "mdns",
}
_CRYPTO_PROTOS = {"tls", "ssl", "ssh", "quic", "dtls", "esp", "wireguard", "openvpn", "ipsec"}

def _family_of(proto: str) -> str:
    p = (proto or "").lower()
    for name, members in _PROTO_FAMILIES:
        if p in members:
            return name
    return "Autre"

def build_packet_analysis(result: "ExtractResult") -> dict[str, Any]:
    """Vue analyse paquets : familles, %, tailles, durée, IP/MAC."""
    counts = dict(getattr(result, "proto_counts", None) or {})
    total = int(result.packets or 0)
    denom = max(total, 1)
    protocols: list[dict[str, Any]] = []
    for p, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        pl = p.lower()
        if pl in _CLEARTEXT_PROTOS:
            classe = "clair"
        elif pl in _CRYPTO_PROTOS:
            classe = "chiffré"
        elif pl in {"kerberos", "ntlmssp", "eapol", "radius", "tacacs"}:
            classe = "auth"
        else:
            classe = "—"
        protocols.append(
            {
                "protocole": p,
                "paquets": int(n),
                "pct": round(100.0 * int(n) / denom, 2),
                "famille": _family_of(p),
                "classe": classe,
            }
        )
    fam: dict[str, int] = defaultdict(int)
    for row in protocols:
        if row["famille"] != "Autre":
            fam[row["famille"]] += row["paquets"]
    families = [{"famille": k, "paquets": v, "pct": round(100.0 * v / denom, 1)} for k, v in sorted(fam.items(), key=lambda kv: -kv[1])]

    st = getattr(result, "packet_stats", None) or {}
    bsum = int(st.get("bytes_sum") or 0)
    t0, t1 = st.get("t_first"), st.get("t_last")
    duration = None
    if t0 is not None and t1 is not None:
        try:
            duration = max(0.0, float(t1) - float(t0))
        except (TypeError, ValueError):
            duration = None
    return {
        "protocols": protocols,
        "families": families,
        "bytes_sum": bsum,
        "bytes_min": st.get("bytes_min"),
        "bytes_max": st.get("bytes_max") or 0,
        "bytes_avg": (bsum / denom) if bsum else 0,
        "duration": duration,
        "bitrate_bps": (bsum * 8 / duration) if duration else None,
        "n_ips": int(st.get("n_ips") or len(st.get("ips") or [])),
        "n_macs": int(st.get("n_macs") or len(st.get("macs") or [])),
        "ips": list(st.get("ips") or [])[:120],
        "macs": list(st.get("macs") or [])[:60],
        "n_ipv4": int(counts.get("ip") or 0),
        "n_ipv6": int(counts.get("ipv6") or 0),
        "n_tcp": int(counts.get("tcp") or 0),
        "n_udp": int(counts.get("udp") or 0),
        "n_icmp": int(counts.get("icmp") or 0) + int(counts.get("icmpv6") or 0),
        "n_wlan": int(counts.get("wlan") or 0),
        "n_eth": int(counts.get("eth") or 0),
        "n_clear": sum(int(counts.get(p) or 0) for p in _CLEARTEXT_PROTOS),
        "n_crypt": sum(int(counts.get(p) or 0) for p in _CRYPTO_PROTOS),
        "n_packets": total,
    }

# Protocoles considérés « en clair / dangereux » pour le rapport de protection
RISKY_CLEARTEXT: dict[str, tuple[str, int, str]] = {
    # proto: (sévérité, malus, conseil)
    "ftp": ("CRITIQUE", 25, "Remplacer FTP par SFTP / FTPS — mots de passe en clair."),
    "telnet": ("CRITIQUE", 30, "Désactiver Telnet, passer en SSH."),
    "http": ("ÉLEVÉ", 12, "Forcer HTTPS (HSTS). Les formulaires et Basic Auth fuient."),
    "snmp": ("CRITIQUE", 28, "SNMPv1/v2c : community = mot de passe en clair. Passer en SNMPv3 authPriv."),
    "ldap": ("ÉLEVÉ", 18, "LDAP simple bind envoie le mot de passe en clair. Exiger LDAPS / StartTLS."),
    "pop": ("ÉLEVÉ", 15, "POP3 en clair. Utiliser POP3S ou IMAPS."),
    "imap": ("ÉLEVÉ", 15, "IMAP en clair. Utiliser IMAPS."),
    "smtp": ("MOYEN", 8, "SMTP sans STARTTLS : AUTH PLAIN/LOGIN visibles."),
    "tftp": ("MOYEN", 8, "TFTP sans authentification. Isoler ou remplacer."),
    "rsh": ("CRITIQUE", 25, "rsh/rlogin : à interdire."),
    "rlogin": ("CRITIQUE", 25, "rlogin : à interdire."),
    "pptp": ("ÉLEVÉ", 12, "PPTP est cassé. Utiliser IKEv2 / WireGuard."),
    "vnc": ("ÉLEVÉ", 12, "VNC souvent peu chiffré. Tunnel SSH ou TightVNC+TLS."),
    "nbns": ("MOYEN", 6, "NetBIOS-NS : usurpation / LLMNR poison fréquente."),
    "llmnr": ("MOYEN", 8, "LLMNR : désactiver (NTLM relay)."),
    "mdns": ("FAIBLE", 3, "mDNS divulgue des noms d'hôtes."),
    "ssdp": ("FAIBLE", 2, "SSDP divulgue des équipements."),
    "redis": ("CRITIQUE", 22, "Redis sans AUTH / en clair. Exiger TLS + mot de passe."),
    "mysql": ("ÉLEVÉ", 14, "MySQL en clair. Forcer TLS."),
    "pgsql": ("ÉLEVÉ", 14, "PostgreSQL en clair. Forcer SSL."),
    "mqtt": ("ÉLEVÉ", 12, "MQTT souvent sans TLS. Utiliser MQTTS."),
    "irc": ("MOYEN", 8, "IRC en clair. Passer en TLS."),
    "rdp": ("MOYEN", 6, "RDP vu — vérifier NLA et chiffrement."),
    "modbus": ("ÉLEVÉ", 16, "Modbus sans authentification. Isoler le réseau OT."),
    "s7comm": ("ÉLEVÉ", 16, "S7comm sans auth. Isoler / VPN."),
}

AUTH_WEAK: dict[str, tuple[str, int, str]] = {
    "ntlmssp": ("ÉLEVÉ", 14, "NTLM capturé → hashcat -m 5500/5600. Préférer Kerberos / désactiver NTLM."),
    "kerberos": ("MOYEN", 6, "Tickets Kerberos extraits (AS-REP / TGS / PA). Surveiller RC4 (etype 23)."),
    "eapol": ("MOYEN", 8, "Handshake WPA vu. Vérifier la force du PSK."),
    "http-digest": ("MOYEN", 6, "HTTP Digest capturé — craquable si le mot de passe est faible."),
    "sip": ("ÉLEVÉ", 10, "SIP Digest → hashcat -m 11400."),
    "chap": ("MOYEN", 8, "CHAP → hashcat -m 4800."),
}

_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+|00)33[\s.\-]?[1-9](?:[\s.\-]?\d{2}){4}(?!\d)"
    r"|(?<!\d)0[1-9](?:[\s.\-]?\d{2}){4}(?!\d)"
)
_USER_PATH_RE = re.compile(
    r"(?i)(?:C:\\Users\\|C:/Users/|/home/|/Users/)([A-Za-z0-9._-]{1,32})"
)
_MAIL_NAME_RE = re.compile(
    r'^\s*"?([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .\-]{1,60})"?\s*<([^>]+@[^>]+)>'
)
_CLEAR_PASSWORD_PROTOS = {
    "FTP/Telnet USER/PASS",
    "FTP PASS",
    "HTTP Basic",
    "HTTP Proxy-Basic",
    "HTTP form",
    "LDAP simple bind",
    "PAP",
    "TACACS+",
    "AUTH PLAIN",
    "AUTH LOGIN",
    "POP PASS",
}
_TOKEN_PROTOS = {
    "HTTP Cookie",
    "HTTP Set-Cookie",
    "HTTP Authorization",
    "HTTP2 Cookie",
    "HTTP Bearer",
    "AWS Access Key",
    "API key",
}
_HASH_EVIDENCE: dict[int, tuple[str, int, str, str]] = {
    5500: ("CRITIQUE", 22, "NetNTLMv1 (très cassable)", "Désactiver NTLMv1 / LM, forcer Kerberos."),
    5600: ("ÉLEVÉ", 16, "NetNTLMv2 capturé", "Désactiver NTLM, imposer Kerberos + EPA."),
    18200: ("ÉLEVÉ", 18, "AS-REP roasting RC4", "Activer la pré-authentification Kerberos."),
    32100: ("ÉLEVÉ", 16, "AS-REP roasting AES128", "Activer la pré-authentification Kerberos."),
    32200: ("ÉLEVÉ", 16, "AS-REP roasting AES256", "Activer la pré-authentification Kerberos."),
    13100: ("ÉLEVÉ", 14, "Kerberoast RC4 (TGS)", "Comptes service : AES only, mots de passe longs."),
    19600: ("ÉLEVÉ", 12, "Kerberoast AES128", "Rotation des mots de passe de comptes service."),
    19700: ("ÉLEVÉ", 12, "Kerberoast AES256", "Rotation des mots de passe de comptes service."),
    7500: ("ÉLEVÉ", 12, "Kerberos PA-ENC-TIMESTAMP RC4", "Passer les etypes en AES."),
    19800: ("MOYEN", 8, "Kerberos PA AES128", "Surveiller les AS-REQ ; AES reste craquable si le mot de passe est faible."),
    19900: ("MOYEN", 8, "Kerberos PA AES256", "Surveiller les AS-REQ ; AES reste craquable si le mot de passe est faible."),
    22000: ("MOYEN", 10, "Handshake / PMKID Wi-Fi", "PSK long et unique ; viser WPA3."),
    16500: ("MOYEN", 8, "JWT capturé", "Révoquer les jetons, passer en RS256, durée de vie courte."),
    11400: ("ÉLEVÉ", 12, "SIP Digest", "SIP-TLS + mots de passe forts."),
    20: ("ÉLEVÉ", 12, "APOP / MD5(salt+pass)", "Abandonner APOP, passer en IMAPS."),
    4800: ("MOYEN", 8, "CHAP", "Préférer EAP-TLS."),
}
_OUI_VENDORS: dict[str, str] = {
    "000c29": "VMware", "005056": "VMware", "000569": "VMware", "001c14": "VMware",
    "080027": "VirtualBox", "0a0027": "VirtualBox", "00163e": "Xen",
    "525400": "QEMU / KVM", "00155d": "Microsoft Hyper-V", "000d3a": "Microsoft",
    "0050f2": "Microsoft", "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "001e13": "Cisco", "00000c": "Cisco",
    "001bd4": "Cisco", "00d0ba": "Cisco", "001e42": "Teltonika",
    "14cc20": "TP-Link", "50c7bf": "TP-Link", "a42bb0": "TP-Link", "f4ec38": "TP-Link",
    "001e58": "D-Link", "00179a": "D-Link", "00e04c": "Realtek",
    "001a79": "Dell", "001ec9": "Dell", "0024e8": "Dell", "14feb5": "Dell",
    "18a99b": "Dell", "f8b156": "Dell", "0019b9": "Dell", "000f1f": "Dell",
    "001cc4": "HP", "002481": "HP", "3cd92b": "HP",
    "001a4b": "Huawei", "001e10": "Huawei", "00e0fc": "Huawei", "04c06f": "Huawei",
    "20f17c": "Huawei", "285fdb": "Huawei", "001632": "Samsung", "00166c": "Samsung",
    "5c0a5b": "Samsung", "001b21": "Intel", "001e67": "Intel", "448500": "Intel",
    "001b63": "Apple", "001ec2": "Apple", "002608": "Apple", "181456": "Apple",
    "28e02c": "Apple", "3c0754": "Apple", "609ac1": "Apple", "a4b197": "Apple",
    "acbc32": "Apple", "f0d1a9": "Apple", "3c5ab4": "Google", "001a11": "Google",
}

def _norm_phone(raw: str) -> Optional[str]:
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("0033"):
        digits = "33" + digits[4:]
    if digits.startswith("0") and len(digits) == 10:
        digits = "33" + digits[1:]
    if not (10 <= len(digits) <= 12):
        return None
    if len(set(digits)) <= 2:
        return None
    return "+" + digits

def _mac_vendor(mac: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    if len(h) < 6:
        return ""
    return _OUI_VENDORS.get(h[:6], "")

def _ip_kind(ip: str) -> str:
    s = (ip or "").strip()
    if ":" in s:
        low = s.lower()
        if low == "::1":
            return "loopback"
        if low.startswith("fe80"):
            return "IPv6 link-local"
        if low.startswith("fc") or low.startswith("fd"):
            return "IPv6 unique-local"
        return "IPv6 publique"
    parts = s.split(".")
    if len(parts) != 4:
        return "autre"
    try:
        a, b, c, d = (int(x) for x in parts)
    except ValueError:
        return "autre"
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return "privé RFC1918"
    if a == 127:
        return "loopback"
    if a == 169 and b == 254:
        return "link-local"
    if a == 100 and 64 <= b <= 127:
        return "CGNAT"
    if a == 192 and b == 0 and c == 2:
        return "documentation"
    if a >= 224:
        return "multicast / réservé"
    return "IPv4 publique"

def _jwt_claims(tok: str) -> dict[str, Any]:
    parts = (tok or "").split(".")
    if len(parts) < 2:
        return {}
    pad = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(pad.encode("ascii", "ignore")))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}

def _looks_like_person_name(s: str) -> bool:
    s = (s or "").strip()
    if len(s) < 3 or len(s) > 60:
        return False
    if "@" in s or "/" in s or "\\" in s:
        return False
    parts = [p for p in re.split(r"[\s._-]+", s) if p]
    if not (2 <= len(parts) <= 4):
        return False
    return all(re.fullmatch(r"[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ'\-]{1,20}", p) for p in parts)

def build_osint_report(result: "ExtractResult", net: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Infos perso / org / machines exposées — pivot OSINT, pas du bruit de protocole."""
    net = net or build_network_report(result)
    emails: list[dict[str, str]] = []
    phones: list[dict[str, str]] = []
    people: list[dict[str, str]] = []
    orgs: list[str] = []
    machines: list[dict[str, str]] = []
    sites: list[dict[str, str]] = []
    devices: list[dict[str, str]] = []
    subjects: list[str] = []
    public_ips: list[str] = []
    lan_ips: list[dict[str, str]] = []

    seen_mail: set[str] = set()
    seen_phone: set[str] = set()
    seen_person: set[str] = set()
    seen_org: set[str] = set()
    seen_machine: set[str] = set()
    seen_site: set[str] = set()

    def _add_email(addr: str, source: str, name: str = "") -> None:
        addr = (addr or "").strip().strip("<>").lower()
        if not addr or "@" not in addr or _is_fake_email(addr) or addr in seen_mail:
            return
        if addr.split("@", 1)[0].endswith("$"):
            return
        if addr.endswith((".local", ".invalid", ".test")):
            return
        seen_mail.add(addr)
        emails.append({"email": addr, "nom": name, "source": source})
        dom = addr.rsplit("@", 1)[-1]
        if dom and dom not in seen_org and "." in dom:
            seen_org.add(dom)
            orgs.append(dom)
        if name and name.lower() not in seen_person:
            seen_person.add(name.lower())
            people.append({"nom": name, "compte": addr, "org": dom, "source": source})

    def _add_phone(raw: str, source: str) -> None:
        norm = _norm_phone(raw)
        if not norm or norm in seen_phone:
            return
        seen_phone.add(norm)
        phones.append({"tel": norm, "brut": raw.strip(), "source": source})

    def _add_person(nom: str, compte: str, org: str, source: str) -> None:
        key = (nom or compte or "").strip().lower()
        if not key or key.startswith("(") or key in seen_person:
            return
        if key in {"admin", "guest", "anonymous", "user", "test", "root"}:
            return
        seen_person.add(key)
        people.append({"nom": nom, "compte": compte, "org": org, "source": source})

    def _add_machine(name: str, source: str) -> None:
        name = (name or "").strip()
        if not name or name.lower() in seen_machine:
            return
        if name in {".", "*", "localhost"}:
            return
        seen_machine.add(name.lower())
        machines.append({"nom": name, "source": source})

    def _add_site(name: str, kind: str) -> None:
        name = decode_maybe_hex((name or "").strip()).rstrip(".")
        if not name or name.lower() in seen_site or name in {".", "*"}:
            return
        if _is_fuzz_payload(name):
            return
        seen_site.add(name.lower())
        sites.append({"nom": name, "type": kind})

    for c in result.credentials:
        proto = c.protocol or ""
        user, secret = c.username or "", c.password or ""
        val = (secret or user).strip()
        src = proto or c.source or ""

        if proto in ("E-mail", "Mail From", "Mail To"):
            blob = " ".join(x for x in (user, secret) if x)
            m = _MAIL_NAME_RE.match(blob)
            if m:
                _add_email(m.group(2), proto, m.group(1).strip())
            else:
                for mm in _EMAIL_RE.finditer(blob):
                    _add_email(mm.group(0), proto)
        elif proto == "Téléphone":
            _add_phone(val or user, src)
        elif proto in ("HTTP User-Agent", "HTTP2 UA", "SIP UA"):
            if val and 8 <= len(val) <= 300:
                devices.append({"type": proto, "valeur": val[:220]})
        elif proto in ("DHCP hostname", "RDP client", "CDP/LLDP nom", "Browser / NetBIOS"):
            _add_machine(decode_maybe_hex(val or user), proto)
        elif proto == "Mail Subject" and val:
            subjects.append(val[:180])
        elif proto in _HOST_LABELS or proto in {"HTTP Referer", "HTTP Location"}:
            _add_site(val or user, proto)
        elif proto in {"DNS / nom", "DNS réponse", "DNS SRV/MX", "LLMNR", "LLMNR resp", "NetBIOS", "mDNS resp"}:
            _add_site(val or user, proto)

        for mm in _EMAIL_RE.finditer(f"{user} {secret}"):
            if proto not in ("E-mail", "Mail From", "Mail To"):
                _add_email(mm.group(0), proto)
        if proto not in {"JA3", "JA3S", "TLS version", "TLS cipher", "ALPN", "QUIC/TLS SNI"}:
            for mm in _PHONE_RE.finditer(f"{user} {secret}"):
                _add_phone(mm.group(0), proto)
        for mm in _USER_PATH_RE.finditer(f"{user} {secret}"):
            _add_person(mm.group(1), mm.group(1), "", f"chemin {proto}")

    for ident in net.get("identities") or []:
        val = (ident.get("valeur") or "").strip()
        typ = ident.get("type") or ""
        if not val or val.startswith("("):
            continue
        if "@" in val:
            left, _, right = val.partition("@")
            if _EMAIL_RE.fullmatch(val) or "." in right:
                _add_email(val, typ)
            else:
                if right and right not in seen_org:
                    seen_org.add(right)
                    orgs.append(right)
                _add_person(left, val, right, typ)
                if left.endswith("$"):
                    _add_machine(left.rstrip("$"), typ)
        elif val.endswith("$"):
            _add_machine(val.rstrip("$"), typ)
        elif _looks_like_person_name(val):
            _add_person(val, val, "", typ)

    for d in net.get("kerberos") or []:
        if d.realm and d.realm not in seen_org:
            seen_org.add(d.realm)
            orgs.append(d.realm)
        if d.user and str(d.user).endswith("$"):
            _add_machine(str(d.user).rstrip("$"), "Kerberos")
        elif d.user:
            upn = f"{d.user}@{d.realm}" if d.realm else str(d.user)
            _add_person(str(d.user), upn, d.realm or "", f"Kerberos {d.msg}")

    for h in (net.get("hashes") or {}).get(16500, []):
        claims = _jwt_claims(h.line)
        name = str(claims.get("name") or claims.get("given_name") or "")
        if claims.get("family_name") and name:
            name = f"{name} {claims.get('family_name')}".strip()
        mail = str(claims.get("email") or claims.get("upn") or "")
        user = str(claims.get("preferred_username") or claims.get("sub") or "")
        if mail:
            _add_email(mail, "JWT", name)
        if user:
            _add_person(name or user, user, str(claims.get("iss") or ""), "JWT")
        if claims.get("iss") and str(claims["iss"]) not in seen_org:
            seen_org.add(str(claims["iss"]))
            orgs.append(str(claims["iss"]))

    st = getattr(result, "packet_stats", None) or {}
    for ip in st.get("ips") or []:
        kind = _ip_kind(str(ip))
        if "publique" in kind:
            public_ips.append(str(ip))
        else:
            lan_ips.append({"ip": str(ip), "classe": kind})
    for mac in st.get("macs") or []:
        vendor = _mac_vendor(str(mac))
        devices.append({"type": f"MAC · {vendor}" if vendor else "MAC", "valeur": str(mac)})

    for w in net.get("wifi") or []:
        if str(w.get("type") or "").startswith("SSID") and w.get("valeur"):
            _add_site(str(w["valeur"]), "SSID")

    # sujets mail trop nombreux = bruit
    subjects = list(dict.fromkeys(subjects))[:20]

    return {
        "emails": emails[:80],
        "phones": phones[:40],
        "people": people[:80],
        "orgs": orgs[:40],
        "machines": machines[:60],
        "sites": sites[:80],
        "devices": devices[:60],
        "subjects": subjects,
        "public_ips": public_ips[:40],
        "lan_ips": lan_ips[:80],
        "n_emails": len(emails),
        "n_phones": len(phones),
        "n_people": len(people),
        "n_orgs": len(orgs),
        "n_machines": len(machines),
        "n_sites": len(sites),
        "n_public_ips": len(public_ips),
    }

def _is_cf_cookie(s: str) -> bool:
    low = (s or "").lower().lstrip()
    if not low:
        return False
    if low.startswith(("__cf", "cf_bm=", "cf_clearance", "__cfruid", "__cfduid", "__cfwaiting", "__cflb")):
        return True
    return "cloudflare" in low

def _is_machine_account(val: str) -> bool:
    s = (val or "").strip()
    if not s:
        return False
    left = s.split("@", 1)[0].rstrip("$")
    return (val or "").split("@", 1)[0].endswith("$") or s.endswith("$")

def _is_human_user(val: str) -> bool:
    s = (val or "").strip()
    if not s or _is_machine_account(s) or _is_realm_not_person(s):
        return False
    left = s.split("@", 1)[0]
    if not left or left.lower() in {"null", "none", "anonymous", "guest", "krbtgt"}:
        return False
    return True

def _is_fake_phone(norm: str) -> bool:
    d = re.sub(r"\D", "", norm or "")
    if d.startswith("33"):
        d = d[2:]
    if len(d) < 8:
        return True
    if re.fullmatch(r"1?234567\d{2}", d):
        return True
    if re.fullmatch(r"0{4,}\d*", d):
        return True
    if re.fullmatch(r"(\d)\1{6,}", d):
        return True
    return False

def _is_realm_not_person(val: str) -> bool:
    s = (val or "").strip()
    if not s:
        return False
    if s.upper() == s and ("." in s or s.endswith("LOCAL") or s.endswith("LAN") or s.endswith("TECH")):
        if " " not in s and not s.endswith("$"):
            # FIRSTTOLAST.TECH / CATCORP.LOCAL
            if "." in s or s.endswith(("LOCAL", "LAN", "TECH", "CORP", "NET")):
                return True
    if s.lower() in {"null", "none", "anonymous", "guest", "user", "admin", "test"}:
        return True
    return False

def _layer_field(layers: dict, *keys: str) -> Optional[str]:
    """Champ tshark : racine layers OU sous-dict frame/ip/eth/wlan."""
    for key in keys:
        v = _top_layer_str(layers, key)
        if v:
            return v
        head = key.split(".", 1)[0]
        sub = layers.get(head) if isinstance(layers, dict) else None
        if isinstance(sub, dict):
            v = _top_layer_str(sub, key)
            if v:
                return v
            raw = sub.get(key)
            if isinstance(raw, str) and raw:
                return raw
            if isinstance(raw, list):
                for x in raw:
                    if isinstance(x, str) and x:
                        return x
    return None

_MACHINE_SPN_HEADS = {
    "host", "cifs", "ldap", "gc", "dns", "restrictedkrbhost", "krbtgt",
    "netlogon", "rpcss", "protectedstorage", "termsrv", "http",
}
# HTTP can be kerberoast if it's a user SPN — we treat host/cifs/ldap/gc/dns/krbtgt/netlogon as "trafic AD"
_AD_SPN_HEADS = {
    "host", "cifs", "ldap", "gc", "dns", "restrictedkrbhost", "krbtgt",
    "netlogon", "rpcss", "protectedstorage", "termsrv",
}

def _spn_head(spn: str) -> str:
    s = (spn or "").strip()
    if "/" in s:
        return s.split("/", 1)[0].lower()
    return s.lower()

def _norm_spn(spn: str) -> str:
    return re.sub(r"\s+", "", (spn or "").strip()).lower()

_MITRE_CATALOG: dict[str, list[tuple[str, str, str]]] = {
    "sniff": [("T1040", "Network Sniffing", "Discovery / Credential Access")],
    "ntlm": [
        ("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access"),
        ("T1003", "OS Credential Dumping", "Credential Access"),
        ("T1110.002", "Password Cracking", "Credential Access"),
        ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Defense Evasion"),
    ],
    "asrep": [
        ("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "Credential Access"),
        ("T1110.002", "Password Cracking", "Credential Access"),
        ("T1078.002", "Valid Accounts: Domain Accounts", "Persistence"),
    ],
    "kerberoast": [
        ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ],
    "ad_access": [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ("T1080", "Taint Shared Content", "Lateral Movement"),
        ("T1615", "Group Policy Discovery", "Discovery"),
    ],
    "llmnr": [
        ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access"),
        ("T1557", "Adversary-in-the-Middle", "Credential Access"),
    ],
    "wpad": [
        ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        ("T1090", "Proxy", "Command and Control"),
    ],
    "ldap": [
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1069.002", "Permission Groups Discovery: Domain Groups", "Discovery"),
        ("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    ],
    "wpa": [
        ("T1110.002", "Password Cracking", "Credential Access"),
        ("T1016", "System Network Configuration Discovery", "Discovery"),
    ],
    "snmp": [
        ("T1046", "Network Service Discovery", "Discovery"),
        ("T1602.001", "Data from Configuration Repository: SNMP", "Collection"),
    ],
    "apop": [
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1078", "Valid Accounts", "Persistence"),
    ],
    "ftp": [
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control"),
    ],
    "telnet": [
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1021.004", "Remote Services: SSH (absence — Telnet à la place)", "Lateral Movement"),
    ],
    "cookie": [("T1539", "Steal Web Session Cookie", "Credential Access")],
    "pii": [
        ("T1589", "Gather Victim Identity Information", "Reconnaissance"),
        ("T1530", "Data from Cloud Storage", "Collection"),
    ],
    "clearpwd": [
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1078", "Valid Accounts", "Persistence"),
    ],
    "files": [
        ("T1039", "Data from Network Shared Drive", "Collection"),
        ("T1005", "Data from Local System", "Collection"),
    ],
}

def _mitre_rows(keys: Iterable[str]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for k in keys:
        for tid, name, tactic in _MITRE_CATALOG.get(k, []):
            if tid in seen:
                continue
            seen.add(tid)
            out.append({"id": tid, "technique": name, "tactique": tactic, "preuve": k})
    return out

def _join(items: Iterable[str], n: int = 8) -> str:
    vals = [str(x) for x in items if x]
    vals = list(dict.fromkeys(vals))
    if len(vals) <= n:
        return ", ".join(vals)
    return ", ".join(vals[:n]) + f" (+{len(vals) - n})"

def _interesting_file(name: str) -> bool:
    low = (name or "").lower()
    if not low:
        return False
    keys = (
        "contact", "customer", "client", "salaire", "payroll", "rh", "hr",
        "password", "passwd", "secret", "confident", "finance", "balance",
        "sales", "facture", "invoice", "bank", "iban", "contrat", "contrat",
        "budget", "compta", "employee", "personnel", "identité", "identite",
        "tracker", "quarterly", "report",
    )
    return any(k in low for k in keys)

def build_audit_report(result: "ExtractResult", net: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Rapport d'audit pentester : synthèse rédigée, findings, MITRE, chemins, écarts."""
    net = net or build_network_report(result)
    osint = build_osint_report(result, net)

    # --- nettoyage OSINT lab ---
    osint["phones"] = [
        p for p in (osint.get("phones") or [])
        if not _is_fake_phone(p.get("tel") or "")
        and "ja3" not in (p.get("source") or "").lower()
        and "tls" not in (p.get("source") or "").lower()
    ]
    osint["n_phones"] = len(osint["phones"])
    osint["people"] = [
        p
        for p in (osint.get("people") or [])
        if _is_human_user(p.get("nom") or "")
        and not _is_machine_account(p.get("compte") or "")
        and not _is_realm_not_person(p.get("nom") or "")
    ]
    osint["n_people"] = len(osint["people"])
    osint["emails"] = [
        e
        for e in (osint.get("emails") or [])
        if not _is_machine_account(e.get("email") or "")
        and "@" in (e.get("email") or "")
    ]
    osint["n_emails"] = len(osint["emails"])

    hashes = net.get("hashes") or {}
    secrets = [
        c
        for c in (net.get("secrets") or [])
        if not _is_cf_cookie(c.password or "") and not _is_cf_cookie(c.username or "")
    ]
    pwd = [c for c in secrets if (c.protocol or "") in _CLEAR_PASSWORD_PROTOS and (c.password or "").strip()]
    tokens = [
        c
        for c in secrets
        if (c.protocol or "") in _TOKEN_PROTOS and not _is_cf_cookie(c.password or "")
    ]
    real_snmp = list(net.get("snmp_real") or [])
    custom_snmp = [s for s in real_snmp if s.lower() not in {"public"}]
    public_snmp = [s for s in real_snmp if s.lower() == "public"]

    # --- comptes / SPN ---
    humans: list[str] = []
    machines: list[str] = []
    domains: list[str] = []
    asrep_humans: list[str] = []
    asrep_machines: list[str] = []
    roast_spns: list[str] = []  # vrais Kerberoast (SPN non-machine)
    ad_spns: list[str] = []  # cifs/ldap/host vus
    tgs_by_human: dict[str, list[str]] = {}

    for mode in (5500, 5600, 18200, 32100, 32200, 13100, 19600, 19700, 7500, 19800, 19900):
        for h in hashes.get(mode, []):
            user = (h.user or "").strip()
            dom = (h.domain or "").strip()
            if dom:
                domains.append(dom)
            who = f"{user}@{dom}" if user and dom else user
            if _is_machine_account(user):
                machines.append(user.rstrip("$"))
                if mode in (18200, 32100, 32200):
                    asrep_machines.append(who or user)
            elif _is_human_user(user):
                humans.append(who or user)
                if mode in (18200, 32100, 32200):
                    asrep_humans.append(who or user)
            spn = str((h.extra or {}).get("spn") or "")
            if spn:
                head = _spn_head(spn)
                if head in _AD_SPN_HEADS:
                    ad_spns.append(spn)
                else:
                    roast_spns.append(spn)
                if _is_human_user(user):
                    tgs_by_human.setdefault(who or user, []).append(spn)

    for ident in net.get("identities") or []:
        val = ident.get("valeur") or ""
        if "@" in val:
            left, _, right = val.partition("@")
            if right:
                domains.append(right)
            if _is_machine_account(left):
                machines.append(left.rstrip("$"))
            elif _is_human_user(left):
                humans.append(val)
        elif _is_machine_account(val):
            machines.append(val.rstrip("$"))
        elif _is_human_user(val) and "kerberos" in (ident.get("type") or "").lower():
            humans.append(val)

    for m in osint.get("machines") or []:
        if m.get("nom"):
            machines.append(str(m["nom"]))

    def _dedupe_users(items: list[str]) -> list[str]:
        by_left: dict[str, str] = {}
        for u in items:
            left = u.split("@", 1)[0].lower()
            if not left:
                continue
            prev = by_left.get(left)
            if prev is None or ("@" in u and "@" not in prev):
                by_left[left] = u
        return list(by_left.values())

    humans = _dedupe_users(list(dict.fromkeys(humans)))
    machines = list(dict.fromkeys(machines))
    domains = list(dict.fromkeys(d for d in domains if d and not d.endswith("$")))
    asrep_humans = list(dict.fromkeys(asrep_humans))
    asrep_machines = list(dict.fromkeys(asrep_machines))
    roast_spns = list(dict.fromkeys(roast_spns))
    ad_spns = list(dict.fromkeys(ad_spns))

    # domaine « métier » : le plus long / avec un point
    domaine = ""
    if domains:
        domaine = sorted(domains, key=lambda x: ("." not in x, -len(x), x.lower()))[0]

    # DC depuis SPN / hôtes / fichiers
    dc_names: list[str] = []
    for spn in ad_spns:
        part = spn.split("/", 1)[-1]
        host = part.split("/", 1)[0]
        host = host.split(":", 1)[0]
        if "dc" in host.lower() or host.lower().startswith("dc"):
            dc_names.append(host)
        elif _spn_head(spn) in {"ldap", "gc", "krbtgt"} and host:
            dc_names.append(host)
    for row in net.get("hosts") or []:
        nom = str(row.get("nom") or "")
        low = nom.lower()
        if "dc._msdcs." in low or low.startswith("_ldap._tcp"):
            continue
        if re.search(r"(^|[.-])dc(\d*)([.-]|$)", low) or "-dc." in low or low.endswith("-dc"):
            if "<" not in nom and " " not in nom:
                dc_names.append(nom)
    for row in net.get("files") or []:
        chemin = str(row.get("chemin") or "")
        m = re.search(r"\\\\([^\\]+)\\", chemin)
        if m:
            host = m.group(1)
            if "dc" in host.lower():
                dc_names.append(host)
    dc_names = list(dict.fromkeys(dc_names))
    dc = dc_names[0] if dc_names else ""

    files = list(net.get("files") or [])
    shares = [r.get("chemin") or "" for r in files if (r.get("type") or "") == "SMB share"]
    share_files = [r.get("chemin") or "" for r in files if "fichier" in (r.get("type") or "").lower()]
    interesting = [f for f in share_files if _interesting_file(f)]
    sysvol = [f for f in (shares + share_files) if "sysvol" in (f or "").lower() or "gpt" in (f or "").lower() or "policies\\{" in (f or "").lower()]

    protos = {p.lower() for p in (result.proto_seen or [])} | {
        p.lower() for p in (getattr(result, "proto_counts", None) or {})
    }
    proto_counts = dict(getattr(result, "proto_counts", None) or {})
    n_ldap = int(proto_counts.get("ldap") or 0)
    n_llmnr = int(proto_counts.get("llmnr") or 0)
    n_nbns = int(proto_counts.get("nbns") or proto_counts.get("nbdgm") or 0)

    hosts_flat = " ".join(str(r.get("nom") or "") for r in (net.get("hosts") or [])).lower()
    has_wpad = "wpad." in hosts_flat or "wpad" in protos
    has_llmnr = "llmnr" in protos or n_llmnr > 0
    has_nbns = "nbns" in protos or n_nbns > 0

    # LAN IPs utiles
    lan = []
    for row in osint.get("lan_ips") or []:
        lan.append(row.get("ip") or "")
    for row in net.get("hosts") or []:
        nom = str(row.get("nom") or "")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", nom):
            lan.append(nom)
    lan = list(dict.fromkeys(x for x in lan if x))[:12]

    expos: list[dict[str, Any]] = []
    mitre_keys: list[str] = ["sniff"]
    recos: list[str] = []
    n_find = [0]

    def expo(
        sev: str,
        titre: str,
        detail: str,
        impact: str,
        preuve: str,
        reco: str,
        mitre: str,
        poids: int,
        famille: str,
        actifs: str = "",
    ) -> None:
        n_find[0] += 1
        fid = f"T2H-{n_find[0]:02d}"
        expos.append(
            {
                "id": fid,
                "sev": sev,
                "titre": titre,
                "detail": detail,
                "impact": impact,
                "preuve": preuve,
                "reco": reco,
                "mitre": mitre,
                "poids": poids,
                "famille": famille,
                "actifs": actifs,
            }
        )
        if reco:
            recos.append(reco)
        if mitre:
            mitre_keys.append(mitre)

    if pwd:
        sample = ", ".join(f"{c.protocol} {c.username}".strip() for c in pwd[:6])
        expo(
            "CRITIQUE",
            f"{len(pwd)} mot(s) de passe transitent en clair",
            (
                "La capture contient des authentifications où le secret n'est pas chiffré "
                f"({sample}). N'importe quel hôte sur le même segment (Wi-Fi ouvert, SPAN, "
                "TAP, malware déjà présent) lit le mot de passe et le réutilise. Ce n'est pas "
                "un hash à casser : le compte est utilisable tout de suite."
            ),
            "Compte utilisable immédiatement, sans cassage ni relais.",
            sample,
            "Révoquer ces comptes, forcer un changement, imposer TLS (LDAPS, HTTPS, IMAPS, SFTP) et couper le proto clair.",
            "clearpwd",
            36,
            "Identifiants",
            sample,
        )

    if asrep_humans:
        who = _join(asrep_humans, 6)
        n = len(asrep_humans)
        expo(
            "CRITIQUE" if n >= 2 else "ÉLEVÉ",
            f"AS-REP roasting : {n} compte(s) sans pré-authentification Kerberos",
            (
                f"Les comptes {who} ont reçu un AS-REP AES256/RC4 alors qu'aucune pré-authentification "
                "n'était exigée. Concrètement : n'importe quel principal du domaine (même un compte "
                "machine fraîchement joint, même un attaquant qui connaît seulement le nom du compte) "
                "demande un ticket AS-REP et le casse hors-ligne avec hashcat -m 18200/32100/32200. "
                "La victime ne voit rien, le DC journalise une demande Kerberos banale. "
                "C'est l'une des plus rapides prises de compte AD depuis le réseau."
            ),
            "Mot de passe du compte AD obtenu sans jamais toucher le poste de la victime.",
            who,
            (
                f"Activer « Do not require Kerberos preauthentication » = décoché sur {who}. "
                " auditer msDS-UserDontRequirePreAuth dans tout le domaine. MFA sur ces comptes."
            ),
            "asrep",
            24 if n >= 2 else 20,
            "Active Directory",
            who,
        )

    if roast_spns:
        expo(
            "ÉLEVÉ",
            f"Kerberoast : {len(roast_spns)} SPN de compte service",
            (
                "Des tickets TGS ont été émis pour des SPN qui ne sont pas des services machine "
                f"standard : {_join(roast_spns, 6)}. Un utilisateur du domaine peut demander ces "
                "tickets et casser hors-ligne le mot de passe du compte service (hashcat -m 13100/"
                "19600/19700). Un mot de passe service faible = prise du service, souvent privilèges "
                "élevés (SQL, HTTP intranet, backup)."
            ),
            "Compte service cassable hors-ligne, puis accès à l'application / base / partage.",
            _join(roast_spns, 8),
            "Mots de passe service ≥ 25 caractères aléatoires, AES only, rotation, gMSA si possible.",
            "kerberoast",
            16,
            "Active Directory",
            _join(roast_spns, 6),
        )

    # Accès DC / SYSVOL / shares — PAS du Kerberoast
    if ad_spns and (humans or sysvol or interesting):
        cifs = [s for s in ad_spns if _spn_head(s) == "cifs"]
        who = _join(humans, 4) or "un compte du domaine"
        bits = []
        if cifs:
            bits.append(f"tickets CIFS vers {_join(cifs, 3)}")
        if sysvol:
            bits.append(f"lecture SYSVOL / GPO ({_join(sysvol, 3)})")
        if interesting:
            bits.append(f"fichiers métier ouverts : {_join(interesting, 4)}")
        elif share_files:
            bits.append(f"fichiers vus sur partage : {_join(share_files, 4)}")
        expl = " ; ".join(bits) or "tickets de service AD"
        expo(
            "ÉLEVÉ" if (sysvol or interesting) else "MOYEN",
            "Accès aux ressources du domaine (DC / SYSVOL / partages)",
            (
                f"Ce ne sont pas des tickets Kerberoast : {who} s'est authentifié auprès des "
                f"services machine du domaine ({_join(ad_spns, 5)}). {expl}. "
                "Un attaquant qui casse l'un des comptes roastables ci-dessus emprunte exactement "
                "ce chemin : TGS CIFS → SYSVOL (GPO, scripts de logon, parfois mots de passe) → "
                "partages métier. Les classeurs vus (contacts, finance, ventes) sont de la donnée "
                "à exfiltrer, pas du bruit de protocole."
            ),
            "Mouvement latéral vers le DC et exfiltration de fichiers métier / GPO.",
            expl,
            "Restreindre SYSVOL aux admins, auditer les ACL des partages, DLP sur les xlsx nominatifs, tiering admin.",
            "ad_access",
            12 if (sysvol or interesting) else 6,
            "Active Directory",
            _join([dc] + humans + interesting[:3], 8),
        )

    if 5500 in hashes:
        users = " · ".join(hash_context(h) for h in hashes[5500][:4])
        expo(
            "CRITIQUE",
            "NetNTLMv1 capturé",
            (
                "NTLMv1 se casse en minutes (tables arc-en-ciel / hashcat -m 5500) et se relaie. "
                f"Comptes vus : {users}. Sur un LAN où LLMNR/NBNS répondent encore, un attaquant "
                "force l'auth et récupère le hash."
            ),
            "Compte domaine compromis en minutes, relais NTLM possible.",
            users,
            "Interdire NTLMv1/LM (LmCompatibilityLevel=5), forcer Kerberos, EPA + SMB signing.",
            "ntlm",
            28,
            "Active Directory",
            users,
        )
    if 5600 in hashes:
        users = " · ".join(hash_context(h) for h in hashes[5600][:4])
        expo(
            "ÉLEVÉ",
            "NetNTLMv2 capturé",
            (
                f"Challenge/response NTLMv2 observé ({users}). Le hash se casse hors-ligne "
                "(hashcat -m 5600) si le mot de passe est faible, et se relaie vers SMB/LDAP "
                "tant que le signing n'est pas obligatoire."
            ),
            "Compte domaine relaisable ou cassable hors-ligne.",
            users,
            "Désactiver NTLM là où Kerberos suffit, SMB signing obligatoire, LDAP signing + channel binding, EPA.",
            "ntlm",
            18,
            "Active Directory",
            users,
        )

    if has_llmnr or has_nbns:
        proto_lbl = []
        if has_llmnr:
            proto_lbl.append(f"LLMNR ({n_llmnr or 'oui'})")
        if has_nbns:
            proto_lbl.append(f"NBNS/NetBIOS ({n_nbns or 'oui'})")
        expo(
            "ÉLEVÉ",
            "LLMNR / NetBIOS-NS encore actifs — relais NTLM",
            (
                "Le poste interroge le LAN pour résoudre des noms (" + ", ".join(proto_lbl) + "). "
                "Un attaquant répond à sa place (Responder, Inveigh) : le poste lui envoie une "
                "authentification NTLM. Combiné à un signing SMB/LDAP absent, c'est un relais "
                "vers le DC. Même sans relais, le hash NetNTLMv2 se casse hors-ligne."
            ),
            "Vol d'authentification Windows depuis le même segment, sans malware sur le poste.",
            ", ".join(proto_lbl),
            "Désactiver LLMNR (GPO) et NetBIOS-NS sur les cartes ; activer SMB signing et LDAP signing.",
            "llmnr",
            12,
            "Active Directory",
            ", ".join(proto_lbl),
        )

    if has_wpad:
        expo(
            "MOYEN",
            "WPAD exposé (wpad.<domaine>)",
            (
                "La capture contient une résolution wpad — le poste cherche un fichier de "
                "configuration proxy. Un attaquant qui répond (LLMNR/DNS pirate) devient le "
                "proxy de la victime : interception HTTP, injection, vol de cookies intranet."
            ),
            "Homme du milieu sur le trafic web interne.",
            "wpad." + (domaine.lower() if domaine else "<domaine>"),
            "Publier WPAD uniquement en DNS interne contrôlé, ou le désactiver (WinHTTP AutoProxy).",
            "wpad",
            7,
            "Infra",
            "wpad." + (domaine.lower() if domaine else ""),
        )

    if n_ldap >= 20 or "ldap" in protos:
        expo(
            "MOYEN",
            f"LDAP en clair ({n_ldap or 'présent'})",
            (
                f"{n_ldap or 'Des'} trames LDAP non chiffrées. Bind, recherches, attributs "
                "(souvent mail, displayName, memberOf) passent en clair. Un écouteur cartographie "
                "le domaine et, si un simple bind apparaît, récupère un mot de passe."
            ),
            "Reconnaissance AD gratuite, parfois identifiant en clair.",
            f"ldap × {n_ldap}" if n_ldap else "protocole ldap",
            "Imposer LDAPS / StartTLS, refuser les binds simples hors TLS, LDAP signing + channel binding.",
            "ldap",
            8,
            "Active Directory",
            dc or domaine or "LDAP",
        )

    if custom_snmp:
        expo(
            "CRITIQUE",
            "Community SNMP secrète en clair",
            (
                "La community SNMP vaut un mot de passe d'administration des équipements. "
                f"Valeur extraite : {_join(custom_snmp, 6)}. Walk = inventaire, souvent écriture."
            ),
            "Lecture / écriture du parc réseau.",
            _join(custom_snmp, 8),
            "SNMPv3 authPriv uniquement ; rotation immédiate de la community.",
            "snmp",
            24,
            "Infra",
            _join(custom_snmp, 6),
        )
    elif public_snmp:
        expo(
            "MOYEN",
            "SNMP « public » en clair",
            (
                "La community par défaut « public » circule en clair. Un walk SNMP donne "
                "modèles, interfaces, VLAN, logiciels — la carte du parc avant toute attaque."
            ),
            "Reconnaissance réseau sans authentification forte.",
            "community public",
            "Couper SNMPv1/v2c ou changer « public », filtrer UDP/161, passer en SNMPv3.",
            "snmp",
            8,
            "Infra",
            "public",
        )

    if 20 in hashes:
        users = " · ".join(hash_context(h) or (h.user or "") for h in hashes[20][:4])
        expo(
            "ÉLEVÉ",
            "Messagerie APOP (MD5 salé)",
            (
                f"Digest APOP capturé ({users or 'APOP'}). hashcat -m 20 casse le mot de passe "
                "de la boîte. Une boîte mail = reset de tous les autres comptes (Microsoft, VPN, RH)."
            ),
            "Compte mail compromis, pivot vers le reste du SI.",
            users or "APOP",
            "Abandonner APOP ; IMAPS/POP3S + AUTH PLAIN sous TLS.",
            "apop",
            12,
            "Messagerie",
            users or "APOP",
        )
    if 22000 in hashes:
        ssids = " · ".join(hash_context(h) for h in hashes[22000][:4])
        expo(
            "MOYEN",
            "Handshake / PMKID Wi-Fi",
            (
                f"Un PMKID ou handshake 4-way a été extrait ({ssids}). Si la passphrase est "
                "un mot du dictionnaire, hashcat -m 22000 ouvre le LAN — et toutes les attaques AD ci-dessus."
            ),
            "Accès couche 2, puis tout le reste du rapport.",
            ssids,
            "WPA3-SAE ou 802.1X entreprise ; PSK unique, long, non partagé.",
            "wpa",
            10,
            "Wi-Fi",
            ssids,
        )

    if tokens:
        expo(
            "MOYEN",
            f"{len(tokens)} cookie(s) / jeton(s) applicatif(s) (hors Cloudflare)",
            (
                "Des cookies de session applicatifs circulent en clair. Tant qu'ils ne sont pas "
                "invalidés, ils valent une session utilisateur. Les cookies Cloudflare (__cf_bm, "
                "__cfduid) ont été écartés : ce n'est pas un secret métier."
            ),
            "Session web réutilisable.",
            ", ".join(sorted({c.protocol for c in tokens})),
            "Invalider les sessions, Secure+HttpOnly+SameSite, durée courte, HTTPS partout.",
            "cookie",
            6,
            "Web",
            ", ".join(sorted({c.protocol for c in tokens})),
        )

    pii_mails = [e["email"] for e in osint.get("emails") or [] if not _is_machine_account(e.get("email") or "")]
    pii_phones = [p["tel"] for p in osint.get("phones") or []]
    if (pii_mails or pii_phones or interesting) and (len(pii_mails) + len(pii_phones) + len(interesting)) >= 1:
        bits = []
        if pii_mails:
            bits.append("e-mails " + _join(pii_mails, 5))
        if pii_phones:
            bits.append("tél. " + _join(pii_phones, 4))
        if interesting:
            bits.append("fichiers " + _join(interesting, 4))
        expo(
            "MOYEN",
            "Données personnelles / métier exposées",
            (
                "La capture livre des identités exploitables en phishing ou en usurpation : "
                + " ; ".join(bits)
                + ". Un classeur « Customer Contact List » ou « Balance Sheet » sur un partage "
                "ouvert est une fuite RGPD / financière, pas un simple nom DNS."
            ),
            "Phishing ciblé, stuffing, violation de données.",
            " · ".join(bits),
            "Minimiser la collecte, ACL des partages, informer les personnes si la capture sort du SI.",
            "pii",
            5,
            "OSINT / RGPD",
            " · ".join(bits),
        )

    if "telnet" in protos and not any("telnet" in (c.protocol or "").lower() for c in pwd):
        expo(
            "ÉLEVÉ",
            "Telnet encore présent",
            "Telnet envoie tout en clair, y compris les prochains mots de passe. SSH le remplace depuis 25 ans.",
            "Écoute passive de tout ce qui passe sur la session.",
            "protocole telnet vu",
            "Remplacer par SSH, couper TCP/23.",
            "telnet",
            12,
            "Remote",
            "telnet",
        )
    if "ftp" in protos and not any("ftp" in (c.protocol or "").lower() for c in pwd):
        expo(
            "MOYEN",
            "FTP en clair",
            "Fichiers et identifiants FTP transitent sans protection. Un écouteur récupère les deux.",
            "Vol de fichiers et d'identifiants.",
            "protocole ftp vu",
            "SFTP ou FTPS, couper TCP/21.",
            "ftp",
            6,
            "Fichiers",
            "ftp",
        )

    # --- score : chemins, pas somme brute ---
    familles: dict[str, int] = {}
    for e in expos:
        fam = e["famille"]
        familles[fam] = max(familles.get(fam, 0), int(e["poids"]))
    ordered = sorted(familles.values(), reverse=True)
    malus = 0.0
    for i, w in enumerate(ordered):
        malus += w * (1.0 if i == 0 else 0.55 if i == 1 else 0.35 if i == 2 else 0.20)
    score = int(max(8, min(100, round(100 - malus))))
    n_c = sum(1 for e in expos if e["sev"] == "CRITIQUE")
    n_e = sum(1 for e in expos if e["sev"] == "ÉLEVÉ")
    has_ad = any(e["famille"] == "Active Directory" for e in expos)
    if n_c >= 1 or (has_ad and n_e >= 2) or score < 35:
        niveau = "CRITIQUE"
    elif n_e >= 1 or score < 60:
        niveau = "ÉLEVÉ"
    elif expos:
        niveau = "MOYEN"
    else:
        niveau = "FAIBLE"
        score = max(score, 88)

    # --- chemins d'attaque (récit) ---
    chemins: list[dict[str, str]] = []
    ad_users = [u for u in humans if _is_human_user(u)]
    if 5600 in hashes or 5500 in hashes:
        chemins.append(
            {
                "etape": "1",
                "nom": "Vol d'authentification Windows",
                "scenario": (
                    f"Sur le même segment, l'attaquant capture un challenge/response NTLM "
                    f"({_join(ad_users[:3], 3) or 'compte domaine'}). "
                    "Il casse le hash (hashcat -m 5600/5500) ou le relaie vers SMB/LDAP si le signing est off."
                ),
                "resultat": "Compte domaine compromis",
                "mitre": "T1557.001 · T1110.002",
            }
        )
    if asrep_humans:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "AS-REP roasting",
                "scenario": (
                    f"Sans aucun privilège, l'attaquant demande un AS-REP pour "
                    f"{_join(asrep_humans, 4)}. Pré-auth absente → ticket cassable hors-ligne "
                    "(hashcat -m 18200/32200). Rien n'apparaît sur le poste de la victime."
                ),
                "resultat": "Mot de passe AD obtenu à distance, en silence",
                "mitre": "T1558.004",
            }
        )
    if roast_spns:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "Kerberoast compte service",
                "scenario": (
                    f"Avec n'importe quel compte domaine, demande d'un TGS pour "
                    f"{_join(roast_spns, 4)} puis cassage hors-ligne du secret du compte service."
                ),
                "resultat": "Service (SQL / HTTP / backup…) compromis",
                "mitre": "T1558.003",
            }
        )
    if ad_spns and (sysvol or interesting or any(_spn_head(s) == "cifs" for s in ad_spns)):
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "TGS CIFS → SYSVOL / partages DC",
                "scenario": (
                    f"Le compte cassé demande un TGS CIFS pour {dc or 'le DC'}. "
                    f"{'Lecture SYSVOL (GPO, scripts). ' if sysvol else ''}"
                    f"{'Ouverture des classeurs : ' + _join(interesting, 4) + '. ' if interesting else ''}"
                    "C'est le mouvement latéral classique, pas un Kerberoast."
                ),
                "resultat": "Fichiers métier et GPO du contrôleur",
                "mitre": "T1021.002 · T1615 · T1039",
            }
        )
    if has_llmnr or has_nbns:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "Poisoning LLMNR/NBNS",
                "scenario": (
                    "Responder sur le LAN répond aux broadcasts de noms. Le poste authentifie "
                    "l'attaquant en NTLM → relais vers SMB/LDAP ou cassage hors-ligne."
                ),
                "resultat": "Hash NetNTLM frais, parfois un relais jusqu'au DC",
                "mitre": "T1557.001",
            }
        )
    if public_snmp or custom_snmp:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "Reconnaissance SNMP",
                "scenario": (
                    f"Walk SNMP (community {_join(real_snmp) or 'public'}) : modèles, VLAN, ARP, logiciels. "
                    "Sert à choisir la prochaine cible."
                ),
                "resultat": "Cartographie du parc sans authentification forte",
                "mitre": "T1046 · T1602.001",
            }
        )
    if 22000 in hashes:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "Cassage Wi-Fi",
                "scenario": "PMKID ou handshake 4-way → hashcat -m 22000. Une passphrase faible ouvre le LAN.",
                "resultat": "Accès couche 2, puis toutes les attaques ci-dessus",
                "mitre": "T1110.002",
            }
        )
    if 20 in hashes:
        chemins.append(
            {
                "etape": str(len(chemins) + 1),
                "nom": "Boîte mail APOP",
                "scenario": "Digest APOP capturé → hashcat -m 20 → lecture de la messagerie (reset de mots de passe).",
                "resultat": "Compte mail compromis",
                "mitre": "T1040 · T1078",
            }
        )

    # --- écarts ---
    ecarts: list[dict[str, str]] = []

    def gap(controle: str, attendu: str, observe: str, statut: str) -> None:
        ecarts.append({"contrôle": controle, "attendu": attendu, "observé": observe, "écart": statut})

    if asrep_humans:
        gap("Pré-authentification Kerberos", "Activée sur TOUS les comptes utilisateurs", f"AS-REP roast : {_join(asrep_humans, 4)}", "MANQUANT")
    else:
        gap("Pré-authentification Kerberos", "Activée", "Pas d'AS-REP roast utilisateur", "OK / non observé")
    if 5500 in hashes or 5600 in hashes:
        gap("NTLM", "Désactivé, Kerberos only, EPA + SMB signing", "NetNTLM capturé", "MANQUANT")
    else:
        gap("NTLM", "Désactivé", "Pas de hash NTLM dans le périmètre", "OK / non observé")
    if roast_spns:
        gap("Comptes service", "gMSA / mdp ≥ 25 car. aléatoires, AES", f"SPN Kerberoastable : {_join(roast_spns, 3)}", "MANQUANT")
    elif ad_spns:
        gap("Comptes service", "Pas de SPN utilisateur faible", "TGS vus = services machine (CIFS/LDAP/HOST) — pas un Kerberoast", "OK / non observé")
    if has_llmnr or has_nbns:
        gap("LLMNR / NetBIOS-NS", "Désactivés par GPO", f"LLMNR={n_llmnr}  NBNS={n_nbns}", "MANQUANT")
    else:
        gap("LLMNR / NetBIOS-NS", "Désactivés", "Non observés", "OK / non observé")
    if n_ldap >= 20 or "ldap" in protos:
        gap("LDAP", "LDAPS / StartTLS uniquement", f"{n_ldap} trames LDAP claires", "MANQUANT")
    if has_wpad:
        gap("WPAD", "Désactivé ou DNS interne contrôlé", "requête wpad.<domaine>", "PARTIEL")
    if public_snmp or custom_snmp:
        gap("SNMP", "v3 authPriv, pas de community claire", f"v1/v2c {_join(real_snmp) or 'oui'}", "MANQUANT")
    if 22000 in hashes:
        gap("Wi-Fi", "WPA3-SAE ou 802.1X entreprise", "PMKID / handshake PSK", "PARTIEL")
    if 20 in hashes or "ftp" in protos or "telnet" in protos:
        gap("Protocoles en clair", "Aucun (TLS partout)", "APOP / FTP / Telnet observé", "MANQUANT")
    if tokens:
        gap("Sessions web", "Secure + HttpOnly + rotation", f"{len(tokens)} cookie(s) applicatif(s) en clair", "PARTIEL")
    if sysvol:
        gap("SYSVOL / GPO", "Lecture limitée, pas de secret dans les GPO", _join(sysvol, 3), "PARTIEL")

    n_ok = sum(1 for g in ecarts if g["écart"].startswith("OK"))
    n_ko = sum(1 for g in ecarts if g["écart"] == "MANQUANT")
    n_part = sum(1 for g in ecarts if g["écart"] == "PARTIEL")

    # --- cartographie ---
    carto: list[dict[str, str]] = []
    if domaine:
        carto.append({"type": "domaine", "nom": domaine, "rôle": "Active Directory", "détail": f"{len(ad_users)} compte(s) humain(s), {len(machines)} machine(s)"})
    if dc:
        carto.append({"type": "contrôleur", "nom": dc, "rôle": "DC (LDAP / CIFS / NETLOGON)", "détail": _join(dc_names, 4)})
    for u in ad_users[:12]:
        flags = []
        if any(u.split("@")[0].lower() in a.lower() for a in asrep_humans):
            flags.append("AS-REP roastable")
        if u in tgs_by_human:
            flags.append("TGS " + _join(tgs_by_human[u], 3))
        carto.append({"type": "utilisateur", "nom": u, "rôle": "compte AD", "détail": ", ".join(flags) or "vu dans Kerberos"})
    for m in machines[:12]:
        carto.append({"type": "poste / serveur", "nom": m, "rôle": "compte machine", "détail": "Kerberos / DHCP / NetBIOS"})
    for s in shares[:10]:
        carto.append({"type": "partage", "nom": s, "rôle": "SMB", "détail": "ouvert dans la capture"})
    for f in (interesting or share_files)[:10]:
        carto.append({"type": "fichier", "nom": f, "rôle": "données", "détail": "sensible" if _interesting_file(f) else "vu sur partage"})
    for ip in lan[:8]:
        carto.append({"type": "IP interne", "nom": ip, "rôle": "adressage", "détail": _ip_kind(ip) if "_ip_kind" in dir() else ""})

    # --- synthèse rédigée (vrai paragraphe de pentester) ---
    bits: list[str] = []
    if domaine or dc or ad_users:
        bits.append(
            (
                f"Le périmètre observé est le domaine Active Directory {domaine or '(realm non nommé)'}"
                + (f", contrôlé par {dc}" if dc else "")
                + (f" ({_join(lan, 4)})" if lan else "")
                + ". "
                + (
                    f"Comptes utilisateurs vus : {_join(ad_users, 6)}. "
                    if ad_users
                    else ""
                )
                + (f"Postes / serveurs : {_join(machines, 6)}. " if machines else "")
            ).strip()
        )
    if asrep_humans:
        bits.append(
            f"{_join(asrep_humans, 4)} n'exigent pas la pré-authentification Kerberos : "
            "un attaquant sans privilège demande un AS-REP et casse le mot de passe hors-ligne. "
            "C'est le finding le plus actionnable de la capture."
        )
    if ad_spns and (sysvol or interesting):
        bits.append(
            "Ces mêmes identités (ou les comptes machine du domaine) ont ensuite obtenu des tickets "
            f"CIFS/LDAP vers {dc or 'le DC'}. "
            + ("Lecture de SYSVOL / GPO. " if sysvol else "")
            + (f"Fichiers métier ouverts : {_join(interesting, 4)}. " if interesting else "")
            + "Ce n'est pas un Kerberoast : c'est le chemin d'un compte déjà authentifié vers les données."
        )
    elif roast_spns:
        bits.append(
            f"Des SPN de compte service sont Kerberoastables ({_join(roast_spns, 4)})."
        )
    if has_llmnr or has_nbns or has_wpad:
        extra = []
        if has_llmnr or has_nbns:
            extra.append("LLMNR/NBNS (relais NTLM)")
        if has_wpad:
            extra.append("WPAD (proxy pirate)")
        bits.append(
            "Sur le LAN, " + " et ".join(extra) + " restent actifs : un attaquant présent sur le segment "
            "n'a même pas besoin d'un compte pour obtenir un hash Windows."
        )
    if public_snmp or custom_snmp:
        bits.append("SNMP en clair offre la cartographie du parc avant même de casser un mot de passe.")
    if 22000 in hashes:
        bits.append("Le Wi-Fi laisse un handshake/PMKID : une passphrase faible ouvre tout le reste.")
    if 20 in hashes:
        bits.append("La messagerie (APOP) livre un hash MD5 salé, donc une boîte mail.")
    if not bits:
        bits.append(
            "Aucune preuve d'exposition critique n'a été extraite. "
            "Le trafic observé ne suffit pas à conclure à une compromission."
        )

    if niveau == "CRITIQUE":
        verdict = (
            "Verdict : CRITIQUE. Un attaquant passif, ou simplement présent sur le LAN, "
            "dispose d'un chemin jusqu'à des comptes du domaine et, selon les tickets et partages, "
            "jusqu'à des fichiers d'administration ou métier."
        )
    elif niveau == "ÉLEVÉ":
        verdict = (
            "Verdict : ÉLEVÉ. Des secrets cassables ou des protocoles dangereux sont présents ; "
            "la compromission d'un compte est plausible."
        )
    elif niveau == "MOYEN":
        verdict = (
            "Verdict : MOYEN. Des écarts existent (recon, PII, clair ponctuel) "
            "sans chaîne d'attaque complète démontrée."
        )
    else:
        verdict = "Verdict : FAIBLE. Rien d'exploitable n'a été extrait dans ce périmètre."

    synthese = " ".join(bits)
    conclusion = synthese + " " + verdict

    perimetre = (
        f"Domaine {domaine or '—'}  ·  DC {dc or '—'}\n"
        f"Utilisateurs : {_join(ad_users, 8) or '—'}\n"
        f"Machines : {_join(machines, 8) or '—'}\n"
        f"Partages : {_join(shares, 6) or '—'}\n"
        f"Fichiers notables : {_join(interesting or share_files, 6) or '—'}"
    )

    methodo = (
        "Méthode : dissection tshark de chaque trame (tous protocoles, dump hex inclus). "
        "Les hashes sont émis uniquement s'ils respectent la grammaire Hashcat du mode. "
        "Le score ne pénalise pas la présence d'un protocole : uniquement des preuves extraites "
        "(ticket, hash, secret, fichier, nom résolu). "
        "Les tickets CIFS/LDAP/HOST d'un compte machine ne sont pas comptés comme Kerberoast. "
        "Les cookies Cloudflare et les faux téléphones (séquences, JA3) sont écartés."
    )

    mitre = _mitre_rows(mitre_keys)
    findings = [{"sev": e["sev"], "titre": e["titre"], "detail": e["preuve"]} for e in expos]

    return {
        "score": score,
        "niveau": niveau,
        "findings": findings,
        "recommandations": list(dict.fromkeys(recos)),
        "expositions": expos,
        "chemins": chemins,
        "ecarts": ecarts,
        "mitre": mitre,
        "cartographie": carto,
        "conclusion": conclusion,
        "synthese": synthese,
        "verdict": verdict,
        "perimetre": perimetre,
        "methodo": methodo,
        "domaine": domaine,
        "dc": dc,
        "n_ok": n_ok,
        "n_ko": n_ko,
        "n_part": n_part,
        "n_secrets": len(secrets),
        "n_secrets_raw": int(net.get("n_secrets_raw") or len(result.credentials)),
        "n_noise": int(net.get("n_noise") or 0),
        "n_hashes": int(net.get("n_hashes") or result.total()),
        "n_packets": result.packets,
        "protocols": sorted(result.proto_seen),
        "net": net,
        "osint": osint,
        "ad_users": ad_users,
        "machines": machines,
        "asrep_humans": asrep_humans,
        "interesting_files": interesting,
    }

def assess_protection(result: "ExtractResult", net: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Compat : délègue au rapport d'audit."""
    return build_audit_report(result, net)

def print_protection(report: dict[str, Any]) -> None:
    """Affiche le rapport de protection dans le terminal."""
    niveau = report["niveau"]
    score = report["score"]
    color = {
        "FAIBLE": COLOR_GREEN,
        "MOYEN": COLOR_YELLOW,
        "ÉLEVÉ": COLOR_ORANGE,
        "CRITIQUE": COLOR_RED,
    }.get(niveau, COLOR_YELLOW)
    section_title("PROTECTION RÉSEAU")
    if _have_rich():
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        console = Console(highlight=False)
        console.print(
            Panel(
                f"[bold {color}]Risque {niveau}[/]   score {score}/100\n"
                f"[dim]{report['n_packets']} paquets · "
                f"{report['n_hashes']} hash(es) unique(s) · "
                f"{report['n_secrets']} secret(s) utile(s)"
                + (f" · {report.get('n_noise', 0)} bruit filtré" if report.get("n_noise") else "")
                + "[/]",
                border_style=color,
                title="[bold]synthèse[/]",
            )
        )
        if report["findings"]:
            table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}", title="Constats")
            table.add_column("gravité", style="bold")
            table.add_column("constat")
            for f in report["findings"]:
                sev = f["sev"]
                sc = {"CRITIQUE": "bold red", "ÉLEVÉ": "bold yellow", "MOYEN": "yellow", "FAIBLE": "green"}.get(sev, "white")
                table.add_row(f"[{sc}]{sev}[/]", f["titre"])
            console.print(table)
        if report["recommandations"]:
            console.print(f"[bold {COLOR_CYAN}]Recommandations[/]")
            for i, r in enumerate(report["recommandations"], 1):
                console.print(f"  [bold]{i}.[/] {r}")
    else:
        print(f"  Risque {niveau}   score {score}/100")
        for f in report["findings"]:
            print(f"  [{f['sev']}] {f['titre']}")
        for i, r in enumerate(report["recommandations"], 1):
            print(f"  {i}. {r}")

def write_protection_md(report: dict[str, Any], path: Path, source: str = "") -> Path:
    lines = [
        "# Rapport de protection réseau — tshark2hashcat",
        "",
        f"- Source : `{source}`",
        f"- Généré : `{now_iso()}`",
        f"- **Risque : {report['niveau']}**  (score {report['score']}/100)",
        f"- Paquets : {report['n_packets']}",
        f"- Hashes Hashcat : {report['n_hashes']}",
        f"- Secrets extraits : {report['n_secrets']}",
        f"- Protocoles : {', '.join(report['protocols']) or 'aucun'}",
        "",
        "## Constats",
        "",
    ]
    if not report["findings"]:
        lines.append("_Aucun protocole clairement dangereux ni secret extrait._")
    else:
        lines += ["| gravité | constat | détail |", "|---------|---------|--------|"]
        for f in report["findings"]:
            lines.append(f"| {f['sev']} | {f['titre']} | {f['detail']} |")
    lines += ["", "## Recommandations", ""]
    for i, r in enumerate(report["recommandations"], 1):
        lines.append(f"{i}. {r}")
    if not report["recommandations"]:
        lines.append("_ RAS — la capture ne montre pas de fuite évidente._")
    ensure_parent(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

@dataclass
class ExtractResult:
    hashes: dict[int, list[HashHit]] = field(default_factory=lambda: defaultdict(list))
    credentials: list[CredentialHit] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    proto_seen: set[str] = field(default_factory=set)
    proto_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    preauth_users: set[str] = field(default_factory=set)
    diag: list[KerberosIdentity] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    packets: int = 0
    rejected: int = 0
    packet_stats: dict[str, Any] = field(default_factory=dict)

    def all_lines(self) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for mode in sorted(self.hashes):
            for hit in self.hashes[mode]:
                out.append((mode, hit.line))
        return out

    def total(self) -> int:
        return sum(len(v) for v in self.hashes.values())

    def modes(self) -> list[int]:
        return sorted(self.hashes.keys())

    def to_records(self) -> list[dict[str, Any]]:
        recs: list[dict[str, Any]] = []
        for mode, hits in sorted(self.hashes.items()):
            for h in hits:
                recs.append(
                    {
                        "type": "hash",
                        "mode": mode,
                        "line": h.line,
                        "protocol": h.protocol,
                        "source": h.source,
                        "frame": h.frame,
                        "user": h.user,
                        "domain": h.domain,
                        **{f"extra_{k}": v for k, v in (h.extra or {}).items()},
                    }
                )
        for c in self.credentials:
            recs.append(
                {
                    "type": "credential",
                    "mode": None,
                    "line": f"{c.username}:{c.password}",
                    "protocol": c.protocol,
                    "source": c.source,
                    "frame": c.frame,
                    "user": c.username,
                    "domain": None,
                    "password": c.password,
                }
            )
        return recs

class ExtractorEngine:
    """Orchestre NTLM / Kerberos / WPA / APOP / creds / extras."""

    def __init__(
        self,
        *,
        include_ntlm: bool = True,
        include_kerberos: bool = True,
        include_wpa: bool = True,
        include_apop: bool = True,
        include_creds: bool = True,
        include_extra: bool = True,
        raw_scan: bool = True,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self.include_ntlm = include_ntlm
        self.include_kerberos = include_kerberos
        self.include_wpa = include_wpa
        self.include_apop = include_apop
        self.include_creds = include_creds
        self.include_extra = include_extra
        self.raw_scan = raw_scan
        self.progress_cb = progress_cb

    def run(self, packets: Iterable[dict]) -> ExtractResult:
        ctx = ExtractContext()
        result = ExtractResult()
        seen: set[str] = set()
        packet_list = list(packets) if not isinstance(packets, list) else packets
        total = len(packet_list)
        result.packets = total
        layer_secrets: list[CredentialHit] = []

        def push(hit: HashHit) -> None:
            if not validate(hit.mode, hit.line):
                result.rejected += 1
                ctx.miss(f"{hit.source}: ligne rejetée par le validateur du mode {hit.mode}")
                return
            if hit.line in seen:
                return
            seen.add(hit.line)
            result.hashes[hit.mode].append(hit)

        for idx, pkt in enumerate(packet_list, 1):
            if self.progress_cb:
                self.progress_cb(idx, total)
            layers = pkt.get("_source", {}).get("layers", {}) if isinstance(pkt, dict) else {}
            if not isinstance(layers, dict):
                layers = {}
            frame = frame_number(layers, idx)

            protos = frame_protocols(layers)
            for proto in protos:
                ctx.proto_counts[proto] += 1
                ctx.proto_seen.add(proto)
            _collect_packet_stats(ctx, layers, protos)

            # Tous les protocoles : on tente chaque extracteur
            # (un paquet HTTP peut encapsuler NTLM, un UDP du Kerberos, etc.)
            if self.include_kerberos:
                for hit in extract_kerberos(layers, frame, ctx):
                    push(hit)

            if self.include_ntlm:
                for hit in extract_dissected(layers, frame, ctx):
                    push(hit)

            if self.include_wpa:
                for hit in extract_pmkid(layers, frame, ctx):
                    push(hit)
                extract_eapol_hint(layers, frame, ctx)

            if self.include_extra:
                for hit in chap_from_layers(layers, frame, ctx):
                    push(hit)

            raw_this: list[bytes] = _collect_raw(layers) if self.raw_scan else []
            if self.raw_scan:
                ctx.raw_chunks.extend(raw_this)

            if self.include_creds:
                layer_secrets.extend(secrets_from_layers(layers, frame))
                if raw_this:
                    blob = b"".join(raw_this)
                    for comm in snmp_communities_from_bytes(blob):
                        layer_secrets.append(
                            _cred("SNMPv1/v2c community", "(community)", comm, frame, "snmp-ber")
                        )

        raw_blob = b"".join(ctx.raw_chunks) if self.raw_scan else b""
        # séparateur de trames pour les scans TEXTE (évite USER+POST collés)
        text_blob = b"\n".join(ctx.raw_chunks) if self.raw_scan else b""

        if self.raw_scan and raw_blob and self.include_ntlm:
            if NTLMSSP_MAGIC in raw_blob or re.search(rb"[A-Za-z0-9+/]{40,}={0,2}", raw_blob):
                found = ntlm_raw_scan(raw_blob, "-", ctx)
                if found:
                    ctx.proto_seen.add("ntlmssp (brut -x)")
                for hit in found:
                    hit.source = hit.source or "NTLM brut"
                    push(hit)

        if self.raw_scan and text_blob and self.include_apop:
            if re.search(rb"\bAPOP\s+\S+\s+[0-9a-fA-F]{32}\b", text_blob):
                for hit in apop_scan(text_blob, ctx):
                    push(hit)

        if self.raw_scan and text_blob and self.include_extra:
            for hit in sip_scan(text_blob, ctx):
                push(hit)
            for hit in jwt_scan(text_blob, ctx):
                push(hit)
            http_digest_scan(text_blob, ctx)
            cram_md5_scan(text_blob, ctx)

        if self.include_wpa:
            for hit in finalize_eapol(ctx):
                push(hit)

        if self.include_creds:
            all_creds: list[CredentialHit] = list(layer_secrets)
            if text_blob:
                all_creds.extend(creds_scan(text_blob))
                sample = text_blob if len(text_blob) <= 2_000_000 else text_blob[:2_000_000]
                all_creds.extend(secrets_from_raw(sample))
            result.credentials = dedupe_creds(all_creds)
            if result.credentials:
                ctx.proto_seen.add("identifiants en clair")

        result.missing = list(ctx.missing)
        result.proto_seen = set(ctx.proto_seen)
        result.proto_counts = dict(ctx.proto_counts)
        result.preauth_users = set(ctx.preauth_users)
        result.diag = list(ctx.diag)
        result.notes = list(ctx.notes)
        result.packet_stats = _packet_stats_from_ctx(ctx)
        return result

def _collect_packet_stats(ctx: ExtractContext, layers: dict, protos: list[str]) -> None:
    """Stats légères par paquet (taille, temps, IP/MAC) — pas de walk JSON."""
    plen = _top_layer_str(layers, "frame.len")
    if plen and plen.isdigit():
        nlen = int(plen)
        ctx.bytes_sum += nlen
        if ctx.bytes_min is None or nlen < ctx.bytes_min:
            ctx.bytes_min = nlen
        if nlen > ctx.bytes_max:
            ctx.bytes_max = nlen
    ts = _top_layer_str(layers, "frame.time_epoch")
    if ts:
        try:
            tsf = float(ts)
        except ValueError:
            tsf = None
        if tsf is not None:
            if ctx.t_first is None or tsf < ctx.t_first:
                ctx.t_first = tsf
            if ctx.t_last is None or tsf > ctx.t_last:
                ctx.t_last = tsf
    for key in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"):
        val = _top_layer_str(layers, key)
        if val:
            ctx.ips.add(val)
    for key in ("eth.src", "eth.dst", "wlan.sa", "wlan.da", "wlan.bssid"):
        val = _top_layer_str(layers, key)
        if val:
            ctx.macs.add(val.lower())

def _packet_stats_from_ctx(ctx: ExtractContext) -> dict[str, Any]:
    return {
        "bytes_min": ctx.bytes_min,
        "bytes_max": ctx.bytes_max or 0,
        "bytes_sum": ctx.bytes_sum,
        "t_first": ctx.t_first,
        "t_last": ctx.t_last,
        "ips": sorted(ctx.ips),
        "macs": sorted(ctx.macs),
        "n_ips": len(ctx.ips),
        "n_macs": len(ctx.macs),
    }

def merge_packet_stats(parts: Iterable["ExtractResult"]) -> dict[str, Any]:
    bytes_min: Optional[int] = None
    bytes_max = 0
    bytes_sum = 0
    t_first: Optional[float] = None
    t_last: Optional[float] = None
    ips: set[str] = set()
    macs: set[str] = set()
    for r in parts:
        st = getattr(r, "packet_stats", None) or {}
        if st.get("bytes_min") is not None:
            bytes_min = st["bytes_min"] if bytes_min is None else min(bytes_min, int(st["bytes_min"]))
        if st.get("bytes_max"):
            bytes_max = max(bytes_max, int(st["bytes_max"]))
        bytes_sum += int(st.get("bytes_sum") or 0)
        tf, tl = st.get("t_first"), st.get("t_last")
        if tf is not None:
            t_first = float(tf) if t_first is None else min(t_first, float(tf))
        if tl is not None:
            t_last = float(tl) if t_last is None else max(t_last, float(tl))
        ips.update(st.get("ips") or [])
        macs.update(st.get("macs") or [])
    return {
        "bytes_min": bytes_min,
        "bytes_max": bytes_max,
        "bytes_sum": bytes_sum,
        "t_first": t_first,
        "t_last": t_last,
        "ips": sorted(ips),
        "macs": sorted(macs),
        "n_ips": len(ips),
        "n_macs": len(macs),
    }

def _collect_raw(layers: dict) -> list[bytes]:
    out: list[bytes] = []
    for k, v in walk(layers):
        if not (isinstance(k, str) and k.endswith("_raw") and isinstance(v, list) and v):
            continue
        hx = norm_hex(v[0])
        if hx:
            try:
                out.append(bytes.fromhex(hx))
            except ValueError:
                continue
    return out

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"C:\Program Files\Wireshark\tshark",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/wireshark/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "tshark",
]

DUMPCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    "/usr/bin/dumpcap",
    "/usr/local/bin/dumpcap",
    "dumpcap",
]

CAPINFOS_CANDIDATES = [
    r"C:\Program Files\Wireshark\capinfos.exe",
    "/usr/bin/capinfos",
    "/usr/local/bin/capinfos",
    "capinfos",
]

EDITCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\editcap.exe",
    "/usr/bin/editcap",
    "/usr/local/bin/editcap",
    "editcap",
]

MERGECAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\mergecap.exe",
    "/usr/bin/mergecap",
    "/usr/local/bin/mergecap",
    "mergecap",
]

TEXT2PCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\text2pcap.exe",
    "/usr/bin/text2pcap",
    "/usr/local/bin/text2pcap",
    "text2pcap",
]

def _first_existing(candidates: list[str], extra: Optional[str] = None) -> Optional[str]:
    ordered = ([extra] if extra else []) + list(candidates)
    for c in ordered:
        if not c:
            continue
        if os.path.isfile(c) and os.access(c, os.X_OK if os.name != "nt" else os.F_OK):
            return c
        found = shutil.which(c)
        if found:
            return found
    return None

def find_tshark(cli_path: Optional[str] = None) -> Optional[str]:
    env = os.environ.get("T2H_TSHARK_PATH") or os.environ.get("TSHARK")
    return _first_existing(TSHARK_CANDIDATES, cli_path or env)

def find_dumpcap(cli_path: Optional[str] = None) -> Optional[str]:
    return _first_existing(DUMPCAP_CANDIDATES, cli_path)

def find_capinfos(cli_path: Optional[str] = None) -> Optional[str]:
    return _first_existing(CAPINFOS_CANDIDATES, cli_path)

def find_editcap(cli_path: Optional[str] = None) -> Optional[str]:
    return _first_existing(EDITCAP_CANDIDATES, cli_path)

def find_mergecap(cli_path: Optional[str] = None) -> Optional[str]:
    return _first_existing(MERGECAP_CANDIDATES, cli_path)

def find_text2pcap(cli_path: Optional[str] = None) -> Optional[str]:
    return _first_existing(TEXT2PCAP_CANDIDATES, cli_path)

def tshark_version(binary: Optional[str] = None) -> Optional[str]:
    bin_ = binary or find_tshark()
    if not bin_:
        return None
    try:
        r = subprocess.run(
            [bin_, "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = (r.stdout or r.stderr or "").splitlines()
    return line[0].strip() if line else None

def suite_status(tshark_path: Optional[str] = None) -> dict[str, Optional[str]]:
    """Chemins des outils compagnons Wireshark (None = absent)."""
    return {
        "tshark": find_tshark(tshark_path),
        "dumpcap": find_dumpcap(),
        "capinfos": find_capinfos(),
        "editcap": find_editcap(),
        "mergecap": find_mergecap(),
        "text2pcap": find_text2pcap(),
        "version": tshark_version(tshark_path),
    }

class TsharkError(RuntimeError):
    def __init__(self, message: str, code: int = 1, stderr: str = "", cmd: Optional[list[str]] = None):
        super().__init__(message)
        self.code = code
        self.stderr = stderr
        self.cmd = cmd or []

@dataclass
class TsharkResult:
    code: int
    stdout: str
    stderr: str
    cmd: list[str]

    def json(self) -> Any:
        text = self.stdout.strip()
        if not text:
            return []
        return json.loads(text)

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln != ""]

@dataclass
class TsharkRunner:
    binary: str
    timeout: int = 0
    extra_args: list[str] = field(default_factory=list)
    env: Optional[dict[str, str]] = None

    @classmethod
    def discover(cls, cli_path: Optional[str] = None, timeout: int = 0) -> "TsharkRunner":
        bin_ = find_tshark(cli_path)
        if not bin_:
            raise TsharkError("tshark introuvable. Utilise --tshark CHEMIN")
        return cls(binary=bin_, timeout=timeout)

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
        check: bool = False,
        input_data: Optional[str] = None,
    ) -> TsharkResult:
        cmd = [self.binary, *self.extra_args, *args]
        to = timeout if timeout is not None else (self.timeout or None)
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=to if to and to > 0 else None,
                input=input_data,
                env=self.env or os.environ.copy(),
            )
        except subprocess.TimeoutExpired as exc:
            raise TsharkError(f"tshark timeout après {to}s", code=124, cmd=cmd) from exc
        except FileNotFoundError as exc:
            raise TsharkError(f"binaire introuvable : {self.binary}", cmd=cmd) from exc
        result = TsharkResult(r.returncode, r.stdout or "", r.stderr or "", cmd)
        if check and r.returncode != 0 and not r.stdout.strip():
            raise TsharkError(
                f"tshark a échoué (code {r.returncode})",
                code=r.returncode,
                stderr=(r.stderr or "")[:2000],
                cmd=cmd,
            )
        return result

    # ----- lectures PCAP -----
    def read_json(
        self,
        pcap: str,
        *,
        display_filter: str = "",
        read_filter: str = "",
        hexdump: bool = True,
        no_duplicate_keys: bool = True,
        decode_as: Optional[Sequence[str]] = None,
        disable_names: bool = False,
        two_pass: bool = False,
        limit: int = 0,
        extra: Optional[Sequence[str]] = None,
    ) -> list[dict]:
        args: list[str] = ["-r", pcap, "-T", "json"]
        if hexdump:
            args.append("-x")
        if no_duplicate_keys:
            args.append("--no-duplicate-keys")
        args.extend(self._common(display_filter, read_filter, decode_as, disable_names, two_pass, limit))
        if extra:
            args.extend(extra)
        res = self.run(args, check=False)
        if res.code != 0 and not res.stdout.strip():
            raise TsharkError(
                f"tshark a échoué (code {res.code}) : {res.stderr[:500]}",
                code=res.code,
                stderr=res.stderr,
                cmd=res.cmd,
            )
        data = res.json() if res.stdout.strip() else []
        if data and not isinstance(data, list):
            raise TsharkError("sortie tshark inattendue (pas une liste JSON)")
        return data or []

    def read_fields(
        self,
        pcap: str,
        fields: Sequence[str],
        *,
        display_filter: str = "",
        separator: str = "\t",
        quote: str = "d",
        occurrence: str = "a",
        aggregator: str = ",",
        header: bool = False,
        limit: int = 0,
        decode_as: Optional[Sequence[str]] = None,
    ) -> TsharkResult:
        args: list[str] = ["-r", pcap, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", f"separator={separator}"])
        args.extend(["-E", f"quote={quote}"])
        args.extend(["-E", f"occurrence={occurrence}"])
        args.extend(["-E", f"aggregator={aggregator}"])
        if header:
            args.extend(["-E", "header=y"])
        args.extend(self._common(display_filter, "", decode_as, False, False, limit))
        return self.run(args)

    def read_pdml(self, pcap: str, display_filter: str = "", limit: int = 0) -> str:
        args = ["-r", pcap, "-T", "pdml"]
        args.extend(self._common(display_filter, "", None, False, False, limit))
        return self.run(args).stdout

    def read_psml(self, pcap: str, display_filter: str = "", limit: int = 0) -> str:
        args = ["-r", pcap, "-T", "psml"]
        args.extend(self._common(display_filter, "", None, False, False, limit))
        return self.run(args).stdout

    def read_ek(self, pcap: str, display_filter: str = "", limit: int = 0) -> str:
        """Elasticsearch / Kibana JSON (une ligne par paquet)."""
        args = ["-r", pcap, "-T", "ek"]
        args.extend(self._common(display_filter, "", None, False, False, limit))
        return self.run(args).stdout

    def read_tabs(self, pcap: str, display_filter: str = "", limit: int = 0) -> str:
        args = ["-r", pcap, "-T", "tabs"]
        args.extend(self._common(display_filter, "", None, False, False, limit))
        return self.run(args).stdout

    def read_text(self, pcap: str, display_filter: str = "", verbose: bool = False, limit: int = 0) -> str:
        args = ["-r", pcap]
        if verbose:
            args.append("-V")
        args.extend(self._common(display_filter, "", None, False, False, limit))
        return self.run(args).stdout

    # ----- écriture / filtre pcap -----
    def rewrite(
        self,
        pcap: str,
        output: str,
        *,
        display_filter: str = "",
        read_filter: str = "",
        pcapng: bool = True,
        decode_as: Optional[Sequence[str]] = None,
    ) -> TsharkResult:
        args = ["-r", pcap, "-w", output]
        if pcapng and not output.endswith(".pcap"):
            pass  # tshark conserve le format source par défaut
        args.extend(self._common(display_filter, read_filter, decode_as, False, False, 0))
        return self.run(args, check=True)

    # ----- statistiques -z -----
    def stats(
        self,
        pcap: str,
        stat: str,
        *,
        display_filter: str = "",
        extra_stats: Optional[Sequence[str]] = None,
    ) -> str:
        args = ["-r", pcap, "-q", "-z", stat]
        if extra_stats:
            for s in extra_stats:
                args.extend(["-z", s])
        args.extend(self._common(display_filter, "", None, False, False, 0))
        return self.run(args).stdout

    # ----- follow stream -----
    def follow(
        self,
        pcap: str,
        proto: str,
        mode: str,
        filt: str,
        display_filter: str = "",
    ) -> str:
        # proto = tcp|udp|http|tls|sip   mode = ascii|ebcdic|hex|raw|yaml
        spec = f"follow,{proto},{mode},{filt}"
        return self.stats(pcap, spec, display_filter=display_filter)

    # ----- export objects -----
    def export_objects(self, pcap: str, protocol: str, outdir: str, display_filter: str = "") -> TsharkResult:
        os.makedirs(outdir, exist_ok=True)
        # --export-objects proto,dir
        args = ["-r", pcap, "--export-objects", f"{protocol},{outdir}"]
        args.extend(self._common(display_filter, "", None, False, False, 0))
        return self.run(args)

    # ----- live capture -----
    def capture(
        self,
        interface: str,
        output: str,
        *,
        duration: int = 0,
        packets: int = 0,
        capture_filter: str = "",
        snaplen: int = 0,
        promiscuous: bool = True,
        monitor: bool = False,
    ) -> TsharkResult:
        args = ["-i", interface, "-w", output]
        if duration > 0:
            args.extend(["-a", f"duration:{duration}"])
        if packets > 0:
            args.extend(["-c", str(packets)])
        if capture_filter:
            args.extend(["-f", capture_filter])
        if snaplen > 0:
            args.extend(["-s", str(snaplen)])
        if not promiscuous:
            args.append("-p")
        if monitor:
            args.append("-I")
        return self.run(args, check=True)

    def list_interfaces(self) -> str:
        return self.run(["-D"]).stdout

    def list_linktypes(self, interface: str) -> str:
        return self.run(["-i", interface, "-L"]).stdout

    def list_protocols(self) -> str:
        return self.run(["-G", "protocols"]).stdout

    def list_fields(self) -> str:
        return self.run(["-G", "fields"]).stdout

    def list_decodes(self) -> str:
        return self.run(["-G", "decodes"]).stdout

    def list_heuristic_decodes(self) -> str:
        return self.run(["-G", "heuristic-decodes"]).stdout

    def list_plugins(self) -> str:
        return self.run(["-G", "plugins"]).stdout

    def list_values(self) -> str:
        return self.run(["-G", "values"]).stdout

    def dump_glossary(self, kind: str) -> str:
        return self.run(["-G", kind]).stdout

    def _common(
        self,
        display_filter: str,
        read_filter: str,
        decode_as: Optional[Sequence[str]],
        disable_names: bool,
        two_pass: bool,
        limit: int,
    ) -> list[str]:
        args: list[str] = []
        if display_filter:
            args.extend(["-Y", display_filter])
        if read_filter:
            args.extend(["-R", read_filter])
            if not two_pass:
                args.append("-2")
        if two_pass:
            args.append("-2")
        if disable_names:
            args.append("-n")
        if decode_as:
            for d in decode_as:
                args.extend(["-d", d])
        if limit and limit > 0:
            args.extend(["-c", str(limit)])
        return args

def run_tshark_json(pcap: str, tshark_path: Optional[str] = None, **kwargs) -> list[dict]:
    runner = TsharkRunner.discover(tshark_path)
    return runner.read_json(pcap, **kwargs)

def load_packets(path: str, tshark_path: Optional[str] = None, **kwargs) -> list[dict]:
    """Charge un .pcap/.pcapng via tshark, ou un export .json déjà produit."""
    if str(path).lower().endswith(".json"):
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise TsharkError("export JSON inattendu (pas une liste)")
        return data
    return run_tshark_json(path, tshark_path, **kwargs)

# groupe -> liste d'options
# flag, args, summary_fr, summary_en, example

Option = dict[str, Any]

TSHARK_OPTIONS: list[Option] = []

def _o(flag: str, group: str, args: str, fr: str, en: str, example: str = "") -> None:
    TSHARK_OPTIONS.append(
        {
            "flag": flag,
            "group": group,
            "args": args,
            "fr": fr,
            "en": en,
            "example": example,
        }
    )

_o("-i", "capture", "<interface>", "Interface de capture (ou nom dumpcap)", "Capture interface", "-i eth0")
_o("-I", "capture", "", "Mode monitor (Wi-Fi)", "Monitor mode", "-I")
_o("-f", "capture", "<filter>", "Filtre de capture BPF (libpcap)", "BPF capture filter", "-f \"tcp port 445\"")
_o("-s", "capture", "<snaplen>", "Longueur de capture (octets)", "Snapshot length", "-s 128")
_o("-p", "capture", "", "Désactive le mode promiscuous", "Don't capture in promiscuous mode", "-p")
_o("-B", "capture", "<MB>", "Taille du buffer kernel", "Kernel buffer size", "-B 16")
_o("-y", "capture", "<linktype>", "Type de lien (cf. -L)", "Link-layer type", "-y EN10MB")
_o("-D", "capture", "", "Liste les interfaces", "List interfaces", "-D")
_o("-L", "capture", "", "Liste les link-types de l'interface", "List link-layer types", "-i eth0 -L")
_o("-d", "capture", "<layer>==<sel>,<decode>", "Force un décodage (decode-as)", "Force decode", "-d tcp.port==8888,http")
_o("--ifdescr", "capture", "<descr>", "Description d'interface", "Interface description", "")
_o("--ifname", "capture", "<name>", "Nom d'interface", "Interface name", "")

_o("-a", "autostop", "duration:N | filesize:N | files:N | packets:N", "Condition d'arrêt auto", "Autostop condition", "-a duration:60")
_o("-b", "autostop", "duration:N | filesize:N | files:N", "Rotation de fichiers (ring buffer)", "Multiple files / ring buffer", "-b filesize:10000 -b files:5")
_o("-c", "autostop", "<N>", "Arrête après N paquets", "Stop after N packets", "-c 1000")

_o("-r", "input", "<infile>", "Lire un fichier pcap/pcapng", "Read capture file", "-r dump.pcapng")
_o("-R", "input", "<read filter>", "Filtre de lecture (nécessite -2)", "Read filter (needs -2)", "-2 -R http")
_o("-2", "input", "", "Deux passes (requis pour -R et certains -z)", "Two-pass analysis", "-2")
_o("-M", "input", "<N>", "Réinitialise session après N paquets", "Session reset every N packets", "-M 100000")
_o("-n", "input", "", "Désactive toute résolution de noms", "Disable all name resolutions", "-n")
_o("-N", "input", "<flags>", "Active certaines résolutions (mNtCd)", "Enable specific name resolutions", "-N mNt")
_o("-d", "input", "…", "Decode-as (aussi en lecture)", "Decode as", "-d udp.port==5353,dns")

_o("-C", "process", "<config>", "Fichier de configuration Wireshark", "Start with specific config", "-C Default")
_o("-o", "process", "<name>:<value>", "Override d'une préférence", "Override preference", "-o tcp.desegment_tcp_streams:TRUE")
_o("-K", "process", "<keytab>", "Fichier keytab Kerberos", "Kerberos keytab file", "-K /etc/krb5.keytab")
_o("-t", "process", "a|ad|adoy|d|dd|e|r|u|ud|udoy", "Format d'horodatage", "Timestamp format", "-t ad")
_o("-u", "process", "s|hms", "Format des secondes", "Seconds format", "-u s")
_o("-l", "process", "", "Flush stdout à chaque paquet", "Flush after each packet", "-l")
_o("-q", "process", "", "Mode silencieux (stats uniquement)", "Quiet (stats only)", "-q -z io,phs")
_o("-Q", "process", "", "Encore plus silencieux", "Even quieter", "-Q")
_o("-g", "process", "", "Groupe dumpcap (permissions)", "Enable group access", "-g")
_o("-X", "process", "<eXtension>", "Extensions / lua / stdin", "Extensions", "-X lua_script:foo.lua")
_o("-Y", "process", "<display filter>", "Filtre d'affichage", "Display filter", "-Y \"http.request.method == GET\"")
_o("--disable-protocol", "process", "<proto>", "Désactive un protocole", "Disable protocol", "--disable-protocol tcp")
_o("--enable-heuristic", "process", "<proto>", "Active un dissecteur heuristique", "Enable heuristic dissector", "")
_o("--disable-heuristic", "process", "<proto>", "Désactive un dissecteur heuristique", "Disable heuristic dissector", "")
_o("--enable-protocol", "process", "<proto>", "Active un protocole", "Enable protocol", "")

_o("-w", "output", "<outfile|->", "Écrit un pcap (ou stdout)", "Write packets to file", "-w out.pcapng")
_o("-F", "output", "<format>", "Format de fichier de sortie", "Output file format", "-F pcapng")
_o("-V", "output", "", "Arbre de dissection complet", "Packet tree (verbose)", "-V")
_o("-O", "output", "<proto>,…", "Détails seulement pour ces proto", "Detail only for protocols", "-O http,tcp")
_o("-P", "output", "", "Ligne de résumé même avec -V / -O", "Print summary line too", "-P")
_o("-S", "output", "<separator>", "Séparateur ligne résumé / détails", "Summary/detail separator", "")
_o("-x", "output", "", "Hex + ASCII dump de chaque paquet", "Hex + ASCII dump", "-x")
_o("-T", "output", "fields|json|jsonraw|ek|pdml|ps|psml|tabs|text", "Format de sortie texte", "Text output format", "-T json")
_o("-e", "output", "<field>", "Champ à extraire (avec -T fields/ek/json)", "Field to output", "-e ip.src -e http.host")
_o("-E", "output", "aggregator= / occurrence= / separator= / header= / quote=", "Options -T fields", "Fields output options", "-E header=y -E separator=,")
_o("-j", "output", "<protofilt>", "Protocoles filtrés (JSON/EK)", "Protocols filter (JSON)", "-j http")
_o("-J", "output", "<protofilt>", "Comme -j + parents", "Protocols + parents", "-J http")
_o("-G", "output", "[report]", "Glossaire (fields, protocols, …)", "Glossary dump", "-G fields")
_o("-h", "output", "", "Aide", "Help", "-h")
_o("-v", "output", "", "Version", "Version", "-v")
_o("--color", "output", "", "Colorise la sortie texte", "Color output", "--color")
_o("--no-duplicate-keys", "output", "", "JSON : fusionne les clés dupliquées", "JSON merge duplicate keys", "--no-duplicate-keys")
_o("--export-objects", "output", "<proto>,<dir>", "Exporte les objets (http, smb, …)", "Export objects", "--export-objects http,/tmp/http")
_o("--export-tls-session-keys", "output", "<file>", "Exporte les clés de session TLS", "Export TLS session keys", "--export-tls-session-keys keys.log")
_o("--hexdump", "output", "frames|ascii|delimit|noascii", "Contrôle du dump -x", "Hexdump options", "--hexdump ascii")

_o("-z", "stats", "<stat>", "Rapport statistique (voir catalogue -z)", "Statistics report", "-z io,phs")
_o("-z help", "stats", "", "Liste toutes les statistiques", "List statistics", "-z help")

_o("-H", "misc", "<hosts file>", "Fichier hosts supplémentaire", "Extra hosts file", "-H hosts")
_o("--elastic-mapping-filter", "misc", "<protos>", "Filtre mapping Elasticsearch", "Elastic mapping filter", "")

# Glossaire -G
GLOSSARY_REPORTS: list[tuple[str, str, str]] = [
    ("?", "Liste des rapports -G", "List of -G reports"),
    ("column-formats", "Formats de colonnes", "Column formats"),
    ("currentprefs", "Préférences courantes", "Current preferences"),
    ("decodes", "Associations decode-as", "Decode-as associations"),
    ("defaultprefs", "Préférences par défaut", "Default preferences"),
    ("dissector-tables", "Tables de dissecteurs", "Dissector tables"),
    ("elastic-mapping", "Mapping Elasticsearch", "Elasticsearch mapping"),
    ("fieldcount", "Nombre de champs", "Field count"),
    ("fields", "Tous les champs", "All fields"),
    ("fields2", "Champs (format 2)", "Fields format 2"),
    ("ftypes", "Types de champs", "Field types"),
    ("heuristic-decodes", "Dissecteurs heuristiques", "Heuristic decodes"),
    ("plugins", "Plugins chargés", "Loaded plugins"),
    ("protocols", "Protocoles", "Protocols"),
    ("values", "Valeurs / value-strings", "Value strings"),
    ("unicode-text", "Tables unicode", "Unicode tables"),
]

# Formats -T
OUTPUT_TEMPLATES: list[tuple[str, str, str]] = [
    ("text", "Sortie texte classique (défaut)", "Classic text output"),
    ("tabs", "Comme text, colonnes séparées par tab", "Tab-separated text"),
    ("ps", "PostScript", "PostScript"),
    ("psml", "Packet Summary Markup Language (XML)", "Packet summary XML"),
    ("pdml", "Packet Details Markup Language (XML)", "Packet details XML"),
    ("json", "JSON (un tableau de paquets)", "JSON packet array"),
    ("jsonraw", "JSON avec octets bruts", "JSON with raw bytes"),
    ("ek", "JSON Elasticsearch (une ligne / paquet)", "Elasticsearch JSON lines"),
    ("fields", "Champs sélectionnés via -e", "Selected fields via -e"),
]

# Formats de fichier -F (les plus courants)
FILE_FORMATS: list[tuple[str, str]] = [
    ("pcapng", "PCAP Next Generation (recommandé)"),
    ("pcap", "PCAP classique (libpcap / tcpdump)"),
    ("ngsniffer", "Sniffer Pro"),
    ("snoop", "Sun snoop"),
    ("netmon1", "NetMon 1.x"),
    ("netmon2", "NetMon 2.x"),
    ("visual", "Visual Networks"),
    ("5views", "InfoVista 5View"),
    ("niobserverv9", "Network Instruments Observer v9"),
    ("nokianokaiadr", "Nokia NOKIA"),
]

# --export-objects protocoles
EXPORT_OBJECT_PROTOS: list[tuple[str, str]] = [
    ("dicom", "DICOM medical images"),
    ("http", "Objets HTTP (fichiers, images, scripts)"),
    ("imf", "Internet Message Format (e-mail)"),
    ("smb", "Fichiers SMB/CIFS"),
    ("tftp", "Fichiers TFTP"),
]

# Follow protocols
FOLLOW_PROTOS: list[tuple[str, str]] = [
    ("tcp", "Flux TCP (follow,tcp,MODE,FILTER)"),
    ("udp", "Flux UDP"),
    ("dccp", "Flux DCCP"),
    ("tls", "Flux TLS (clair si clés disponibles)"),
    ("http", "Flux HTTP"),
    ("http2", "Flux HTTP/2"),
    ("quic", "Flux QUIC"),
    ("sip", "Flux SIP"),
]

FOLLOW_MODES = ("ascii", "ebcdic", "hex", "raw", "yaml")

def options_by_group() -> dict[str, list[Option]]:
    out: dict[str, list[Option]] = {}
    for o in TSHARK_OPTIONS:
        out.setdefault(o["group"], []).append(o)
    return out

def search_options(query: str) -> list[Option]:
    q = query.lower().strip()
    if not q:
        return []
    return [
        o
        for o in TSHARK_OPTIONS
        if q in o["flag"].lower()
        or q in o["fr"].lower()
        or q in o["en"].lower()
        or q in o["group"].lower()
        or q in (o.get("args") or "").lower()
    ]

def groups() -> list[str]:
    return sorted({o["group"] for o in TSHARK_OPTIONS})

Stat = dict[str, Any]
STAT_CATALOG: list[Stat] = []

def _s(key: str, group: str, fr: str, en: str, syntax: str = "", example: str = "", notes: str = "") -> None:
    STAT_CATALOG.append(
        {
            "key": key,
            "group": group,
            "fr": fr,
            "en": en,
            "syntax": syntax or key,
            "example": example or key,
            "notes": notes,
        }
    )

_s("io,phs", "io", "Hiérarchie de protocoles (frames / octets)", "Protocol hierarchy statistics",
   "io,phs[,filter]", "io,phs", "Équivalent Statistics → Protocol Hierarchy.")
_s("io,stat", "io", "Statistiques d'I/O par intervalle", "I/O statistics by interval",
   "io,stat,interval[,filter][,filter]…", "io,stat,1,tcp,udp,http",
   "interval en secondes (0 = toute la capture).")
_s("plen,tree", "io", "Répartition par taille de paquet", "Packet length tree", "plen,tree")
_s("ptype,tree", "io", "Répartition par type de paquet IP", "IP packet type tree", "ptype,tree")
_s("dests,tree", "io", "Destinations", "Destinations tree", "dests,tree")

for kind, label in (
    ("bluetooth", "Bluetooth"),
    ("eth", "Ethernet"),
    ("fc", "Fibre Channel"),
    ("fddi", "FDDI"),
    ("ip", "IPv4"),
    ("ipv6", "IPv6"),
    ("ipx", "IPX"),
    ("jxta", "JXTA"),
    ("mptcp", "MPTCP"),
    ("ncp", "NCP"),
    ("rsvp", "RSVP"),
    ("sctp", "SCTP"),
    ("sll", "Linux cooked"),
    ("tcp", "TCP"),
    ("tr", "Token Ring"),
    ("udp", "UDP"),
    ("usb", "USB"),
    ("wlan", "802.11"),
    ("wpan", "IEEE 802.15.4"),
    ("zbee_nwk", "ZigBee NWK"),
):
    _s(f"conv,{kind}", "conversations", f"Conversations {label}", f"{label} conversations",
       f"conv,{kind}[,filter]", f"conv,{kind}")
    _s(f"endpoints,{kind}", "endpoints", f"Endpoints {label}", f"{label} endpoints",
       f"endpoints,{kind}[,filter]", f"endpoints,{kind}")

_s("expert", "expert", "Infos expert (chat/note/warn/error)", "Expert information",
   "expert[ ,error|,warn|,note|,chat][,filter]", "expert,warn",
   "Très utile pour diagnostiquer retransmissions, checksums, TLS alerts.")
_s("expert,error", "expert", "Uniquement les erreurs expert", "Expert errors only", "expert,error")
_s("expert,warn", "expert", "Warnings expert", "Expert warnings", "expert,warn")
_s("expert,note", "expert", "Notes expert", "Expert notes", "expert,note")
_s("expert,chat", "expert", "Chat expert", "Expert chat", "expert,chat")

_s("hosts", "hosts", "Fichier hosts (IP ↔ nom) vu dans la capture", "Hosts file from capture",
   "hosts[,ipv4][,ipv6]", "hosts")
_s("hosts,ipv4", "hosts", "Hosts IPv4 seulement", "IPv4 hosts only", "hosts,ipv4")
_s("hosts,ipv6", "hosts", "Hosts IPv6 seulement", "IPv6 hosts only", "hosts,ipv6")
_s("dns,tree", "dns", "Statistiques DNS (types, codes, noms)", "DNS statistics tree", "dns,tree")
_s("ip_hosts,tree", "hosts", "Hôtes IPv4 (arbre)", "IPv4 hosts tree", "ip_hosts,tree")
_s("ip_srcdst,tree", "hosts", "Paires source/dest IPv4", "IPv4 src/dst pairs", "ip_srcdst,tree")
_s("ipv6_hosts,tree", "hosts", "Hôtes IPv6", "IPv6 hosts tree", "ipv6_hosts,tree")
_s("ipv6_srcdst,tree", "hosts", "Paires source/dest IPv6", "IPv6 src/dst pairs", "ipv6_srcdst,tree")
_s("ipv6_dests,tree", "hosts", "Destinations IPv6", "IPv6 destinations", "ipv6_dests,tree")
_s("ipv6_ptype,tree", "hosts", "Types de paquets IPv6", "IPv6 packet types", "ipv6_ptype,tree")

_s("http,stat", "http", "Compteurs HTTP (requêtes, codes)", "HTTP counters", "http,stat")
_s("http,tree", "http", "Arbre HTTP (méthodes, hosts, UA…)", "HTTP tree", "http,tree")
_s("http_req,tree", "http", "Requêtes HTTP", "HTTP requests tree", "http_req,tree")
_s("http_srv,tree", "http", "Serveurs HTTP", "HTTP servers tree", "http_srv,tree")
_s("http_seq,tree", "http", "Séquences HTTP", "HTTP sequence tree", "http_seq,tree")
_s("http2,tree", "http", "Arbre HTTP/2", "HTTP/2 tree", "http2,tree")
_s("rtsp,stat", "http", "Compteurs RTSP", "RTSP counters", "rtsp,stat")
_s("rtsp,tree", "http", "Arbre RTSP", "RTSP tree", "rtsp,tree")

_s("follow,tcp", "follow", "Suivre un flux TCP", "Follow TCP stream",
   "follow,tcp,ascii|hex|raw|yaml,<filter|index>", "follow,tcp,ascii,0")
_s("follow,udp", "follow", "Suivre un flux UDP", "Follow UDP stream",
   "follow,udp,ascii|hex|raw,<filter|index>", "follow,udp,ascii,0")
_s("follow,tls", "follow", "Suivre un flux TLS (déchiffré)", "Follow TLS stream",
   "follow,tls,ascii|hex|raw,<filter|index>", "follow,tls,ascii,0")
_s("follow,http", "follow", "Suivre un flux HTTP", "Follow HTTP stream",
   "follow,http,ascii|hex|raw,<filter|index>", "follow,http,ascii,0")
_s("follow,http2", "follow", "Suivre un flux HTTP/2", "Follow HTTP/2 stream",
   "follow,http2,ascii|hex|raw,<filter|index>", "follow,http2,ascii,0")
_s("follow,quic", "follow", "Suivre un flux QUIC", "Follow QUIC stream",
   "follow,quic,ascii|hex|raw,<filter|index>", "follow,quic,ascii,0")
_s("follow,sip", "follow", "Suivre un flux SIP", "Follow SIP stream",
   "follow,sip,ascii|hex|raw,<filter|index>", "follow,sip,ascii,0")

_s("smb,srt", "srt", "SMB Service Response Time", "SMB SRT", "smb,srt")
_s("smb2,srt", "srt", "SMB2 Service Response Time", "SMB2 SRT", "smb2,srt")
_s("dcerpc,srt", "srt", "DCERPC SRT (UUID + version + filter)", "DCERPC SRT",
   "dcerpc,srt,uuid,major.minor[,filter]", "dcerpc,srt,e1af8308-5d1f-11c9-91a4-08002b14a0fa,3.0")
_s("rpc,srt", "srt", "ONC-RPC SRT", "ONC-RPC SRT", "rpc,srt,program,version[,filter]")
_s("rpc,programs", "srt", "Programmes ONC-RPC vus", "ONC-RPC programs", "rpc,programs")
_s("scsi,srt", "srt", "SCSI SRT", "SCSI SRT", "scsi,srt")
_s("fc,srt", "srt", "Fibre Channel SRT", "Fibre Channel SRT", "fc,srt")
_s("ncp,srt", "srt", "NCP SRT", "NCP SRT", "ncp,srt")
_s("ldap,srt", "srt", "LDAP SRT", "LDAP SRT", "ldap,srt")
_s("gtp,srt", "srt", "GTP SRT", "GTP SRT", "gtp,srt")
_s("diameter,srt", "srt", "Diameter SRT", "Diameter SRT", "diameter,srt")
_s("snmp,srt", "srt", "SNMP SRT", "SNMP SRT", "snmp,srt")
_s("icmp,srt", "srt", "ICMP SRT", "ICMP SRT", "icmp,srt[,filter]")
_s("icmpv6,srt", "srt", "ICMPv6 SRT", "ICMPv6 SRT", "icmpv6,srt")
_s("afp,srt", "srt", "AFP SRT", "AFP SRT", "afp,srt")
_s("camel,srt", "srt", "CAMEL SRT", "CAMEL SRT", "camel,srt")
_s("megaco,rtd", "srt", "MEGACO Response Time", "MEGACO RTD", "megaco,rtd")
_s("mgcp,rtd", "srt", "MGCP Response Time", "MGCP RTD", "mgcp,rtd")
_s("radius,rtd", "srt", "RADIUS Response Time", "RADIUS RTD", "radius,rtd")
_s("h225_ras,rtd", "srt", "H.225 RAS RTD", "H.225 RAS RTD", "h225_ras,rtd")

_s("rtp,streams", "voip", "Flux RTP", "RTP streams", "rtp,streams")
_s("sip,stat", "voip", "Statistiques SIP", "SIP statistics", "sip,stat")
_s("smpp_commands,tree", "voip", "Commandes SMPP", "SMPP commands", "smpp_commands,tree")
_s("isup_msg,tree", "voip", "Messages ISUP", "ISUP messages", "isup_msg,tree")
_s("h225,counter", "voip", "Compteurs H.225", "H.225 counters", "h225,counter")
_s("osmux,tree", "voip", "Osmux", "Osmux tree", "osmux,tree")

_s("wlan,stat", "wifi", "Statistiques 802.11 (si disponible)", "802.11 statistics", "mac-lte,stat",
   notes="Selon version : mac-lte,stat / rlc-lte,stat pour le cellulaire.")
_s("mac-lte,stat", "wifi", "MAC LTE", "LTE MAC stats", "mac-lte,stat")
_s("rlc-lte,stat", "wifi", "RLC LTE", "LTE RLC stats", "rlc-lte,stat")

_s("credentials", "auth", "Identifiants extraits par Wireshark", "Credentials harvested by Wireshark",
   "credentials", "credentials",
   "Complémentaire de l'extracteur t2h (HTTP Basic, etc.).")
_s("smb,sids", "auth", "SIDs SMB vus", "SMB SIDs", "smb,sids")

_s("dhcp,stat", "misc", "Statistiques DHCP", "DHCP stats", "dhcp,stat")
_s("diameter,avp", "misc", "AVP Diameter", "Diameter AVPs", "diameter,avp")
_s("sctp,stat", "misc", "Statistiques SCTP", "SCTP stats", "sctp,stat")
_s("sv", "misc", "IEC 61850 Sampled Values", "IEC 61850 SV", "sv")
_s("ansi_map", "misc", "ANSI MAP", "ANSI MAP", "ansi_map")
_s("ansi_a,bsmap", "misc", "ANSI A-I/F BSMAP", "ANSI A BSMAP", "ansi_a,bsmap")
_s("ansi_a,dtap", "misc", "ANSI A-I/F DTAP", "ANSI A DTAP", "ansi_a,dtap")
_s("gsm_a", "misc", "GSM A-I/F", "GSM A-I/F", "gsm_a")
_s("gsm_map,operation", "misc", "GSM MAP operations", "GSM MAP operations", "gsm_map,operation")
_s("camel,counter", "misc", "Compteurs CAMEL", "CAMEL counters", "camel,counter")
_s("collectd,tree", "misc", "collectd", "collectd tree", "collectd,tree")
_s("ancp,tree", "misc", "ANCP", "ANCP tree", "ancp,tree")
_s("hart_ip,tree", "misc", "HART-IP", "HART-IP tree", "hart_ip,tree")
_s("sametime,tree", "misc", "Sametime", "Sametime tree", "sametime,tree")
_s("ucp_messages,tree", "misc", "Messages UCP", "UCP messages", "ucp_messages,tree")
_s("wsp,stat", "misc", "WSP", "WSP stats", "wsp,stat")
_s("mtp3,msus", "misc", "MTP3 MSUs", "MTP3 MSUs", "mtp3,msus")
_s("someip_messages,tree", "misc", "SOME/IP messages", "SOME/IP messages", "someip_messages,tree")
_s("someip_sd_entries,tree", "misc", "SOME/IP-SD entries", "SOME/IP-SD entries", "someip_sd_entries,tree")
_s("f5_tmm_dist,tree", "misc", "F5 TMM distribution", "F5 TMM distribution", "f5_tmm_dist,tree")
_s("f5_virt_dist,tree", "misc", "F5 virtual distribution", "F5 virtual distribution", "f5_virt_dist,tree")
_s("calcappprotocol,stat", "misc", "CalcApp protocol", "CalcApp protocol", "calcappprotocol,stat")
_s("componentstatusprotocol,stat", "misc", "Component Status protocol", "Component Status protocol", "componentstatusprotocol,stat")
_s("fractalgeneratorprotocol,stat", "misc", "Fractal Generator protocol", "Fractal Generator protocol", "fractalgeneratorprotocol,stat")

_s("flow,any,any", "flow", "Graphe de flux any→any", "Any-to-any flow graph", "flow,any,any")
_s("flow,icmp,network", "flow", "Flux ICMP (réseau)", "ICMP network flow", "flow,icmp,network")
_s("flow,icmpv6,network", "flow", "Flux ICMPv6", "ICMPv6 network flow", "flow,icmpv6,network")
_s("flow,tcp,network", "flow", "Flux TCP (réseau)", "TCP network flow", "flow,tcp,network")
_s("flow,udp,network", "flow", "Flux UDP (réseau)", "UDP network flow", "flow,udp,network")

_s("proto,colinfo", "misc", "Ajoute un champ dans la colonne Info", "Add field to Info column",
   "proto,colinfo,filter,field", "proto,colinfo,http,http.host")

for key, fr in (
    ("lbmr_queue_ads_queue,tree", "LBMR queue ads (queue)"),
    ("lbmr_queue_ads_source,tree", "LBMR queue ads (source)"),
    ("lbmr_queue_queries_queue,tree", "LBMR queue queries (queue)"),
    ("lbmr_queue_queries_receiver,tree", "LBMR queue queries (receiver)"),
    ("lbmr_topic_ads_source,tree", "LBMR topic ads (source)"),
    ("lbmr_topic_ads_topic,tree", "LBMR topic ads (topic)"),
    ("lbmr_topic_ads_transport,tree", "LBMR topic ads (transport)"),
    ("lbmr_topic_queries_pattern,tree", "LBMR topic queries (pattern)"),
    ("lbmr_topic_queries_pattern_receiver,tree", "LBMR topic queries (pattern receiver)"),
    ("lbmr_topic_queries_receiver,tree", "LBMR topic queries (receiver)"),
    ("lbmr_topic_queries_topic,tree", "LBMR topic queries (topic)"),
):
    _s(key, "lbm", fr, fr, key)

# Presets « un clic » utilisés par `analyze`
ANALYZE_PRESETS: list[str] = [
    "io,phs",
    "conv,ip",
    "conv,tcp",
    "conv,udp",
    "endpoints,ip",
    "endpoints,tcp",
    "expert",
    "http,stat",
    "dns,tree",
    "hosts",
    "credentials",
    "sip,stat",
    "rtp,streams",
]

def find_stat(query: str) -> list[Stat]:
    q = query.lower().strip()
    if not q:
        return list(STAT_CATALOG)
    return [
        s
        for s in STAT_CATALOG
        if q in s["key"].lower() or q in s["group"].lower() or q in s["fr"].lower() or q in s["en"].lower()
    ]

def stats_by_group() -> dict[str, list[Stat]]:
    out: dict[str, list[Stat]] = {}
    for s in STAT_CATALOG:
        out.setdefault(s["group"], []).append(s)
    return out

def known_stat_keys() -> list[str]:
    return [s["key"] for s in STAT_CATALOG]

Filter = dict[str, str]
FILTER_LIB: list[Filter] = []

def _f(name: str, group: str, expr: str, fr: str, en: str = "") -> None:
    FILTER_LIB.append({"name": name, "group": group, "expr": expr, "fr": fr, "en": en or fr})

_f("ntlmssp", "auth", "ntlmssp", "Tout NTLMSSP (challenge + auth)")
_f("ntlm_auth", "auth", "ntlmssp.messagetype == 0x00000003", "NTLMSSP AUTH (type 3) uniquement")
_f("ntlm_chal", "auth", "ntlmssp.messagetype == 0x00000002", "NTLMSSP CHALLENGE (type 2)")
_f("ntlm_neg", "auth", "ntlmssp.messagetype == 0x00000001", "NTLMSSP NEGOTIATE (type 1)")
_f("kerberos", "auth", "kerberos", "Tout Kerberos")
_f("krb_asreq", "auth", "kerberos.msg_type == 10", "Kerberos AS-REQ (pré-auth / timestamp)")
_f("krb_asrep", "auth", "kerberos.msg_type == 11", "Kerberos AS-REP (AS-REP roast)")
_f("krb_tgsreq", "auth", "kerberos.msg_type == 12", "Kerberos TGS-REQ")
_f("krb_tgsrep", "auth", "kerberos.msg_type == 13", "Kerberos TGS-REP (Kerberoast)")
_f("krb_apreq", "auth", "kerberos.msg_type == 14", "Kerberos AP-REQ")
_f("krb_error", "auth", "kerberos.msg_type == 30", "Kerberos ERROR")
_f("ldap_bind", "auth", "ldap.protocolOp == 0", "LDAP Bind")
_f("ldap_simple", "auth", "ldap.authentication.simple", "LDAP Simple Bind (mot de passe en clair !)")
_f("http_basic", "auth", "http.authorization matches \"Basic\"", "HTTP Basic")
_f("http_digest", "auth", "http.authorization matches \"Digest\"", "HTTP Digest")
_f("http_ntlm", "auth", "http.authorization matches \"NTLM\" or http.authorization matches \"Negotiate\"", "HTTP NTLM / Negotiate")
_f("http_auth", "auth", "http.authorization", "Toute Authorization HTTP")
_f("smb_ntlm", "auth", "smb or smb2 and ntlmssp", "NTLM encapsulé SMB")
_f("tacacs", "auth", "tacacs", "TACACS+")
_f("radius", "auth", "radius", "RADIUS")
_f("diameter", "auth", "diameter", "Diameter")
_f("eap", "auth", "eap", "EAP (802.1X)")
_f("eapol", "auth", "eapol", "EAPOL (handshake WPA)")
_f("wpa_hs", "auth", "eapol && wlan", "Handshake WPA (EAPOL sur 802.11)")
_f("pmkid", "auth", "wlan.rsn.ie.pmkid", "PMKID (RSN IE)")
_f("chap", "auth", "chap or ppp.chap", "CHAP / PPP-CHAP")
_f("pap", "auth", "pap or ppp.pap", "PAP (mot de passe en clair)")
_f("ike", "auth", "isakmp", "ISAKMP / IKE")
_f("ipmi", "auth", "ipmi", "IPMI")
_f("snmpv3", "auth", "snmp.msgVersion == 3", "SNMPv3")
_f("sip_auth", "auth", "sip.Authorization or sip.WWW-Authenticate", "SIP Digest")
_f("apop", "auth", "pop.request.command == \"APOP\"", "APOP (POP3)")
_f("cram", "auth", "smtp.req.parameter matches \"CRAM\" or imap.request matches \"CRAM\"", "CRAM-MD5")
_f("plain_auth", "auth", "smtp.req.parameter matches \"PLAIN\" or imap.request matches \"PLAIN\"", "AUTH PLAIN")

_f("ftp", "clear", "ftp", "FTP")
_f("ftp_auth", "clear", "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"", "FTP USER/PASS")
_f("telnet", "clear", "telnet", "Telnet")
_f("http", "clear", "http", "HTTP")
_f("http_post", "clear", "http.request.method == \"POST\"", "HTTP POST")
_f("http_get", "clear", "http.request.method == \"GET\"", "HTTP GET")
_f("smtp", "clear", "smtp", "SMTP")
_f("imap", "clear", "imap", "IMAP")
_f("pop", "clear", "pop", "POP3")
_f("http_form", "clear", "urlencoded-form or http.file_data matches \"password=\"", "Formulaires HTTP")

_f("smb", "windows", "smb || smb2", "SMB / SMB2")
_f("smb2", "windows", "smb2", "SMB2 uniquement")
_f("dcerpc", "windows", "dcerpc", "DCERPC")
_f("lsarpc", "windows", "lsarpc", "LSARPC")
_f("samr", "windows", "samr", "SAMR")
_f("netlogon", "windows", "netlogon", "Netlogon")
_f("drsuapi", "windows", "drsuapi", "DRSUAPI (DCSync)")
_f("spoolss", "windows", "spoolss", "Print Spooler")
_f("rdp", "windows", "tpkt or cotp or rdp", "RDP (approximation)")
_f("winrm", "windows", "http.host matches \"wsman\" or http.request.uri matches \"wsman\"", "WinRM")
_f("winreg", "windows", "winreg", "Remote Registry")
_f("svcctl", "windows", "svcctl", "Service Control")
_f("atsvc", "windows", "atsvc", "Task Scheduler")
_f("browser", "windows", "browser", "Browser / NetBIOS")
_f("nbns", "windows", "nbns", "NetBIOS Name Service")
_f("llmnr", "windows", "llmnr", "LLMNR (usurpation fréquente)")
_f("mdns", "windows", "mdns or dns.qry.name matches \".local\"", "mDNS")
_f("kpasswd", "windows", "kpasswd", "Kerberos password change")

_f("tls", "web", "tls", "TLS")
_f("tls_hs", "web", "tls.handshake", "TLS Handshake")
_f("tls_alert", "web", "tls.alert_message", "TLS Alerts")
_f("sni", "web", "tls.handshake.extensions_server_name", "SNI (Server Name Indication)")
_f("http2", "web", "http2", "HTTP/2")
_f("quic", "web", "quic", "QUIC")
_f("dns", "web", "dns", "DNS")
_f("dns_query", "web", "dns.flags.response == 0", "Requêtes DNS")
_f("dns_resp", "web", "dns.flags.response == 1", "Réponses DNS")
_f("dns_txt", "web", "dns.resp.type == 16", "DNS TXT")
_f("doh", "web", "tls.handshake.extensions_server_name matches \"dns\" and tcp.port == 443", "DoH approximatif")

_f("mail", "mail", "smtp or imap or pop or imf", "Tout mail")
_f("imf", "mail", "imf", "Internet Message Format")

_f("ospf", "infra", "ospf", "OSPF (souvent crypto-auth LLS → pas hashcat)")
_f("bgp", "infra", "bgp", "BGP")
_f("vrrp", "infra", "vrrp", "VRRP")
_f("hsrp", "infra", "hsrp", "HSRP")
_f("eigrp", "infra", "eigrp", "EIGRP")
_f("pim", "infra", "pim", "PIM")
_f("igmp", "infra", "igmp", "IGMP")
_f("icmp", "infra", "icmp", "ICMP")
_f("icmpv6", "infra", "icmpv6", "ICMPv6")
_f("arp", "infra", "arp", "ARP")
_f("ndp", "infra", "icmpv6.type == 133 or icmpv6.type == 134 or icmpv6.type == 135 or icmpv6.type == 136", "IPv6 NDP")
_f("dhcp", "infra", "dhcp or bootp", "DHCP / BOOTP")
_f("dhcpv6", "infra", "dhcpv6", "DHCPv6")
_f("ntp", "infra", "ntp", "NTP")
_f("snmp", "infra", "snmp", "SNMP")
_f("ssdp", "infra", "ssdp or http.host matches \"239.255.255.250\"", "SSDP")
_f("cdp", "infra", "cdp", "Cisco Discovery Protocol")
_f("lldp", "infra", "lldp", "LLDP")
_f("stp", "infra", "stp", "Spanning Tree")

_f("mysql", "db", "mysql", "MySQL")
_f("pgsql", "db", "pgsql", "PostgreSQL")
_f("tds", "db", "tds", "TDS (MSSQL)")
_f("mongodb", "db", "mongo", "MongoDB")
_f("redis", "db", "redis", "Redis")

_f("ssh", "remote", "ssh", "SSH")
_f("vnc", "remote", "vnc or rfb", "VNC / RFB")
_f("x11", "remote", "x11", "X11")

_f("sip", "voip", "sip", "SIP")
_f("rtp", "voip", "rtp", "RTP")
_f("rtcp", "voip", "rtcp", "RTCP")
_f("sdp", "voip", "sdp", "SDP")
_f("h323", "voip", "h225 or h245", "H.323")
_f("mgcp", "voip", "mgcp", "MGCP")
_f("skinny", "voip", "skinny", "Cisco Skinny")

_f("modbus", "ot", "modbus", "Modbus")
_f("s7comm", "ot", "s7comm", "Siemens S7")
_f("dnp3", "ot", "dnp3", "DNP3")
_f("iec104", "ot", "iec104", "IEC 60870-5-104")
_f("opcua", "ot", "opcua", "OPC UA")
_f("bacnet", "ot", "bacnet", "BACnet")
_f("enip", "ot", "enip", "EtherNet/IP")

_f("wlan", "wifi", "wlan", "Tout 802.11")
_f("wlan_beacon", "wifi", "wlan.fc.type_subtype == 0x0008", "Beacons")
_f("wlan_probe", "wifi", "wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x0005", "Probe req/resp")
_f("wlan_deauth", "wifi", "wlan.fc.type_subtype == 0x000c", "Deauth")
_f("wlan_data", "wifi", "wlan.fc.type == 2", "Data frames")
_f("wlan_mgmt", "wifi", "wlan.fc.type == 0", "Management frames")

_f("tcp_retrans", "triage", "tcp.analysis.retransmission", "Retransmissions TCP")
_f("tcp_rst", "triage", "tcp.flags.reset == 1", "TCP RST")
_f("tcp_syn", "triage", "tcp.flags.syn == 1 and tcp.flags.ack == 0", "TCP SYN")
_f("tcp_synack", "triage", "tcp.flags.syn == 1 and tcp.flags.ack == 1", "TCP SYN-ACK")
_f("small_ttl", "triage", "ip.ttl < 5", "TTL très bas (traceroute / anomaly)")
_f("frag", "triage", "ip.flags.mf == 1 or ip.frag_offset > 0", "Fragments IP")
_f("icmp_unreach", "triage", "icmp.type == 3", "ICMP unreachable")
_f("large", "triage", "frame.len > 1400", "Paquets > 1400 o")
_f("broadcast", "triage", "eth.dst == ff:ff:ff:ff:ff:ff", "Broadcast Ethernet")
_f("multicast", "triage", "eth.dst[0] & 1", "Multicast Ethernet")

_f("auth_all", "combo",
   "ntlmssp or kerberos or http.authorization or ftp.request.command == \"PASS\" or pop.request.command == \"APOP\" or ldap.authentication.simple or eapol or sip.Authorization",
   "Tout ce qui ressemble à de l'authentification")
_f("cleartext_all", "combo",
   "ftp or telnet or http or smtp or imap or pop or ldap.authentication.simple",
   "Protocoles potentiellement en clair")
_f("ad_core", "combo",
   "kerberos or ldap or smb or smb2 or ntlmssp or dns or cldap",
   "Cœur Active Directory")
_f("secrets", "combo",
   "http.authorization or http.cookie or http.file_data matches \"password\" or jwt or ntlmssp or kerberos",
   "Secrets / tokens / hashes")

# Champs fréquemment extraits (-e)
COMMON_FIELDS: list[tuple[str, str]] = [
    ("frame.number", "N° de trame"),
    ("frame.time", "Horodatage"),
    ("frame.time_epoch", "Epoch"),
    ("frame.len", "Taille"),
    ("frame.protocols", "Pile de protocoles"),
    ("eth.src", "MAC source"),
    ("eth.dst", "MAC dest"),
    ("ip.src", "IPv4 source"),
    ("ip.dst", "IPv4 dest"),
    ("ipv6.src", "IPv6 source"),
    ("ipv6.dst", "IPv6 dest"),
    ("ip.proto", "Protocole IP"),
    ("tcp.srcport", "Port TCP src"),
    ("tcp.dstport", "Port TCP dst"),
    ("tcp.stream", "Index de flux TCP"),
    ("tcp.flags", "Flags TCP"),
    ("udp.srcport", "Port UDP src"),
    ("udp.dstport", "Port UDP dst"),
    ("udp.stream", "Index de flux UDP"),
    ("http.host", "Host HTTP"),
    ("http.request.method", "Méthode HTTP"),
    ("http.request.uri", "URI HTTP"),
    ("http.response.code", "Code HTTP"),
    ("http.user_agent", "User-Agent"),
    ("http.authorization", "Authorization"),
    ("http.cookie", "Cookie"),
    ("http.file_data", "Corps HTTP"),
    ("tls.handshake.extensions_server_name", "SNI TLS"),
    ("dns.qry.name", "Nom DNS demandé"),
    ("dns.resp.name", "Nom DNS répondu"),
    ("dns.a", "DNS A"),
    ("dns.aaaa", "DNS AAAA"),
    ("kerberos.CNameString", "Kerberos client name"),
    ("kerberos.realm", "Kerberos realm"),
    ("kerberos.msg_type", "Kerberos msg-type"),
    ("kerberos.SNameString", "Kerberos sname"),
    ("kerberos.etype", "Kerberos etype"),
    ("ntlmssp.auth.username", "NTLM user"),
    ("ntlmssp.auth.domain", "NTLM domain"),
    ("ntlmssp.ntlmserverchallenge", "NTLM challenge"),
    ("ntlmssp.auth.ntresponse", "NTLM NT response"),
    ("wlan.ssid", "SSID"),
    ("wlan.sa", "WLAN SA"),
    ("wlan.da", "WLAN DA"),
    ("wlan.bssid", "BSSID"),
    ("eapol.keydes.mic", "EAPOL MIC"),
    ("eapol.keydes.nonce", "EAPOL nonce"),
    ("ftp.request.command", "Commande FTP"),
    ("ftp.request.arg", "Argument FTP"),
    ("smtp.req.command", "Commande SMTP"),
    ("sip.Method", "Méthode SIP"),
    ("sip.From", "SIP From"),
    ("sip.To", "SIP To"),
    ("smb2.filename", "Nom de fichier SMB2"),
    ("smb2.cmd", "Commande SMB2"),
    ("ldap.simple", "LDAP simple bind password"),
    ("ldap.name", "LDAP name"),
]

DEFAULT_PACKET_FIELDS = [
    "frame.number",
    "frame.time",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.protocols",
    "_ws.col.Info",
]

def filters_by_group() -> dict[str, list[Filter]]:
    out: dict[str, list[Filter]] = {}
    for f in FILTER_LIB:
        out.setdefault(f["group"], []).append(f)
    return out

def find_filter(query: str) -> list[Filter]:
    q = query.lower().strip()
    if not q:
        return list(FILTER_LIB)
    return [
        f
        for f in FILTER_LIB
        if q in f["name"].lower()
        or q in f["group"].lower()
        or q in f["expr"].lower()
        or q in f["fr"].lower()
        or q in f["en"].lower()
    ]

def get_filter(name: str) -> Filter | None:
    for f in FILTER_LIB:
        if f["name"] == name:
            return f
    return None

Field = dict[str, str]
FIELD_CATALOG: list[Field] = []

def _fld(name: str, group: str, ftype: str, fr: str, hint: str = "") -> None:
    FIELD_CATALOG.append(
        {"name": name, "group": group, "type": ftype, "fr": fr, "hint": hint}
    )

_fld("frame.number", "frame", "uint", "Numéro de trame (1-based)")
_fld("frame.time", "frame", "absolute time", "Horodatage local")
_fld("frame.time_epoch", "frame", "double", "Horodatage UNIX")
_fld("frame.time_delta", "frame", "rel time", "Delta depuis le paquet précédent")
_fld("frame.time_relative", "frame", "rel time", "Delta depuis le 1er paquet")
_fld("frame.len", "frame", "uint", "Taille capturée")
_fld("frame.cap_len", "frame", "uint", "Octets réellement capturés (snaplen)")
_fld("frame.marked", "frame", "bool", "Paquet marqué")
_fld("frame.ignored", "frame", "bool", "Paquet ignoré")
_fld("frame.protocols", "frame", "string", "Pile proto (eth:ethertype:ip:tcp:http)")
_fld("frame.coloring_rule.name", "frame", "string", "Règle de couleur Wireshark")
_fld("_ws.col.Info", "frame", "string", "Colonne Info (résumé humain)")
_fld("_ws.col.Protocol", "frame", "string", "Colonne Protocol")
_fld("_ws.col.Source", "frame", "string", "Colonne Source")
_fld("_ws.col.Destination", "frame", "string", "Colonne Destination")

_fld("eth.src", "eth", "ether", "MAC source")
_fld("eth.dst", "eth", "ether", "MAC destination")
_fld("eth.type", "eth", "uint16", "Ethertype")
_fld("eth.addr", "eth", "ether", "N'importe quelle MAC")
_fld("vlan.id", "eth", "uint", "VLAN ID")
_fld("vlan.priority", "eth", "uint", "PCP")
_fld("wlan.sa", "wifi", "ether", "Source Address 802.11")
_fld("wlan.da", "wifi", "ether", "Destination Address 802.11")
_fld("wlan.ta", "wifi", "ether", "Transmitter Address")
_fld("wlan.ra", "wifi", "ether", "Receiver Address")
_fld("wlan.bssid", "wifi", "ether", "BSSID")
_fld("wlan.ssid", "wifi", "string", "SSID (beacon / probe / assoc)")
_fld("wlan.fc.type", "wifi", "uint", "Type (0 mgmt, 1 ctrl, 2 data)")
_fld("wlan.fc.type_subtype", "wifi", "uint", "Type+subtype")
_fld("wlan.fc.retry", "wifi", "bool", "Retry flag")
_fld("wlan.rsn.ie.pmkid", "wifi", "bytes", "PMKID (hashcat 22000 WPA*01*)", "hex 16 o")
_fld("wlan.fixed.reason_code", "wifi", "uint", "Reason code (deauth/disassoc)")
_fld("radiotap.dbm_antsignal", "wifi", "int", "RSSI (dBm)")
_fld("wlan_radio.signal_dbm", "wifi", "int", "Signal dBm (dissecteur radio)")
_fld("wlan_radio.channel", "wifi", "uint", "Canal")

_fld("ip.src", "ip", "ipv4", "IPv4 source")
_fld("ip.dst", "ip", "ipv4", "IPv4 dest")
_fld("ip.addr", "ip", "ipv4", "N'importe quelle IPv4")
_fld("ip.proto", "ip", "uint8", "Protocole (6=TCP, 17=UDP, 1=ICMP)")
_fld("ip.ttl", "ip", "uint8", "TTL")
_fld("ip.id", "ip", "uint16", "Identification (fragments)")
_fld("ip.flags.mf", "ip", "bool", "More Fragments")
_fld("ip.frag_offset", "ip", "uint", "Offset de fragment")
_fld("ip.dsfield.dscp", "ip", "uint", "DSCP")
_fld("ip.len", "ip", "uint", "Longueur totale")
_fld("ipv6.src", "ip", "ipv6", "IPv6 source")
_fld("ipv6.dst", "ip", "ipv6", "IPv6 dest")
_fld("ipv6.nxt", "ip", "uint", "Next header")
_fld("ipv6.hlim", "ip", "uint", "Hop limit")

_fld("tcp.srcport", "tcp", "uint16", "Port source TCP")
_fld("tcp.dstport", "tcp", "uint16", "Port dest TCP")
_fld("tcp.port", "tcp", "uint16", "N'importe quel port TCP")
_fld("tcp.stream", "tcp", "uint", "Index de flux (follow,tcp)")
_fld("tcp.seq", "tcp", "uint32", "Sequence number")
_fld("tcp.ack", "tcp", "uint32", "Ack number")
_fld("tcp.flags", "tcp", "uint", "Flags (bitfield)")
_fld("tcp.flags.syn", "tcp", "bool", "SYN")
_fld("tcp.flags.ack", "tcp", "bool", "ACK")
_fld("tcp.flags.fin", "tcp", "bool", "FIN")
_fld("tcp.flags.reset", "tcp", "bool", "RST")
_fld("tcp.flags.push", "tcp", "bool", "PSH")
_fld("tcp.analysis.retransmission", "tcp", "none", "Retransmission détectée")
_fld("tcp.analysis.fast_retransmission", "tcp", "none", "Fast retransmit")
_fld("tcp.analysis.duplicate_ack", "tcp", "none", "Duplicate ACK")
_fld("tcp.analysis.zero_window", "tcp", "none", "Zero window")
_fld("tcp.window_size_value", "tcp", "uint", "Fenêtre")
_fld("tcp.len", "tcp", "uint", "Longueur payload")
_fld("tcp.payload", "tcp", "bytes", "Payload TCP")
_fld("udp.srcport", "udp", "uint16", "Port source UDP")
_fld("udp.dstport", "udp", "uint16", "Port dest UDP")
_fld("udp.port", "udp", "uint16", "N'importe quel port UDP")
_fld("udp.stream", "udp", "uint", "Index de flux UDP")
_fld("udp.length", "udp", "uint", "Longueur UDP")
_fld("sctp.srcport", "sctp", "uint16", "Port SCTP src")
_fld("sctp.dstport", "sctp", "uint16", "Port SCTP dst")

_fld("http.host", "http", "string", "Host")
_fld("http.request.method", "http", "string", "GET/POST/…")
_fld("http.request.uri", "http", "string", "URI")
_fld("http.request.full_uri", "http", "string", "URI complète")
_fld("http.request.version", "http", "string", "HTTP/1.0 / 1.1")
_fld("http.response.code", "http", "uint", "Code statut")
_fld("http.response.phrase", "http", "string", "Phrase statut")
_fld("http.user_agent", "http", "string", "User-Agent")
_fld("http.authorization", "http", "string", "Authorization (Basic/Digest/NTLM/Bearer)")
_fld("http.proxy_authorization", "http", "string", "Proxy-Authorization")
_fld("http.cookie", "http", "string", "Cookie")
_fld("http.set_cookie", "http", "string", "Set-Cookie")
_fld("http.content_type", "http", "string", "Content-Type")
_fld("http.content_length", "http", "uint", "Content-Length")
_fld("http.location", "http", "string", "Location (redirect)")
_fld("http.referer", "http", "string", "Referer")
_fld("http.file_data", "http", "bytes", "Corps (souvent form-urlencoded)")
_fld("http.request.line", "http", "string", "Ligne de requête brute")
_fld("urlencoded-form.key", "http", "string", "Clé de formulaire")
_fld("urlencoded-form.value", "http", "string", "Valeur de formulaire")
_fld("http2.headers.method", "http", "string", "Méthode HTTP/2")
_fld("http2.headers.path", "http", "string", ":path HTTP/2")
_fld("http2.headers.authority", "http", "string", ":authority HTTP/2")
_fld("http2.headers.status", "http", "string", ":status HTTP/2")

_fld("tls.handshake.type", "tls", "uint", "Type handshake")
_fld("tls.handshake.version", "tls", "uint", "Version annoncée")
_fld("tls.handshake.extensions_server_name", "tls", "string", "SNI")
_fld("tls.handshake.ciphersuite", "tls", "uint", "Cipher suite choisie")
_fld("tls.handshake.certificate", "tls", "bytes", "Certificat")
_fld("tls.handshake.ja3", "tls", "string", "JA3 (si plugin)")
_fld("tls.handshake.ja3s", "tls", "string", "JA3S")
_fld("tls.record.content_type", "tls", "uint", "Content type")
_fld("tls.alert_message.desc", "tls", "uint", "Alerte TLS")
_fld("tls.app_data", "tls", "bytes", "Application data (chiffré)")

_fld("dns.qry.name", "dns", "string", "Nom demandé")
_fld("dns.qry.type", "dns", "uint", "Type (1=A, 28=AAAA, 16=TXT…)")
_fld("dns.resp.name", "dns", "string", "Nom en réponse")
_fld("dns.flags.response", "dns", "bool", "1 = réponse")
_fld("dns.flags.rcode", "dns", "uint", "RCODE")
_fld("dns.a", "dns", "ipv4", "Enregistrement A")
_fld("dns.aaaa", "dns", "ipv6", "Enregistrement AAAA")
_fld("dns.cname", "dns", "string", "CNAME")
_fld("dns.mx.mail_exchange", "dns", "string", "MX")
_fld("dns.txt", "dns", "string", "TXT")
_fld("dns.srv.target", "dns", "string", "SRV target")
_fld("dns.id", "dns", "uint", "Transaction ID")

_fld("ntlmssp.messagetype", "ntlm", "uint", "1=NEG, 2=CHAL, 3=AUTH")
_fld("ntlmssp.ntlmserverchallenge", "ntlm", "bytes", "Challenge 8 o", "hashcat 5500/5600")
_fld("ntlmssp.auth.username", "ntlm", "string", "Username type 3")
_fld("ntlmssp.auth.domain", "ntlm", "string", "Domain type 3")
_fld("ntlmssp.auth.hostname", "ntlm", "string", "Hostname client")
_fld("ntlmssp.auth.lmresponse", "ntlm", "bytes", "LM response")
_fld("ntlmssp.auth.ntresponse", "ntlm", "bytes", "NT response (v1=24o, v2>24o)")
_fld("ntlmssp.negotiate.flags", "ntlm", "uint", "Flags")
_fld("ntlmssp.version", "ntlm", "string", "Version OS annoncée")
_fld("ntlmssp.target_name", "ntlm", "string", "Target name (type 2)")
_fld("ntlmssp.ntlmserverchallenge.ntlmv2", "ntlm", "bytes", "Alias challenge")

_fld("kerberos.msg_type", "krb", "uint", "10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 30 ERROR")
_fld("kerberos.CNameString", "krb", "string", "Client name (user)")
_fld("kerberos.cname-string", "krb", "string", "Alias cname")
_fld("kerberos.crealm", "krb", "string", "Client realm")
_fld("kerberos.realm", "krb", "string", "Realm")
_fld("kerberos.SNameString", "krb", "string", "Service name (partie de SPN)")
_fld("kerberos.sname-string", "krb", "string", "Alias sname")
_fld("kerberos.etype", "krb", "uint", "17 AES128, 18 AES256, 23 RC4")
_fld("kerberos.enctype", "krb", "uint", "Alias etype")
_fld("kerberos.salt", "krb", "string", "Salt ETYPE_INFO2 (casse exacte UPN)")
_fld("kerberos.PA_ENC_TIMESTAMP_cipher", "krb", "bytes", "Timestamp chiffré AS-REQ", "7500/19800/19900")
_fld("kerberos.PA_ENC_TIMESTAMP_etype", "krb", "uint", "etype du timestamp")
_fld("kerberos.encryptedKDCREPData_cipher", "krb", "bytes", "enc-part AS-REP/TGS-REP", "18200/32100/32200")
_fld("kerberos.encryptedTicketData_cipher", "krb", "bytes", "Ticket chiffré", "13100/19600/19700")
_fld("kerberos.error_code", "krb", "uint", "Code d'erreur Kerberos")
_fld("kerberos.ticket_rvno", "krb", "uint", "kvno du ticket")

_fld("smb.cmd", "smb", "uint", "Commande SMB1")
_fld("smb.path", "smb", "string", "Chemin SMB1")
_fld("smb.file", "smb", "string", "Fichier SMB1")
_fld("smb.auth.username", "smb", "string", "User SMB1")
_fld("smb2.cmd", "smb", "uint", "Commande SMB2 (0 neg, 1 sess, 3 tree, 5 create…)")
_fld("smb2.filename", "smb", "string", "Nom de fichier SMB2")
_fld("smb2.tree", "smb", "string", "Share (\\\\srv\\share)")
_fld("smb2.sesid", "smb", "uint", "Session ID")
_fld("smb2.nt_status", "smb", "uint", "NTSTATUS")
_fld("smb2.ioctl.function", "smb", "uint", "IOCTL")

_fld("ldap.name", "ldap", "string", "Bind DN / name")
_fld("ldap.simple", "ldap", "string", "Mot de passe simple bind (CLAIR)")
_fld("ldap.protocolOp", "ldap", "uint", "0 bind, 3 search, 2 unbind…")
_fld("ldap.baseObject", "ldap", "string", "Base DN search")
_fld("ldap.filter", "ldap", "string", "Filtre search")
_fld("ldap.AttributeDescription", "ldap", "string", "Attribut demandé")
_fld("ldap.AttributeValue", "ldap", "string", "Valeur renvoyée")

_fld("ftp.request.command", "mail", "string", "USER/PASS/RETR/STOR…")
_fld("ftp.request.arg", "mail", "string", "Argument")
_fld("ftp.response.code", "mail", "uint", "Code FTP")
_fld("telnet.data", "mail", "string", "Données Telnet")
_fld("smtp.req.command", "mail", "string", "EHLO/AUTH/MAIL…")
_fld("smtp.req.parameter", "mail", "string", "Paramètre (PLAIN, LOGIN…)")
_fld("smtp.response.code", "mail", "uint", "Code SMTP")
_fld("imap.request", "mail", "string", "Requête IMAP")
_fld("imap.request.command", "mail", "string", "Commande IMAP")
_fld("pop.request.command", "mail", "string", "USER/PASS/APOP/RETR")
_fld("pop.request.parameter", "mail", "string", "Paramètre POP")
_fld("imf.from", "mail", "string", "From:")
_fld("imf.to", "mail", "string", "To:")
_fld("imf.subject", "mail", "string", "Subject:")

_fld("sip.Method", "voip", "string", "INVITE/REGISTER/…")
_fld("sip.From", "voip", "string", "From")
_fld("sip.To", "voip", "string", "To")
_fld("sip.Call-ID", "voip", "string", "Call-ID")
_fld("sip.Contact", "voip", "string", "Contact")
_fld("sip.User-Agent", "voip", "string", "User-Agent")
_fld("sip.Authorization", "voip", "string", "Digest auth", "11400")
_fld("sip.WWW-Authenticate", "voip", "string", "Challenge digest")
_fld("sdp.connection_info.address", "voip", "string", "IP média SDP")
_fld("rtp.ssrc", "voip", "uint", "SSRC")
_fld("rtp.p_type", "voip", "uint", "Payload type")

_fld("eapol.type", "wpa", "uint", "Type EAPOL")
_fld("eapol.keydes.key_info", "wpa", "uint", "Key info (msg 1/2/3/4)")
_fld("eapol.keydes.nonce", "wpa", "bytes", "ANonce / SNonce")
_fld("eapol.keydes.mic", "wpa", "bytes", "MIC")
_fld("eapol.keydes.replay_counter", "wpa", "uint", "Replay counter")
_fld("wlan_rsna_eapol.keydes.mic", "wpa", "bytes", "MIC (alias)")
_fld("wlan_rsna_eapol.keydes.nonce", "wpa", "bytes", "Nonce (alias)")
_fld("wlan_rsna_eapol.keydes.pmkid", "wpa", "bytes", "PMKID dans EAPOL M1")

_fld("dhcp.option.hostname", "infra", "string", "Hostname DHCP")
_fld("dhcp.option.domain_name", "infra", "string", "Domain DHCP")
_fld("dhcp.ip.client", "infra", "ipv4", "Requested / assigned IP")
_fld("dhcp.option.dhcp", "infra", "uint", "Message type (1 disc, 2 offer…)")
_fld("arp.src.proto_ipv4", "infra", "ipv4", "IP source ARP")
_fld("arp.dst.proto_ipv4", "infra", "ipv4", "IP cible ARP")
_fld("arp.src.hw_mac", "infra", "ether", "MAC source ARP")
_fld("icmp.type", "infra", "uint", "Type ICMP")
_fld("icmp.code", "infra", "uint", "Code ICMP")

_fld("snmp.community", "authp", "string", "Community SNMPv1/v2c (clair !)")
_fld("snmp.msgUserName", "authp", "string", "User SNMPv3")
_fld("snmp.v3.auth_param", "authp", "bytes", "authParameter SNMPv3", "25000+")
_fld("isakmp.exchangetype", "authp", "uint", "Type d'échange IKE")
_fld("radius.User_Name", "authp", "string", "User-Name RADIUS")
_fld("radius.User_Password", "authp", "bytes", "User-Password (chiffré shared-secret)")
_fld("radius.Calling_Station_Id", "authp", "string", "Calling-Station-Id")
_fld("tacacs.username", "authp", "string", "User TACACS+")
_fld("tacacs.password", "authp", "string", "Password (si non chiffré)")

_fld("mysql.user", "db", "string", "User MySQL")
_fld("mysql.passwd", "db", "bytes", "Scramble MySQL")
_fld("pgsql.user", "db", "string", "User PostgreSQL")
_fld("pgsql.password", "db", "string", "Password PG (si clair)")
_fld("tds.username", "db", "string", "User MSSQL")

_fld("ssh.protocol", "remote", "string", "Bannière SSH")
_fld("vnc.auth_challenge", "remote", "bytes", "Challenge VNC")
_fld("vnc.auth_response", "remote", "bytes", "Réponse VNC")

def fields_by_group() -> dict[str, list[Field]]:
    out: dict[str, list[Field]] = {}
    for f in FIELD_CATALOG:
        out.setdefault(f["group"], []).append(f)
    return out

def find_fields(query: str) -> list[Field]:
    q = query.lower().strip()
    if not q:
        return list(FIELD_CATALOG)
    return [
        f
        for f in FIELD_CATALOG
        if q in f["name"].lower() or q in f["group"].lower() or q in f["fr"].lower()
    ]

# Presets d'export (-e …) prêts à l'emploi
FIELD_PRESETS: dict[str, list[str]] = {
    "minimal": ["frame.number", "frame.time", "ip.src", "ip.dst", "frame.protocols", "_ws.col.Info"],
    "l4": [
        "frame.number", "frame.time", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags", "frame.len",
    ],
    "http": [
        "frame.number", "ip.src", "ip.dst", "http.request.method", "http.host",
        "http.request.uri", "http.response.code", "http.user_agent", "http.authorization",
    ],
    "dns": ["frame.number", "ip.src", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.flags.rcode"],
    "tls": [
        "frame.number", "ip.src", "ip.dst", "tls.handshake.extensions_server_name",
        "tls.handshake.version", "tls.handshake.ciphersuite",
    ],
    "ntlm": [
        "frame.number", "ip.src", "ip.dst", "ntlmssp.messagetype", "ntlmssp.auth.username",
        "ntlmssp.auth.domain", "ntlmssp.ntlmserverchallenge",
    ],
    "kerberos": [
        "frame.number", "ip.src", "ip.dst", "kerberos.msg_type", "kerberos.CNameString",
        "kerberos.realm", "kerberos.SNameString", "kerberos.etype", "kerberos.salt",
    ],
    "smb": ["frame.number", "ip.src", "ip.dst", "smb2.cmd", "smb2.filename", "smb2.tree", "smb2.nt_status"],
    "wifi": ["frame.number", "wlan.sa", "wlan.da", "wlan.bssid", "wlan.ssid", "wlan.fc.type_subtype"],
    "voip": ["frame.number", "ip.src", "sip.Method", "sip.From", "sip.To", "sip.Call-ID", "sip.Authorization"],
}

@dataclass
class ExportRequest:
    output: str                          # hashes.txt  (préfixe + ext)
    formats: list[str] = field(default_factory=lambda: ["txt"])
    wordlist: str = "wordlist.txt"
    source_pcap: str = ""
    elapsed: float = 0.0
    extra_sheets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

@dataclass
class ExportArtifact:
    kind: str
    path: str
    count: int = 0
    note: str = ""

def _base(req: ExportRequest) -> Path:
    p = Path(req.output)
    if p.suffix.lower() in {".txt", ".csv", ".json", ".xlsx", ".html", ".htm", ".md"}:
        return p.with_suffix("")
    return p

def export_all(result: ExtractResult, req: ExportRequest) -> list[ExportArtifact]:
    """Écrit tous les formats demandés. Retourne la liste des fichiers créés."""
    arts: list[ExportArtifact] = []
    base = _base(req)
    ensure_parent(base)
    formats = [f.lower().lstrip(".") for f in req.formats] or ["xlsx"]

    if "txt" in formats and result.total():
        arts.extend(_write_txt(result, req, base))
    if "csv" in formats:
        arts.append(_write_csv(result, req, base.with_suffix(".csv")))
    if "json" in formats:
        arts.append(_write_json(result, req, base.with_suffix(".json")))
    if "xlsx" in formats or "excel" in formats or "xls" in formats:
        arts.append(_write_xlsx(result, req, base.with_suffix(".xlsx")))
    if "html" in formats or "htm" in formats:
        arts.append(_write_html(result, req, base.with_suffix(".html")))
    if "md" in formats or "markdown" in formats:
        arts.append(_write_md(result, req, base.with_suffix(".md")))
    # pas de fichiers annexes : tout va dans l'Excel

    return arts

def _write_txt(result: ExtractResult, req: ExportRequest, base: Path) -> list[ExportArtifact]:
    """Un fichier .txt par mode Hashcat (prêt à lancer : hashcat -m MODE fichier.txt)."""
    arts: list[ExportArtifact] = []
    ensure_parent(base)
    for mode in result.modes():
        fn = base.with_name(f"{base.name}_m{mode}.txt")
        lines = list(dict.fromkeys(h.line for h in result.hashes[mode]))
        with open(fn, "w", encoding="ascii", errors="replace") as f:
            f.write("\n".join(lines) + "\n")
        arts.append(ExportArtifact(f"txt_m{mode}", str(fn), len(lines), f"hashcat -m {mode}"))
    return arts

def _write_creds(result: ExtractResult, path: Path) -> ExportArtifact:
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        for c in result.credentials:
            f.write(f"{c.protocol}\tuser={c.username}\tpass={c.password}\n")
    return ExportArtifact("credentials", str(path), len(result.credentials))

def _records(result: ExtractResult) -> list[dict[str, Any]]:
    return result.to_records()

def _write_csv(result: ExtractResult, req: ExportRequest, path: Path) -> ExportArtifact:
    recs = _records(result)
    ensure_parent(path)
    fields = [
        "type", "mode", "protocol", "user", "domain", "frame", "source", "line",
    ]
    # extra keys
    extras: set[str] = set()
    for r in recs:
        extras.update(k for k in r if k.startswith("extra_") or k == "password")
    fields.extend(sorted(extras))
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in recs:
            w.writerow({k: r.get(k, "") for k in fields})
    return ExportArtifact("csv", str(path), len(recs))

def _meta(result: ExtractResult, req: ExportRequest) -> dict[str, Any]:
    return {
        "generated_at": now_iso(),
        "source": req.source_pcap,
        "elapsed_seconds": round(req.elapsed, 3),
        "packets": result.packets,
        "hash_count": result.total(),
        "credential_count": len(result.credentials),
        "modes": result.modes(),
        "protocols": sorted(result.proto_seen),
        "protocol_counts": dict(getattr(result, "proto_counts", {}) or {}),
        "preauth_users": sorted(result.preauth_users),
        "rejected": result.rejected,
        "notes": result.notes,
        "missing": result.missing,
    }

def _write_json(result: ExtractResult, req: ExportRequest, path: Path) -> ExportArtifact:
    ensure_parent(path)
    payload = {
        "meta": _meta(result, req),
        "hashes": [
            {
                "mode": h.mode,
                "line": h.line,
                "protocol": h.protocol,
                "source": h.source,
                "frame": h.frame,
                "user": h.user,
                "domain": h.domain,
                "extra": h.extra,
            }
            for mode in result.modes()
            for h in result.hashes[mode]
        ],
        "credentials": [
            {
                "protocol": c.protocol,
                "username": c.username,
                "password": c.password,
                "frame": c.frame,
                "source": c.source,
            }
            for c in result.credentials
        ],
        "kerberos_identities": [
            {
                "frame": d.frame,
                "msg": d.msg,
                "user": d.user,
                "realm": d.realm,
                "spn": d.spn,
                "salts": d.salts,
                "etypes": d.etypes,
            }
            for d in result.diag
        ],
        "hashcat_commands": [
            {
                "mode": mode,
                "name": (mode_info(mode) or {}).get("name"),
                "cmd": hashcat_command(mode, f"{_base(req).name}_m{mode}.txt", req.wordlist),
            }
            for mode in result.modes()
        ],
        "extra": req.extra_sheets,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return ExportArtifact("json", str(path), result.total() + len(result.credentials))

def _write_xlsx(result: ExtractResult, req: ExportRequest, path: Path) -> ExportArtifact:
    try:
        from openpyxl import Workbook
        from openpyxl.chart import BarChart, Reference
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.page import PageMargins
    except ImportError as exc:
        raise RuntimeError("openpyxl est requis pour l'export Excel (pip install openpyxl)") from exc

    wb = Workbook()
    wb.properties.creator = "tshark2hashcat"
    wb.properties.title = "tshark2hashcat — rapport réseau"
    wb.properties.subject = "Analyse de capture réseau · hashes Hashcat · secrets"

    # ---- palette rapport ------------------------------------------------
    NAVY = "0B1F3A"
    NAVY2 = "123056"
    TEAL = "0E7490"
    CYAN = "0891B2"
    GOLD = "D97706"
    WHITE = "FFFFFF"
    INK = "0F172A"
    SLATE = "334155"
    MUTED = "64748B"
    LINE = "CBD5E1"
    ZEBRA = "F1F5F9"
    PAPER = "F8FAFC"
    CRIT = "B91C1C"
    HIGH = "C2410C"
    MED = "A16207"
    LOW = "15803D"
    OKC = "0F766E"
    CRIT_BG = "FEE2E2"
    HIGH_BG = "FFEDD5"
    MED_BG = "FEF3C7"
    LOW_BG = "DCFCE7"
    TEAL_BG = "CFFAFE"
    GOLD_BG = "FEF3C7"

    fill_navy = PatternFill("solid", fgColor=NAVY)
    fill_navy2 = PatternFill("solid", fgColor=NAVY2)
    fill_teal = PatternFill("solid", fgColor=TEAL)
    fill_cyan = PatternFill("solid", fgColor=CYAN)
    fill_gold = PatternFill("solid", fgColor=GOLD)
    fill_zebra = PatternFill("solid", fgColor=ZEBRA)
    fill_paper = PatternFill("solid", fgColor=PAPER)
    fill_white = PatternFill("solid", fgColor=WHITE)
    fill_crit = PatternFill("solid", fgColor=CRIT)
    fill_high = PatternFill("solid", fgColor=HIGH)
    fill_med = PatternFill("solid", fgColor=MED)
    fill_low = PatternFill("solid", fgColor=LOW)
    fill_ok = PatternFill("solid", fgColor=OKC)
    fill_crit_bg = PatternFill("solid", fgColor=CRIT_BG)
    fill_high_bg = PatternFill("solid", fgColor=HIGH_BG)
    fill_med_bg = PatternFill("solid", fgColor=MED_BG)
    fill_low_bg = PatternFill("solid", fgColor=LOW_BG)
    fill_teal_bg = PatternFill("solid", fgColor=TEAL_BG)
    fill_gold_bg = PatternFill("solid", fgColor=GOLD_BG)

    font_title = Font(name="Calibri", bold=True, size=22, color=WHITE)
    font_sub = Font(name="Calibri", italic=True, size=11, color="BAE6FD")
    font_h = Font(name="Calibri", bold=True, size=11, color=WHITE)
    font_h2 = Font(name="Calibri", bold=True, size=13, color=NAVY)
    font_kpi = Font(name="Calibri", bold=True, size=18, color=NAVY)
    font_kpi_lbl = Font(name="Calibri", size=9, color=MUTED, bold=True)
    font_ink = Font(name="Calibri", size=11, color=INK)
    font_muted = Font(name="Calibri", size=10, color=MUTED)
    font_white = Font(name="Calibri", bold=True, size=11, color=WHITE)
    font_white_sm = Font(name="Calibri", size=9, color=WHITE)
    font_fact = Font(name="Calibri", size=11, color=INK)

    thin = Border(
        left=Side(style="thin", color=LINE),
        right=Side(style="thin", color=LINE),
        top=Side(style="thin", color=LINE),
        bottom=Side(style="thin", color=LINE),
    )
    none_b = Border()
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left_c = Alignment(horizontal="left", vertical="center", wrap_text=True)
    left_top = Alignment(horizontal="left", vertical="top", wrap_text=True)

    SEV_FILL = {
        "CRITIQUE": fill_crit,
        "ÉLEVÉ": fill_high,
        "ELEVE": fill_high,
        "MOYEN": fill_med,
        "FAIBLE": fill_low,
        "INFO": fill_ok,
        "RECO": fill_teal,
        "MANQUANT": fill_crit,
        "PARTIEL": fill_gold,
        "OK": fill_ok,
        "OK / NON OBSERVÉ": fill_ok,
    }
    SEV_BG = {
        "CRITIQUE": fill_crit_bg,
        "ÉLEVÉ": fill_high_bg,
        "ELEVE": fill_high_bg,
        "MOYEN": fill_med_bg,
        "FAIBLE": fill_low_bg,
        "INFO": fill_low_bg,
        "RECO": fill_teal_bg,
        "MANQUANT": fill_crit_bg,
        "PARTIEL": fill_gold_bg,
        "OK": fill_low_bg,
        "OK / NON OBSERVÉ": fill_low_bg,
    }
    TAB_COLORS = {
        "Couverture": NAVY,
        "Analyse": TEAL,
        "Expositions": CRIT,
        "MITRE": "7C3AED",
        "Chemins": HIGH,
        "Écarts": GOLD,
        "Cartographie": "0F766E",
        "Findings": CRIT,
        "OSINT": "7C3AED",
        "Identités": "6D28D9",
        "Hôtes": "0F766E",
        "Wi-Fi": "DB2777",
        "Fichiers": "57534E",
        "Secrets": GOLD,
        "Hashes": "B45309",
        "Kerberos": "6D28D9",
        "SNMP": "0F766E",
        "Hashcat": "15803D",
        "Protection": CRIT,
        "Bruit": MUTED,
        "Manquants": MUTED,
        "Notes": MUTED,
        "Fichiers_src": "334155",
    }

    def _style_ws(ws, tab: str = "") -> None:
        ws.sheet_view.showGridLines = False
        ws.page_setup.orientation = "landscape"
        ws.page_setup.fitToPage = True
        ws.page_setup.fitToWidth = 1
        ws.page_setup.fitToHeight = 0
        ws.page_setup.paperSize = ws.PAPERSIZE_A4
        ws.page_margins = PageMargins(left=0.5, right=0.5, top=0.6, bottom=0.6, header=0.2, footer=0.2)
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        ws.oddHeader.left.text = "tshark2hashcat  ·  rapport réseau"
        ws.oddFooter.left.text = "&D  &T"
        ws.oddFooter.right.text = "page &P / &N"
        color = TAB_COLORS.get(tab or ws.title, TEAL)
        try:
            ws.sheet_properties.tabColor = color
        except Exception:
            pass

    def _paint_row(ws, row: int, fill, font=None, align=None, last_col: int = 8) -> None:
        for col in range(1, last_col + 1):
            cell = ws.cell(row, col)
            cell.fill = fill
            if font is not None:
                cell.font = font
            if align is not None:
                cell.alignment = align

    def _sheet(title: str, headers: list[str], rows: list[list[Any]], *, widths: Optional[list[int]] = None, wrap_last: bool = False) -> Any:
        if not rows:
            return None
        ws = wb.create_sheet(title[:31])
        _style_ws(ws, title)
        # bandeau
        last = max(len(headers), 2)
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=last)
        ws.cell(1, 1, f"  tshark2hashcat  ·  {title}")
        ws.row_dimensions[1].height = 22
        _paint_row(ws, 1, fill_navy, font_white, Alignment(vertical="center"), last)
        ws.append(headers)
        for cell in ws[2]:
            cell.fill = fill_teal
            cell.font = font_h
            cell.alignment = center
            cell.border = thin
        ws.row_dimensions[2].height = 20
        for i, row in enumerate(rows, 3):
            ws.append([_xlsx_cell(x) for x in row])
            zebra = fill_zebra if i % 2 == 0 else fill_white
            sev = str(row[0]).upper() if row else ""
            row_fill = SEV_BG.get(sev, zebra)
            for c_i, cell in enumerate(ws[i], 1):
                cell.border = thin
                cell.alignment = left_c if c_i > 1 else center
                cell.font = font_ink
                cell.fill = row_fill
                if c_i == 1 and sev in SEV_FILL:
                    cell.fill = SEV_FILL[sev]
                    cell.font = font_white
                    cell.alignment = center
                if wrap_last and c_i == len(headers):
                    cell.alignment = left_top
        ws.auto_filter.ref = f"A2:{get_column_letter(len(headers))}{max(ws.max_row, 2)}"
        ws.freeze_panes = "A3"
        ws.auto_filter.ref = f"A2:{get_column_letter(max(len(headers), 1))}{max(ws.max_row, 2)}"
        if widths:
            for i, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(i)].width = w
        else:
            for col in range(1, len(headers) + 1):
                letter = get_column_letter(col)
                maxlen = len(str(headers[col - 1]))
                for row in ws.iter_rows(min_col=col, max_col=col, min_row=3, max_row=min(ws.max_row, 60)):
                    for cell in row:
                        maxlen = max(maxlen, min(len(str(cell.value or "")), 56))
                ws.column_dimensions[letter].width = min(maxlen + 3, 62)
        ws.sheet_view.showGridLines = False
        return ws

    net = build_network_report(result)
    try:
        report = assess_protection(result, net=net)
    except Exception:
        report = {"score": 100, "niveau": "—", "findings": [], "recommandations": [], "osint": {}}
    osint = report.get("osint") or build_osint_report(result, net)
    pkt = build_packet_analysis(result)
    meta = _meta(result, req)

    # ================================================================== #
    # Couverture
    # ================================================================== #
    ws = wb.active
    ws.title = "Couverture"
    _style_ws(ws, "Couverture")
    for col, w in enumerate((22, 28, 18, 18, 18, 18, 18, 22), 1):
        ws.column_dimensions[get_column_letter(col)].width = w
    for r in range(1, 48):
        _paint_row(ws, r, fill_paper, last_col=8)

    ws.merge_cells("A1:H1")
    ws["A1"] = "  RAPPORT D'AUDIT RÉSEAU  —  tshark2hashcat"
    ws["A1"].font = font_title
    ws["A1"].alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 36
    _paint_row(ws, 1, fill_navy, font_title, Alignment(vertical="center"), 8)

    ws.merge_cells("A2:H2")
    src_label = meta.get("source") or "—"
    ws["A2"] = f"  Périmètre  {src_label}   ·   {net.get('n_files') or 1} capture(s)   ·   {result.packets} paquets   ·   {meta.get('generated_at') or now_iso()}   ·   v{__version__}"
    ws["A2"].font = font_sub
    ws.row_dimensions[2].height = 18
    _paint_row(ws, 2, fill_navy2, font_sub, Alignment(vertical="center"), 8)

    # bandeau risque
    niveau = str(report.get("niveau") or "")
    score = report.get("score")
    risk_fill = {
        "CRITIQUE": fill_crit,
        "ÉLEVÉ": fill_high,
        "ELEVE": fill_high,
        "MOYEN": fill_med,
        "FAIBLE": fill_low,
        "BON": fill_ok,
    }.get(niveau.upper(), fill_teal)
    ws.merge_cells("A3:H3")
    ws["A3"] = f"  Risque {niveau}   ·   score {score}/100"
    ws["A3"].font = Font(name="Calibri", bold=True, size=14, color=WHITE)
    ws.row_dimensions[3].height = 24
    _paint_row(ws, 3, risk_fill, Font(name="Calibri", bold=True, size=14, color=WHITE), Alignment(vertical="center"), 8)

    kpis = [
        ("NIVEAU", str(niveau)),
        ("SCORE", f"{score}/100"),
        ("FINDINGS", str(len(report.get("expositions") or []))),
        ("COMPTES AD", str(len(report.get("ad_users") or []))),
        ("DOMAINE", str(report.get("domaine") or "—")[:18]),
        ("DC", str(report.get("dc") or "—")[:18]),
        ("ÉCARTS KO", str(report.get("n_ko") or 0)),
        ("HASHES", str(net.get("n_hashes") or 0)),
    ]
    for i, (lbl, val) in enumerate(kpis):
        col = i + 1
        ws.cell(5, col, lbl).font = font_white_sm
        ws.cell(5, col).fill = fill_teal
        ws.cell(5, col).alignment = center
        ws.cell(5, col).border = thin
        ws.cell(6, col, val).font = font_kpi if i < 3 else Font(name="Calibri", bold=True, size=12, color=NAVY)
        ws.cell(6, col).fill = fill_white
        ws.cell(6, col).alignment = center
        ws.cell(6, col).border = thin
    ws.row_dimensions[5].height = 16
    ws.row_dimensions[6].height = 28

    ws.merge_cells("A8:H8")
    ws["A8"] = "  Synthèse exécutive"
    _paint_row(ws, 8, fill_navy, font_white, Alignment(vertical="center"), 8)
    ws.merge_cells("A9:H16")
    ws["A9"] = report.get("conclusion") or report.get("synthese") or ""
    ws["A9"].font = font_ink
    ws["A9"].alignment = Alignment(wrap_text=True, vertical="top")
    for r in range(9, 17):
        for c in range(1, 9):
            ws.cell(r, c).fill = fill_white
            ws.cell(r, c).border = thin
        ws.row_dimensions[r].height = 18

    ws.merge_cells("A18:H18")
    ws["A18"] = "  Périmètre observé"
    _paint_row(ws, 18, fill_navy, font_white, Alignment(vertical="center"), 8)
    ws.merge_cells("A19:H21")
    ws["A19"] = report.get("perimetre") or ""
    ws["A19"].font = font_ink
    ws["A19"].alignment = Alignment(wrap_text=True, vertical="top")
    for r in range(19, 22):
        for c in range(1, 9):
            ws.cell(r, c).fill = fill_zebra
            ws.cell(r, c).border = thin
        ws.row_dimensions[r].height = 16

    ws.merge_cells("A23:H23")
    ws["A23"] = "  Findings (fiches complètes dans l'onglet Findings)"
    _paint_row(ws, 23, fill_navy, font_white, Alignment(vertical="center"), 8)
    expos = list(report.get("expositions") or [])[:10]
    headers = [("A", "id"), ("B", "gravité"), ("C", "finding"), ("F", "actifs / preuve")]
    ws.cell(24, 1, "id").font = font_h
    ws.cell(24, 2, "gravité").font = font_h
    ws.merge_cells("C24:E24")
    ws.cell(24, 3, "finding").font = font_h
    ws.merge_cells("F24:H24")
    ws.cell(24, 6, "pourquoi / actifs").font = font_h
    for c in range(1, 9):
        ws.cell(24, c).fill = fill_teal
        ws.cell(24, c).font = font_h
        ws.cell(24, c).border = thin
    if not expos:
        ws.merge_cells("A25:H25")
        ws["A25"] = "  Aucune exposition exploitable extraite."
        ws["A25"].font = font_muted
    for i, e in enumerate(expos):
        r = 25 + i
        sev = str(e.get("sev") or "")
        ws.cell(r, 1, e.get("id") or f"T2H-{i+1:02d}")
        ws.cell(r, 2, sev).fill = SEV_FILL.get(sev.upper(), fill_teal)
        ws.cell(r, 2).font = font_white
        ws.cell(r, 2).alignment = center
        ws.merge_cells(start_row=r, start_column=3, end_row=r, end_column=5)
        ws.cell(r, 3, e.get("titre") or "")
        ws.merge_cells(start_row=r, start_column=6, end_row=r, end_column=8)
        ws.cell(r, 6, (e.get("impact") or "") + (("  —  " + (e.get("actifs") or e.get("preuve") or "")) if (e.get("actifs") or e.get("preuve")) else ""))
        bg = SEV_BG.get(sev.upper(), fill_white)
        for c in range(1, 9):
            ws.cell(r, c).border = thin
            if c != 2:
                ws.cell(r, c).fill = bg
                ws.cell(r, c).font = font_ink
                ws.cell(r, c).alignment = left_c
        ws.row_dimensions[r].height = 32

    reco_row = 25 + max(len(expos), 1) + 1
    recos = list(report.get("recommandations") or [])[:8]
    if recos:
        ws.merge_cells(start_row=reco_row, start_column=1, end_row=reco_row, end_column=8)
        ws.cell(reco_row, 1, "  Actions prioritaires")
        _paint_row(ws, reco_row, fill_navy, font_white, Alignment(vertical="center"), 8)
        for i, reco in enumerate(recos):
            r = reco_row + 1 + i
            prio = "P1" if i < 2 else "P2" if i < 5 else "P3"
            ws.cell(r, 1, prio).fill = fill_crit if prio == "P1" else fill_gold if prio == "P2" else fill_teal
            ws.cell(r, 1).font = font_white
            ws.cell(r, 1).alignment = center
            ws.merge_cells(start_row=r, start_column=2, end_row=r, end_column=8)
            ws.cell(r, 2, reco).font = font_ink
            ws.cell(r, 2).alignment = left_c
            for c in range(1, 9):
                ws.cell(r, c).border = thin
                if c > 1:
                    ws.cell(r, c).fill = fill_white if i % 2 == 0 else fill_zebra

    meth_row = reco_row + (len(recos) + 2 if recos else 1)
    ws.merge_cells(start_row=meth_row, start_column=1, end_row=meth_row, end_column=8)
    ws.cell(meth_row, 1, "  Méthode")
    _paint_row(ws, meth_row, fill_navy2, font_sub, Alignment(vertical="center"), 8)
    ws.merge_cells(start_row=meth_row + 1, start_column=1, end_row=meth_row + 2, end_column=8)
    ws.cell(meth_row + 1, 1, report.get("methodo") or "")
    ws.cell(meth_row + 1, 1).font = font_muted
    ws.cell(meth_row + 1, 1).alignment = Alignment(wrap_text=True, vertical="top")

    # ================================================================== #
    # Analyse paquets
    # ================================================================== #
    wa = wb.create_sheet("Analyse")
    _style_ws(wa, "Analyse")
    for col, w in enumerate((22, 16, 14, 36, 18, 14, 14, 18), 1):
        wa.column_dimensions[get_column_letter(col)].width = w
    wa.merge_cells("A1:H1")
    wa["A1"] = "  Analyse des paquets"
    wa.row_dimensions[1].height = 24
    _paint_row(wa, 1, fill_navy, font_white, Alignment(vertical="center"), 8)
    wa.merge_cells("A2:H2")
    wa["A2"] = "  Volume, durée, mix L3/L4 et familles de protocoles — base pour une analyse ultérieure."
    wa["A2"].font = font_sub
    _paint_row(wa, 2, fill_navy2, font_sub, Alignment(vertical="center"), 8)

    mix = [
        ("Paquets", pkt.get("n_packets") or 0),
        ("Volume total", human_bytes(pkt.get("bytes_sum") or 0)),
        ("Paquet min", human_bytes(pkt.get("bytes_min") or 0)),
        ("Paquet max", human_bytes(pkt.get("bytes_max") or 0)),
        ("Paquet moyen", human_bytes(pkt.get("bytes_avg") or 0)),
        ("Durée", human_duration(pkt.get("duration"))),
        ("Débit moyen", human_bps(pkt.get("bitrate_bps"))),
        ("IPv4 (trames)", pkt.get("n_ipv4") or 0),
        ("IPv6 (trames)", pkt.get("n_ipv6") or 0),
        ("TCP", pkt.get("n_tcp") or 0),
        ("UDP", pkt.get("n_udp") or 0),
        ("ICMP / ICMPv6", pkt.get("n_icmp") or 0),
        ("Ethernet", pkt.get("n_eth") or 0),
        ("Wi-Fi (wlan)", pkt.get("n_wlan") or 0),
        ("Protocoles en clair", pkt.get("n_clear") or 0),
        ("Protocoles chiffrés", pkt.get("n_crypt") or 0),
        ("IP uniques", pkt.get("n_ips") or 0),
        ("MAC uniques", pkt.get("n_macs") or 0),
    ]
    wa["A4"] = "Indicateur"
    wa["B4"] = "Valeur"
    for cell in (wa["A4"], wa["B4"]):
        cell.fill = fill_teal
        cell.font = font_h
        cell.alignment = center
        cell.border = thin
    for i, (k, v) in enumerate(mix):
        r = 5 + i
        wa.cell(r, 1, k).font = font_ink
        wa.cell(r, 2, _xlsx_cell(v)).font = font_ink
        bg = fill_white if i % 2 == 0 else fill_zebra
        for c in (1, 2):
            wa.cell(r, c).fill = bg
            wa.cell(r, c).border = thin
            wa.cell(r, c).alignment = left_c

    wa["D4"] = "Famille"
    wa["E4"] = "Paquets"
    wa["F4"] = "%"
    for cell in (wa["D4"], wa["E4"], wa["F4"]):
        cell.fill = fill_teal
        cell.font = font_h
        cell.alignment = center
        cell.border = thin
    families = list(pkt.get("families") or [])
    for i, fam in enumerate(families):
        r = 5 + i
        wa.cell(r, 4, fam.get("famille", "")).font = font_ink
        wa.cell(r, 5, fam.get("paquets", 0)).font = font_ink
        wa.cell(r, 6, fam.get("pct", 0)).font = font_ink
        bg = fill_white if i % 2 == 0 else fill_zebra
        for c in (4, 5, 6):
            wa.cell(r, c).fill = bg
            wa.cell(r, c).border = thin
            wa.cell(r, c).alignment = center if c > 4 else left_c

    if families:
        try:
            chart = BarChart()
            chart.type = "bar"
            chart.style = 10
            chart.title = "Familles de protocoles"
            chart.y_axis.title = None
            chart.x_axis.title = "paquets"
            data = Reference(wa, min_col=5, min_row=4, max_row=4 + len(families))
            cats = Reference(wa, min_col=4, min_row=5, max_row=4 + len(families))
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(cats)
            chart.shape = 4
            chart.height = 8
            chart.width = 15
            wa.add_chart(chart, "D24")
        except Exception:
            pass

    # protocoles + adresses dans Analyse (plus d'onglets fantômes)
    proto_list = list(pkt.get("protocols") or [])
    wa["A25"] = "Protocole"
    wa["B25"] = "Paquets"
    wa["C25"] = "%"
    wa["D25"] = "Famille"
    wa["E25"] = "Classe"
    for cell in (wa["A25"], wa["B25"], wa["C25"], wa["D25"], wa["E25"]):
        cell.fill = fill_teal
        cell.font = font_h
        cell.alignment = center
        cell.border = thin
    for i, p in enumerate(proto_list[:40]):
        r = 26 + i
        wa.cell(r, 1, p["protocole"]).font = font_ink
        wa.cell(r, 2, p["paquets"]).font = font_ink
        wa.cell(r, 3, p["pct"]).font = font_ink
        wa.cell(r, 4, p.get("famille") or "").font = font_ink
        cl = p.get("classe") or "—"
        c5 = wa.cell(r, 5, cl)
        c5.font = font_white if cl in {"clair", "chiffré", "auth"} else font_ink
        if cl == "clair":
            c5.fill = fill_crit
        elif cl == "chiffré":
            c5.fill = fill_ok
        elif cl == "auth":
            c5.fill = fill_gold
        bg = fill_white if i % 2 == 0 else fill_zebra
        for c in range(1, 5):
            wa.cell(r, c).fill = bg
            wa.cell(r, c).border = thin
            wa.cell(r, c).alignment = left_c
        wa.cell(r, 5).border = thin
        wa.cell(r, 5).alignment = center

    # ================================================================== #
    # Expositions / MITRE / Chemins / Écarts
    # ================================================================== #
    _sheet(
        "Findings",
        ["id", "gravité", "titre", "actifs", "description", "preuve", "impact", "remédiation", "MITRE"],
        [
            [
                e.get("id") or "",
                e.get("sev") or "",
                e.get("titre") or "",
                e.get("actifs") or "",
                e.get("detail") or "",
                e.get("preuve") or "",
                e.get("impact") or "",
                e.get("reco") or "",
                ", ".join(t[0] for t in _MITRE_CATALOG.get(e.get("mitre") or "", [])[:4]),
            ]
            for e in (report.get("expositions") or [])
        ],
        widths=[10, 12, 40, 28, 64, 32, 36, 44, 28],
        wrap_last=True,
    )
    _sheet(
        "Expositions",
        ["id", "gravité", "titre", "actifs", "impact", "preuve", "remédiation"],
        [
            [
                e.get("id") or "",
                e.get("sev") or "",
                e.get("titre") or "",
                e.get("actifs") or "",
                e.get("impact") or "",
                e.get("preuve") or "",
                e.get("reco") or "",
            ]
            for e in (report.get("expositions") or [])
        ],
        widths=[10, 12, 44, 28, 44, 36, 44],
        wrap_last=True,
    )
    _sheet(
        "Cartographie",
        ["type", "nom", "rôle", "détail"],
        [
            [r.get("type") or "", r.get("nom") or "", r.get("rôle") or "", r.get("détail") or ""]
            for r in (report.get("cartographie") or [])
        ],
        widths=[16, 40, 32, 48],
        wrap_last=True,
    )
    _sheet(
        "MITRE",
        ["ID", "technique", "tactique", "preuve"],
        [
            [m.get("id") or "", m.get("technique") or "", m.get("tactique") or "", m.get("preuve") or ""]
            for m in (report.get("mitre") or [])
        ],
        widths=[14, 56, 28, 16],
    )
    _sheet(
        "Chemins",
        ["étape", "nom", "scénario", "résultat", "MITRE"],
        [
            [c.get("etape") or "", c.get("nom") or "", c.get("scenario") or "", c.get("resultat") or "", c.get("mitre") or ""]
            for c in (report.get("chemins") or [])
        ],
        widths=[8, 28, 72, 36, 22],
        wrap_last=True,
    )
    _sheet(
        "Écarts",
        ["écart", "contrôle", "attendu", "observé"],
        [
            [g.get("écart") or "", g.get("contrôle") or "", g.get("attendu") or "", g.get("observé") or ""]
            for g in (report.get("ecarts") or [])
        ],
        widths=[16, 32, 40, 40],
    )

    osint = report.get("osint") or build_osint_report(result, net)

    osint_rows: list[list[Any]] = []
    for p in osint.get("people") or []:
        osint_rows.append(["personne", p.get("nom") or "", p.get("compte") or "", p.get("org") or "", p.get("source") or ""])
    for e in osint.get("emails") or []:
        osint_rows.append(["e-mail", e.get("nom") or "", e.get("email") or "", "", e.get("source") or ""])
    for t_ in osint.get("phones") or []:
        osint_rows.append(["téléphone", "", t_.get("tel") or "", t_.get("brut") or "", t_.get("source") or ""])
    for o in osint.get("orgs") or []:
        osint_rows.append(["organisation", o, "", "", "domaine / realm"])
    for m in osint.get("machines") or []:
        osint_rows.append(["machine", m.get("nom") or "", "", "", m.get("source") or ""])
    for s in osint.get("sites") or []:
        osint_rows.append(["site / SNI / DNS", s.get("nom") or "", s.get("type") or "", "", ""])
    for d in osint.get("devices") or []:
        osint_rows.append(["équipement", d.get("type") or "", d.get("valeur") or "", "", ""])
    for ip in osint.get("public_ips") or []:
        osint_rows.append(["IP publique", ip, _ip_kind(ip), "", "pivot OSINT"])
    for row in osint.get("lan_ips") or []:
        osint_rows.append(["IP interne", row.get("ip") or "", row.get("classe") or "", "", ""])
    for sub in osint.get("subjects") or []:
        osint_rows.append(["sujet mail", sub, "", "", "IMF"])
    _sheet(
        "OSINT",
        ["catégorie", "nom / libellé", "valeur", "détail", "source"],
        osint_rows,
        widths=[18, 36, 40, 28, 22],
        wrap_last=True,
    )
    _sheet(
        "Identités",
        ["type", "identité", "détail", "fichier"],
        [[r.get("type", ""), r.get("valeur", ""), r.get("detail", ""), r.get("fichier", "")] for r in net["identities"]],
        widths=[22, 36, 40, 28],
    )
    _sheet(
        "Hôtes",
        ["type", "nom", "fichier", "source"],
        [[r.get("type", ""), r.get("nom", ""), r.get("fichier", ""), r.get("source", "")] for r in net["hosts"]],
        widths=[16, 44, 28, 22],
    )
    _sheet(
        "Secrets",
        ["fichier", "protocole", "user", "password", "frame", "source"],
        [
            [
                (c.extra or {}).get("fichier", ""),
                c.protocol,
                c.username,
                c.password,
                c.frame or "",
                c.source,
            ]
            for c in net["secrets"]
            if not _is_cf_cookie(c.password or "") and not _is_cf_cookie(c.username or "")
        ],
        widths=[24, 26, 24, 36, 10, 28],
    )
    _sheet(
        "Hashes",
        ["fichier", "mode", "nom", "user", "contexte", "commande", "ligne"],
        [
            [
                (h.extra or {}).get("fichier", ""),
                mode,
                (mode_info(mode) or {}).get("name", ""),
                h.user or "",
                hash_context(h),
                hashcat_command(mode, f"{_base(req).name}_m{mode}.txt", req.wordlist),
                h.line,
            ]
            for mode, hits in sorted(net["hashes"].items())
            for h in hits
        ],
        widths=[20, 10, 28, 18, 28, 48, 48],
        wrap_last=True,
    )
    _sheet(
        "Wi-Fi",
        ["type", "valeur", "hex", "fichier"],
        [[r.get("type", ""), r.get("valeur", ""), r.get("brut", ""), r.get("fichier", "")] for r in net["wifi"]],
        widths=[16, 32, 28, 28],
    )
    _sheet(
        "Fichiers",
        ["type", "chemin", "fichier"],
        [[r.get("type", ""), r.get("chemin", ""), r.get("fichier", "")] for r in net["files"]],
        widths=[16, 56, 28],
    )

    for name, recs in req.extra_sheets.items():
        if not recs:
            continue
        keys: list[str] = []
        for r in recs:
            for k in r:
                if k not in keys:
                    keys.append(k)
        title = "Captures" if name.lower() in {"fichiers", "files"} else name
        _sheet(title, keys, [[r.get(k, "") for k in keys] for r in recs])

    ensure_parent(path)
    wb.save(path)
    return ExportArtifact("xlsx", str(path), result.total() + len(result.credentials))

def _write_html(result: ExtractResult, req: ExportRequest, path: Path) -> ExportArtifact:
    meta = _meta(result, req)
    rows_h = []
    for mode in result.modes():
        name = (mode_info(mode) or {}).get("name", "")
        for h in result.hashes[mode]:
            rows_h.append(
                f"<tr><td>{mode}</td><td>{_esc(name)}</td><td>{_esc(h.protocol)}</td>"
                f"<td>{_esc(h.user)}</td><td>{_esc(h.domain)}</td><td>{h.frame or ''}</td>"
                f"<td><code>{_esc(h.line)}</code></td></tr>"
            )
    rows_c = [
        f"<tr><td>{_esc(c.protocol)}</td><td>{_esc(c.username)}</td><td><code>{_esc(c.password)}</code></td></tr>"
        for c in result.credentials
    ]
    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>tshark2hashcat — rapport</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; background:#0b1220; color:#e8eef7; margin:0; }}
 header {{ background:linear-gradient(90deg,#0ea5e9,#6366f1); padding:24px 32px; }}
 h1 {{ margin:0 0 4px; font-size:22px; }}
 main {{ padding:24px 32px; }}
 .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 28px; }}
 .card {{ background:#152238; border:1px solid #24344d; border-radius:12px; padding:14px 18px; min-width:140px; }}
 .card b {{ display:block; font-size:22px; color:#7dd3fc; }}
 table {{ border-collapse:collapse; width:100%; margin:12px 0 28px; font-size:13px; }}
 th {{ background:#1e3a5f; text-align:left; padding:8px; }}
 td {{ border-bottom:1px solid #24344d; padding:6px 8px; vertical-align:top; }}
 code {{ color:#86efac; word-break:break-all; }}
 h2 {{ color:#93c5fd; border-bottom:1px solid #24344d; padding-bottom:6px; }}
 .muted {{ color:#94a3b8; }}
</style></head><body>
<header>
  <h1>tshark2hashcat</h1>
  <div class="muted">Généré { _esc(meta['generated_at']) } — source { _esc(meta['source']) }</div>
</header>
<main>
<div class="cards">
  <div class="card"><b>{meta['hash_count']}</b>hashes</div>
  <div class="card"><b>{meta['credential_count']}</b>identifiants</div>
  <div class="card"><b>{meta['packets']}</b>paquets</div>
  <div class="card"><b>{len(meta['modes'])}</b>modes</div>
</div>
<h2>Hashes</h2>
<table><thead><tr><th>mode</th><th>nom</th><th>proto</th><th>user</th><th>domain</th><th>frame</th><th>ligne</th></tr></thead>
<tbody>{''.join(rows_h) or '<tr><td colspan="7" class="muted">aucun</td></tr>'}</tbody></table>
<h2>Identifiants en clair</h2>
<table><thead><tr><th>protocole</th><th>user</th><th>password</th></tr></thead>
<tbody>{''.join(rows_c) or '<tr><td colspan="3" class="muted">aucun</td></tr>'}</tbody></table>
<h2>Protocoles détectés</h2>
<p>{_esc(', '.join(meta['protocols']) or 'aucun')}</p>
</main></body></html>
"""
    ensure_parent(path)
    path.write_text(html, encoding="utf-8")
    return ExportArtifact("html", str(path), result.total())

def _write_md(result: ExtractResult, req: ExportRequest, path: Path) -> ExportArtifact:
    meta = _meta(result, req)
    lines = [
        "# tshark2hashcat — rapport",
        "",
        f"- Généré : `{meta['generated_at']}`",
        f"- Source : `{meta['source']}`",
        f"- Paquets : **{meta['packets']}**",
        f"- Hashes : **{meta['hash_count']}**",
        f"- Identifiants : **{meta['credential_count']}**",
        f"- Protocoles : {', '.join(meta['protocols']) or 'aucun'}",
        f"- Durée : {human_duration(meta['elapsed_seconds'])}",
        "",
        "## Hashes",
        "",
        "| mode | nom | proto | user | frame | ligne |",
        "|-----:|-----|-------|------|------:|-------|",
    ]
    for mode in result.modes():
        name = (mode_info(mode) or {}).get("name", "")
        for h in result.hashes[mode]:
            lines.append(
                f"| {mode} | {name} | {h.protocol} | {h.user or ''} | {h.frame or ''} | `{h.line}` |"
            )
    lines += ["", "## Données confidentielles", "", "| proto | user | password |", "|-------|------|----------|"]
    for c in result.credentials:
        lines.append(f"| {c.protocol} | {c.username} | `{c.password}` |")
    lines += ["", "## Commandes Hashcat", ""]
    for mode in result.modes():
        lines.append(f"- `{hashcat_command(mode, f'{_base(req).name}_m{mode}.txt', req.wordlist)}`")
    if result.diag:
        lines += ["", "## Identités Kerberos", "", "| frame | msg | user | realm | spn | salts | etypes |",
                  "|------:|-----|------|-------|-----|-------|--------|"]
        for d in result.diag:
            lines.append(
                f"| {d.frame} | {d.msg} | {d.user or '?'} | {d.realm or '?'} | {d.spn or '-'} | "
                f"{' + '.join(d.salts) or '-'} | {','.join(map(str, d.etypes)) or '-'} |"
            )
    if result.missing:
        lines += ["", "## Éléments ignorés", ""]
        for m in result.missing:
            lines.append(f"- {m}")
    ensure_parent(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ExportArtifact("md", str(path), result.total())

_ILLEGAL_XLSX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

def _xlsx_cell(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, (int, float, bool)):
        return v
    return _ILLEGAL_XLSX.sub("", str(v))

def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

@dataclass
class CaptureInfo:
    path: str
    size: int = 0
    sha256: str = ""
    capinfos: dict[str, str] = field(default_factory=dict)
    stats: dict[str, str] = field(default_factory=dict)
    tshark_version: str = ""
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "size_human": human_bytes(self.size),
            "sha256": self.sha256,
            "capinfos": self.capinfos,
            "stats": self.stats,
            "tshark_version": self.tshark_version,
            "generated_at": self.generated_at,
        }

def run_capinfos(path: str, binary: Optional[str] = None) -> dict[str, str]:
    cap = binary or find_capinfos()
    if not cap:
        # fallback tshark -q -z io,phs ne donne pas les mêmes métadonnées
        return {"note": "capinfos introuvable"}
    try:
        r = subprocess.run(
            [cap, "-A", "-M", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    info: dict[str, str] = {}
    for line in (r.stdout or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    return info

def analyze_capture(
    path: str,
    *,
    tshark_path: Optional[str] = None,
    presets: Optional[list[str]] = None,
    display_filter: str = "",
    compute_hash: bool = True,
    extra_stats: Optional[list[str]] = None,
) -> CaptureInfo:
    info = CaptureInfo(path=os.path.abspath(path), size=file_size(path), generated_at=now_iso())
    if compute_hash and info.size and info.size < 200 * 1024 * 1024:
        try:
            info.sha256 = file_sha256(path)
        except OSError:
            info.sha256 = ""
    info.capinfos = run_capinfos(path)
    runner = TsharkRunner.discover(tshark_path)

    info.tshark_version = tshark_version(runner.binary) or ""
    wanted = list(presets or ANALYZE_PRESETS)
    if extra_stats:
        wanted.extend(extra_stats)
    # dédoublonnage
    seen: set[str] = set()
    ordered: list[str] = []
    for s in wanted:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    for stat in ordered:
        try:
            info.stats[stat] = runner.stats(path, stat, display_filter=display_filter)
        except Exception as exc:  # noqa: BLE001
            info.stats[stat] = f"[erreur] {exc}"
    return info

def parse_io_phs(text: str) -> list[dict[str, Any]]:
    """Parse approximatif de ``io,phs`` → liste {proto, frames, bytes, indent}."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        #  "  http  frames:12 bytes:3456"
        stripped = line.lstrip()
        if not stripped or stripped.startswith("====") or stripped.startswith("Protocol"):
            continue
        indent = len(line) - len(stripped)
        parts = stripped.split()
        if len(parts) < 2:
            continue
        proto = parts[0]
        frames = bytes_ = None
        for p in parts[1:]:
            if p.startswith("frames:"):
                try:
                    frames = int(p.split(":", 1)[1].replace(",", ""))
                except ValueError:
                    pass
            if p.startswith("bytes:"):
                try:
                    bytes_ = int(p.split(":", 1)[1].replace(",", ""))
                except ValueError:
                    pass
        rows.append({"proto": proto, "frames": frames, "bytes": bytes_, "indent": indent})
    return rows

def packets_to_records(
    pcap: str,
    fields: Optional[Sequence[str]] = None,
    *,
    display_filter: str = "",
    limit: int = 0,
    tshark_path: Optional[str] = None,
    decode_as: Optional[Sequence[str]] = None,
) -> tuple[list[str], list[dict[str, str]]]:
    cols = list(fields or DEFAULT_PACKET_FIELDS)
    runner = TsharkRunner.discover(tshark_path)
    res = runner.read_fields(
        pcap,
        cols,
        display_filter=display_filter,
        separator="\t",
        quote="n",
        occurrence="a",
        aggregator=",",
        header=False,
        limit=limit,
        decode_as=decode_as,
    )
    recs: list[dict[str, str]] = []
    for line in res.lines():
        parts = line.split("\t")
        rec: dict[str, str] = {}
        for i, col in enumerate(cols):
            rec[col] = parts[i] if i < len(parts) else ""
        recs.append(rec)
    return cols, recs

def export_packets(
    pcap: str,
    output: str,
    *,
    fmt: str = "csv",
    fields: Optional[Sequence[str]] = None,
    display_filter: str = "",
    limit: int = 0,
    tshark_path: Optional[str] = None,
    decode_as: Optional[Sequence[str]] = None,
) -> str:
    cols, recs = packets_to_records(
        pcap,
        fields,
        display_filter=display_filter,
        limit=limit,
        tshark_path=tshark_path,
        decode_as=decode_as,
    )
    path = Path(output)
    ensure_parent(path)
    fmt = fmt.lower().lstrip(".")
    if fmt == "json":
        path.write_text(json.dumps(recs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return str(path)
    if fmt in {"xlsx", "excel", "xls"}:
        return _xlsx(path.with_suffix(".xlsx"), cols, recs)
    if fmt in {"md", "markdown"}:
        return _md(path.with_suffix(".md"), cols, recs)
    if fmt == "txt":
        with open(path.with_suffix(".txt"), "w", encoding="utf-8") as f:
            f.write("\t".join(cols) + "\n")
            for r in recs:
                f.write("\t".join(r.get(c, "") for c in cols) + "\n")
        return str(path.with_suffix(".txt"))
    # csv default
    out = path if path.suffix.lower() == ".csv" else path.with_suffix(".csv")
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(recs)
    return str(out)

def _xlsx(path: Path, cols: list[str], recs: list[dict[str, str]]) -> str:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Paquets"
    ws.append(cols)
    fill = PatternFill("solid", fgColor="1F4E79")
    font = Font(bold=True, color="FFFFFF")
    for cell in ws[1]:
        cell.fill = fill
        cell.font = font
        cell.alignment = Alignment(horizontal="center")
    for r in recs:
        ws.append([r.get(c, "") for c in cols])
    for i, c in enumerate(cols, 1):
        ws.column_dimensions[get_column_letter(i)].width = min(max(len(c) + 2, 12), 48)
    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"
    ensure_parent(path)
    wb.save(path)
    return str(path)

def _md(path: Path, cols: list[str], recs: list[dict[str, str]]) -> str:
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for r in recs:
        lines.append("| " + " | ".join((r.get(c, "") or "").replace("|", "\\|") for c in cols) + " |")
    ensure_parent(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)

def convert(
    src: str,
    dst: str,
    *,
    fmt: str = "pcapng",
    tshark_path: Optional[str] = None,
    display_filter: str = "",
) -> str:
    """Réécrit une capture (filtre optionnel) via tshark -w."""
    runner = TsharkRunner.discover(tshark_path)
    extra = ["-F", fmt] if fmt else []
    args = ["-r", src, "-w", dst, *extra]
    if display_filter:
        args.extend(["-Y", display_filter])
    runner.run(args, check=True)
    return dst

def split_by_packets(src: str, dst_prefix: str, count: int, editcap: Optional[str] = None) -> str:
    bin_ = editcap or find_editcap()
    if not bin_:
        raise TsharkError("editcap introuvable")
    subprocess.run([bin_, "-c", str(count), src, dst_prefix], check=True)
    return dst_prefix

def split_by_seconds(src: str, dst_prefix: str, seconds: int, editcap: Optional[str] = None) -> str:
    bin_ = editcap or find_editcap()
    if not bin_:
        raise TsharkError("editcap introuvable")
    subprocess.run([bin_, "-i", str(seconds), src, dst_prefix], check=True)
    return dst_prefix

def merge(inputs: Sequence[str], dst: str, mergecap: Optional[str] = None, chrono: bool = True) -> str:
    bin_ = mergecap or find_mergecap()
    if not bin_:
        raise TsharkError("mergecap introuvable")
    args = [bin_, "-w", dst]
    if not chrono:
        args.append("-a")
    args.extend(inputs)
    subprocess.run(args, check=True)
    return dst

def strip_comments(src: str, dst: str, editcap: Optional[str] = None) -> str:
    bin_ = editcap or find_editcap()
    if not bin_:
        raise TsharkError("editcap introuvable")
    subprocess.run([bin_, src, dst], check=True)
    return dst

def change_time(src: str, dst: str, offset: str, editcap: Optional[str] = None) -> str:
    """Décale les timestamps (syntaxe editcap -t)."""
    bin_ = editcap or find_editcap()
    if not bin_:
        raise TsharkError("editcap introuvable")
    subprocess.run([bin_, "-t", offset, src, dst], check=True)
    return dst

def build_full_report(
    result: ExtractResult,
    info: Optional[CaptureInfo],
    output_prefix: str,
    *,
    source: str = "",
    elapsed: float = 0.0,
    wordlist: str = "wordlist.txt",
) -> list[str]:
    extra = {}
    if info is not None:
        extra["capinfos"] = [{"key": k, "value": v} for k, v in info.capinfos.items()]
        extra["meta_capture"] = [
            {"key": "path", "value": info.path},
            {"key": "size", "value": info.size},
            {"key": "sha256", "value": info.sha256},
            {"key": "tshark", "value": info.tshark_version},
        ]
    req = ExportRequest(
        output=str(Path(output_prefix)),
        formats=["html", "md", "json", "xlsx", "txt"],
        wordlist=wordlist,
        source_pcap=source,
        elapsed=elapsed,
        extra_sheets=extra,
    )
    arts = export_all(result, req)
    # dump stats brutes à côté
    written = [a.path for a in arts]
    if info is not None:
        stats_dir = Path(output_prefix)
        if stats_dir.suffix:
            stats_dir = stats_dir.with_suffix("")
        stats_dir = Path(str(stats_dir) + "_stats")
        stats_dir.mkdir(parents=True, exist_ok=True)
        for name, text in info.stats.items():
            safe = name.replace(",", "_").replace(" ", "_")
            p = stats_dir / f"{safe}.txt"
            p.write_text(text or "", encoding="utf-8", errors="replace")
            written.append(str(p))
    return written

def _console():
    from rich.console import Console
    return Console(highlight=False)

def _table(title: str, columns: Sequence[tuple[str, dict]]):
    from rich.table import Table
    from rich import box

    t = Table(title=title, box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}", expand=True)
    for name, kwargs in columns:
        t.add_column(name, **kwargs)
    return t

def print_hashes(result: ExtractResult, wordlist: str = "wordlist.txt", prefix: str = "hashes") -> None:
    if not result.total():
        return
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        for mode in result.modes():
            print(f"  [m{mode}] {len(result.hashes[mode])} hash(es)")
        return
    console = _console()
    table = Table(title="Hashes extraits", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
    table.add_column("mode", style="bold yellow", justify="right")
    table.add_column("nom", style="white")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("commande hashcat", style="green")
    for mode in result.modes():
        info = mode_info(mode) or {}
        table.add_row(
            str(mode),
            info.get("name") or "",
            str(len(result.hashes[mode])),
            hashcat_command(mode, f"{prefix}_m{mode}.txt", wordlist),
        )
    console.print(table)

def print_creds(result: ExtractResult, limit: int = 40) -> None:
    """N'affiche que les secrets utiles (pas le fuzz SNMP / bannières SSH)."""
    net = build_network_report(result)
    secrets = list(net.get("secrets") or [])
    if not secrets:
        return
    shown = secrets[:limit]
    extra = len(secrets) - len(shown)
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        for c in shown:
            print(f"  {c.protocol:<22} {c.username} : {c.password}")
        if extra > 0:
            print(f"  … +{extra} secret(s)")
        return
    console = _console()
    title = "Secrets utiles"
    if extra > 0:
        title += f"  ({len(secrets)} au total, {extra} masqué(s))"
    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
    table.add_column("type", style="magenta")
    table.add_column("identité", style="yellow")
    table.add_column("secret", style="green")
    table.add_column("#", justify="right", style="dim")
    table.add_column("source", style="dim")
    for c in shown:
        table.add_row(c.protocol, c.username, c.password, str(c.frame or ""), c.source)
    console.print(table)

def print_network_report(
    result: ExtractResult,
    net: Optional[dict[str, Any]] = None,
    *,
    wordlist: str = "wordlist.txt",
    prefix: str = "hashes",
) -> None:
    """Briefing pentester : synthèse, findings expliqués, chemins, MITRE, comparaison."""
    net = net or build_network_report(result)
    try:
        report = assess_protection(result, net=net)
    except Exception:
        report = {
            "score": 100,
            "niveau": "—",
            "findings": [],
            "recommandations": [],
            "osint": {},
            "expositions": [],
            "chemins": [],
            "ecarts": [],
            "mitre": [],
            "cartographie": [],
            "conclusion": "",
            "synthese": "",
            "verdict": "",
            "perimetre": "",
        }
    osint = report.get("osint") or {}
    niveau = str(report.get("niveau") or "—")
    score = report.get("score")
    sev_style = {
        "CRITIQUE": "bold red",
        "ÉLEVÉ": "bold yellow",
        "ELEVE": "bold yellow",
        "MOYEN": "yellow",
        "FAIBLE": "green",
        "MANQUANT": "bold red",
        "PARTIEL": "yellow",
        "OK": "green",
    }
    hashes = net.get("hashes") or {}
    krb = net.get("kerberos") or []

    if _have_rich():
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        from rich.text import Text
        from rich.markdown import Markdown

        console = _console()
        head = Text()
        head.append("tshark2hashcat", style=f"bold {COLOR_CYAN}")
        head.append("  ·  rapport d'audit\n", style="dim")
        if report.get("domaine") or report.get("dc"):
            head.append(
                f"domaine {report.get('domaine') or '—'}  ·  DC {report.get('dc') or '—'}\n",
                style="white",
            )
        if net.get("n_files"):
            head.append(f"{net['n_files']} capture(s)  ·  ", style="dim")
        head.append(f"{result.packets} paquets", style="bold white")
        head.append(
            f"  ·  {len(report.get('ad_users') or [])} compte(s) AD  ·  "
            f"{len(report.get('expositions') or [])} finding(s)\n",
            style="white",
        )
        head.append(f"Risque {niveau}  ·  score {score}/100", style=sev_style.get(niveau, "white"))
        head.append("\n\n", style="white")
        head.append(report.get("conclusion") or report.get("verdict") or "Pas de conclusion.", style="white")
        console.print(
            Panel(
                head,
                title="[bold]synthèse exécutive[/]",
                border_style="red" if niveau == "CRITIQUE" else COLOR_CYAN,
                padding=(0, 1),
            )
        )
        if report.get("perimetre"):
            console.print(Panel(report["perimetre"], title="périmètre", border_style=COLOR_BLUE, padding=(0, 1)))

        expos = list(report.get("expositions") or [])
        if expos:
            for e in expos:
                sev = e.get("sev") or ""
                body = Text()
                body.append((e.get("detail") or e.get("impact") or "") + "\n\n", style="white")
                if e.get("preuve"):
                    body.append("Preuve : ", style="dim")
                    body.append(str(e.get("preuve")) + "\n", style="yellow")
                if e.get("actifs"):
                    body.append("Actifs : ", style="dim")
                    body.append(str(e.get("actifs")) + "\n", style="cyan")
                if e.get("reco"):
                    body.append("Remédiation : ", style="dim")
                    body.append(str(e.get("reco")), style="green")
                mids = ", ".join(t[0] for t in _MITRE_CATALOG.get(e.get("mitre") or "", [])[:4])
                title = f"[{sev_style.get(sev, 'white')}]{e.get('id') or ''}  {sev}  —  {e.get('titre') or ''}[/]"
                if mids:
                    title += f"  [dim]{mids}[/]"
                console.print(Panel(body, title=title, border_style="red" if sev == "CRITIQUE" else "yellow" if sev == "ÉLEVÉ" else COLOR_DIM, padding=(0, 1)))

        chemins = list(report.get("chemins") or [])
        if chemins:
            table = Table(title="Chemin d'attaque", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}", expand=True)
            table.add_column("#", style="bold yellow", width=3)
            table.add_column("étape", style="white", max_width=26)
            table.add_column("scénario", style="dim")
            table.add_column("résultat", style="yellow", max_width=28)
            table.add_column("MITRE", style="cyan", max_width=22)
            for c in chemins:
                table.add_row(str(c.get("etape") or ""), c.get("nom") or "", c.get("scenario") or "", c.get("resultat") or "", c.get("mitre") or "")
            console.print(table)

        carto = list(report.get("cartographie") or [])
        if carto:
            table = Table(title="Cartographie (ce qui a vraiment été vu)", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
            table.add_column("type", style="magenta")
            table.add_column("nom", style="yellow")
            table.add_column("rôle", style="white")
            table.add_column("détail", style="dim")
            for row in carto[:24]:
                table.add_row(row.get("type") or "", row.get("nom") or "", row.get("rôle") or "", row.get("détail") or "")
            console.print(table)

        mitre = list(report.get("mitre") or [])
        if mitre:
            table = Table(title="MITRE ATT&CK", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
            table.add_column("ID", style="bold yellow", width=12)
            table.add_column("technique", style="white")
            table.add_column("tactique", style="magenta")
            for m in mitre:
                table.add_row(m.get("id") or "", m.get("technique") or "", m.get("tactique") or "")
            console.print(table)

        ecarts = list(report.get("ecarts") or [])
        if ecarts:
            table = Table(title="Comparaison  attendu  vs  observé", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}", expand=True)
            table.add_column("écart", style="bold", width=14)
            table.add_column("contrôle", style="white", max_width=26)
            table.add_column("attendu", style="green", max_width=34)
            table.add_column("observé", style="yellow")
            for g in ecarts:
                st = g.get("écart") or ""
                key = st.upper().split("/")[0].strip()
                table.add_row(f"[{sev_style.get(key, 'white')}]{st}[/]", g.get("contrôle") or "", g.get("attendu") or "", g.get("observé") or "")
            console.print(table)

        recos = list(report.get("recommandations") or [])
        if recos:
            console.print(f"[bold {COLOR_CYAN}]Actions prioritaires[/]")
            for i, reco in enumerate(recos[:8], 1):
                prio = "P1" if i <= 2 else "P2" if i <= 5 else "P3"
                col = "bold red" if prio == "P1" else "yellow" if prio == "P2" else "cyan"
                console.print(f"  [{col}]{prio}[/]  {reco}")
    else:
        print("tshark2hashcat — rapport d'audit")
        print(f"  Risque {niveau}  ·  score {score}/100")
        print(f"  {report.get('conclusion') or ''}")
        print(report.get("perimetre") or "")
        for e in report.get("expositions") or []:
            print(f"  [{e.get('id')}] [{e.get('sev')}] {e.get('titre')}")
            print(f"      {e.get('detail') or ''}")
        for c in report.get("chemins") or []:
            print(f"  chemin {c.get('etape')}. {c.get('nom')} → {c.get('resultat')}")

    if hashes:
        try:
            from rich.table import Table
            from rich import box

            table = Table(title="Hashes Hashcat (uniques)", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
            table.add_column("mode", style="bold yellow", justify="right")
            table.add_column("nom")
            table.add_column("#", justify="right", style="cyan")
            table.add_column("contexte", style="white")
            table.add_column("commande", style="green")
            for mode in sorted(hashes):
                hits = hashes[mode]
                ctxs = []
                for h in hits[:4]:
                    ctx = hash_context(h)
                    if ctx and ctx not in ctxs:
                        ctxs.append(ctx)
                info_ = mode_info(mode) or {}
                table.add_row(
                    str(mode),
                    info_.get("name") or "",
                    str(len(hits)),
                    " | ".join(ctxs),
                    hashcat_command(mode, f"{prefix}_m{mode}.txt", wordlist),
                )
            _console().print(table)
        except ImportError:
            for mode, hits in sorted(hashes.items()):
                print(f"  [m{mode}] {len(hits)}  {hash_context(hits[0]) if hits else ''}")

    if krb:
        try:
            from rich.table import Table
            from rich import box

            table = Table(title="Kerberos (dédoublonné)", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
            table.add_column("msg", style="yellow")
            table.add_column("user")
            table.add_column("realm")
            table.add_column("spn", style="magenta")
            table.add_column("etypes", style="cyan")
            for d in krb[:16]:
                table.add_row(d.msg, d.user or "?", d.realm or "?", d.spn or "-", ",".join(map(str, d.etypes)) or "-")
            _console().print(table)
        except ImportError:
            for d in krb[:16]:
                print(f"  {d.msg} {d.user}@{d.realm} {d.spn or '-'}")

    print_creds(result)

def print_protocols(result: ExtractResult) -> None:
    """Affiche les protocoles réellement vus (frame.protocols), avec compteurs."""
    counts = getattr(result, "proto_counts", None) or {}
    if counts:
        items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    else:
        items = [(p, 0) for p in sorted(result.proto_seen)]
    if not items:
        info(t("res.protocols", protos=t("res.none")))
        return
    shown = items[:30]
    summary = ", ".join(f"{p}×{n}" if n else p for p, n in shown)
    if len(items) > 30:
        summary += f"  (+{len(items) - 30})"
    info(t("res.protocols", protos=summary))
    if not _have_rich() or len(items) < 3:
        return
    try:
        from rich.table import Table
        from rich import box
        table = Table(title="Protocoles de la capture", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
        table.add_column("protocole", style="cyan")
        table.add_column("paquets", justify="right", style="yellow")
        for p, n in shown:
            table.add_row(p, str(n))
        _console().print(table)
    except Exception:
        pass

def print_kerberos(result: ExtractResult) -> None:
    items = dedupe_kerberos(result.diag)
    if not items:
        return
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        for d in items:
            print(
                f"    frame #{d.frame:<5} {d.msg:<8} user={d.user or '?'} realm={d.realm or '?'}"
                f" spn={d.spn or '-'} salt={' + '.join(d.salts) or '-'}"
                f" etypes={','.join(map(str, d.etypes)) or '-'}"
            )
        return
    console = _console()
    table = Table(title="Identités Kerberos vues", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
    table.add_column("#", justify="right")
    table.add_column("msg", style="yellow")
    table.add_column("user")
    table.add_column("realm")
    table.add_column("spn", style="magenta")
    table.add_column("salt", style="dim")
    table.add_column("etypes", style="cyan")
    for d in items:
        table.add_row(
            str(d.frame),
            d.msg,
            d.user or "?",
            d.realm or "?",
            d.spn or "-",
            " + ".join(d.salts) or "-",
            ",".join(map(str, d.etypes)) or "-",
        )
    console.print(table)

def print_artifacts(arts: list[ExportArtifact]) -> None:
    if not arts:
        return
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        for a in arts:
            print(f"  [{a.kind}] {a.path}  ({a.count})")
        return
    console = _console()
    table = Table(title="Fichiers exportés", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
    table.add_column("type", style="yellow")
    table.add_column("fichier", style="green")
    table.add_column("#", justify="right")
    table.add_column("note", style="dim")
    for a in arts:
        table.add_row(a.kind, a.path, str(a.count), a.note)
    console.print(table)

def print_modes(rows: Iterable[dict[str, Any]], pcap_only: bool = False) -> None:
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        for info in rows:
            if pcap_only and not info.get("from_pcap"):
                continue
            print(f"  {info['mode']:>5}  {info['name']}")
        return
    console = _console()
    table = Table(title="Modes Hashcat", box=box.SIMPLE_HEAVY, header_style=f"bold {COLOR_CYAN}")
    table.add_column("mode", justify="right", style="yellow")
    table.add_column("nom")
    table.add_column("catégorie", style="magenta")
    table.add_column("protocole", style="cyan")
    table.add_column("PCAP", justify="center")
    n = 0
    for info in rows:
        if pcap_only and not info.get("from_pcap"):
            continue
        table.add_row(*format_mode_row(info))
        n += 1
    console.print(table)
    console.print(f"  [dim]{n} mode(s) affiché(s) / {len(MODE_CATALOG)} au catalogue[/]")

def print_kv_panel(title: str, items: Sequence[tuple[str, Any]]) -> None:
    try:
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
    except ImportError:
        print(f"=== {title} ===")
        for k, v in items:
            print(f"  {k:<24} {v}")
        return
    table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    table.add_column(style="dim")
    table.add_column()
    for k, v in items:
        table.add_row(str(k), str(v))
    _console().print(Panel(table, title=f"[bold cyan]{title}[/]", border_style="blue"))

def _ask(prompt: str, default: str = "") -> str:
    suffix = f"  [{default}]" if default else ""
    try:
        val = input(f"  → {prompt}{suffix}\n    ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return val or default

def _ask_file(prompt: str = "Fichier de capture (.pcap / .pcapng / .cap / .json)") -> str:
    while True:
        path = _ask(prompt).strip().strip('"').strip("'")
        if not path:
            return ""
        # glisser-déposer Windows : parfois le chemin arrive avec des quotes
        if os.path.isfile(path):
            return path
        # relatif au dossier courant
        cand = os.path.abspath(path)
        if os.path.isfile(cand):
            return cand
        err(f"Fichier introuvable : {path}")
        tip("Glissez-déposez le fichier ici, ou collez le chemin complet.")

def _pause() -> None:
    try:
        input("\n  [Entrée] pour revenir au menu… ")
    except (EOFError, KeyboardInterrupt):
        print()

def _ask_dir(prompt: str = "Dossier contenant les .pcap / .pcapng / .cap") -> str:
    while True:
        path = _ask(prompt).strip().strip('"').strip("'")
        if not path:
            return ""
        if os.path.isdir(path):
            return path
        cand = os.path.abspath(path)
        if os.path.isdir(cand):
            return cand
        err(f"Dossier introuvable : {path}")
        tip("Glissez-déposez le dossier ici, ou collez le chemin complet.")

def _print_menu() -> None:
    """3 options max : fichier / dossier / quitter."""
    items = [
        ("1", "Un fichier   →   Excel + txt Hashcat"),
        ("2", "Un dossier   →   Excel + txt Hashcat (tous les pcap)"),
        ("0", "Quitter"),
    ]
    if _have_rich():
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        table = Table(box=box.SIMPLE, show_header=False, pad_edge=False, expand=True)
        table.add_column(justify="right", style=f"bold {COLOR_YELLOW}", width=4)
        table.add_column(style="white")
        for num, label in items:
            table.add_row(num, label)
        Console(highlight=False).print(
            Panel(
                table,
                title=f"[bold {COLOR_CYAN}]tshark2hashcat[/]  [dim]— menu[/]",
                border_style=COLOR_BLUE,
                padding=(0, 1),
            )
        )
    else:
        print()
        print("  tshark2hashcat  —  menu")
        print("  " + "─" * 56)
        for num, label in items:
            print(f"    {num}.  {label}")
        print()

def run_wizard(lang: str = "fr") -> int:
    """Menu interactif : on tape un numéro, pas une commande."""
    set_lang(lang)
    first = True
    while True:
        if first:
            print_logo(lang=lang)
            first = False
        else:
            print()
        _print_menu()
        try:
            choix = input("  Votre choix : ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choix in {"0", "q", "quit", "exit", "n", "non"}:
            ok("À bientôt.")
            return 0
        if choix not in {"1", "2"}:
            warn("Tapez 1 (fichier), 2 (dossier) ou 0 (quitter).")
            continue

        try:
            if choix == "1":
                pcap = _ask_file()
                if not pcap:
                    continue
                main(["auto", pcap, "--no-banner"])
            elif choix == "2":
                dossier = _ask_dir()
                if not dossier:
                    continue
                main(["folder", dossier, "--no-banner"])
        except SystemExit as exc:
            # les cmd_* font parfois sys.exit — on reste dans le menu
            if exc.code not in (0, None):
                warn(f"terminé avec le code {exc.code}")
        except Exception as exc:  # noqa: BLE001
            err(str(exc))
        _pause()

def _global_parent() -> argparse.ArgumentParser:
    """Options globales acceptées AVANT et APRÈS la sous-commande."""
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--lang", choices=("fr", "en"), default=None, help="Langue de l'interface")
    g.add_argument("--no-banner", action="store_true", help="Masquer le logo")
    g.add_argument("--no-color", action="store_true", help="Désactiver les couleurs")
    g.add_argument("--quiet", "-q", action="store_true", help="Moins de sortie")
    g.add_argument("--verbose", "-v", action="store_true", help="Plus de détails")
    g.add_argument("--no-progress", action="store_true", help="Masquer les barres de progression")
    g.add_argument("--config", help="Fichier de config JSON/TOML")
    g.add_argument("--tshark", help="Chemin complet vers tshark")
    return g

def _build_parser() -> argparse.ArgumentParser:
    parent = _global_parent()
    p = argparse.ArgumentParser(
        prog="tshark2hashcat",
        description="tshark2hashcat — hashes Hashcat + analyse PCAP via Tshark.\n"
        "Sans argument : menu numéroté (aucune commande à retenir).",
        epilog="Lancez simplement le script (double-clic ou python tshark2hashcat.py) pour le menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[parent],
    )
    p.add_argument("-V", "--version", action="version", version=f"{__app_name__} {__version__}")

    sub = p.add_subparsers(dest="cmd", metavar="COMMANDE", parser_class=argparse.ArgumentParser)
    # chaque sous-commande hérite des flags globaux (extract --no-banner, etc.)
    def _sub(name: str, **kwargs):
        kwargs.setdefault("parents", [parent])
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        return sub.add_parser(name, **kwargs)

    # extract
    e = _sub("extract", help=t("help.extract"), description=t("help.extract"))
    e.add_argument("pcap", help="Fichier .pcap / .pcapng / .cap / export .json tshark")
    e.add_argument("-o", "--output", default="hashes.txt", help="Fichier / préfixe de sortie (défaut: hashes.txt)")
    e.add_argument("-f", "--formats", default="txt", help="Formats : txt,csv,json,xlsx,html,md (séparés par des virgules)")
    e.add_argument("-Y", "--display-filter", default="", help="Filtre d'affichage tshark")
    e.add_argument("-d", "--decode-as", action="append", default=[], help="decode-as (répétable) ex: tcp.port==8888,http")
    e.add_argument("--wordlist", default="wordlist.txt", help="Wordlist affichée dans les commandes hashcat")
    e.add_argument("--no-ntlm", action="store_true")
    e.add_argument("--no-kerberos", action="store_true")
    e.add_argument("--no-wpa", action="store_true")
    e.add_argument("--no-apop", action="store_true")
    e.add_argument("--no-creds", action="store_true")
    e.add_argument("--no-raw", action="store_true", help="Ne pas scanner les octets bruts (-x)")
    e.add_argument("--limit", type=int, default=0, help="Limiter au N premiers paquets")
    e.set_defaults(_fn=cmd_extract)

    # auto — un fichier, tout extraire, rapport de protection
    au = _sub("auto", help="Analyse automatique : hashes + secrets + rapport de protection")
    au.add_argument("pcap", help="Fichier .pcap / .pcapng / .cap / export .json tshark")
    au.add_argument("-o", "--output", default="", help="Fichier .xlsx (défaut : tshark2hashcat-rapport.xlsx)")
    au.add_argument("-f", "--formats", default="xlsx,txt", help="Excel + txt Hashcat")
    au.add_argument("-Y", "--display-filter", default="")
    au.add_argument("-d", "--decode-as", action="append", default=[])
    au.add_argument("--wordlist", default="wordlist.txt")
    au.add_argument("--limit", type=int, default=0)
    au.add_argument("--no-raw", action="store_true")
    au.set_defaults(_fn=cmd_auto)

    # folder — un dossier de pcap → un seul Excel
    fd = _sub("folder", help="Dossier de captures → un seul classeur Excel")
    fd.add_argument("folder", help="Dossier contenant des .pcap / .pcapng / .cap")
    fd.add_argument("-o", "--output", default="", help="Fichier .xlsx (défaut : tshark2hashcat-rapport.xlsx)")
    fd.add_argument("-Y", "--display-filter", default="")
    fd.add_argument("-d", "--decode-as", action="append", default=[])
    fd.add_argument("--wordlist", default="wordlist.txt")
    fd.add_argument("--limit", type=int, default=0)
    fd.add_argument("--no-raw", action="store_true")
    fd.add_argument("--raw", action="store_true", help="Dump hex (-x) : plus lent, pour NTLM/APOP brut")
    fd.add_argument("--no-recursive", action="store_true", help="Ne pas descendre dans les sous-dossiers")
    fd.set_defaults(_fn=cmd_folder)

    # analyze
    a = _sub("analyze", help=t("help.analyze"))
    a.add_argument("pcap")
    a.add_argument("-Y", "--display-filter", default="")
    a.add_argument("-z", "--stat", action="append", default=[], help="Stats supplémentaires (répétable)")
    a.add_argument("--no-hash", action="store_true", help="Ne pas calculer le SHA-256")
    a.add_argument("-o", "--output", default="", help="Sauver les stats dans un dossier")
    a.set_defaults(_fn=cmd_analyze)

    # stats
    s = _sub("stats", help=t("help.stats"))
    s.add_argument("pcap")
    s.add_argument("-z", "--stat", action="append", required=True, help="Statistique tshark (répétable)")
    s.add_argument("-Y", "--display-filter", default="")
    s.add_argument("-o", "--output", default="", help="Fichier de sortie (sinon stdout)")
    s.set_defaults(_fn=cmd_stats)

    # packets
    pk = _sub("packets", help=t("help.packets"))
    pk.add_argument("pcap")
    pk.add_argument("-o", "--output", required=True, help="Fichier de sortie")
    pk.add_argument("--format", default="", help="csv / json / xlsx / md / txt (sinon d'après l'extension)")
    pk.add_argument("-Y", "--display-filter", default="")
    pk.add_argument("-e", "--field", action="append", default=[], help="Champ tshark (répétable)")
    pk.add_argument("--limit", type=int, default=0)
    pk.add_argument("-d", "--decode-as", action="append", default=[])
    pk.set_defaults(_fn=cmd_packets)

    # follow
    fo = _sub("follow", help=t("help.follow"))
    fo.add_argument("pcap")
    fo.add_argument("--tcp", dest="tcp_idx", default=None, help="Index de flux TCP")
    fo.add_argument("--udp", dest="udp_idx", default=None)
    fo.add_argument("--http", dest="http_idx", default=None)
    fo.add_argument("--tls", dest="tls_idx", default=None)
    fo.add_argument("--sip", dest="sip_idx", default=None)
    fo.add_argument("--mode", default="ascii", choices=("ascii", "ebcdic", "hex", "raw", "yaml"))
    fo.add_argument("-o", "--output", default="")
    fo.set_defaults(_fn=cmd_follow)

    # objects
    ob = _sub("objects", help=t("help.objects"))
    ob.add_argument("pcap")
    ob.add_argument("--proto", default="http", help="http / smb / imf / tftp / dicom")
    ob.add_argument("-o", "--output", default="objects", help="Dossier de sortie")
    ob.add_argument("-Y", "--display-filter", default="")
    ob.set_defaults(_fn=cmd_objects)

    # filter / rewrite pcap
    fl = _sub("filter", help=t("help.filter"))
    fl.add_argument("pcap")
    fl.add_argument("-Y", "--display-filter", required=True)
    fl.add_argument("-o", "--output", required=True, help="Nouveau .pcap / .pcapng")
    fl.add_argument("-F", "--file-format", default="", help="pcap / pcapng")
    fl.set_defaults(_fn=cmd_filter)

    # report
    rp = _sub("report", help=t("help.report"))
    rp.add_argument("pcap")
    rp.add_argument("-o", "--output", default="rapport")
    rp.add_argument("-Y", "--display-filter", default="")
    rp.add_argument("--wordlist", default="wordlist.txt")
    rp.set_defaults(_fn=cmd_report)

    # wizard
    wz = _sub("wizard", help=t("help.wizard"))
    wz.set_defaults(_fn=cmd_wizard)

    # info (capinfos)
    inf = _sub("info", help=t("help.info"))
    inf.add_argument("pcap")
    inf.set_defaults(_fn=cmd_info)

    # interfaces
    iff = _sub("ifaces", help=t("help.ifaces"))
    iff.set_defaults(_fn=cmd_ifaces)

    # protocols / fields glossary
    pr = _sub("protocols", help=t("help.protocols"))
    pr.add_argument("--fields", action="store_true", help="Lister les champs au lieu des protocoles")
    pr.add_argument("--search", default="", help="Filtrer par sous-chaîne")
    pr.add_argument("-G", "--glossary", default="", help="Rapport -G (protocols/fields/plugins/…)")
    pr.set_defaults(_fn=cmd_protocols)

    # hashcat helper
    hc = _sub("hashcat", help=t("help.hashcat"))
    hc.add_argument("hashfile", help="Fichier de hashes")
    hc.add_argument("-m", "--mode", type=int, default=0, help="Mode (0 = auto)")
    hc.add_argument("--wordlist", default="wordlist.txt")
    hc.set_defaults(_fn=cmd_hashcat)

    # creds only
    cr = _sub("creds", help=t("help.creds"))
    cr.add_argument("pcap")
    cr.add_argument("-o", "--output", default="credentials.txt")
    cr.set_defaults(_fn=cmd_creds)

    # convert
    cv = _sub("convert", help=t("help.convert"))
    cv.add_argument("inputs", nargs="+", help="Fichier(s) source")
    cv.add_argument("-o", "--output", required=True)
    cv.add_argument("-F", "--file-format", default="pcapng")
    cv.add_argument("--merge", action="store_true", help="Fusionner plusieurs fichiers")
    cv.add_argument("--split-packets", type=int, default=0, help="Découper tous les N paquets")
    cv.add_argument("--split-seconds", type=int, default=0, help="Découper toutes les N secondes")
    cv.set_defaults(_fn=cmd_convert)

    # expert
    ex = _sub("expert", help=t("help.expert"))
    ex.add_argument("pcap")
    ex.add_argument("--level", default="", choices=("", "error", "warn", "note", "chat"))
    ex.add_argument("-o", "--output", default="")
    ex.set_defaults(_fn=cmd_expert)

    # hosts
    ho = _sub("hosts", help=t("help.hosts"))
    ho.add_argument("pcap")
    ho.add_argument("-o", "--output", default="")
    ho.set_defaults(_fn=cmd_hosts)

    # voip
    vo = _sub("voip", help=t("help.voip"))
    vo.add_argument("pcap")
    vo.add_argument("-o", "--output", default="")
    vo.set_defaults(_fn=cmd_voip)

    # capture live
    cap = _sub("capture", help=t("help.capture"))
    cap.add_argument("-i", "--interface", required=True)
    cap.add_argument("-o", "--output", required=True)
    cap.add_argument("-a", "--duration", type=int, default=0, help="Durée en secondes")
    cap.add_argument("-c", "--packets", type=int, default=0)
    cap.add_argument("-f", "--capture-filter", default="", help="Filtre BPF")
    cap.add_argument("-s", "--snaplen", type=int, default=0)
    cap.add_argument("-p", "--no-promisc", action="store_true")
    cap.add_argument("-I", "--monitor", action="store_true")
    cap.set_defaults(_fn=cmd_capture)

    # decode-as helper (just documents + runs -d)
    dec = _sub("decode", help=t("help.decode"))
    dec.add_argument("pcap")
    dec.add_argument("-d", "--decode-as", action="append", required=True)
    dec.add_argument("-Y", "--display-filter", default="")
    dec.add_argument("-o", "--output", default="", help="Réécrire le pcap décodé")
    dec.add_argument("-V", dest="verbose_tree", action="store_true", help="Afficher l'arbre")
    dec.set_defaults(_fn=cmd_decode)

    # fields
    fi = _sub("fields", help=t("help.fields"))
    fi.add_argument("pcap")
    fi.add_argument("-e", "--field", action="append", required=True)
    fi.add_argument("-Y", "--display-filter", default="")
    fi.add_argument("--limit", type=int, default=0)
    fi.add_argument("-o", "--output", default="")
    fi.set_defaults(_fn=cmd_fields)

    # modes catalog
    mo = _sub("modes", help=t("help.modes"))
    mo.add_argument("query", nargs="?", default="", help="Recherche (nom, proto, n°) ")
    mo.add_argument("--pcap-only", action="store_true", help="Uniquement les modes extractibles d'un PCAP")
    mo.set_defaults(_fn=cmd_modes)

    # filters catalog
    flt = _sub("filters", help="Bibliothèque de filtres d'affichage")
    flt.add_argument("query", nargs="?", default="")
    flt.add_argument("--group", default="")
    flt.set_defaults(_fn=cmd_filters)

    # tshark help / options catalog
    th = _sub("tshark-help", help="Catalogue des options et statistiques tshark")
    th.add_argument("query", nargs="?", default="")
    th.add_argument("--stats", action="store_true")
    th.set_defaults(_fn=cmd_tshark_help)

    # suite status
    st = _sub("doctor", help="Vérifie tshark / editcap / mergecap / dépendances")
    st.set_defaults(_fn=cmd_doctor)

    # examples
    eg = _sub("examples", help="Exemples d'utilisation")
    eg.set_defaults(_fn=cmd_examples)

    # init config
    ic = _sub("init-config", help="Écrire un fichier de config exemple")
    ic.add_argument("-o", "--output", default="tshark2hashcat.json")
    ic.set_defaults(_fn=cmd_init_config)

    return p

def _maybe_banner(args) -> None:
    if getattr(args, "no_banner", False) or getattr(args, "quiet", False):
        return
    print_logo(lang=get_lang(), compact=False, no_color=getattr(args, "no_color", False))

def _need_file(path: str) -> None:
    if not os.path.isfile(path):
        err(t("err.pcap_missing", path=path))
        raise SystemExit(2)

def _run_extraction(
    pcap: str,
    output: str,
    formats: list[str],
    *,
    tshark_path: Optional[str] = None,
    display_filter: str = "",
    decode_as: Optional[list[str]] = None,
    wordlist: str = "wordlist.txt",
    limit: int = 0,
    no_raw: bool = False,
    no_ntlm: bool = False,
    no_kerberos: bool = False,
    no_wpa: bool = False,
    no_apop: bool = False,
    no_creds: bool = False,
    no_progress: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> tuple[ExtractResult, list[ExportArtifact], float]:
    """Charge, extrait, exporte. Partagé par extract et auto."""
    stages = MultiStage(
        [
            ("load", t("stage.run_tshark") if not is_json_export(pcap) else t("stage.parse_json")),
            ("extract", t("stage.extract")),
            ("export", t("stage.export")),
        ],
        disable=no_progress or quiet,
    )
    with Timer() as timer, stages:
        stages.start("load")
        want_hex = not no_raw
        packets = load_packets(
            pcap,
            tshark_path,
            display_filter=display_filter,
            decode_as=decode_as or None,
            limit=limit,
            hexdump=want_hex,
            disable_names=True,
        )
        stages.done("load")

        stages.start("extract")
        engine = ExtractorEngine(
            include_ntlm=not no_ntlm,
            include_kerberos=not no_kerberos,
            include_wpa=not no_wpa,
            include_apop=not no_apop,
            include_creds=not no_creds,
            raw_scan=want_hex,
        )
        if no_progress or quiet:
            result = engine.run(packets)
        else:
            with progress_bar(t("stage.extract"), total=len(packets)) as bar:
                engine.progress_cb = lambda i, n: bar.update(i)
                result = engine.run(packets)
        stages.done("extract")

        stages.start("export")
        req = ExportRequest(
            output=output,
            formats=formats,
            wordlist=wordlist,
            source_pcap=pcap,
            elapsed=timer.seconds,
        )
        arts = export_all(result, req)
        stages.done("export")
    return result, arts, timer.seconds

def _print_extract_results(
    result: ExtractResult,
    arts: list[ExportArtifact],
    *,
    output: str,
    wordlist: str,
    elapsed: float,
    verbose: bool = False,
) -> int:
    section_title("RAPPORT RÉSEAU" if get_lang() == "fr" else "NETWORK REPORT")
    net = build_network_report(result)
    info(t("res.packets", n=result.packets))
    if result.preauth_users:
        info(t("res.preauth", users=", ".join(sorted(result.preauth_users))))
    print_network_report(
        result,
        net,
        wordlist=wordlist,
        prefix=os.path.splitext(output)[0],
    )
    print_artifacts(arts)
    if result.notes and verbose:
        section_title("Notes")
        for n in result.notes:
            tip(n)
    if result.missing and verbose:
        section_title(t("res.missing"))
        for m0 in sorted(set(result.missing)):
            warn(m0)
    if not result.total() and not result.credentials:
        warn(t("err.no_hashes"))
        return 1
    ok(t("res.total", n=result.total(), path=output) + f"  ({elapsed:.2f}s)")
    return 0

def cmd_auto(args) -> int:
    """Un fichier → hashes + toutes les données confidentielles + rapport."""
    _need_file(args.pcap)
    fmts = split_csv(args.formats) or ["xlsx", "txt"]
    src = Path(args.pcap)
    out = args.output or str(src.with_name("tshark2hashcat-rapport.xlsx"))
    try:
        result, arts, elapsed = _run_extraction(
            args.pcap,
            out,
            fmts,
            tshark_path=args.tshark,
            display_filter=getattr(args, "display_filter", "") or "",
            decode_as=getattr(args, "decode_as", None),
            wordlist=getattr(args, "wordlist", "wordlist.txt"),
            limit=getattr(args, "limit", 0) or 0,
            no_raw=getattr(args, "no_raw", False),
            no_progress=args.no_progress,
            quiet=args.quiet,
            verbose=args.verbose,
        )
    except TsharkError as exc:
        err(str(exc))
        return 1
    return _print_extract_results(
        result,
        arts,
        output=out,
        wordlist=getattr(args, "wordlist", "wordlist.txt"),
        elapsed=elapsed,
        verbose=args.verbose,
    )

def discover_pcaps(root: str | os.PathLike, recursive: bool = True) -> list[Path]:
    """Liste les .pcap / .pcapng / .cap / .dmp d'un dossier."""
    base = Path(root).expanduser()
    if not base.is_dir():
        return []
    it = base.rglob("*") if recursive else base.iterdir()
    found: list[Path] = []
    for p in it:
        try:
            if p.is_file() and is_pcap_path(p):
                found.append(p)
        except OSError:
            continue
    return sorted(found, key=lambda x: str(x).lower())

def quick_packet_count(path: str | os.PathLike) -> int:
    """Nombre de paquets via capinfos (rapide). 0 si inconnu."""
    cap = find_capinfos()
    if not cap:
        return 0
    try:
        r = subprocess.run(
            [cap, "-c", "-M", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    for line in (r.stdout or "").splitlines():
        if "packet" in line.lower() or "paquet" in line.lower():
            digits = "".join(ch for ch in line if ch.isdigit())
            if digits:
                return int(digits)
    return 0

_CHUNK_PACKETS = 1500

def split_pcap_chunks(path: str | os.PathLike, workdir: Path) -> list[Path]:
    """Découpe un gros pcap (editcap -c) pour traiter les morceaux en parallèle."""
    src = Path(path)
    n = quick_packet_count(src)
    if n <= _CHUNK_PACKETS:
        return [src]
    edit = find_editcap()
    if not edit:
        return [src]
    workdir.mkdir(parents=True, exist_ok=True)
    prefix = workdir / (safe_filename(src.stem) + "_chk")
    try:
        subprocess.run(
            [edit, "-c", str(_CHUNK_PACKETS), str(src), str(prefix)],
            check=False,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [src]
    chunks = sorted(p for p in prefix.parent.glob(prefix.name + "*") if p.is_file())
    return chunks or [src]

def _extract_job(job: dict[str, Any]) -> dict[str, Any]:
    """Worker (processus/thread) : extraction COMPLÈTE d'un fichier ou d'un chunk."""
    path = job["path"]
    try:
        result = extract_pcap_result(
            path,
            tshark_path=job.get("tshark"),
            display_filter=job.get("display_filter") or "",
            decode_as=job.get("decode_as"),
            limit=job.get("limit") or 0,
            no_raw=False,
            raw=True,
        )
        return {
            "name": job["name"],
            "path": path,
            "ok": True,
            "result": result,
            "error": None,
            "size": file_size(path),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": job["name"],
            "path": path,
            "ok": False,
            "result": None,
            "error": str(exc),
            "size": file_size(path),
        }

def extract_pcap_result(
    pcap: str,
    *,
    tshark_path: Optional[str] = None,
    display_filter: str = "",
    decode_as: Optional[list[str]] = None,
    limit: int = 0,
    no_raw: bool = False,
    no_progress: bool = True,
    raw: bool = False,
) -> ExtractResult:
    """Charge + extrait TOUT (dissection + dump hex) d'un pcap."""
    hexdump = not no_raw
    packets = load_packets(
        pcap,
        tshark_path,
        display_filter=display_filter,
        decode_as=decode_as or None,
        limit=limit,
        hexdump=hexdump,
        disable_names=True,
    )
    engine = ExtractorEngine(raw_scan=hexdump)
    return engine.run(packets)

def _tag_result_file(result: ExtractResult, filename: str) -> ExtractResult:
    """Marque chaque hit avec le nom du pcap d'origine."""
    for _mode, hits in result.hashes.items():
        for h in hits:
            extra = dict(h.extra or {})
            extra["fichier"] = filename
            h.extra = extra
            if filename not in (h.source or ""):
                h.source = f"{filename} · {h.source}" if h.source else filename
    for c in result.credentials:
        extra = dict(c.extra or {})
        extra["fichier"] = filename
        c.extra = extra
        if filename not in (c.source or ""):
            c.source = f"{filename} · {c.source}" if c.source else filename
    return result

def merge_extract_results(parts: list[tuple[str, ExtractResult]]) -> ExtractResult:
    """Fusionne N extractions en un seul ExtractResult (un Excel)."""
    acc = ExtractResult()
    counts: dict[str, int] = defaultdict(int)
    for name, r in parts:
        _tag_result_file(r, name)
        for mode, hits in r.hashes.items():
            acc.hashes[mode].extend(hits)
        acc.credentials.extend(r.credentials)
        acc.missing.extend([f"[{name}] {m}" for m in r.missing])
        acc.proto_seen |= set(r.proto_seen)
        acc.preauth_users |= set(r.preauth_users)
        acc.diag.extend(r.diag)
        acc.notes.extend([f"[{name}] {n}" for n in r.notes])
        acc.packets += int(r.packets or 0)
        acc.rejected += int(r.rejected or 0)
        for proto, n in (getattr(r, "proto_counts", None) or {}).items():
            counts[proto] += int(n)
    acc.proto_counts = dict(counts)
    acc.packet_stats = merge_packet_stats(r for _n, r in parts)
    return finalize_extract_result(acc)

def write_folder_xlsx(
    result: ExtractResult,
    path: str | os.PathLike,
    *,
    source_dir: str,
    elapsed: float,
    files_meta: list[dict[str, Any]],
    wordlist: str = "wordlist.txt",
) -> ExportArtifact:
    """Un seul classeur Excel pour tout le dossier."""
    out = Path(path)
    if out.suffix.lower() != ".xlsx":
        out = out.with_suffix(".xlsx") if out.suffix else Path(str(out) + ".xlsx")
    req = ExportRequest(
        output=str(out.with_suffix("")),
        formats=["xlsx"],
        wordlist=wordlist,
        source_pcap=source_dir,
        elapsed=elapsed,
        extra_sheets={"Fichiers": files_meta},
    )
    return _write_xlsx(result, req, out)

def cmd_folder(args) -> int:
    """Un dossier de captures → un seul Excel (hashes + secrets + protocoles)."""
    root = args.folder
    if not os.path.isdir(root):
        err(f"Dossier introuvable : {root}")
        return 2
    pcaps = discover_pcaps(root, recursive=not getattr(args, "no_recursive", False))
    if not pcaps:
        warn("Aucun .pcap / .pcapng / .cap dans ce dossier.")
        return 1
    info(f"{len(pcaps)} capture(s) trouvée(s) dans {root}")
    info("extraction COMPLÈTE (tous protocoles + dump hex) · parallèle")
    out = args.output or str(Path(root) / "tshark2hashcat-rapport.xlsx")
    if not str(out).lower().endswith((".xlsx", ".xls")):
        out = f"{out}.xlsx"

    parts: list[tuple[str, ExtractResult]] = []
    files_meta: list[dict[str, Any]] = []
    workers = max(1, min(4, os.cpu_count() or 2))
    tmp = Path(tempfile.mkdtemp(prefix="t2h_chunks_"))
    jobs: list[dict[str, Any]] = []
    elapsed_box = [0.0]
    try:
        for pcap_path in pcaps:
            chunks = split_pcap_chunks(pcap_path, tmp / pcap_path.stem)
            if len(chunks) > 1:
                info(f"{pcap_path.name} : {len(chunks)} morceaux (parallèle)")
            for ch in chunks:
                jobs.append(
                    {
                        "path": str(ch),
                        "name": pcap_path.name,
                        "tshark": args.tshark,
                        "display_filter": getattr(args, "display_filter", "") or "",
                        "decode_as": getattr(args, "decode_as", None),
                        "limit": getattr(args, "limit", 0) or 0,
                    }
                )
        info(f"{len(jobs)} tâche(s) · {workers} worker(s)")

        elapsed_box = [0.0]
        with Timer() as timer:
            Pool = ThreadPoolExecutor
            with progress_bar(
                "Dossier",
                total=len(jobs),
                disable=args.no_progress or args.quiet,
            ) as bar:
                with Pool(max_workers=min(workers, len(jobs))) as pool:
                    futs = [pool.submit(_extract_job, job) for job in jobs]
                    done_by_name: dict[str, list[ExtractResult]] = defaultdict(list)
                    err_by_name: dict[str, list[str]] = defaultdict(list)
                    for fut in as_completed(futs):
                        rec = fut.result()
                        label = rec["name"]
                        bar.set_desc(str(label)[:36])
                        if not rec["ok"] or rec["result"] is None:
                            warn(f"{label} : {rec['error']}")
                            err_by_name[label].append(rec["error"] or "échec")
                        else:
                            done_by_name[label].append(rec["result"])
                            ok(
                                f"{label}  {rec['result'].packets} pkt  "
                                f"{rec['result'].total()} hash  "
                                f"{len(rec['result'].credentials)} secret(s)"
                            )
                        bar.advance()

            # fusion par fichier d'origine (chunks + fichiers)
            for pcap_path in pcaps:
                name = pcap_path.name
                if name in done_by_name:
                    merged_one = merge_extract_results(
                        [(name, r) for r in done_by_name[name]]
                    )
                    parts.append((name, merged_one))
                    files_meta.append(
                        {
                            "fichier": name,
                            "chemin": str(pcap_path),
                            "taille": file_size(pcap_path),
                            "paquets": merged_one.packets,
                            "hashes": merged_one.total(),
                            "secrets": len(merged_one.credentials),
                            "protocoles": ", ".join(sorted(merged_one.proto_seen)[:24]),
                        }
                    )
                elif name in err_by_name:
                    files_meta.append(
                        {
                            "fichier": name,
                            "chemin": str(pcap_path),
                            "erreur": " | ".join(err_by_name[name])[:500],
                        }
                    )
            elapsed_box[0] = timer.seconds
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except OSError:
            pass

    merged = merge_extract_results(parts)
    try:
        art = write_folder_xlsx(
            merged,
            out,
            source_dir=os.path.abspath(root),
            elapsed=elapsed_box[0],
            files_meta=files_meta,
            wordlist=getattr(args, "wordlist", "wordlist.txt"),
        )
    except Exception as exc:  # noqa: BLE001
        err(str(exc))
        return 1
    arts = [art]
    if merged.total():
        base = Path(out).with_suffix("")
        arts.extend(_write_txt(merged, ExportRequest(output=str(base)), base))
    return _print_extract_results(
        merged,
        arts,
        output=str(out),
        wordlist=getattr(args, "wordlist", "wordlist.txt"),
        elapsed=elapsed_box[0],
        verbose=args.verbose,
    )

def cmd_extract(args) -> int:
    _need_file(args.pcap)
    fmts = split_csv(args.formats) or ["txt"]
    unknown = [f for f in fmts if f not in EXPORT_FORMATS and f not in {"xls", "excel", "markdown", "htm"}]
    if unknown:
        err(t("err.invalid_format", fmt=",".join(unknown), choices=",".join(EXPORT_FORMATS)))
        return 2
    try:
        result, arts, elapsed = _run_extraction(
            args.pcap,
            args.output,
            fmts,
            tshark_path=args.tshark,
            display_filter=args.display_filter,
            decode_as=args.decode_as or None,
            wordlist=args.wordlist,
            limit=args.limit,
            no_raw=args.no_raw,
            no_ntlm=args.no_ntlm,
            no_kerberos=args.no_kerberos,
            no_wpa=args.no_wpa,
            no_apop=args.no_apop,
            no_creds=args.no_creds,
            no_progress=args.no_progress,
            quiet=args.quiet,
            verbose=args.verbose,
        )
    except TsharkError as exc:
        err(str(exc))
        return 1
    return _print_extract_results(
        result, arts, output=args.output, wordlist=args.wordlist,
        elapsed=elapsed, verbose=args.verbose,
    )

def cmd_analyze(args) -> int:

    _need_file(args.pcap)
    with progress_bar(t("stage.analyze"), total=None, disable=args.no_progress or args.quiet) as bar:
        bar.set_desc(t("stage.analyze"))
        info_ = analyze_capture(
            args.pcap,
            tshark_path=args.tshark,
            extra_stats=args.stat or None,
            display_filter=args.display_filter,
            compute_hash=not args.no_hash,
        )
    print_kv_panel(
        "Capture",
        [
            ("fichier", info_.path),
            ("taille", f"{info_.size} o"),
            ("sha256", info_.sha256 or "—"),
            ("tshark", info_.tshark_version or "—"),
        ],
    )
    if info_.capinfos:
        print_kv_panel("capinfos", list(info_.capinfos.items())[:40])
    for name, text in info_.stats.items():
        section_title(name)
        # on n'inonde pas : 80 premières lignes sauf verbose
        lines = (text or "").splitlines()
        shown = lines if args.verbose else lines[:80]
        print("\n".join(shown))
        if not args.verbose and len(lines) > 80:
            tip(f"{len(lines) - 80} lignes supplémentaires — relancez avec -v ou -o DIR")
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for name, text in info_.stats.items():
            safe = name.replace(",", "_").replace(" ", "_")
            path = os.path.join(args.output, f"{safe}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text or "")
            ok(path)
    return 0

def cmd_stats(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    chunks = []
    for stat in args.stat:
        section_title(stat)
        text = runner.stats(args.pcap, stat, display_filter=args.display_filter)
        print(text)
        chunks.append(f"===== {stat} =====\n{text}\n")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(chunks))
        ok(args.output)
    return 0

def cmd_packets(args) -> int:

    _need_file(args.pcap)
    fmt = args.format or os.path.splitext(args.output)[1].lstrip(".") or "csv"
    with progress_bar(t("stage.packets"), total=None, disable=args.no_progress or args.quiet):
        path = export_packets(
            args.pcap,
            args.output,
            fmt=fmt,
            fields=args.field or None,
            display_filter=args.display_filter,
            limit=args.limit,
            tshark_path=args.tshark,
            decode_as=args.decode_as or None,
        )
    ok(t("res.export_ok", fmt=fmt, path=path))
    return 0

def cmd_follow(args) -> int:

    _need_file(args.pcap)
    mapping = {
        "tcp": args.tcp_idx,
        "udp": args.udp_idx,
        "http": args.http_idx,
        "tls": args.tls_idx,
        "sip": args.sip_idx,
    }
    chosen = [(k, v) for k, v in mapping.items() if v is not None]
    if not chosen:
        err("Précisez --tcp N  ou --udp N  ou --http N  ou --tls N  ou --sip N")
        return 2
    proto, idx = chosen[0]
    runner = TsharkRunner.discover(args.tshark)
    text = runner.follow(args.pcap, proto, args.mode, str(idx))
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        ok(args.output)
    else:
        print(text)
    return 0

def cmd_objects(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    with progress_bar(t("stage.objects"), total=None, disable=args.no_progress or args.quiet):
        runner.export_objects(args.pcap, args.proto, args.output, display_filter=args.display_filter)
    n = 0
    if os.path.isdir(args.output):
        n = len([f for f in os.listdir(args.output) if os.path.isfile(os.path.join(args.output, f))])
    ok(f"{n} objet(s) → {args.output}")
    return 0

def cmd_filter(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    extra = []
    if args.file_format:
        extra.extend(["-F", args.file_format])
    with progress_bar(t("stage.filter"), total=None, disable=args.no_progress or args.quiet):
        cmd = ["-r", args.pcap, "-w", args.output, "-Y", args.display_filter, *extra]
        runner.run(cmd, check=True)
    ok(args.output)
    return 0

def cmd_report(args) -> int:

    _need_file(args.pcap)
    with Timer() as timer:
        with progress_bar(t("stage.report"), total=3, disable=args.no_progress or args.quiet) as bar:
            bar.set_desc(t("stage.run_tshark"))
            packets = load_packets(args.pcap, args.tshark, display_filter=args.display_filter)
            bar.advance()
            bar.set_desc(t("stage.extract"))
            result = ExtractorEngine().run(packets)
            bar.advance()
            bar.set_desc(t("stage.analyze"))
            info_ = analyze_capture(args.pcap, tshark_path=args.tshark, display_filter=args.display_filter)
            bar.advance()
        written = build_full_report(
            result, info_, args.output, source=args.pcap, elapsed=timer.seconds, wordlist=args.wordlist
        )
    for p in written:
        ok(p)
    return 0

def cmd_wizard(args) -> int:

    return run_wizard(lang=get_lang())

def cmd_info(args) -> int:

    _need_file(args.pcap)
    info_ = run_capinfos(args.pcap)
    print_kv_panel("capinfos", list(info_.items()))
    return 0

def cmd_ifaces(args) -> int:

    runner = TsharkRunner.discover(args.tshark)
    print(runner.list_interfaces())
    return 0

def cmd_protocols(args) -> int:

    runner = TsharkRunner.discover(args.tshark)
    kind = args.glossary or ("fields" if args.fields else "protocols")
    text = runner.dump_glossary(kind)
    if args.search:
        q = args.search.lower()
        lines = [ln for ln in text.splitlines() if q in ln.lower()]
        print("\n".join(lines))
        info(f"{len(lines)} ligne(s)")
    else:
        print(text)
    return 0

def cmd_hashcat(args) -> int:

    _need_file(args.hashfile)
    if args.mode:
        info_ = mode_info(args.mode)
        if info_:
            info(f"mode {args.mode} — {info_['name']}")
        presets = attack_presets(args.mode, args.hashfile, args.wordlist)
    else:
        presets = suggest_for_file(args.hashfile, args.wordlist)
    for p in presets:
        print(f"  # {p['title']}")
        print(f"  {p['cmd']}")
        print()
    return 0

def cmd_creds(args) -> int:

    _need_file(args.pcap)
    packets = load_packets(args.pcap, args.tshark)
    result = ExtractorEngine(
        include_ntlm=False, include_kerberos=False, include_wpa=False, include_apop=False, include_extra=False
    ).run(packets)
    print_creds(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for c in result.credentials:
                f.write(f"{c.protocol}\tuser={c.username}\tpass={c.password}\n")
        ok(args.output)
    return 0 if result.credentials else 1

def cmd_convert(args) -> int:

    if args.merge:
        merge(args.inputs, args.output)
        ok(args.output)
        return 0
    if args.split_packets:
        split_by_packets(args.inputs[0], args.output, args.split_packets)
        ok(args.output)
        return 0
    if args.split_seconds:
        split_by_seconds(args.inputs[0], args.output, args.split_seconds)
        ok(args.output)
        return 0
    convert(args.inputs[0], args.output, fmt=args.file_format, tshark_path=args.tshark)
    ok(args.output)
    return 0

def cmd_expert(args) -> int:

    _need_file(args.pcap)
    stat = "expert" if not args.level else f"expert,{args.level}"
    text = TsharkRunner.discover(args.tshark).stats(args.pcap, stat)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(text)
        ok(args.output)
    else:
        print(text)
    return 0

def cmd_hosts(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    text = runner.stats(args.pcap, "hosts")
    if args.output:
        open(args.output, "w", encoding="utf-8").write(text)
        ok(args.output)
    else:
        print(text)
    return 0

def cmd_voip(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    chunks = []
    for stat in ("sip,stat", "rtp,streams"):
        section_title(stat)
        text = runner.stats(args.pcap, stat)
        print(text)
        chunks.append(f"===== {stat} =====\n{text}\n")
    if args.output:
        open(args.output, "w", encoding="utf-8").write("\n".join(chunks))
        ok(args.output)
    return 0

def cmd_capture(args) -> int:

    runner = TsharkRunner.discover(args.tshark)
    info(f"capture {args.interface} → {args.output}")
    runner.capture(
        args.interface,
        args.output,
        duration=args.duration,
        packets=args.packets,
        capture_filter=args.capture_filter,
        snaplen=args.snaplen,
        promiscuous=not args.no_promisc,
        monitor=args.monitor,
    )
    ok(args.output)
    return 0

def cmd_decode(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    extra = []
    for d in args.decode_as:
        extra.extend(["-d", d])
    if args.output:
        cmd = ["-r", args.pcap, "-w", args.output, *extra]
        if args.display_filter:
            cmd.extend(["-Y", args.display_filter])
        runner.run(cmd, check=True)
        ok(args.output)
        return 0
    cmd = ["-r", args.pcap, *extra]
    if args.display_filter:
        cmd.extend(["-Y", args.display_filter])
    if args.verbose_tree:
        cmd.append("-V")
    print(runner.run(cmd).stdout)
    return 0

def cmd_fields(args) -> int:

    _need_file(args.pcap)
    runner = TsharkRunner.discover(args.tshark)
    res = runner.read_fields(
        args.pcap, args.field, display_filter=args.display_filter, header=True, limit=args.limit
    )
    if args.output:
        open(args.output, "w", encoding="utf-8").write(res.stdout)
        ok(args.output)
    else:
        print(res.stdout)
    return 0

def cmd_modes(args) -> int:

    if args.query:
        rows = search_modes(args.query)
    elif args.pcap_only:
        rows = pcap_modes()
    else:
        rows = list(MODE_CATALOG.values())
    print_modes(rows, pcap_only=args.pcap_only and not args.query)
    return 0

def cmd_filters(args) -> int:

    rows = find_filter(args.query) if args.query else list(FILTER_LIB)
    if args.group:
        rows = [f for f in rows if f["group"] == args.group]
    try:
        from rich.table import Table
        from rich.console import Console
        from rich import box

        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
        table.add_column("nom", style="yellow")
        table.add_column("groupe", style="magenta")
        table.add_column("filtre", style="green")
        table.add_column("description")
        for f in rows:
            table.add_row(f["name"], f["group"], f["expr"], f["fr"])
        Console(highlight=False).print(table)
    except ImportError:
        for f in rows:
            print(f"{f['name']:<16} {f['group']:<10} {f['expr']}")
    return 0

def cmd_tshark_help(args) -> int:

    if args.stats:
        rows = find_stat(args.query) if args.query else STAT_CATALOG
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box

            table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", title="tshark -z")
            table.add_column("clé", style="yellow")
            table.add_column("groupe", style="magenta")
            table.add_column("description")
            table.add_column("exemple", style="green")
            for s in rows:
                table.add_row(s["key"], s["group"], s["fr"], s["example"])
            Console(highlight=False).print(table)
        except ImportError:
            for s in rows:
                print(f"{s['key']:<28} {s['fr']}")
        return 0
    rows = search_options(args.query) if args.query else TSHARK_OPTIONS
    try:
        from rich.table import Table
        from rich.console import Console
        from rich import box

        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", title="options tshark")
        table.add_column("flag", style="yellow")
        table.add_column("groupe", style="magenta")
        table.add_column("args", style="dim")
        table.add_column("description")
        for o in rows:
            table.add_row(o["flag"], o["group"], o["args"], o["fr"])
        Console(highlight=False).print(table)
    except ImportError:
        for o in rows:
            print(f"{o['flag']:<22} {o['fr']}")
    return 0

def cmd_doctor(args) -> int:

    st = suite_status(args.tshark)
    print_kv_panel("Suite Wireshark", list(st.items()))
    deps = {}
    for name in ("rich", "openpyxl", "tqdm"):
        try:
            __import__(name)
            deps[name] = "ok"
        except ImportError:
            deps[name] = "MANQUANT"
    print_kv_panel("Dépendances Python", list(deps.items()))
    if not st.get("tshark"):
        warn(t("err.tshark_missing"))
        return 1
    ok("environnement opérationnel" if get_lang() == "fr" else "environment OK")
    return 0

def cmd_examples(args) -> int:
    print_examples(get_lang())
    return 0

def cmd_init_config(args) -> int:

    path = write_example_config(args.output)
    ok(str(path))
    return 0

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # pré-parse langue / banner pour que --help soit déjà traduit
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default=None)
    pre.add_argument("--no-banner", action="store_true")
    pre.add_argument("--no-color", action="store_true")
    pre.add_argument("--quiet", "-q", action="store_true")
    pre.add_argument("--config", default=None)
    known, _rest = pre.parse_known_args(argv)
    if known.lang:
        set_lang(known.lang)
    else:
        env_lang = os.environ.get("T2H_LANG") or os.environ.get("LANG", "fr")
        set_lang("en" if str(env_lang).lower().startswith("en") else "fr")

    parser = _build_parser()
    if not argv:
        # double-clic / py hash.py  → menu, pas de commandes à retenir
        return run_wizard(lang=get_lang())

    args = parser.parse_args(argv)
    if known.lang:
        args.lang = known.lang
    set_lang(getattr(args, "lang", None) or get_lang())

    fn = getattr(args, "_fn", None)
    if fn is None:
        # flags globaux seuls (--no-color, --lang…) → même menu que sans argument
        return run_wizard(lang=get_lang())

    # banner sauf pour les commandes « data » silencieuses
    silent = {"fields", "follow", "stats", "hosts", "expert", "protocols", "ifaces"}
    if args.cmd not in silent and not args.quiet and not args.no_banner:
        if args.cmd in {"extract", "auto", "folder", "analyze", "report", "doctor"}:
            print_logo(lang=get_lang(), compact=True, no_color=args.no_color)

    try:
        return int(fn(args) or 0)
    except KeyboardInterrupt:
        warn("interrompu")
        return 130
    except BrokenPipeError:
        return 0

# Compatibilité v1 : un fichier .pcap en 1er argument = auto
# un dossier = folder → un Excel

def _legacy_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    known = {
        "extract", "auto", "folder", "analyze", "stats", "packets", "follow",
        "objects", "filter", "report", "wizard", "info", "ifaces", "protocols",
        "hashcat", "creds", "convert", "expert", "hosts", "voip", "capture",
        "decode", "fields", "modes", "filters", "tshark-help", "doctor",
        "examples", "init-config", "-h", "--help", "-V", "--version",
    }
    if argv[0] in known or argv[0].startswith("-"):
        return argv
    cand = Path(argv[0]).expanduser()
    if cand.is_dir():
        return ["folder", *argv]
    low = argv[0].lower()
    if any(low.endswith(ext) for ext in (".pcap", ".pcapng", ".cap", ".dmp", ".json")):
        return ["auto", *argv]
    if cand.is_file():
        return ["auto", *argv]
    return argv

if __name__ == "__main__":
    sys.exit(main(_legacy_argv(sys.argv[1:])))
