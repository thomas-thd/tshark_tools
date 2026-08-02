#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tshark2hashcat.py — Extraction de hash cassables (Hashcat) depuis un .pcap/.pcapng,
via Tshark uniquement.

Protocoles détectés automatiquement :
  - NetNTLMv2          ... NTLMSSP_AUTH (NT response > 24 o)      -> hashcat -m 5600
  - NetNTLMv1 (+ESS)   ... NTLMSSP_AUTH (NT response = 24 o)      -> hashcat -m 5500
  - Kerberos AS-REQ    ... msg-type 10, PA-ENC-TIMESTAMP          -> hashcat -m 7500 / 19800 / 19900
  - Kerberos AS-REP    ... msg-type 11, enc-part etype 23         -> hashcat -m 18200
                           (etype 17/18 -> 32100/32200)
  - Kerberos TGS-REP   ... msg-type 13, ticket etype 23           -> hashcat -m 13100
                           (etype 17/18 -> 19600/19700)

En fin d'exécution, une section « IDENTITÉS KERBEROS VUES » affiche, pour chaque
message Kerberos : n° de trame, type (AS-REQ/AS-REP/TGS-REP), utilisateur, realm,
SPN, salt (ETYPE_INFO2) et etypes — utile pour vérifier la casse exacte d'un
userPrincipalName (format de flag CTF, etc.).

Fonctionne sous Windows. Source de données : Tshark UNIQUEMENT.
Appel unique :  tshark -r <pcap> -T json -x
  - les champs disséqués (ntlmssp.*, kerberos.*) servent en priorité ;
  - le '-x' fournit les octets bruts de chaque couche : si le dissecteur n'a
    pas reconnu l'encapsulation (ex. NTLMSSP mal marqué), les messages NTLMSSP
    sont retrouvés par signature binaire (clair + base64 HTTP/IMAP/SMTP).

Exemples :
    python tshark2hashcat.py capture.pcapng
    python tshark2hashcat.py capture.pcap -o hashes.txt --tshark "D:\\Wireshark\\tshark.exe"
    python tshark2hashcat.py dump_tshark.json            # rejoue un export (debug/tests)

Sortie :  hashes.txt (toutes lignes) + hashes_m<mode>.txt par mode + récapitulatif.
          hashcat -m <mode> hashes_m<mode>.txt wordlist.txt
"""
import argparse
import base64
import json
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",                       # présent dans le PATH
]

HEX = "0123456789abcdef"
NTLMSSP_MAGIC = b"NTLMSSP\x00"

# --------------------------------------------------------------------------- #
# Helpers génériques
# --------------------------------------------------------------------------- #
def norm_hex(v):
    """Normalise une valeur tshark en hex continu minuscule ('aa:bb' / 'AABB' / ['aabb'])."""
    if isinstance(v, list):
        v = next((x for x in v if isinstance(x, str)), None)
    if not isinstance(v, str):
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", v).lower()
    return s if s and len(s) % 2 == 0 and all(c in HEX for c in s) else None


def first_str(v):
    """Première chaîne non vide (récursif dans les listes JSON de tshark)."""
    if isinstance(v, list):
        for x in v:
            r = first_str(x)
            if r:
                return r
        return None
    return v if isinstance(v, str) and v else None


def walk(node):
    """Itère (clé, valeur) récursivement sur une structure JSON tshark."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from walk(v)
    elif isinstance(node, list):
        for it in node:
            yield from walk(it)


def find_str(layers, keys):
    """Première valeur texte trouvée pour une des clés (alias multiples)."""
    for k, v in walk(layers):
        if k in keys:
            r = first_str(v)
            if r:
                return r
    return None


def find_hex(layers, keys):
    for k, v in walk(layers):
        if k in keys:
            r = norm_hex(v)
            if r:
                return r
    return None


def sibling_etype(parent, layers):
    """etype posé à côté d'un champ *_cipher (même dict), sinon etype du paquet."""
    e = parent.get("kerberos.etype")
    s = first_str(e)
    if s and str(s).isdigit():
        return int(s)
    e = find_str(layers, ("kerberos.etype",))
    return int(e) if e and str(e).isdigit() else None


def tuple4(layers):
    """(src, dst, sport, dport) IP/TCP de la trame, pour appairer challenge/auth."""
    src = find_str(layers, ("ip.src", "ipv6.src"))
    dst = find_str(layers, ("ip.dst", "ipv6.dst"))
    sp  = find_str(layers, ("tcp.srcport", "udp.srcport"))
    dp  = find_str(layers, ("tcp.dstport", "udp.dstport"))
    return (src, dst, sp, dp) if all((src, dst, sp, dp)) else None

# --------------------------------------------------------------------------- #
# Validateurs : la ligne n'est écrite QUE si elle respecte la grammaire du mode
# --------------------------------------------------------------------------- #
def _is_hex(s, length=None, minlen=0, maxlen=None):
    if not s or any(c not in HEX for c in s):
        return False
    if length is not None and len(s) != length:
        return False
    if len(s) < minlen or (maxlen and len(s) > maxlen):
        return False
    return len(s) % 2 == 0


def validate(mode, line):
    """True si la ligne respecte EXACTEMENT la syntaxe attendue par hashcat <mode>."""
    p = line.split(":") if mode in (5500, 5600) else None

    if mode == 5600:                       # user::domain:chal:NTProofStr:blob
        return (p and len(p) == 6 and 1 <= len(p[0]) <= 60 and len(p[1]) == 0
                and len(p[2]) <= 45
                and _is_hex(p[3], 16) and _is_hex(p[4], 32)
                and _is_hex(p[5], minlen=2, maxlen=1024))
    if mode == 5500:                       # user::domain:chal:LM(24o):NT(24o)
        return (p and len(p) == 6 and 1 <= len(p[0]) <= 60 and len(p[1]) == 0
                and len(p[2]) <= 45
                and _is_hex(p[3], 16) and _is_hex(p[4], 48) and _is_hex(p[5], 48))
    if mode == 18200:                      # $krb5asrep$23$user@dom:$chk(16o)$edata2
        m = re.fullmatch(r"\$krb5asrep\$23\$([^@$]+)@([^:$]+):([0-9a-f]{32})\$([0-9a-f]+)", line)
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0
    if mode in (32100, 32200):             # $krb5asrep$17|18$user$realm$chk24$edata2
        e = 17 if mode == 32100 else 18
        m = re.fullmatch(rf"\$krb5asrep\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)", line)
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0
    if mode in (19800, 19900):             # $krb5pa$17|18$user$realm$cipher(104..112)
        e = 17 if mode == 19800 else 18
        m = re.fullmatch(rf"\$krb5pa\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]+)", line)
        return bool(m) and 104 <= len(m.group(3)) <= 112
    if mode == 7500:                       # $krb5pa$23$user$realm$cipher (RC4)
        return bool(re.fullmatch(r"\$krb5pa\$23\$([^$]+)\$([^$]+)\$([0-9a-f]+)", line))
    if mode == 13100:                      # $krb5tgs$23$*user$dom$spn*$chk32$edata2
        m = re.fullmatch(r"\$krb5tgs\$23\$\*([^$]+)\$([^$]+)\$([^$]+)\*\$([0-9a-f]{32})\$([0-9a-f]+)", line)
        return bool(m) and 64 <= len(m.group(5)) <= 40960 and len(m.group(5)) % 2 == 0
    if mode in (19600, 19700):             # $krb5tgs$17|18$user$realm$chk24$edata2 (sans *)
        e = 17 if mode == 19600 else 18
        m = re.fullmatch(rf"\$krb5tgs\${e}\$([^$]+)\$([^$]+)\$([0-9a-f]{{24}})\$([0-9a-f]+)", line)
        return bool(m) and 64 <= len(m.group(4)) <= 40960 and len(m.group(4)) % 2 == 0
    return False

# --------------------------------------------------------------------------- #
# NTLM (NetNTLMv1 / NetNTLMv2)
# --------------------------------------------------------------------------- #
def ntlm_build(user, dom, chal, lm, nt, frame, missing):
    """Construit les lignes 5500/5600 si tout est présent, sinon rapporte le manquant."""
    for name, val, in (("username", user), ("server_challenge", chal), ("nt_response", nt)):
        if not val:
            missing.append(f"NTLM frame #{frame}: '{name}' manquant -> hash non généré")
            return []
    if len(nt) == 48 and lm and len(lm) == 48:          # NetNTLMv1 / +ESS
        return [(5500, f"{user}::{dom}:{chal}:{lm}:{nt}")]
    if len(nt) > 48:                                     # NetNTLMv2
        return [(5600, f"{user}::{dom}:{chal}:{nt[:32]}:{nt[32:]}")]
    missing.append(f"NTLM frame #{frame}: NT response de {len(nt)//2} octets "
                   f"(ni v1=24o, ni v2>24o) -> ignoré")
    return []


def ntlm_secbuf(msg, off):
    """Security buffer NTLMSSP : <uint16 len><uint16 max><uint32 offset>."""
    ln, _mx, rel = struct.unpack_from("<HHI", msg, off)
    return msg[rel:rel + ln]


def ntlm_parse_t2(msg):
    """NTLMSSP_CHALLENGE : challenge @ +24 (8 o), target name en secbuf +12."""
    flags = struct.unpack_from("<I", msg, 20)[0]
    uni = bool(flags & 0x1)
    dom = ntlm_secbuf(msg, 12).decode("utf-16-le" if uni else "latin-1", "replace")
    return msg[24:32].hex(), dom


def ntlm_parse_t3(msg):
    """NTLMSSP_AUTH : LM@12, NT@20, domain@28, user@36 (secbufs)."""
    lm = ntlm_secbuf(msg, 12).hex()
    nt = ntlm_secbuf(msg, 20).hex()
    flags = struct.unpack_from("<I", msg, 60)[0] if len(msg) >= 64 else 0x1
    enc = "utf-16-le" if flags & 0x1 else "latin-1"
    return lm, nt, ntlm_secbuf(msg, 28).decode(enc, "replace"), ntlm_secbuf(msg, 36).decode(enc, "replace")


def ntlm_raw_scan(raw, frame, missing):
    """Retrouve les NTLMSSP type2/type3 dans les octets bruts fournis par tshark (-x),
    en clair ou encodés base64 (en-têtes HTTP, IMAP/SMTP AUTH, ...)."""
    blobs = [raw]
    for m in re.finditer(rb"[A-Za-z0-9+/]{40,}={0,2}", raw):
        try:
            d = base64.b64decode(m.group(0), validate=True)
        except Exception:
            continue
        if d.startswith(NTLMSSP_MAGIC):
            blobs.append(d)
    chals, auths = [], []
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
                    chals.append(ntlm_parse_t2(blob[i:i + 2048]))
                elif t == 3:
                    auths.append(ntlm_parse_t3(blob[i:i + 8192]))
            except (struct.error, UnicodeDecodeError):
                pass
    res = []
    for lm, nt, dom, usr in auths:
        chal, cdom = (chals[-1] if chals else (None, None))
        res.extend(ntlm_build(usr, dom or cdom or "", chal, lm, nt, frame, missing))
    return res

# --------------------------------------------------------------------------- #
# Kerberos (formats vérifiés dans les modules hashcat officiels)
# --------------------------------------------------------------------------- #
MODE_ASREP = {17: 32100, 18: 32200, 23: 18200}   # AS-REP enc-part
MODE_TGS   = {17: 19600, 18: 19700, 23: 13100}   # TGS-REP ticket (Kerberoast)
MODE_ASREQ = {17: 19800, 18: 19900, 23: 7500}    # AS-REQ PA-ENC-TIMESTAMP


def krb_asrep_line(e, user, realm, h):
    if e == 23:                                            # RC4 : chk = 16 premiers octets
        return 18200, f"$krb5asrep$23${user}@{realm}:{h[:32]}${h[32:]}"
    # AES : checksum = 12 derniers octets, hashcat 32100/32200
    return MODE_ASREP[e], f"$krb5asrep${e}${user}${realm}${h[-24:]}${h[:-24]}"


def krb_tgs_line(e, user, realm, spn, h):
    if e == 23:
        return 13100, f"$krb5tgs$23$*{user}${realm}${spn}*${h[:32]}${h[32:]}"
    # AES TGS (19600/19700) : salt = REALM + compte du service (souvent 1re partie du SPN)
    svc = spn.split("/", 1)[0] if spn else user
    return MODE_TGS[e], f"$krb5tgs${e}${svc}${realm}${h[-24:]}${h[:-24]}"


def krb_asreq_line(e, user, realm, h):
    return MODE_ASREQ.get(e), f"$krb5pa${e}${user}${realm}${h}"


MT_NAMES = {"10": "AS-REQ", "11": "AS-REP", "13": "TGS-REP"}


def krb_packet(layers, frame, missing, preauth_users, diag):
    mt = first_str(find_str(layers, ("kerberos.msg_type",)))
    if mt not in MT_NAMES:
        return []
    user  = find_str(layers, ("kerberos.CNameString", "kerberos.cname-string"))
    realm = find_str(layers, ("kerberos.crealm", "kerberos.realm"))
    res = []

    # ---- diagnostic : identités vues (casse exacte pour flag / salt) ----
    salts, etypes = set(), set()
    for k, v in walk(layers):
        if k == "kerberos.salt":
            salts.update(x for x in (v if isinstance(v, list) else [v]) if isinstance(x, str))
        elif k == "kerberos.etype":
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, str) and x.isdigit():
                    etypes.add(int(x))

    # un AS-REQ avec timestamp => le compte a la pré-auth (juste informatif)
    if mt == "10" and any(k == "kerberos.pA_ENC_TIMESTAMP_cipher" for k, _ in walk(layers)):
        if user:
            preauth_users.add(user)

    spn_parts = []
    for k, v in walk(layers):
        if k in ("kerberos.SNameString", "kerberos.sname-string"):
            spn_parts += [x for x in v if isinstance(x, str)] if isinstance(v, list) else [v]
    spn = "/".join(spn_parts) if spn_parts else None
    diag.append((frame, MT_NAMES[mt], user, realm, spn, sorted(salts), sorted(etypes)))

    for k, v, parent in ((k, v, p) for k, v, p in walk_parent(layers)):
        h = norm_hex(v)
        if not h:
            continue
        if k == "kerberos.pA_ENC_TIMESTAMP_cipher" and mt == "10":         # AS-REQ pré-auth
            if not (user and realm):
                missing.append(f"Kerberos frame #{frame}: AS-REQ sans cname/realm -> ignoré")
                continue
            e = sibling_etype(parent, layers)
            if e in MODE_ASREQ:
                res.append(krb_asreq_line(e, user, realm, h))
            else:
                missing.append(f"Kerberos frame #{frame}: AS-REQ etype inconnu ({e}) -> ignoré")
        elif k == "kerberos.encryptedKDCREPData_cipher" and mt == "11":    # AS-REP
            if not (user and realm):
                missing.append(f"Kerberos frame #{frame}: AS-REP mais cname/realm manquant -> ignoré")
                continue
            e = sibling_etype(parent, layers)
            if e in MODE_ASREP:
                res.append(krb_asrep_line(e, user, realm, h))
            else:
                missing.append(f"Kerberos frame #{frame}: AS-REP etype inconnu ({e}) -> ignoré")
        elif k == "kerberos.encryptedTicketData_cipher" and mt == "13":     # TGS-REP (ticket)
            if spn and spn.lower().startswith("krbtgt"):
                continue
            if not (user and realm and spn):
                missing.append(f"Kerberos frame #{frame}: TGS-REP mais cname/realm/spn manquant "
                               f"(user={user}, realm={realm}, spn={spn}) -> ignoré")
                continue
            e = sibling_etype(parent, layers)
            if e in MODE_TGS:
                res.append(krb_tgs_line(e, user, realm, spn, h))
            else:
                missing.append(f"Kerberos frame #{frame}: TGS-REP etype inconnu ({e}) -> ignoré")
    return res


def walk_parent(node, parent=None):
    """Comme walk() mais fournit aussi le dict parent (pour trouver l'etype frère)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v, node
            yield from walk_parent(v, node)
    elif isinstance(node, list):
        for it in node:
            yield from walk_parent(it, parent)

# --------------------------------------------------------------------------- #
# Tshark
# --------------------------------------------------------------------------- #
def find_tshark(cli_path):
    for c in [cli_path] + TSHARK_CANDIDATES if cli_path else TSHARK_CANDIDATES:
        if c and (os.path.isfile(c) or shutil_which(c)):
            return shutil_which(c) or c
    return None


def shutil_which(name):
    from shutil import which
    return which(name)


def run_tshark(tshark, pcap):
    """Un seul appel : champs disséqués + octets bruts (-x)."""
    cmd = [tshark, "-r", pcap, "-T", "json", "-x"]
    print(f"[i] {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 and not r.stdout.strip():
        sys.exit(f"[-] tshark a échoué (code {r.returncode}) :\n{r.stderr[:500]}")
    out = r.stdout.strip()
    return json.loads(out) if out else []

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Extraction de hash Hashcat depuis un pcap (via tshark).")
    ap.add_argument("pcap", help="fichier .pcap/.pcapng (ou export .json tshark pour debug)")
    ap.add_argument("-o", "--output", default="hashes.txt", help="fichier de sortie global (defaut: hashes.txt)")
    ap.add_argument("--tshark", help="chemin complet vers tshark.exe", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.pcap.lower().endswith(".json"):
        print(f"[i] lecture directe de l'export JSON : {args.pcap}")
        packets = json.load(open(args.pcap, encoding="utf-8", errors="replace"))
    else:
        tshark = find_tshark(args.tshark)
        if not tshark:
            sys.exit("[-] tshark introuvable. Utilise --tshark \"C:\\...\\tshark.exe\"")
        print(f"[i] tshark : {tshark}")
        packets = run_tshark(tshark, args.pcap)
    if not isinstance(packets, list):
        sys.exit("[-] sortie tshark inattendue (pas une liste JSON)")

    results   = defaultdict(list)   # mode -> [lignes]
    missing   = []                  # données absentes -> empêchant de construire un hash
    seen      = set()
    preauth_users = set()
    proto_seen = set()
    diag = []                     # identités Kerberos vues (diagnostic)
    ntlm_chals = []                 # [(frame, tuple4, challenge_hex)] pour l'appairage
    raw_all    = []                 # octets bruts (-x) de toutes les trames (scan NTLMSSP global)

    def push(mode, line, src_desc):
        if not validate(mode, line):                      # garde-fou : jamais de hash invalide
            missing.append(f"{src_desc}: ligne rejetée par le validateur du mode {mode}")
            return
        if line not in seen:
            seen.add(line)
            results[mode].append(line)
            print(f"    [m{mode}] {src_desc}")

    for idx, pkt in enumerate(packets, 1):
        layers = pkt.get("_source", {}).get("layers", {})

        # ---- Kerberos ----
        if any("kerb" in k.lower() for k in layers):
            proto_seen.add("kerberos")
            for r in krb_packet(layers, idx, missing, preauth_users, diag):
                push(*r, f"frame #{idx} Kerberos")

        # ---- NTLM via champs disséqués ----
        ntlm = {k: v for k, v in layers.items() if "ntlm" in k.lower()}
        if ntlm:
            proto_seen.add("ntlmssp")
            mt_raw = find_str(ntlm, ("ntlmssp.messagetype",))
            mtype = int(mt_raw, 0) if mt_raw else None
            t4 = tuple4(layers)
            if mtype == 2:                                            # CHALLENGE (srv->cli)
                chal = find_hex(ntlm, ("ntlmssp.ntlmserverchallenge",))
                if chal and len(chal) == 16:
                    ntlm_chals.append((idx, t4, chal))
            elif mtype == 3:                                          # AUTH (cli->srv)
                user = find_str(ntlm, ("ntlmssp.auth.username",))
                dom  = find_str(ntlm, ("ntlmssp.auth.domain",)) or ""
                lm   = find_hex(ntlm, ("ntlmssp.auth.lmresponse", "ntlmssp.lmresponse"))
                nt   = find_hex(ntlm, ("ntlmssp.auth.ntresponse", "ntlmssp.ntresponse"))
                chal = find_hex(ntlm, ("ntlmssp.ntlmserverchallenge",))
                if not chal:                                          # appairer au challenge
                    want = (t4[1], t4[0], t4[3], t4[2]) if t4 else None
                    chal = next((c for _f, t, c in reversed(ntlm_chals) if want and t == want),
                                ntlm_chals[-1][2] if ntlm_chals else None)
                for mode, line in ntlm_build(user, dom, chal, lm, nt, idx, missing):
                    push(mode, line, f"frame #{idx} NTLM ({user})")

        # ---- octets bruts (-x) accumulés pour scan NTLMSSP global ----
        if not ntlm:
            raw_all.extend(
                bytes.fromhex(norm_hex(v[0]) or "")
                for k, v in walk(layers) if k.endswith("_raw") and isinstance(v, list) and v)

    # ---- NTLM non disséqué : scan brut GLOBAL (appairage challenge/auth dans l'ordre) ----
    raw_blob = b"".join(raw_all)
    if raw_blob and (NTLMSSP_MAGIC in raw_blob or re.search(rb"[A-Za-z0-9+/]{40,}={0,2}", raw_blob)):
        found = ntlm_raw_scan(raw_blob, "-", missing)
        if found:
            proto_seen.add("ntlmssp (brut -x)")
        for mode, line in found:
            push(mode, line, "NTLM brut")

    # ---------------- rapport ----------------
    print("\n=== RÉSULTATS ===")
    print(f"[i] protocoles détectés : {', '.join(sorted(proto_seen)) or 'aucun'}")
    if preauth_users:
        print(f"[i] comptes AVEC pré-auth Kerberos vus : {', '.join(sorted(preauth_users))}")
    if diag:
        print("\n=== IDENTITÉS KERBEROS VUES (diagnostic) ===")
        for frame, name, u, rlm, s, salts, ets in diag:
            print(f"    frame #{frame:<5} {name:<8} user={u or '?'} realm={rlm or '?'}"
                  f" spn={s or '-'} salt={' + '.join(salts) or '-'}"
                  f" etypes={','.join(map(str, ets)) or '-'}")


    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    total = 0
    with open(args.output, "w", encoding="ascii") as f:
        for mode in sorted(results):
            for line in results[mode]:
                f.write(line + "\n")
                total += 1
    for mode in sorted(results):
        fn = os.path.splitext(args.output)[0] + f"_m{mode}.txt"
        with open(fn, "w", encoding="ascii") as f:
            f.write("\n".join(results[mode]) + "\n")
        print(f"[+] {len(results[mode]):3d} hash ({mode}) -> {fn}")
        print(f"    hashcat -m {mode} {fn} wordlist.txt")

    if missing:
        print("\n[!] Données manquantes / éléments ignorés :")
        for m0 in sorted(set(missing)):
            print(f"    - {m0}")
    if not total:
        print("[-] aucun hash produit. Vérifie que la capture contient bien de l'auth "
              "NTLMSSP ou Kerberos (tshark -q -z io,phs).")
    else:
        print(f"\n[i] {total} hash écrit(s) aussi dans .\\{args.output}")


if __name__ == "__main__":
    main()
