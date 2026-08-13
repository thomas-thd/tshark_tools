<p align="center">
  <img src="banner.png" alt="tshark2hashcat — PCAP → Hashcat" width="100%">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://www.wireshark.org/"><img src="https://img.shields.io/badge/tshark-Wireshark-1679a7?style=for-the-badge&logo=wireshark&logoColor=white" alt="Tshark / Wireshark"></a>
  <a href="https://hashcat.net/hashcat/"><img src="https://img.shields.io/badge/hashcat-ready-d75fff?style=for-the-badge" alt="Hashcat ready"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-5fd75f?style=for-the-badge" alt="Licence MIT"></a>
</p>

<p align="center">
  <b>Un PCAP entre, des hashes Hashcat et un rapport Excel sortent.</b><br>
  <i>Un fichier ou un dossier — tout dans Excel.</i><br>
  <code>v1.0.0</code> &nbsp;·&nbsp; Windows · Linux · macOS &nbsp;·&nbsp; MIT
</p>

> Audit, pentest, CTF : uniquement sur des captures que vous êtes autorisé à analyser.

---

## Installation

```bash
# 1. tshark (Wireshark)
sudo apt install tshark          # Debian/Ubuntu
sudo dnf install wireshark-cli   # Fedora
brew install wireshark           # macOS
winget install WiresharkFoundation.Wireshark   # Windows

# 2. l'outil + extras
git clone https://github.com/tshark2hashcat/tshark2hashcat && cd tshark2hashcat
pip install openpyxl rich tqdm

# 3. go
python tshark2hashcat.py doctor
python tshark2hashcat.py auto capture.pcapng     # 1 fichier → Excel + hashes
python tshark2hashcat.py folder ./captures       # 1 dossier → 1 Excel
```

`tshark` hors `PATH` ? `--tshark CHEMIN` ou `T2H_TSHARK_PATH`.

---

## Hashes Hashcat extraits

Chaque ligne est validée contre la grammaire exacte du mode avant écriture ;
dédoublonnage systématique.

| Protocole | Détection | Mode |
|:---|:---|---:|
| NetNTLMv2 | NTLMSSP AUTH, NT response > 24 o | `-m 5600` |
| NetNTLMv1 / +ESS | NTLMSSP AUTH, NT response = 24 o | `-m 5500` |
| Kerberos AS-REQ | msg-type 10, PA-ENC-TIMESTAMP | `-m 7500` / `19800` / `19900` |
| Kerberos AS-REP | msg-type 11, enc-part | `-m 18200` / `32100` / `32200` |
| Kerberos TGS-REP | msg-type 13, ticket (krbtgt ignoré) | `-m 13100` / `19600` / `19700` |
| WPA PMKID | RSN IE / EAPOL M1 → `WPA*01*` | `-m 22000` |
| APOP (POP3) | digest = MD5(challenge + pass) | `-m 20` |
| SIP Digest | `Authorization: Digest` en contexte SIP | `-m 11400` |
| JWT | `Bearer eyJ…` | `-m 16500` |
| CHAP | champs tshark CHAP | `-m 4800` |

Aussi détectés et documentés : HTTP Digest (rapport), CRAM-MD5 (note + follow),
EAPOL M1–M4 (note `hcxpcapngtool` pour le `WPA*02*`).

**Double chemin d'extraction** : champs disséqués `ntlmssp.*` / `kerberos.*` en priorité ;
sinon scan binaire des octets `-x` (signature `NTLMSSP\0`, base64 HTTP/IMAP/SMTP) ;
appairage challenge/auth par 4-tuple IP/ports.

**Diagnostic Kerberos** : section « Identités Kerberos vues » (frame, msg-type,
user, realm, SPN, salt ETYPE_INFO2, etypes) ; liste des comptes **avec** pré-auth ;
casse exacte de l'UPN pour les flags CTF.

---

## Identifiants en clair et secrets

- **Clair** : FTP/Telnet `USER`+`PASS`, HTTP Basic, Proxy-Basic, AUTH PLAIN,
  AUTH LOGIN, formulaires HTTP (`user=…&pass=…`), PAP, LDAP simple bind, TACACS+,
  commandes POP/IMAP/SMTP, MQTT.
- **Tokens** : cookies / Set-Cookie, `Authorization`, Bearer, clés API, AWS Access Keys.
- **Réseau** : community SNMPv1/v2c (champs + scan BER), user SNMPv3, RADIUS User-Name,
  DHCP hostname, TLS SNI / QUIC SNI / DTLS SNI.
- **OSINT** : e-mails, téléphones FR (+33), noms dans chemins (`C:\Users\…`, `/home/…`),
  claims JWT (name, email, upn, iss), sujets de mails, hosts DNS/mDNS/LLMNR/NBNS,
  noms CDP/LLDP, partages et fichiers SMB, SSID/BSSID Wi-Fi.
- **Métadonnées** : ~100 champs tshark récoltés sur tous les protocoles
  (HTTP, TLS, SSH, DNS, SMB, LDAP, DB, OT/IoT, VoIP, routage, Wi-Fi…).
- **Filtrage du bruit** : fuzz SNMP (`aaaa`, `%s%s`…), bannières SSH prises pour des
  e-mails, cookies Cloudflare, faux téléphones, comptes machine vs humains.

---

## Rapport d'audit

- **Score /100 + niveau** (FAIBLE → CRITIQUE), calculé sur preuves extraites, pas sur
  la simple présence de protocoles.
- **Findings** avec gravité, preuve, impact, remédiation, actifs concernés :
  mots de passe en clair, AS-REP roasting, Kerberoast, NetNTLMv1/v2, LLMNR/NBNS,
  WPAD, LDAP clair, SNMP, APOP, WPA, cookies, PII/RGPD, Telnet/FTP.
- **Chemins d'attaque** rédigés étape par étape (vol NTLM → roasting → TGS CIFS →
  SYSVOL/partages → exfiltration).
- **Mapping MITRE ATT&CK** (T1558.003/.004, T1557.001, T1003, T1021.002, T1040…).
- **Écarts attendu vs observé** (pré-auth, NTLM, LLMNR, LDAP, SNMP, Wi-Fi, SYSVOL…).
- **Cartographie** : domaine, DC, users humains, comptes machine, SPN, partages,
  fichiers sensibles, IP LAN.
- **Synthèse exécutive** rédigée + verdict.
- **Rapport OSINT** : personnes, e-mails, téléphones, organisations, machines,
  sites/SNI, équipements (vendeurs OUI), IP publiques/privées.

---

## Export Excel (`.xlsx`)

Onglets : Couverture (KPI, synthèse, findings, actions P1/P2/P3, méthode) · Analyse
(volumes, durée, débit, familles + graphique, protocoles classés clair/chiffré/auth,
IP/MAC) · Findings · Expositions · MITRE · Chemins · Écarts · Cartographie · OSINT ·
Identités · Hôtes · Wi-Fi · Fichiers · Secrets · Hashes (+ commandes hashcat) ·
Kerberos · Fichiers sources (mode dossier).

Mise en forme : palette de sévérités, zébrures, filtres auto, volets figés, en-têtes/pieds de page.

**Autres exports** : TXT par mode (`*_m5600.txt`…), CSV, JSON (méta + hashes + creds +
Kerberos + commandes), HTML, Markdown, ré-export PCAP/PCAPNG filtré.

---

## Wrapper tshark — 29 sous-commandes

| Commande | Fait |
|:---|:---|
| `auto` | fichier → hashes + secrets + rapport + Excel + txt par mode |
| `folder` | dossier (récursif) → 1 Excel, découpe editcap + extraction parallèle |
| `extract` | extraction avec choix des formats, `-Y`, `-d`, `--limit`, `--no-*` par famille |
| `analyze` | capinfos + SHA-256 + presets `-z` (io,phs · conv · endpoints · expert · http · dns · hosts · credentials · sip · rtp) + `-z` libres |
| `stats` | toute statistique `-z` du catalogue |
| `packets` | paquets filtrés → CSV/JSON/XLSX/MD/TXT, champs `-e` au choix |
| `follow` | flux TCP/UDP/HTTP/TLS/SIP (ascii/hex/raw/yaml) |
| `objects` | export objets HTTP/SMB/IMF/TFTP/DICOM |
| `filter` | ré-écriture pcap/pcapng filtrée |
| `report` | rapport complet HTML/MD/JSON/XLSX + dump des stats |
| `creds` | identifiants en clair uniquement |
| `convert` | pcap ↔ pcapng, découpe (paquets/secondes), fusion (mergecap) |
| `capture` | capture live : durée, nb paquets, BPF, snaplen, promisc, monitor |
| `decode` | decode-as, ré-écriture ou arbre `-V` |
| `fields` | extraction de champs `-T fields` |
| `info` | capinfos |
| `ifaces` | interfaces de capture (`-D`) |
| `protocols` | glossaires `-G` (protocols/fields/plugins/…) |
| `expert` | infos expert (error/warn/note/chat) |
| `hosts` | fichier hosts vu dans la capture |
| `voip` | `sip,stat` + `rtp,streams` |
| `hashcat` | commandes prêtes : dictionnaire, règles (best64, rockyou-30000), combinator, masques, hybrides, `--show`, `--left`, mode auto-détecté |
| `modes` | catalogue 300+ modes Hashcat (catégorie, protocole, exemple, flag PCAP) |
| `filters` | bibliothèque ~100 filtres d'affichage par cas d'usage |
| `tshark-help` | catalogue des options tshark et des stats `-z` |
| `wizard` | menu interactif (1 fichier / 2 dossier / 0 quitter) |
| `doctor` | tshark/dumpcap/capinfos/editcap/mergecap/text2pcap + dépendances Python |
| `examples` | exemples d'utilisation |
| `init-config` | fichier de config exemple |

Sans argument (ou double-clic) : menu interactif. `python tshark2hashcat.py capture.pcap` = `auto` ; `python tshark2hashcat.py ./dossier` = `folder` ; relit aussi un export JSON tshark.

---

## Moteur et interface

- Un seul appel `tshark -r … -T json -x` ; gros fichiers découpés (`editcap`) et
  traités en parallèle.
- i18n FR/EN (`--lang`, `T2H_LANG`).
- Config : CLI > `T2H_*` > `tshark2hashcat.toml`/`.json` (cwd ou `~`) > défauts.
- Sortie : logo/bannière, tableaux et barres Rich (repli tqdm / texte brut),
  `--quiet`, `--verbose`, `--no-color`, `--no-progress`, `--limit`.
- Filtre d'affichage `-Y`, read filter `-R`/`-2`, decode-as `-d`, `-n`, timeout tshark.
- Un seul fichier Python, zéro dépendance obligatoire (Excel excepté).

---

## Limites

- `WPA*02*` : sans octets EAPOL bruts, préférer `hcxpcapngtool`.
- OSPF : pas de mode hashcat natif (crypto-auth LLS, RFC 4813).
- CRAM-MD5 : export via follow SMTP/IMAP.

---

<p align="center">
  <i>tshark2hashcat — tous les protocoles, sécurisés ou non. Licence MIT.</i>
</p>
