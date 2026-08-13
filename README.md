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

> Audit, pentest, CTF : à utiliser uniquement sur des captures que vous êtes autorisé à analyser.

---

## Installation — 2 minutes

**1.** Installez [Wireshark](https://www.wireshark.org/) (fournit `tshark`) :

```bash
sudo apt install tshark          # Debian/Ubuntu
sudo dnf install wireshark-cli   # Fedora
brew install wireshark           # macOS
winget install WiresharkFoundation.Wireshark   # Windows
```

**2.** Récupérez l'outil (un seul fichier Python) et ses extras optionnels :

```bash
git clone https://github.com/tshark2hashcat/tshark2hashcat && cd tshark2hashcat
pip install openpyxl rich tqdm   # openpyxl = Excel, rich/tqdm = joli terminal
```

**3.** Vérifiez, puis lancez :

```bash
python tshark2hashcat.py doctor   # tshark ok ? dépendances ok ?
python tshark2hashcat.py          # menu : 1 fichier · 2 dossier · 0 quitter
```

Pas dans le `PATH` ? `python tshark2hashcat.py --tshark "C:\Program Files\Wireshark\tshark.exe" …`

---

## Utilisation — 3 lignes à connaître

```bash
python tshark2hashcat.py auto capture.pcapng    # 1 capture → Excel + txt par mode Hashcat
python tshark2hashcat.py folder ./captures      # 1 dossier → 1 seul classeur Excel
hashcat -m 5600 capture_m5600.txt wordlist.txt  # cassage
```

C'est tout. Le reste (`--help`, `wizard`, 29 sous-commandes) est en bas de page.

---

## Ce qui sort d'une capture

| Protocole | Mode Hashcat |
|:---|---:|
| NetNTLMv2 | `-m 5600` |
| NetNTLMv1 (+ESS) | `-m 5500` |
| Kerberos AS-REQ (PA-ENC-TIMESTAMP) | `-m 7500` · `19800` · `19900` |
| Kerberos AS-REP (roasting) | `-m 18200` · `32100` · `32200` |
| Kerberos TGS-REP (Kerberoast) | `-m 13100` · `19600` · `19700` |
| WPA PMKID / handshake | `-m 22000` |
| APOP (POP3) | `-m 20` |
| SIP Digest | `-m 11400` |
| JWT | `-m 16500` |
| CHAP | `-m 4800` |

Plus, dans le rapport : identifiants en clair (FTP, Telnet, HTTP Basic, AUTH PLAIN/LOGIN,
formulaires), community SNMP, cookies, tokens, clés API, e-mails, et la section
**« Identités Kerberos vues »** (user, realm, SPN, salt, etypes — casse exacte du flag CTF).

Chaque hash est validé contre la grammaire exacte du mode Hashcat avant d'être écrit.
OSPF : pas de mode hashcat natif (crypto-auth LLS, RFC 4813).

---

## Et dans l'Excel ?

Couverture & score de risque · Findings expliqués · Chemins d'attaque · MITRE ATT&CK ·
Écarts attendu/observé · Cartographie du domaine · OSINT · Identités · Hôtes · Wi-Fi ·
Fichiers vus · Secrets · Hashes + commandes hashcat · Kerberos.

Autres exports : TXT par mode, CSV, JSON, HTML, Markdown, ré-export PCAP filtré.

---

## Pour aller plus loin

```bash
python tshark2hashcat.py extract dump.pcap -f txt,csv,json,xlsx   # formats au choix
python tshark2hashcat.py analyze capture.pcapng                   # stats, conversations, expert
python tshark2hashcat.py packets dump.pcap -Y http -o http.xlsx   # paquets filtrés → Excel
python tshark2hashcat.py follow capture.pcapng --tcp 0            # suivre un flux
python tshark2hashcat.py filter capture.pcapng -Y kerberos -o k.pcapng
python tshark2hashcat.py hashcat hashes.txt                       # commandes prêtes à copier
python tshark2hashcat.py modes kerberos                           # catalogue des modes Hashcat
```

Sous-commandes disponibles : `auto · folder · extract · analyze · stats · packets ·
follow · objects · filter · report · creds · convert · capture · decode · fields ·
info · ifaces · protocols · expert · hosts · voip · hashcat · modes · filters ·
tshark-help · wizard · doctor · examples · init-config`.

En cas de pépin : `--tshark CHEMIN` si tshark n'est pas trouvé, `--no-color` si le
terminal n'aime pas les couleurs, `-v` pour voir pourquoi un élément a été ignoré.

---

<p align="center">
  <i>tshark2hashcat — tous les protocoles, sécurisés ou non. Licence MIT.</i>
</p>
