<div align="center">
<img src="assets/banner.svg" alt="tshark2hashcat" width="880">

# tshark2hashcat

**Tu poses un pcap. Tshark disséque. Hashcat reçoit des lignes propres.  
Toi, tu récupères un Excel qu’un pentester peut poser sur la table.**

[![2.7.0](https://img.shields.io/badge/2.7.0-00d7ff?style=flat-square)](#)
[![python ≥ 3.10](https://img.shields.io/badge/python-%3E%3D%203.10-3776AB?style=flat-square&logo=python&logoColor=white)](#installation)
[![tshark](https://img.shields.io/badge/engine-tshark-5f87ff?style=flat-square)](#installation)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

```
  1 fichier   ·   2 dossier   ·   0 quitter
```

</div>

Un seul script. Un menu à trois touches. Pas de roman argparse, pas douze fichiers de sortie qui pourrissent le bureau.

| Tu lui donnes | Tu récupères |
|---|---|
| un `.pcap` / `.pcapng` | un classeur d’audit + un `.txt` par mode Hashcat |
| un dossier de captures | **un** Excel fusionné, même logique |
| une interface réseau (`-live`) | le même Excel, mis à jour en direct, mail si ça dérape |

Tshark est la seule source. Python ne lit jamais le pcap tout seul.

---

## En 30 secondes

```text
1. Installer Python 3.10+ et Wireshark (ça pose tshark)
2. pip install -r requirements.txt
3. py tshark2hashcat.py
4. Touche 1 → ton fichier   ou   touche 2 → ton dossier
```

C’est tout. Le nom du rapport et le format, l’outil les choisit.

---

## Installation

### Ce qu’il te faut

| | Quoi | Pourquoi |
|---|---|---|
| **1** | Python **3.10 ou plus** | le script |
| **2** | **Wireshark** (donc `tshark`) | la dissection |
| **3** | 3 paquets pip | Excel + joli terminal |
| **4** | Hashcat | seulement si tu veux casser ensuite |

### 1 — Python

**Windows** — le plus simple, depuis un terminal **en admin** :

```powershell
winget install Python.Python.3.12
```

Sinon : [python.org/downloads](https://www.python.org/downloads/) — coche **« Add python.exe to PATH »**.

Vérifie :

```powershell
py --version
```

Tu dois voir `Python 3.10` ou plus. `py` est le lanceur Windows. Si tu n’as que `python`, utilise `python`.

**Linux**

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

# Fedora
sudo dnf install -y python3 python3-pip
```

```bash
python3 --version
```

**macOS**

```bash
brew install python
```

### 2 — Tshark (Wireshark)

Sans ça, rien ne tourne. C’est le moteur.

**Windows**

```powershell
winget install WiresharkFoundation.Wireshark
```

Ou l’installeur : [wireshark.org/download](https://www.wireshark.org/download.html).  
Coche **Tshark** si l’installeur te le demande (c’est le cas par défaut).

Ferme et rouvre le terminal, puis :

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -v
```

**Linux**

```bash
# Debian / Ubuntu
sudo apt install -y tshark
# on te demande si les non-root peuvent capturer → Yes si tu veux le live

# Fedora
sudo dnf install -y wireshark-cli
```

```bash
tshark -v
```

**macOS**

```bash
brew install wireshark
```

### 3 — Paquets Python

Dans le dossier du projet :

```powershell
# Windows
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

```bash
# Linux / macOS — un venv, et tu dors tranquille
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` installe :

| Paquet | Version | Sert à |
|---|---|---|
| **openpyxl** | ≥ 3.1 | écrire l’Excel — **obligatoire** |
| **rich** | ≥ 13.7 | logo, couleurs, barres — fortement conseillé |
| **tqdm** | ≥ 4.66 | barre de repli si pas de Rich |
| **tomli** | ≥ 2.0 | config TOML, seulement sous Python 3.10 |

Envie du strict minimum ?

```text
py -m pip install "openpyxl>=3.1,<4"
```

L’Excel sortira. Le terminal sera juste moins joli.

### 4 — On vérifie que tout est là

```powershell
py tshark2hashcat.py doctor
```

```text
Suite Wireshark     tshark = C:\Program Files\Wireshark\tshark.exe
Dépendances Python  openpyxl = ok    rich = ok    tqdm = ok
environnement opérationnel
```

Trois lumières vertes, tu roules.

`tshark introuvable` ? Réouvre le terminal après l’install Wireshark, ou pointe-le à la main :

```powershell
py tshark2hashcat.py --tshark "C:\Program Files\Wireshark\tshark.exe"
```

Tu peux aussi poser une variable d’environnement et n’y plus penser :

```powershell
setx T2H_TSHARK_PATH "C:\Program Files\Wireshark\tshark.exe"
```

### 5 — Hashcat (optionnel)

Pour casser les hashes **après** l’extraction.

```powershell
winget install Hashcat.Hashcat
```

```bash
# Linux
sudo apt install -y hashcat
# ou le binaire officiel : https://hashcat.net/hashcat/
```

---

## Premier lancement

```powershell
py tshark2hashcat.py
```

```text
    1.  Un fichier   →   Excel + txt Hashcat
    2.  Un dossier   →   Excel + txt Hashcat (tous les pcap)
    0.  Quitter

  Votre choix :
```

Tape `1`, colle le chemin du pcap, Entrée.  
Tape `2`, colle le dossier, Entrée — un seul Excel pour tout le tas.

Pour les scripts / CI, sans menu :

```bash
python tshark2hashcat.py auto   capture.pcapng
python tshark2hashcat.py folder ./captures/
```

---

## Qu’est-ce qui sort ?

À côté de ta capture :

```text
tshark2hashcat-rapport.xlsx     ← le livrable
capture_m5600.txt               ← NetNTLMv2, prêt pour hashcat -m 5600
capture_m18200.txt              ← AS-REP
capture_m22000.txt              ← WPA
… un .txt par mode réellement vu
```

Pas de CSV, pas de JSON, pas six Markdown. Excel + hashes. Point.

### L’Excel, feuille par feuille

| Feuille | Ce que tu y lis |
|---|---|
| **Couverture** | le verdict, le score, la conclusion — la page qu’on ouvre en premier |
| **Findings** | les fiches T2H-xx : preuve, impact, remédiation, MITRE |
| **Expositions** | la version courte, pour la restitution |
| **Cartographie** | domaine, DC, comptes, partages |
| **MITRE** | uniquement ce que la capture étaye |
| **Chemins** | comment un attaquant enchaîne, d’après le trafic |
| **Écarts** | ce qui devrait être là / ce qui est vraiment là |
| **OSINT** | gens, mails, tél, orgs, IP publiques |
| **Identités** | comptes AD. Un `MACHINE$` n’est pas un humain |
| **Secrets** | vrais secrets. Un cookie Cloudflare, ça ne compte pas |
| **Hashes** | l’inventaire Hashcat |
| **Paquets** | le volume, par famille |

### Casser ensuite

```bash
hashcat -m 5600  capture_m5600.txt  wordlist.txt
hashcat -m 18200 capture_m18200.txt wordlist.txt
hashcat -m 19700 capture_m19700.txt wordlist.txt
hashcat -m 22000 capture_m22000.txt wordlist.txt
hashcat -m 5600  capture_m5600.txt  --show
```

Ne touche pas aux lignes. Hashcat est allergique aux espaces « améliorés ».

---

## Ce que l’outil extrait

<details>
<summary><b>Formats Hashcat — cliquer pour déplier</b></summary>

<br>

| Auth | Condition | Mode |
|---|---|:---:|
| NetNTLMv2 | réponse NT > 24 o | `5600` |
| NetNTLMv1 / ESS | LM + NT = 24 o | `5500` |
| Kerberos AS-REP RC4 / AES | etype 23 / 17 / 18 | `18200` `32100` `32200` |
| Kerberos AS-REQ (pré-auth) | PA-ENC-TIMESTAMP | `7500` `19800` `19900` |
| Kerberos TGS-REP | etype 23 / 17 / 18 | `13100` `19600` `19700` |
| APOP | bannière + commande `APOP` | `20` |
| WPA/WPA2 PMKID + EAPOL | RSN / handshake M1+M2 | `22000` |
| SNMPv3 USM | | `25000` → `27300` |
| SIP Digest | | `11400` |
| JWT | `Bearer eyJ…` | `16500` |
| CRAM-MD5 / Dovecot | IMAP, SMTP | `10200` `16400` |
| IKE-PSK | | `5300` `5400` |
| IPMI2 RAKP | | `7300` |
| TACACS+ | | `16100` |
| iSCSI CHAP | | `4800` |
| PostgreSQL / MySQL CRAM | | `11100` `11200` |
| XMPP SCRAM | | `23200` |
| AWS SigV4 | | `28700` |
| MS SNTP | | `31300` |

En clair, sans hash : FTP, Telnet, HTTP Basic, formulaires, `AUTH PLAIN` / `LOGIN`, community SNMP v1/v2c, tokens. Feuille **Secrets**.

</details>

L’outil est un peu maniaque, exprès :

- un TGS `cifs/DC` ce n’est **pas** un Kerberoast — c’est juste l’AD qui vit ;
- Kerberoast = un humain qui demande un SPN de service ;
- `MACHINE$` n’est pas un e-mail, ni une personne ;
- `__cf_bm` n’est pas un secret ;
- un JA3 n’est pas un numéro de téléphone.

Si un champ manque, la ligne n’est pas inventée. Tu le vois dans le rapport, pas dans Hashcat.

---

## Capture en direct

Même dossier, autre script : `tshark2hashcat-live.py`.

```powershell
py tshark2hashcat-live.py
```

```text
    1.  Démarrer la surveillance
    2.  Choisir l'interface
    3.  Tester l'envoi du mail
    4.  Rejouer un pcap
    0.  Quitter
```

Ça capture par tranches, réécrit l’Excel, et n’envoie un mail **que** si le niveau passe `CRITIQUE` ou `ÉLEVÉ` — et seulement quand un **nouveau** finding apparaît. Pas un mail toutes les minutes.

Config : `t2h-live.conf` (destinataire, SMTP). Mot de passe d’application Gmail, jamais dans le `.py`.  
Windows : lance **en administrateur**, sinon l’interface reste muette.

---

## Ça coince ?

| Tu vois | Tu fais |
|---|---|
| `tshark introuvable` | réinstalle Wireshark, rouvre le terminal, ou `--tshark "C:\Program Files\Wireshark\tshark.exe"` |
| `openpyxl est requis` | `py -m pip install -r requirements.txt` |
| `py` n’est pas reconnu | installe Python en cochant PATH, ou tape `python` |
| `find_tshark() missing … cli_path` | ton `tshark2hashcat.py` est trop vieux — remets la 2.7.0 à côté du live |
| Hashcat : `Separator unmatched` | tu as touché au `.txt` — reprends celui de l’outil |
| live : 0 paquet | pas admin / pas root |
| mail SMTP refusé | ce n’est pas le mot de passe du compte Gmail, c’est un **mot de passe d’application** |

---

## Licence

[Apache 2.0](LICENSE).  
Wireshark, Tshark et Hashcat appartiennent à leurs auteurs. On n’est affilié à personne — on s’assoit juste dessus.
