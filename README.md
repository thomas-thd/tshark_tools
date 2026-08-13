<div align="center">
<img src="assets/banner.svg" alt="tshark2hashcat" width="880">

# tshark2hashcat

**Extraction de hashes Hashcat et rapport d’audit réseau à partir d’une capture Tshark.**

[![version](https://img.shields.io/badge/version-2.7.0-0ea5e9)](#)
[![python](https://img.shields.io/badge/python-%3E%3D%203.10-3776AB?logo=python&logoColor=white)](#dépendances)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-111827)](#dépendances)
[![engine](https://img.shields.io/badge/engine-Tshark%20--T%20json%20-x-6366f1)](#architecture)

</div>

---

`tshark2hashcat` lit un fichier `.pcap` / `.pcapng` (ou un répertoire de captures), le fait disséquer par **Tshark** (`-T json -x`), reconstruit les authentifications réseau dans le format exact attendu par [Hashcat](https://hashcat.net/hashcat/), et produit un **classeur Excel d’audit** (findings, MITRE ATT&CK, cartographie, secrets, OSINT).

Le décodage des paquets n’est jamais effectué en Python. Tshark est la seule source de données.

Utilisation autorisée uniquement : laboratoire, CTF, audit contractuel, environnement dont vous avez la maîtrise.

## Table des matières

1. [Dépendances](#dépendances)
2. [Installation](#installation)
3. [Utilisation](#utilisation)
4. [Livrables](#livrables)
5. [Formats Hashcat](#formats-hashcat)
6. [Règles d’analyse](#règles-danalyse)
7. [Surveillance temps réel](#surveillance-temps-réel)
8. [Architecture](#architecture)
9. [Limites](#limites)
10. [Diagnostic](#diagnostic)
11. [Licence](#licence)

## Dépendances

### Environnement

| Composant | Version minimale | Rôle |
|---|---|---|
| Python | **3.10** (3.11+ recommandé) | Interpréteur |
| Tshark | Wireshark **3.6+** | Dissection et dump hexadécimal |
| Hashcat | 6.2+ | Cassage (optionnel, hors de cet outil) |

Tshark est recherché dans cet ordre : `T2H_TSHARK_PATH`, `TSHARK`,  
`C:\Program Files\Wireshark\tshark.exe`, `C:\Program Files (x86)\Wireshark\tshark.exe`, puis le `PATH`.

### Paquets Python

Fichier : [`requirements.txt`](requirements.txt)

| Paquet | Contrainte | Statut | Usage |
|---|---|---|---|
| **openpyxl** | `>=3.1.0,<4` | **obligatoire** | Génération du classeur `.xlsx` (livrable principal) |
| **rich** | `>=13.7.0,<15` | recommandé | Logo, tableaux, barres de progression, menus |
| **tqdm** | `>=4.66.0,<5` | optionnel | Barre de progression si `rich` est absent |
| **tomli** | `>=2.0.1,<3` | Python **3.10** uniquement | Lecture de `tshark2hashcat.toml` (`tomllib` est natif dès 3.11) |

Bibliothèque standard utilisée (aucun pip) : `argparse`, `json`, `hashlib`, `subprocess`, `concurrent.futures`, `smtplib`, `email`, `configparser`, `tomllib` (3.11+).

Vérification après installation :

```text
python tshark2hashcat.py doctor
```

| Module | Attendu |
|---|---|
| `openpyxl` | `ok` |
| `rich` | `ok` |
| `tqdm` | `ok` (sinon repli texte) |
| `tshark` | chemin du binaire |

Sans `openpyxl`, l’export Excel échoue avec :

```text
openpyxl est requis pour l'export Excel (pip install openpyxl)
```

Sans `rich`, l’outil reste fonctionnel (sortie texte).

## Installation

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Installation minimale (Excel uniquement) :

```bash
python -m pip install "openpyxl>=3.1.0,<4"
```

Installation complète :

```bash
python -m pip install -r requirements.txt
```

Contrôle :

```bash
python -c "import openpyxl, rich, tqdm; print(openpyxl.__version__, rich.__version__, tqdm.__version__)"
python tshark2hashcat.py doctor
```

## Utilisation

L’interface par défaut est un **menu numéroté**. Aucune sous-commande n’est requise.

```bash
python tshark2hashcat.py
```

```
  1.  Un fichier   →   Excel + txt Hashcat
  2.  Un dossier   →   Excel + txt Hashcat (tous les pcap)
  0.  Quitter
```

| Choix | Entrée | Sortie |
|:---:|---|---|
| `1` | un `.pcap` / `.pcapng` | un classeur + un `.txt` par mode Hashcat |
| `2` | un répertoire (récursif) | **un** classeur fusionné + les `.txt` |
| `0` | — | sortie |

Le format et le nom des fichiers sont déterminés automatiquement.

### Automatisation

```bash
python tshark2hashcat.py auto    capture.pcapng
python tshark2hashcat.py folder  ./captures/
python tshark2hashcat.py doctor
```

Chemin Tshark explicite :

```bash
python tshark2hashcat.py --tshark /usr/bin/tshark
```

```powershell
python tshark2hashcat.py --tshark "C:\Program Files\Wireshark\tshark.exe"
```

## Livrables

Chaque analyse produit :

| Fichier | Contenu |
|---|---|
| `tshark2hashcat-rapport.xlsx` | Rapport d’audit (voir ci-dessous) |
| `<préfixe>_m<mode>.txt` | Hashes validés, un fichier par mode Hashcat |

### Classeur Excel

| Feuille | Contenu |
|---|---|
| Couverture | Verdict, score, périmètre, conclusion |
| Findings | Fiches T2H-xx (gravité, preuve, impact, remédiation, MITRE) |
| Expositions | Synthèse destinée à la restitution |
| Cartographie | Domaine, DC, comptes, partages, hôtes |
| MITRE | Techniques étayées par la capture |
| Chemins | Scénarios d’attaque observés |
| Écarts | Contrôle attendu / observé |
| OSINT | Personnes, e-mails, téléphones, organisations, IP publiques |
| Identités | Comptes AD / UPN |
| Secrets | Identifiants et secrets extraits |
| Hashes | Inventaire des lignes Hashcat |
| Paquets | Volume par famille de protocoles |

## Formats Hashcat

| Authentification | Condition | Mode | Format |
|---|---|:---:|---|
| NetNTLMv2 | réponse NT > 24 octets | 5600 | `user::domain:challenge:NTProofStr:blob` |
| NetNTLMv1 / ESS | réponses LM et NT = 24 octets | 5500 | `user::domain:LM:NT:challenge` |
| Kerberos AS-REP RC4 | etype 23 | 18200 | `$krb5asrep$23$…` |
| Kerberos AS-REP AES128 / AES256 | etype 17 / 18 | 32100 / 32200 | `$krb5asrep$17/18$…` |
| Kerberos AS-REQ (PA-ENC-TIMESTAMP) | etype 23 / 17 / 18 | 7500 / 19800 / 19900 | `$krb5pa$…` |
| Kerberos TGS-REP | etype 23 / 17 / 18 | 13100 / 19600 / 19700 | `$krb5tgs$…` |
| APOP | bannière `<challenge>` + commande `APOP` | 20 | `digest:challenge` |
| WPA/WPA2 PMKID et EAPOL | RSN IE / handshake M1+M2 | 22000 | `WPA*01*` / `WPA*02*` |
| SNMPv3 USM | authentification USM | 25000–27300 | `$SNMPv3$…` |
| SIP Digest | `Authorization: Digest` | 11400 | `$sip$…` |
| JWT | `Bearer eyJ…` | 16500 | jeton JWT |
| CRAM-MD5 / Dovecot | IMAP, SMTP | 10200 / 16400 | |
| IKE-PSK | ISAKMP | 5300 / 5400 | |
| IPMI2 RAKP | HMAC-SHA1 | 7300 | |
| TACACS+ | | 16100 | |
| iSCSI CHAP | | 4800 | |
| PostgreSQL / MySQL CRAM | | 11100 / 11200 | |
| XMPP SCRAM | | 23200 | |
| AWS Signature V4 | | 28700 | |
| MS SNTP | | 31300 | |

Identifiants transmis en clair (FTP, Telnet, HTTP Basic, formulaires, `AUTH PLAIN` / `LOGIN`, community SNMPv1/v2c, jetons Bearer) : feuille **Secrets**, pas de fichier annexe.

### Cassage

```bash
hashcat -m 5600  capture_m5600.txt  wordlist.txt
hashcat -m 18200 capture_m18200.txt wordlist.txt
hashcat -m 19700 capture_m19700.txt wordlist.txt
hashcat -m 22000 capture_m22000.txt wordlist.txt
hashcat -m 25000 capture_m25000.txt wordlist.txt

hashcat -m 5600 capture_m5600.txt --show
```

Les lignes doivent rester telles quelles. Toute modification manuelle provoque `Separator unmatched`.

## Règles d’analyse

Une ligne n’est écrite que si le validateur du mode Hashcat l’accepte. Les champs absents sont signalés, jamais interpolés.

| Observation | Classification |
|---|---|
| Compte `MACHINE$` / `name$@REALM` | compte machine — exclu des personnes et des e-mails |
| TGS `cifs/` `ldap/` `host/` `krbtgt` | accès Active Directory observé |
| TGS demandé par un utilisateur humain vers un SPN non-machine | Kerberoasting (T1558.003) |
| Cookies `__cf_bm`, `cf_clearance` | exclus des secrets |
| Empreinte JA3 / JA3S | exclue des numéros de téléphone |

Le score d’audit est calculé par **famille** de findings (rendements décroissants 1.00 / 0.55 / 0.35 / 0.20), puis `max(8, 100 − malus)`. Il décrit la capture, pas la posture globale du SI.

## Surveillance temps réel

Script : [`tshark2hashcat-live.py`](tshark2hashcat-live.py)  
Configuration : [`t2h-live.conf`](t2h-live.conf)  
Dépend des mêmes paquets, plus la bibliothèque standard (`smtplib`, `email`).

```bash
python tshark2hashcat-live.py
```

| Choix | Action |
|:---:|---|
| `1` | capture cyclique, mise à jour du classeur |
| `2` | sélection de l’interface |
| `3` | envoi d’un message de test |
| `4` | rejeu d’un pcap (alerte si non-conforme) |
| `0` | quitter |

Un courriel est émis uniquement si le niveau est `CRITIQUE` ou `ÉLEVÉ`, et uniquement lorsqu’un finding **nouveau** apparaît.

Le mot de passe SMTP se lit dans `t2h-live.conf` ou dans `T2H_MAIL_PASS`. Ne pas le versionner. Sous Windows, lancer le processus en administrateur.

## Architecture

```text
.pcap / .pcapng / répertoire
        │
        ▼
 tshark -n -2 -r <fichier> -T json -x     ← appel unique
        │
        ├── champs disséqués (ntlmssp.*, kerberos.*, wlan.*, snmp.*, …)
        └── octets bruts     (frame_raw, payload, *_raw)
        │
        ▼
 extracteurs + réassemblage TCP/UDP + validateurs Hashcat
        │
        ├── <préfixe>_m<mode>.txt
        └── tshark2hashcat-rapport.xlsx
```

1. Tshark décode la capture.
2. Les champs structurés sont utilisés en priorité.
3. Les octets bruts rattrapent NTLMSSP encapsulé, APOP, PA-ENC-TIMESTAMP, Base64 et JWT.
4. Chaque candidat est validé avant écriture.
5. Le rapport d’audit ne retient que les faits présents dans la capture.

## Limites

- Une authentification incomplète ou filtrée ne produit pas de hash.
- L’appariement NTLM utilise d’abord le tuple adresse/port, puis l’ordre des trames.
- PKINIT, FAST et les échanges Kerberos sans matériel cassable sont ignorés.
- WPA/WPA2 exige les éléments du handshake et, selon le cas, le SSID.
- OSPF n’a pas de mode Hashcat natif.
- Le score porte sur le trafic observé, pas sur l’ensemble du système d’information.

## Diagnostic

| Symptôme | Cause | Action |
|---|---|---|
| `tshark introuvable` | binaire absent du `PATH` | installer Wireshark, ou `--tshark` / `T2H_TSHARK_PATH` |
| `openpyxl est requis` | paquet non installé | `python -m pip install -r requirements.txt` |
| `find_tshark() missing 1 required positional argument` | `tshark2hashcat.py` antérieur à 2.7.0 | remplacer le module par la 2.7.0 |
| `Separator unmatched` (Hashcat) | ligne altérée | reprendre le `.txt` généré |
| capture live vide | privilèges insuffisants | Windows : administrateur — Linux : `cap_net_raw` ou root |
| authentification SMTP refusée | mot de passe de compte au lieu d’un mot de passe d’application | Google Account → Mots de passe des applications |

## Licence

[Apache License 2.0](LICENSE).

Wireshark, Tshark et Hashcat restent la propriété de leurs auteurs respectifs. Ce projet n’est affilié ni à la Wireshark Foundation ni au projet Hashcat.
