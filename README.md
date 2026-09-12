<p align="center">
  <img src="banner.png" alt="tshark2hashcat" width="100%">
</p>

<h1 align="center">tshark2hashcat</h1>

<p align="center">
  <b>Analyse de captures réseau, extraction de secrets et génération Hashcat.</b>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  </a>
  <a href="https://www.wireshark.org/">
    <img src="https://img.shields.io/badge/TShark-Wireshark-1679a7?style=for-the-badge&logo=wireshark&logoColor=white" alt="TShark">
  </a>
  <a href="https://hashcat.net/hashcat/">
    <img src="https://img.shields.io/badge/Hashcat-ready-d75fff?style=for-the-badge" alt="Hashcat">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-5fd75f?style=for-the-badge" alt="MIT License">
  </a>
</p>

<p align="center">
  Windows · Linux · macOS · Python 3.10+
</p>

> Audit réseau, pentest et CTF. Utilisez uniquement des captures que vous êtes autorisé à analyser.

---

## Présentation

**tshark2hashcat** est un outil d'analyse de captures réseau basé sur **TShark**.

Il transforme une ou plusieurs captures PCAP/PCAPNG en données directement exploitables pour l'audit :

* hashes compatibles Hashcat ;
* identifiants et secrets observés ;
* informations Kerberos et Active Directory ;
* exposition réseau ;
* métadonnées et OSINT ;
* findings de sécurité ;
* chemins d'attaque ;
* mapping MITRE ATT&CK ;
* rapports HTML, Markdown, JSON, CSV et Excel ;
* commandes Hashcat prêtes à être utilisées.

Le fonctionnement principal est simple :

```text
PCAP / PCAPNG
      │
      ▼
   TShark
      │
      ├── Protocoles
      ├── Credentials
      ├── Hashes
      ├── Kerberos
      ├── Wi-Fi
      ├── Métadonnées
      └── OSINT
      │
      ▼
 Analyse / Corrélation
      │
      ├── Findings
      ├── Score
      ├── MITRE ATT&CK
      ├── Chemins d'attaque
      └── Cartographie
      │
      ▼
 Hashcat + Rapports
```

---

# Installation

## 1. Installer TShark

### Debian / Ubuntu

```bash
sudo apt install tshark
```

### Fedora

```bash
sudo dnf install wireshark-cli
```

### macOS

```bash
brew install wireshark
```

### Windows

```powershell
winget install WiresharkFoundation.Wireshark
```

Vérification :

```bash
tshark --version
```

---

## 2. Installer tshark2hashcat

```bash
git clone https://github.com/tshark2hashcat/tshark2hashcat.git
cd tshark2hashcat
```

Dépendances optionnelles :

```bash
pip install openpyxl rich tqdm
```

Le programme reste utilisable sans ces dépendances, avec une sortie texte simplifiée.

---

# Démarrage rapide

### Vérifier l'environnement

```bash
python tshark2hashcat.py doctor
```

### Analyser une capture

```bash
python tshark2hashcat.py auto capture.pcapng
```

### Analyser un dossier

```bash
python tshark2hashcat.py folder ./captures
```

### Utilisation implicite

```bash
python tshark2hashcat.py capture.pcap
```

équivaut à :

```bash
python tshark2hashcat.py auto capture.pcap
```

Et :

```bash
python tshark2hashcat.py ./captures
```

équivaut à :

```bash
python tshark2hashcat.py folder ./captures
```

---

# Hashes compatibles Hashcat

Les hashes sont validés contre le format attendu avant leur export et sont dédupliqués automatiquement.

| Protocole        | Détection                              |                    Hashcat |
| ---------------- | -------------------------------------- | -------------------------: |
| NetNTLMv2        | NTLMSSP AUTH, NT Response > 24 octets  |                  `-m 5600` |
| NetNTLMv1        | NTLMSSP AUTH, NT Response = 24 octets  |                  `-m 5500` |
| NetNTLMv1 + ESS  | NTLMSSP avec Extended Session Security |                  `-m 5500` |
| Kerberos AS-REQ  | PA-ENC-TIMESTAMP                       |  `-m 7500 / 19800 / 19900` |
| Kerberos AS-REP  | `msg-type 11` + `enc-part`             | `-m 18200 / 32100 / 32200` |
| Kerberos TGS-REP | Ticket Service                         | `-m 13100 / 19600 / 19700` |
| WPA PMKID        | RSN / EAPOL M1                         |                 `-m 22000` |
| APOP             | MD5(challenge + password)              |                    `-m 20` |
| SIP Digest       | Authorization Digest                   |                 `-m 11400` |
| JWT              | Bearer JWT                             |                 `-m 16500` |
| CHAP             | Champs CHAP disséqués                  |                  `-m 4800` |

### Extraction multi-niveaux

L'extraction utilise en priorité les champs disséqués par TShark :

```text
ntlmssp.*
kerberos.*
...
```

Si les champs ne sont pas disponibles, un second chemin peut analyser les octets bruts :

```text
TShark -x
    │
    ├── NTLMSSP signatures
    ├── Base64
    ├── HTTP
    ├── IMAP
    └── SMTP
```

Les échanges sont ensuite corrélés lorsque cela est possible par :

```text
IP source
IP destination
port source
port destination
```

---

# Identifiants et secrets

tshark2hashcat recherche également les informations sensibles visibles directement dans les captures.

## Identifiants en clair

Protocoles et mécanismes pris en charge notamment :

* FTP `USER/PASS`
* Telnet
* HTTP Basic
* Proxy Basic
* HTTP Forms
* SMTP
* POP3
* IMAP
* AUTH PLAIN
* AUTH LOGIN
* PAP
* LDAP Simple Bind
* TACACS+
* MQTT

## Tokens et clés

Détection notamment de :

* Cookies ;
* `Set-Cookie` ;
* `Authorization` ;
* Bearer tokens ;
* JWT ;
* API keys ;
* AWS Access Keys.

## Informations réseau

Extraction de :

* SNMP community strings ;
* utilisateurs SNMPv3 ;
* RADIUS User-Name ;
* DHCP hostname ;
* TLS SNI ;
* QUIC SNI ;
* DTLS SNI.

---

# Analyse réseau et OSINT

L'outil collecte également les informations utiles à la compréhension de l'environnement observé.

### Identités

* utilisateurs ;
* comptes machine ;
* domaines ;
* UPN ;
* realms Kerberos ;
* SPN ;
* identités avec ou sans pré-authentification.

### Réseau

* IPv4 / IPv6 ;
* MAC ;
* fabricants via OUI ;
* DNS ;
* mDNS ;
* LLMNR ;
* NBNS ;
* DHCP ;
* hosts ;
* équipements réseau.

### Active Directory

* domaine ;
* contrôleurs de domaine ;
* utilisateurs ;
* SPN ;
* comptes machine ;
* partages SMB ;
* fichiers observés ;
* informations Kerberos.

### Wi-Fi

* SSID ;
* BSSID ;
* RSN ;
* EAPOL ;
* PMKID ;
* informations WPA/WPA2/WPA3.

### OSINT réseau

Détection de :

* adresses e-mail ;
* numéros français ;
* noms présents dans les chemins ;
* claims JWT ;
* sujets d'e-mails ;
* noms de machines ;
* organisations ;
* domaines ;
* SNI ;
* équipements ;
* partages et fichiers.

Des filtres réduisent certains faux positifs courants :

* cookies Cloudflare ;
* chaînes de test ;
* faux numéros de téléphone ;
* bannières SSH ;
* comptes machine ;
* valeurs SNMP de test.

---

# Analyse de sécurité

Le moteur transforme les éléments observés en findings exploitables.

Chaque finding peut contenir :

```text
Gravité
Preuve
Impact
Remédiation
Actifs concernés
MITRE ATT&CK
```

## Exemples de findings

* mots de passe en clair ;
* FTP / Telnet ;
* HTTP Basic ;
* LDAP non chiffré ;
* NetNTLMv1 ;
* NetNTLMv2 ;
* AS-REP Roasting ;
* Kerberoasting ;
* LLMNR ;
* NBNS ;
* WPAD ;
* SNMP ;
* APOP ;
* WPA ;
* exposition de cookies ;
* exposition de PII.

---

# Score de sécurité

Un score sur 100 est calculé à partir des **preuves effectivement observées dans la capture**.

```text
FAIBLE
MODÉRÉ
ÉLEVÉ
CRITIQUE
```

La simple présence d'un protocole ne suffit pas à déclencher automatiquement un finding critique.

L'objectif est de distinguer :

```text
Protocole observé
        ≠
Vulnérabilité démontrée
```

---

# Chemins d'attaque

Lorsque les données disponibles permettent une corrélation, l'outil peut reconstruire des scénarios d'attaque.

Exemple :

```text
Capture réseau
      │
      ▼
Vol d'authentification NTLM
      │
      ▼
Cracking / récupération du secret
      │
      ▼
Kerberoasting
      │
      ▼
Compte de service compromis
      │
      ▼
Accès SMB / SYSVOL
      │
      ▼
Exposition de données
```

Les chemins sont accompagnés des preuves disponibles dans la capture.

---

# MITRE ATT&CK

Les observations peuvent être associées à des techniques MITRE ATT&CK pertinentes.

Exemples :

| Technique | Utilisation                                 |
| --------- | ------------------------------------------- |
| T1040     | Network Sniffing                            |
| T1003     | OS Credential Dumping / Credential Material |
| T1558.003 | Kerberoasting                               |
| T1558.004 | AS-REP Roasting                             |
| T1557.001 | LLMNR/NBT-NS Poisoning                      |
| T1021.002 | SMB/Windows Admin Shares                    |

Le mapping est basé sur les éléments réellement observés et non uniquement sur les protocoles présents.

---

# Kerberos

Une section dédiée permet de retrouver les identités Kerberos observées :

```text
Frame
Message Type
User
Realm
UPN
SPN
Salt
ETYPE_INFO2
Encryption Types
Pre-authentication
```

Les informations de casse exacte peuvent également être conservées lorsqu'elles sont nécessaires à certains environnements CTF.

---

# Commandes Hashcat

Le module `hashcat` génère des commandes directement exploitables.

Exemples de méthodes supportées :

```text
Dictionnaire
Rules
Best64
Rockyou
Combinator
Mask
Hybrid
--show
--left
```

Le mode Hashcat est sélectionné automatiquement lorsque le format extrait est suffisamment déterminé.

Les résultats récupérés peuvent ensuite être associés aux hashes correspondants afin de faciliter leur classement dans le rapport.

---

# Rapport d'audit

La commande `report` génère un rapport complet :

```bash
python tshark2hashcat.py report capture.pcapng
```

Formats disponibles :

```text
HTML
Markdown
JSON
XLSX
```

Le rapport contient notamment :

* synthèse exécutive ;
* score ;
* findings ;
* preuves ;
* remédiations ;
* expositions ;
* MITRE ATT&CK ;
* chemins d'attaque ;
* écarts attendu / observé ;
* cartographie réseau ;
* OSINT ;
* identités ;
* hôtes ;
* Wi-Fi ;
* fichiers ;
* secrets ;
* hashes ;
* informations Kerberos.

---

# Export Excel

L'export `.xlsx` est organisé en plusieurs onglets.

### Synthèse

* Couverture
* KPI
* Synthèse
* Findings
* Actions P1/P2/P3
* Méthodologie

### Analyse

* volumes ;
* durée ;
* débit ;
* familles de protocoles ;
* protocoles clair/chiffré/authentifié ;
* IP ;
* MAC.

### Sécurité

* Findings ;
* Expositions ;
* MITRE ATT&CK ;
* Chemins ;
* Écarts.

### Inventaire

* Cartographie ;
* OSINT ;
* Identités ;
* Hôtes ;
* Wi-Fi ;
* Fichiers ;
* Kerberos.

### Credentials

* Secrets ;
* Hashes ;
* commandes Hashcat.

Le classeur utilise notamment :

* filtres automatiques ;
* volets figés ;
* en-têtes ;
* pieds de page ;
* zébrage ;
* niveaux de sévérité ;
* graphiques.

---

# Autres exports

L'analyse peut également produire :

```text
TXT
CSV
JSON
HTML
Markdown
PCAP
PCAPNG
```

Les fichiers Hashcat peuvent être séparés par mode :

```text
*_m5600.txt
*_m5500.txt
*_m22000.txt
...
```

---

# CLI

tshark2hashcat fournit un wrapper autour des principales fonctions TShark/Wireshark.

| Commande      | Fonction                         |
| ------------- | -------------------------------- |
| `auto`        | Analyse complète d'un fichier    |
| `folder`      | Analyse récursive d'un dossier   |
| `extract`     | Extraction des données           |
| `analyze`     | Analyse générale + statistiques  |
| `stats`       | Statistiques TShark              |
| `packets`     | Extraction de paquets            |
| `follow`      | Suivi de flux                    |
| `objects`     | Extraction d'objets              |
| `filter`      | Réécriture d'une capture filtrée |
| `report`      | Génération du rapport            |
| `creds`       | Identifiants en clair            |
| `convert`     | Conversion / découpage / fusion  |
| `capture`     | Capture réseau live              |
| `decode`      | Decode-as / arbre protocolaire   |
| `fields`      | Extraction de champs TShark      |
| `info`        | Informations capinfos            |
| `ifaces`      | Interfaces de capture            |
| `protocols`   | Catalogue TShark                 |
| `expert`      | Informations Expert              |
| `hosts`       | Hosts observés                   |
| `voip`        | SIP / RTP                        |
| `hashcat`     | Génération de commandes Hashcat  |
| `modes`       | Catalogue des modes Hashcat      |
| `filters`     | Bibliothèque de filtres          |
| `tshark-help` | Aide et statistiques TShark      |
| `wizard`      | Interface interactive            |
| `doctor`      | Diagnostic de l'environnement    |
| `examples`    | Exemples                         |
| `init-config` | Configuration initiale           |

---

# Analyse de dossiers

Le mode `folder` permet d'analyser plusieurs captures :

```bash
python tshark2hashcat.py folder ./captures
```

Fonctionnement :

```text
captures/
├── capture1.pcap
├── capture2.pcapng
├── wifi/
│   └── capture3.cap
└── kerberos/
    └── capture4.pcapng
```

Les fichiers peuvent être traités en parallèle et les résultats regroupés dans un rapport unique.

Pour les captures importantes, le traitement peut utiliser `editcap` afin de découper les fichiers en plusieurs segments.

---

# Configuration

Ordre de priorité :

```text
Arguments CLI
     ↓
Variables T2H_*
     ↓
tshark2hashcat.toml / .json
     ↓
Valeurs par défaut
```

Exemple :

```text
T2H_TSHARK_PATH
T2H_LANG
```

Si TShark n'est pas dans le `PATH` :

```bash
python tshark2hashcat.py doctor --tshark "C:\Program Files\Wireshark\tshark.exe"
```

ou :

```text
T2H_TSHARK_PATH
```

---

# Interface

L'interface utilise Rich lorsqu'il est disponible :

* tableaux ;
* barres de progression ;
* couleurs de sévérité ;
* résumé d'analyse ;
* statistiques.

Options disponibles notamment :

```text
--quiet
--verbose
--no-color
--no-progress
--limit
--lang
--tshark
```

Un mode texte de repli est disponible lorsque Rich n'est pas installé.

---

# Architecture

Le projet reste volontairement contenu dans **un seul fichier Python**.

```text
tshark2hashcat.py
```

Pipeline simplifié :

```text
Input
 │
 ├── PCAP / PCAPNG
 ├── JSON TShark
 └── dossier de captures
 │
 ▼
TShark
 │
 ▼
Extraction
 │
 ├── Protocoles
 ├── Credentials
 ├── Hashes
 ├── Kerberos
 ├── Wi-Fi
 ├── OSINT
 └── Métadonnées
 │
 ▼
Corrélation
 │
 ▼
Analyse sécurité
 │
 ├── Findings
 ├── Score
 ├── MITRE
 └── Attack Paths
 │
 ▼
Exports
 │
 ├── Hashcat
 ├── TXT
 ├── CSV
 ├── JSON
 ├── Markdown
 ├── HTML
 └── XLSX
```

---

# Compatibilité

| Composant       | Support      |
| --------------- | ------------ |
| Python          | 3.10+        |
| Windows         | ✅            |
| Linux           | ✅            |
| macOS           | ✅            |
| TShark          | Requis       |
| Hashcat         | Optionnel    |
| John the Ripper | Optionnel    |
| Rich            | Optionnel    |
| tqdm            | Optionnel    |
| openpyxl        | Export Excel |

---

# Limites connues

### WPA

Pour certains handshakes WPA nécessitant les octets EAPOL complets, `hcxpcapngtool` reste recommandé pour produire le format Hashcat correspondant.

### OSPF

OSPF avec authentification cryptographique ne dispose pas d'un mode Hashcat natif équivalent aux formats précédents.

### CRAM-MD5

L'extraction peut nécessiter l'utilisation du module `follow` SMTP/IMAP plutôt qu'un export Hashcat direct.

---

# Sécurité et utilisation

`tshark2hashcat` est destiné à :

* l'audit de sécurité ;
* le pentest autorisé ;
* l'analyse forensique ;
* les environnements de laboratoire ;
* les CTF ;
* la recherche et l'apprentissage.

Les captures réseau peuvent contenir des informations extrêmement sensibles :

```text
Mots de passe
Cookies
Tokens
Adresses IP
Adresses e-mail
Données personnelles
Informations Active Directory
Communications privées
```

**Ne publiez jamais une capture provenant d'un environnement réel sans avoir vérifié son contenu et obtenu les autorisations nécessaires.**

Pour un dépôt GitHub, privilégiez des captures synthétiques ou spécialement préparées pour les tests.

---

# Licence

Distribué sous licence **MIT**.

Voir [`LICENSE`](LICENSE).

---

<p align="center">
  <b>tshark2hashcat</b><br>
  <i>From network capture to actionable security intelligence.</i>
</p>
