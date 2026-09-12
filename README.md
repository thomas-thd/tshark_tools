<p align="center">
  <img src="banner.png" alt="tshark2hashcat" width="100%">
</p>

<h1 align="center">tshark2hashcat</h1>

<p align="center">
  <b>Extraction de hashes Hashcat et analyse de captures réseau via TShark.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/TShark-Wireshark-1679a7?style=for-the-badge&logo=wireshark&logoColor=white">
  <img src="https://img.shields.io/badge/Hashcat-ready-d75fff?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-Apache--2.0-5fd75f?style=for-the-badge">
</p>

<p align="center">
  <code>v1.2.0</code> · Windows · Linux · macOS
</p>

> Audit, pentest, CTF et recherche : utilisez uniquement des captures que vous êtes autorisé à analyser.

---

## Présentation

`tshark2hashcat` est un outil Python qui utilise **TShark** pour analyser des captures réseau et extraire des informations exploitables pour l'analyse réseau et le cracking hors ligne.

Le programme peut travailler sur :

* un fichier PCAP / PCAPNG / CAP / DMP ;
* un export JSON TShark ;
* un dossier de captures ;
* un projet d'analyse complet.

Le traitement peut produire des hashes Hashcat, des identifiants, des secrets, des informations réseau, des données Kerberos, des résultats d'analyse et différents formats de rapports.

Le projet est contenu dans un **seul fichier Python**.

---

# Installation

## TShark

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

## Dépendances Python optionnelles

```bash
pip install rich openpyxl tqdm
```

Le code teste automatiquement leur présence.

`doctor` permet de vérifier l'environnement :

```bash
python tshark2hashcat.py doctor
```

Le diagnostic vérifie notamment TShark, les outils Wireshark utilisés par le programme et les dépendances Python. Un self-test des solveurs intégrés est également exécuté.

---

# Utilisation rapide

## Analyse automatique d'une capture

```bash
python tshark2hashcat.py auto capture.pcapng
```

`auto` effectue l'extraction puis lance les solveurs intégrés, sauf avec `--no-solve`.

## Extraction

```bash
python tshark2hashcat.py extract capture.pcapng
```

Formats disponibles :

```bash
python tshark2hashcat.py extract capture.pcapng -f txt,csv,json,xlsx,html,md
```

## Analyse d'un dossier

```bash
python tshark2hashcat.py folder ./captures
```

Les captures sont découvertes récursivement par défaut et traitées en parallèle. Le résultat est regroupé dans un classeur Excel.

## Menu interactif

```bash
python tshark2hashcat.py wizard
```

Sans argument :

```bash
python tshark2hashcat.py
```

le programme ouvre directement le menu interactif.

---

# Extraction Hashcat

Le code définit actuellement les modes Hashcat suivants :

```text
20
4800
5500
5600
7500
11400
13100
16500
18200
19600
19700
19800
19900
22000
32100
32200
```

Les hashes extraits sont regroupés par mode et les commandes Hashcat correspondantes peuvent être générées automatiquement.

```bash
python tshark2hashcat.py hashcat hashes.txt
```

Avec un mode explicite :

```bash
python tshark2hashcat.py hashcat hashes.txt -m 5600
```

Une wordlist peut être associée aux commandes :

```bash
python tshark2hashcat.py hashcat hashes.txt --wordlist wordlist.txt
```

---

# NTLM

Le moteur d'extraction traite notamment les échanges NTLMSSP.

Les données peuvent être extraites depuis les champs TShark et, lorsque nécessaire, depuis les octets bruts de la capture.

Le code valide les données avant leur génération en cible Hashcat.

Les erreurs d'extraction NTLM sont également signalées lorsque des champs nécessaires sont absents ou que la longueur de la réponse ne correspond pas aux formats attendus.

---

# Kerberos

Le programme analyse les échanges Kerberos et conserve notamment les informations permettant de caractériser les identités observées.

Le rapport peut afficher :

* frame ;
* type de message ;
* utilisateur ;
* realm ;
* SPN ;
* salt ;
* types de chiffrement.

Le programme conserve également les utilisateurs Kerberos ayant une pré-authentification observée.

Les modes Hashcat associés aux différentes cibles Kerberos sont intégrés dans le catalogue du programme.

---

# WPA / Wi-Fi

Le projet contient plusieurs traitements liés au Wi-Fi.

Le moteur de solveurs intégré comprend :

### WPA2-Enterprise / RADIUS

Le solveur `wpa2e` traite notamment :

* secret RADIUS ;
* `Message-Authenticator` ;
* PMK ;
* MS-MPPE-Recv-Key ;
* handshake 4-way ;
* PTK ;
* MIC EAPOL ;
* déchiffrement AES-CCMP.

### WEP

Le solveur `wep` traite le WEP-40 avec :

* clair connu ;
* différents alphabets ;
* validation ICV ;
* validation CRC32.

### WPA3-SAE

Le solveur `sae` traite notamment :

* récupération du PWE ;
* masks ;
* confirmation SAE ;
* dérivation KCK / PMK ;
* PTK / KEK / TK ;
* GTK ;
* déchiffrement CCMP.

Ces quatre solveurs sont intégrés directement dans le fichier Python.

---

# Authentifications réseau

Le solveur `auth` intégré traite plusieurs mécanismes d'authentification.

### XMPP / SASL

* SCRAM-SHA-1
* SCRAM-SHA-256
* SCRAM-SHA-512
* DIGEST-MD5
* CRAM-MD5
* PLAIN
* LOGIN

### HTTP

* Basic
* Digest

### POP3

* USER/PASS
* APOP

### IMAP

* LOGIN

### SMTP

* AUTH PLAIN
* AUTH LOGIN
* CRAM-MD5

### FTP

* USER/PASS

### Telnet

* authentification observée dans la session.

Le solveur peut utiliser une wordlist, des variantes dérivées du login, des fragments du login, du brute force incrémental et des masks selon le mécanisme.

---

# Identifiants et secrets

L'extraction réseau détecte notamment des données d'authentification en clair.

Exemples présents dans le code :

* FTP ;
* POP3 ;
* IMAP ;
* SMTP ;
* Telnet ;
* IRC ;
* XMPP ;
* LDAP ;
* SNMP ;
* SIP.

Le parseur FTP extrait notamment `USER`, `PASS`, `ACCT` et `AUTH`.

Le parseur POP3 traite `USER`, `PASS`, `AUTH PLAIN` et APOP.

Le parseur IMAP traite notamment `LOGIN` et `AUTHENTICATE PLAIN`.

Le parseur SMTP traite notamment `AUTH PLAIN`, `AUTH LOGIN` et certains en-têtes de messages.

---

# Inventaire réseau

La commande `inventory` fournit un moteur d'inventaire indépendant du reste du pipeline.

```bash
python tshark2hashcat.py inventory capture.pcap
```

Ou sur un dossier :

```bash
python tshark2hashcat.py inventory ./captures
```

Les sorties sont :

```text
.txt
.json
.csv
```

Elles sont générées systématiquement par cette commande.

L'inventaire conserve notamment :

* secrets ;
* identités ;
* PII ;
* métadonnées ;
* protocoles ;
* parseurs utilisés ;
* anomalies ;
* compteurs ;
* découvertes ;
* frame ;
* source ;
* destination ;
* notes.

Dans la version `1.2.0`, les valeurs de l'inventaire sont explicitement conservées et exportées **en clair**, sans masquage.

---

# Protocoles analysés

Le moteur possède un système de dispatch par ports et par reconnaissance structurelle des payloads.

Il peut notamment identifier ou analyser :

* ARP ;
* IPv4 ;
* IPv6 ;
* TCP ;
* UDP ;
* ICMP ;
* DNS ;
* DHCP ;
* RADIUS ;
* SNMP ;
* TLS ;
* SSH ;
* HTTP ;
* POP3 ;
* SMTP ;
* FTP ;
* MySQL ;
* PostgreSQL ;
* XMPP ;
* SIP ;
* Redis ;
* LDAP ;
* Kerberos ;
* IRC ;
* RDP.

La reconnaissance structurelle permet également d'identifier certains protocoles lorsque le port ne suffit pas.

Le système limite le nombre de parseurs candidats et isole les erreurs de chaque parseur afin qu'une anomalie ne fasse pas arrêter toute l'analyse.

---

# Protocoles supplémentaires

Le moteur d'inventaire contient également des parseurs pour plusieurs protocoles et environnements spécifiques, notamment :

* NTP ;
* Modbus ;
* S7 ;
* BACnet ;
* MySQL ;
* TLS ;
* DHCP ;
* SNMP ;
* SIP.

Par exemple, le parseur Modbus identifie certaines fonctions et signale le contexte OT/SCADA.

Le parseur S7 identifie notamment le type de message et la fonction S7comm.

---

# TLS

Le moteur d'inventaire peut analyser les structures TLS présentes dans les données disponibles.

Il extrait notamment :

* ClientHello ;
* version TLS ;
* SNI ;
* ALPN ;
* extension PSK ;
* ServerHello ;
* certificats ;
* sujet ;
* émetteur ;
* numéro de série ;
* validité ;
* SAN DNS.

Le réassemblage TCP utilisé pour ces données est borné afin de limiter la mémoire utilisée par les flux.

---

# Rapport d'analyse

L'analyse réseau peut produire un rapport contenant notamment :

* score ;
* niveau de risque ;
* findings ;
* expositions ;
* recommandations ;
* OSINT ;
* chemins ;
* écarts ;
* mapping MITRE ;
* cartographie ;
* conclusion ;
* périmètre.

Le rapport console présente également les hashes Hashcat et les informations Kerberos associées.

Le score est basé sur les éléments extraits par l'analyse plutôt que simplement sur la présence d'un protocole. La méthode de rapport le précise explicitement.

---

# MITRE ATT&CK

Le moteur de rapport associe certains éléments observés à des techniques MITRE ATT&CK.

Le rapport console possède une section dédiée :

```text
MITRE ATT&CK
```

avec :

```text
ID
Technique
Tactique
```

---

# Chemins d'attaque

Le rapport peut présenter des chemins d'attaque sous forme d'étapes.

Chaque entrée peut contenir :

```text
Étape
Nom
Scénario
Résultat
MITRE
```

---

# Cartographie

Le rapport peut afficher les éléments effectivement observés sous forme de cartographie :

```text
Type
Nom
Rôle
Détail
```

---

# Projet d'analyse

Le mode `project` constitue le moteur complet du programme.

```bash
python tshark2hashcat.py project ./captures
```

Le contexte peut être déclaré :

```bash
--context CTF
--context PENTEST
--context AUDIT
--context RESEARCH
```

Le projet accepte également :

```text
--scope
--exclude
--wordlist
--knowledge
--deep
--budget
--cores
--hashcat
--hashcat-run
--rounds
--sae-mask
--auth-mask
--no-cache
--no-recursive
--no-excel
--no-html
--fresh
--no-ask
```

---

# Knowledge Base

Un projet peut conserver une base de connaissances.

```bash
python tshark2hashcat.py knowledge projet/
```

Elle peut être filtrée par :

```bash
--type password
--status VALIDATED
```

et exportée en JSON :

```bash
--json-out resultat.json
```

Un fichier externe peut également être importé avec `--knowledge`.

---

# Graphe

Le projet possède une commande dédiée à la génération du graphe de connaissances :

```bash
python tshark2hashcat.py graph projet/
```

Elle produit un fichier `.dot` et des informations associées au graphe et à la timeline.

---

# Targets

La commande `targets` traite les cibles Hashcat d'un projet :

```bash
python tshark2hashcat.py targets projet/
```

Elle effectue notamment une revalidation des formats, organise les hashes par cible et génère les commandes associées.

---

# Solve

Un projet peut être repris ultérieurement :

```bash
python tshark2hashcat.py solve projet/
```

Le moteur peut effectuer plusieurs rounds :

```text
analyse
  ↓
cibles
  ↓
solveurs
  ↓
propagation
  ↓
post-crack
  ↓
nouveaux candidats
  ↓
nouveau round
```

Le cycle continue jusqu'à atteindre l'état stable ou le nombre maximal de rounds configuré.

Les informations récupérées par les solveurs peuvent être réinjectées dans le projet comme nouveaux candidats.

---

# Hashcat externe

Le moteur projet peut également utiliser un exécutable Hashcat externe.

```bash
python tshark2hashcat.py project ./captures \
  --hashcat /chemin/vers/hashcat \
  --hashcat-run
```

Le code prévoit l'association d'une wordlist aux cibles et l'exécution des cibles `READY`.

---

# Commandes disponibles

## Extraction et analyse

```text
auto
folder
extract
analyze
stats
packets
follow
objects
filter
report
creds
```

## Outils TShark / Wireshark

```text
capture
decode
fields
info
ifaces
protocols
expert
hosts
voip
```

## Hashcat

```text
hashcat
modes
```

## Utilitaires

```text
filters
tshark-help
doctor
examples
init-config
wizard
```

## Moteur projet

```text
project
knowledge
graph
targets
solve
inventory
```

L'ensemble de ces sous-commandes est directement déclaré dans le parser CLI du programme.

---

# Commandes principales

| Commande      | Fonction                                    |
| ------------- | ------------------------------------------- |
| `auto`        | Extraction automatique + rapport + solveurs |
| `folder`      | Analyse d'un dossier vers un Excel unique   |
| `extract`     | Extraction des hashes et identifiants       |
| `analyze`     | Analyse et statistiques d'une capture       |
| `stats`       | Exécution de statistiques TShark            |
| `packets`     | Export de paquets et champs                 |
| `follow`      | Suivi de flux                               |
| `objects`     | Export d'objets                             |
| `filter`      | Filtrage et réécriture de capture           |
| `report`      | Génération du rapport                       |
| `creds`       | Extraction des identifiants                 |
| `convert`     | Conversion, découpage et fusion             |
| `capture`     | Capture live                                |
| `decode`      | Decode-as                                   |
| `fields`      | Extraction de champs TShark                 |
| `info`        | Informations capinfos                       |
| `ifaces`      | Interfaces TShark                           |
| `protocols`   | Protocoles et champs                        |
| `expert`      | Informations Expert                         |
| `hosts`       | Informations hosts                          |
| `voip`        | Statistiques SIP/RTP                        |
| `hashcat`     | Commandes Hashcat                           |
| `modes`       | Catalogue des modes Hashcat                 |
| `filters`     | Catalogue de filtres                        |
| `tshark-help` | Catalogue options/statistiques TShark       |
| `doctor`      | Diagnostic                                  |
| `examples`    | Exemples                                    |
| `init-config` | Génération de configuration                 |
| `wizard`      | Menu interactif                             |
| `project`     | Projet d'analyse complet                    |
| `knowledge`   | Base de connaissances                       |
| `graph`       | Graphe de connaissances                     |
| `targets`     | Gestion des cibles Hashcat                  |
| `solve`       | Poursuite d'un projet                       |
| `inventory`   | Inventaire réseau exhaustif                 |

---

# Exports

Les formats déclarés par le programme comprennent :

```text
TXT
CSV
JSON
XLSX
HTML
Markdown
PCAP
PCAPNG
```

Pour `extract`, les formats `txt`, `csv`, `json`, `xlsx`, `html` et `md` sont directement proposés par la CLI.

---

# Excel

L'export Excel utilise `openpyxl`.

L'export générique de paquets crée notamment :

* feuille `Paquets` ;
* en-têtes ;
* filtres automatiques ;
* volets figés ;
* largeur automatique des colonnes.

Le rapport complet possède également plusieurs feuilles spécialisées correspondant aux différentes catégories d'analyse du moteur.

---

# Traitement des gros fichiers

Le mode dossier compte rapidement les paquets avec `capinfos`.

Lorsque la capture dépasse le seuil interne de **1500 paquets**, elle peut être découpée avec `editcap`, puis les morceaux sont traités en parallèle et fusionnés dans le résultat final.

---

# TShark

Le moteur principal charge les captures avec TShark et peut utiliser :

```text
-Y
-d
--limit
-x
```

L'extraction peut désactiver individuellement certains traitements :

```text
--no-ntlm
--no-kerberos
--no-wpa
--no-apop
--no-creds
--no-raw
```

---

# Interface

L'interface utilise `Rich` lorsqu'il est disponible.

Le programme possède notamment :

* logo ;
* tableaux ;
* panneaux ;
* couleurs ;
* progression ;
* messages d'état ;
* mode verbeux ;
* mode silencieux ;
* mode sans couleurs.

Sans `Rich`, le programme utilise une sortie texte simplifiée.

Les options globales comprennent :

```text
--lang fr|en
--no-banner
--no-color
--quiet
--verbose
--no-progress
--config
--tshark
```

---

# Internationalisation

Deux langues sont intégrées :

```text
fr
en
```

La langue peut être sélectionnée avec :

```bash
--lang fr
```

ou :

```bash
--lang en
```

Le programme peut également utiliser `T2H_LANG`.

---

# Configuration

Le programme permet de générer un fichier de configuration :

```bash
python tshark2hashcat.py init-config
```

Un fichier personnalisé peut ensuite être utilisé avec :

```text
--config
```

Le chemin de TShark peut être spécifié directement :

```text
--tshark
```

---

# Formats de captures

Le code reconnaît notamment :

```text
.pcap
.pcapng
.cap
.dmp
```

ainsi que les exports JSON TShark pour les fonctions qui les acceptent.

---

# Compatibilité avec l'utilisation directe

Le programme conserve une compatibilité avec l'utilisation historique :

```bash
python tshark2hashcat.py capture.pcap
```

est automatiquement transformé en :

```bash
python tshark2hashcat.py auto capture.pcap
```

Un dossier est automatiquement transformé en :

```bash
python tshark2hashcat.py folder dossier/
```

---

# Sécurité et données analysées

L'outil peut extraire des informations sensibles présentes dans une capture :

```text
identifiants
mots de passe
hashes
tokens
cookies
adresses e-mail
PII
informations réseau
informations Kerberos
```

Dans la version actuelle de l'inventaire réseau, ces valeurs sont conservées en clair dans les sorties TXT, JSON et CSV.

**Ne publiez donc pas de captures réelles contenant des données sensibles dans le dépôt GitHub.**

---

# Licence

Le code fourni déclare actuellement :

```text
Apache-2.0
```

avec la version :

```text
1.2.0
```

et le projet :

```text
tshark2hashcat
```

---

<p align="center">
  <b>tshark2hashcat v1.2.0</b><br>
  <i>PCAP · TShark · Hashcat · Network Analysis</i>
</p>
