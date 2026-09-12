# tshark2hashcat

**tshark2hashcat** est un outil Python d'analyse de captures réseau basé sur **TShark**, avec extraction d'informations, identification de cibles, génération de formats Hashcat et gestion de projets d'analyse.

> Version **1.2.0** · Licence **Apache-2.0**

---

## Sommaire

* [Fonctionnement](#fonctionnement)
* [Installation](#installation)
* [Utilisation CLI](#utilisation-cli)

  * [1. Nouveau projet](#1--nouveau-projet)
  * [2. Ouvrir un projet](#2--ouvrir-un-projet)
  * [3. Mode classique](#3--mode-classique)
* [Menu projet](#menu-projet)
* [Hashcat](#hashcat)
* [Inventaire réseau](#inventaire-réseau)
* [Protocoles analysés](#protocoles-analysés)
* [Options CLI](#options-cli)
* [Diagnostic](#diagnostic)
* [Formats de sortie](#formats-de-sortie)

---

# Fonctionnement

Le programme propose deux approches principales :

```text
                         tshark2hashcat
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
          Nouveau projet   Projet existant   Classique
                │              │              │
                ▼              ▼              ▼
          Analyse complète   Reprise       Extraction
          + rapports         + rounds      directe
                │              │
                └───────┬──────┘
                        ▼
                 Cibles / Hashcat
                        │
                        ▼
                  Rapports
```

Le mode **projet** permet de conserver les résultats entre plusieurs analyses et de poursuivre le traitement ultérieurement.

---

# Installation

Le programme nécessite notamment :

* Python
* TShark / Wireshark
* les dépendances Python du projet

Le chemin vers TShark peut être fourni directement avec `--tshark`.

Exemple Windows :

```powershell
python tshark2hashcat.py --tshark "C:\Program Files\Wireshark\tshark.exe"
```

---

# Utilisation CLI

Lancement :

```powershell
python tshark2hashcat.py
```

Le menu principal est :

```text
◆ tshark2hashcat  —  menu principal

  1.  MOTEUR ▸ projet complet — dossier de captures :
      analyse, crackage, rapports lisibles

  2.  MOTEUR ▸ ouvrir un projet :
      poursuivre, knowledge base, graphe, cibles, rapport HTML

  3.  classique ▸ fichier OU dossier de captures :
      Excel + txt Hashcat (auto-détecté)

  0.  Quitter

  Votre choix :
```

---

# 1. Nouveau projet

L'option **1** crée un nouveau projet à partir d'un dossier de captures.

Le programme demande :

```text
Dossier de captures (.pcap/.pcapng/.cap/.json) :
Dossier de sortie :
Fichier knowledge optionnel :
Deep mode ? [o/N] :
```

Le programme effectue ensuite l'analyse du projet.

À la fin :

```text
TOUT EST DANS : <dossier de sortie>

ouvrez d'abord GUIDE.txt (le guide), puis
RAPPORT.txt (rapport texte) ou rapport.html
(double-clic → navigateur)
```

### Organisation générale

Le projet conserve ses données afin de pouvoir être rouvert et poursuivi.

Les résultats peuvent notamment contenir :

* informations réseau
* identités
* secrets
* métadonnées
* protocoles détectés
* anomalies
* cibles
* résultats des solveurs
* résultats de cracking
* rapports

---

# 2. Ouvrir un projet

L'option **2** permet de reprendre un projet existant.

Le programme demande un dossier contenant notamment :

```text
data.json
```

Puis affiche :

```text
▸ PROJET — <dossier>

  1.  poursuivre — nouveaux rounds
      (solveurs → post-crack → rapports)

  2.  knowledge base — afficher / filtrer / importer

  3.  graphe de connaissances
      — graphe.dot + fenêtres temporelles

  4.  hashes hashcat
      — un dossier par hash, commandes prêtes

  5.  ouvrir le rapport HTML — navigateur

  6.  inventaire réseau
      — tout extraire d'une capture

  0.  revenir au menu principal

  Votre choix :
```

---

## 2.1 Poursuivre le projet

L'option **1** reprend l'analyse d'un projet.

Le moteur peut enchaîner plusieurs rounds :

```text
analyse
   ↓
identification des cibles
   ↓
solveurs
   ↓
post-crack
   ↓
propagation des informations
   ↓
nouveau round
```

Les informations récupérées peuvent être réinjectées dans le projet afin de servir de nouvelles candidates lors des rounds suivants.

---

## 2.2 Knowledge Base

L'option **2** permet d'utiliser la base de connaissances du projet.

Elle permet notamment :

* d'afficher les informations enregistrées ;
* de filtrer les données ;
* d'importer un fichier de knowledge.

Un fichier de knowledge peut également être fourni lors de la reprise d'un projet.

---

## 2.3 Graphe de connaissances

L'option **3** génère et exploite le graphe de connaissances du projet.

Le programme peut produire :

```text
graphe.dot
```

Le graphe permet notamment de représenter les relations découvertes pendant l'analyse et d'utiliser des fenêtres temporelles.

---

## 2.4 Hashes Hashcat

L'option **4** prépare les cibles destinées à Hashcat.

Le programme organise les cibles dans des dossiers individuels et prépare les commandes nécessaires.

Exemple de structure :

```text
<projet>/
└── ...
    └── hash/
        ├── ...
        ├── ...
        └── ...
```

Une wordlist peut être demandée lors du traitement.

Les modes Hashcat déclarés par le projet sont :

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

Le moteur sait également générer des commandes utilisant notamment :

```text
hashcat
--show
--wordlist
```

ainsi que différents types d'attaques selon la cible.

---

## 2.5 Rapport HTML

L'option **5** ouvre directement le rapport HTML du projet dans le navigateur.

Le programme tente d'ouvrir automatiquement le fichier.

Si l'ouverture automatique échoue, le chemin du rapport est indiqué afin de pouvoir l'ouvrir manuellement.

---

## 2.6 Inventaire réseau

L'option **6** lance l'inventaire réseau sur une capture.

L'inventaire extrait notamment :

```text
IPs
protocoles
identités
secrets
métadonnées
anomalies
découvertes
```

Les résultats sont exportés dans plusieurs formats :

```text
TXT
JSON
CSV
```

Les informations de trames et les relations source/destination sont également conservées dans les résultats.

---

# 3. Mode classique

L'option **3** permet de travailler directement sur un fichier ou un dossier de captures.

```text
Fichier OU dossier de captures
(.pcap / .pcapng / .cap / .json) :
```

Le programme détecte automatiquement s'il s'agit :

* d'un fichier ;
* d'un dossier.

### Fichier

Exemple :

```powershell
python tshark2hashcat.py capture.pcap
```

Le fichier est traité en mode `auto`.

### Dossier

Exemple :

```powershell
python tshark2hashcat.py .\captures
```

Le dossier est traité en mode `folder`.

Le traitement des dossiers prend en charge la recherche récursive des captures et le traitement parallèle.

---

# Hashcat

Le projet intègre plusieurs étapes autour de Hashcat :

```text
Capture
   │
   ▼
Analyse TShark
   │
   ▼
Détection / extraction
   │
   ▼
Identification du format
   │
   ▼
Cible Hashcat
   │
   ▼
Commande Hashcat
   │
   ▼
Résultat
```

Les commandes générées peuvent utiliser une wordlist et différentes stratégies d'attaque.

Le projet dispose également de mécanismes permettant de réutiliser les informations récupérées pendant un cracking dans les analyses suivantes du projet.

---

# Solveurs intégrés

Le moteur contient quatre solveurs principaux :

```text
auth
wpa2e
wep
sae
```

### `auth`

Prise en charge de plusieurs mécanismes d'authentification, notamment :

* XMPP / SASL
* SCRAM-SHA-1
* SCRAM-SHA-256
* SCRAM-SHA-512
* DIGEST-MD5
* CRAM-MD5
* PLAIN
* LOGIN
* HTTP Basic
* HTTP Digest
* POP3
* IMAP
* SMTP
* FTP
* Telnet

### `wpa2e`

Analyse des échanges WPA2-Enterprise avec notamment :

* RADIUS
* Message-Authenticator
* PMK
* MS-MPPE
* EAPOL 4-way
* PTK
* MIC
* AES-CCMP

### `wep`

Analyse WEP avec notamment :

* WEP-40
* IV
* known plaintext
* ICV
* CRC32

### `sae`

Analyse WPA3-SAE avec notamment :

* PWE
* masks
* confirmation
* KCK
* PMK
* PTK
* KEK
* TK
* GTK
* CCMP

---

# Inventaire réseau

L'inventaire prend en charge l'extraction de nombreuses informations présentes dans une capture.

Les résultats peuvent inclure :

```text
┌──────────────────────────────────┐
│ Frame                            │
│ Source / Destination             │
│ Protocoles                       │
│ Identités                        │
│ Secrets                          │
│ Métadonnées                      │
│ Anomalies                        │
│ Découvertes                      │
│ Notes                            │
└──────────────────────────────────┘
```

Les valeurs extraites sont actuellement conservées telles quelles dans les sorties générées.

---

# Protocoles analysés

Le moteur contient des parseurs et traitements pour notamment :

### Réseau

```text
ARP
IPv4
IPv6
TCP
UDP
ICMP
```

### Infrastructure

```text
DNS
DHCP
NTP
RADIUS
SNMP
```

### Web / chiffrement

```text
HTTP
TLS
```

Pour TLS, l'inventaire peut notamment relever :

```text
ClientHello
ServerHello
version TLS
SNI
ALPN
PSK
certificat
subject
issuer
serial
validité
SAN
```

### Authentification / accès

```text
SSH
FTP
Telnet
LDAP
Kerberos
RDP
```

### Messagerie

```text
POP3
IMAP
SMTP
```

### Applications / autres protocoles

```text
MySQL
PostgreSQL
XMPP
SIP
Redis
IRC
Modbus
S7
BACnet
```

---

# Extraction

Le mode d'extraction accepte notamment :

```text
-Y
-d
--limit
-x
```

Des extractions spécifiques peuvent être désactivées avec :

```text
--no-ntlm
--no-kerberos
--no-wpa
--no-apop
--no-creds
--no-raw
```

Le mode `-x` permet notamment de conserver les données hexadécimales brutes lorsque le traitement spécifique ne permet pas d'extraire directement l'information recherchée.

---

# Formats de sortie

Le projet utilise plusieurs formats selon le mode utilisé :

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

Le mode `extract` permet notamment de sélectionner :

```text
txt
csv
json
xlsx
html
md
```

---

# Gros fichiers et dossiers

Lorsqu'une capture dépasse un certain volume de paquets, le programme peut utiliser `editcap` afin de découper la capture, traiter les morceaux en parallèle puis fusionner les résultats.

Pour les dossiers, la recherche des captures est récursive et le traitement peut être effectué en parallèle.

Extensions reconnues :

```text
.pcap
.pcapng
.cap
.dmp
```

Les JSON produits par TShark peuvent également être utilisés lorsque le traitement correspondant est disponible.

---

# Options CLI

Les options globales comprennent notamment :

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

### Langue

```powershell
python tshark2hashcat.py --lang fr
```

ou :

```powershell
python tshark2hashcat.py --lang en
```

La variable d'environnement `T2H_LANG` peut également être utilisée.

---

# Diagnostic

Le programme fournit une commande `doctor` permettant de vérifier l'environnement.

Elle contrôle notamment :

```text
TShark / Wireshark
dépendances Python
solveurs
self-tests
```

Exemple :

```powershell
python tshark2hashcat.py doctor
```

---

# Exemples d'utilisation

### Lancer l'interface interactive

```powershell
python tshark2hashcat.py
```

Puis :

```text
1
```

pour créer un projet.

---

### Reprendre un projet

```powershell
python tshark2hashcat.py
```

Puis :

```text
2
```

et sélectionner ensuite l'action voulue.

---

### Analyser une capture directement

```powershell
python tshark2hashcat.py capture.pcap
```

---

### Analyser un dossier de captures

```powershell
python tshark2hashcat.py .\captures
```

---

### Vérifier l'environnement

```powershell
python tshark2hashcat.py doctor
```

---

# Résumé du CLI

```text
MENU PRINCIPAL
│
├── 1  Nouveau projet
│      ├── Analyse
│      ├── Solveurs
│      ├── Cracking
│      └── Rapports
│
├── 2  Ouvrir un projet
│      ├── 1  Poursuivre
│      ├── 2  Knowledge Base
│      ├── 3  Graphe
│      ├── 4  Hashcat
│      ├── 5  Rapport HTML
│      └── 6  Inventaire réseau
│
├── 3  Mode classique
│      ├── Fichier
│      └── Dossier
│
└── 0  Quitter
```

---

## Licence

Ce projet est distribué sous licence **Apache-2.0**.
