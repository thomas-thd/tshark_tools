<div align="center">

# 🦈 tshark2hashcat

### De la capture réseau à l'analyse d'authentification

<p>
  <strong>Transformez vos captures PCAP/PCAPNG en fichiers Hashcat propres, validés et directement exploitables.</strong><br>
  <sub>Un seul appel à Tshark · aucune dépendance Python · sorties normalisées · diagnostics détaillés</sub>
</p>

<br>

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tshark](https://img.shields.io/badge/Tshark-required-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/)
[![Windows Linux macOS](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-555555?style=for-the-badge)](#compatibilité)
[![Dépendances](https://img.shields.io/badge/dépendances%20Python-aucune-2ea44f?style=for-the-badge)](#prérequis)
[![Licence Apache 2.0](https://img.shields.io/badge/licence-Apache--2.0-0d6efd?style=for-the-badge)](LICENSE)

</div>

---

## ✨ En bref

`tshark2hashcat` est un extracteur d'authentifications réseau conçu pour les audits autorisés, l'analyse forensic, les laboratoires et les CTF.

Il analyse les champs disséqués **et les octets bruts** fournis par Tshark afin de générer des lignes compatibles avec les modules officiels de Hashcat :

- **NetNTLMv1, NetNTLMv1 ESS et NetNTLMv2** ;
- **Kerberos AS-REQ, AS-REP et TGS-REP** ;
- **APOP** ;
- **SNMPv3 USM** ;
- **WPA/WPA2 PMKID et EAPOL** ;
- **identifiants transmis en clair**.

Chaque candidat est validé avant d'être écrit. Si une donnée indispensable manque, le programme refuse de fabriquer une ligne incertaine et explique précisément pourquoi.

> [!WARNING]
> **Usage autorisé uniquement.** Une capture peut contenir des mots de passe, des tokens, des données personnelles et des informations d'infrastructure. Utilisez cet outil uniquement sur des données dont l'analyse vous est légalement autorisée. Protégez les fichiers générés comme des secrets.

---

## 🎯 Pourquoi cet outil ?

La conversion manuelle d'une capture en hash exploitable est source d'erreurs :

- mauvais mode Hashcat ;
- checksum placé au mauvais endroit ;
- séparateurs incorrects ;
- challenge absent ou mal appairé ;
- distinction confuse entre ticket Kerberos et EncPart ;
- réponse NTLM découpée entre plusieurs paquets ;
- message encapsulé en Base64 ou non reconnu par le dissecteur.

`tshark2hashcat` automatise cette chaîne tout en conservant une logique prudente et vérifiable :

```text
Capture réseau
      │
      ▼
Tshark : champs disséqués + octets bruts
      │
      ▼
Réassemblage, appairage et analyse des signatures
      │
      ▼
Validation stricte par mode Hashcat
      │
      ▼
Fichiers prêts à l'emploi + diagnostics
```

---

## 📚 Sommaire

- [Fonctionnalités](#-fonctionnalités)
- [Formats pris en charge](#-formats-pris-en-charge)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Démarrage rapide](#-démarrage-rapide)
- [Référence de la ligne de commande](#-référence-de-la-ligne-de-commande)
- [Fichiers générés](#-fichiers-générés)
- [Utilisation avec Hashcat](#-utilisation-avec-hashcat)
- [Identifiants en clair](#-identifiants-transmis-en-clair)
- [Fonctionnement interne](#-fonctionnement-interne)
- [Kerberos et compatibilité Wireshark](#-kerberos-et-compatibilité-wireshark)
- [Performances et grosses captures](#-performances-et-grosses-captures)
- [Limites connues](#-limites-connues)
- [Dépannage](#-dépannage)
- [Contribution](#-contribution)
- [Licence](#-licence)

---

## 🚀 Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| **Décodage délégué à Tshark** | Le script ne lit jamais directement un PCAP avec une bibliothèque Python. |
| **Un seul appel Tshark** | Les champs JSON et les octets bruts sont récupérés avec `-T json -x`. |
| **NetNTLM complet** | NetNTLMv1/ESS et NetNTLMv2, y compris dans des flux Base64. |
| **Kerberos étendu** | AS-REQ avec PA-ENC-TIMESTAMP, AS-REP et TGS-REP en RC4/AES. |
| **WPA/WPA2** | PMKID et handshake EAPOL au format unifié Hashcat `22000`. |
| **SNMPv3** | Extraction de l'USM authentifié au format `25000`. |
| **Analyse APOP** | Appairage de la bannière POP3 et de la commande `APOP`. |
| **Détection en clair** | FTP, Telnet, HTTP Basic, formulaires HTTP, SMTP/IMAP/POP `AUTH`. |
| **Analyse des octets bruts** | Repli sur les signatures binaires, les charges utiles et le Base64. |
| **Réassemblage des flux** | Reconstruction des messages répartis sur plusieurs segments. |
| **Validation stricte** | Contrôle des longueurs, séparateurs, bornes et formats Hashcat. |
| **Déduplication** | Aucun doublon dans les fichiers de sortie. |
| **Diagnostics forensic** | Chaque élément rejeté peut être expliqué dans le rapport final. |
| **Traitement progressif** | Les exports JSON sont lus paquet par paquet pour limiter la mémoire Python. |
| **Multiplateforme** | Windows, Linux et macOS. |
| **Zéro dépendance tierce** | Bibliothèque standard Python uniquement. |

---

## 🔐 Formats pris en charge

| Protocole / authentification | Condition | Mode | Sortie |
|---|---|:---:|---|
| NetNTLMv1 / ESS | Réponse NT de 24 octets avec réponse LM | `5500` | `user::domain:LM:NT:challenge` |
| NetNTLMv2 | Réponse NT supérieure à 24 octets | `5600` | `user::domain:challenge:NTProofStr:blob` |
| Kerberos AS-REQ RC4 | PA-ENC-TIMESTAMP, etype `23` | `7500` | `$krb5pa$23$...` |
| Kerberos AS-REQ AES128 | PA-ENC-TIMESTAMP, etype `17` | `19800` | `$krb5pa$17$...` |
| Kerberos AS-REQ AES256 | PA-ENC-TIMESTAMP, etype `18` | `19900` | `$krb5pa$18$...` |
| Kerberos AS-REP RC4 | Etype `23` | `18200` | `$krb5asrep$23$...` |
| Kerberos AS-REP AES128 | Etype `17` | `32100` | `$krb5asrep$17$...` |
| Kerberos AS-REP AES256 | Etype `18` | `32200` | `$krb5asrep$18$...` |
| Kerberos TGS-REP RC4 | Etype `23` | `13100` | `$krb5tgs$23$...` |
| Kerberos TGS-REP AES128 | Etype `17` | `19600` | `$krb5tgs$17$...` |
| Kerberos TGS-REP AES256 | Etype `18` | `19700` | `$krb5tgs$18$...` |
| APOP | Challenge POP3 + commande `APOP` | `20` | `digest:challenge` |
| SNMPv3 USM | Authentification USM | `25000` | `$SNMPv3$0$...` |
| WPA/WPA2 PMKID | PMKID RSN disponible | `22000` | `WPA*01*...` |
| WPA/WPA2 EAPOL | Handshake M1 + M2 disponible | `22000` | `WPA*02*...` |

### Détails importants

- En **NetNTLMv2**, les 16 premiers octets de la réponse NT deviennent le `NTProofStr`, le reste devient le blob.
- En **Kerberos RC4**, le checksum est extrait du début du cipher selon le format du module.
- En **Kerberos AES**, les 12 derniers octets sont utilisés comme checksum.
- Les tickets `krbtgt` sont ignorés dans les TGS-REP : ils ne correspondent pas à un hash de service utile au Kerberoasting.
- Pour **APOP**, aucun résultat n'est généré si la bannière contenant le challenge `<...>` n'a pas été capturée.
- Pour **WPA EAPOL**, la zone MIC de la trame est remise à zéro avant de construire la ligne Hashcat.

---

## 🧰 Prérequis

| Composant | Version / rôle |
|---|---|
| **Python** | 3.10 ou supérieur |
| **Tshark** | Obligatoire ; fourni avec Wireshark |
| **Hashcat** | Optionnel ; nécessaire uniquement pour le cassage |
| **Wireshark** | Optionnel ; utile pour inspecter les captures |

Aucune dépendance Python supplémentaire n'est nécessaire.

Vérification :

```bash
python3 --version
tshark --version
```

Sous Windows :

```powershell
python --version
tshark.exe --version
```

### Emplacements Tshark détectés automatiquement

```text
C:\Program Files\Wireshark\tshark.exe
C:\Program Files (x86)\Wireshark\tshark.exe
tshark        # recherche dans le PATH
```

---

## 📦 Installation

### Cloner le dépôt

```bash
git clone https://github.com/<organisation>/tshark2hashcat.git
cd tshark2hashcat
```

### Vérifier le script

```bash
python3 tshark2hashcat.py --help
```

Aucune commande `pip install` n'est requise.

### Windows : raccourci glisser-déposer

Créez un fichier `run.bat` à côté de `tshark2hashcat.py` :

```bat
@echo off
python "%~dp0tshark2hashcat.py" %*
pause
```

Vous pouvez ensuite déposer un fichier `.pcap` ou `.pcapng` sur ce fichier batch.

---

## ⚡ Démarrage rapide

### Analyse d'une capture

```bash
python3 tshark2hashcat.py capture.pcapng
```

### Sortie personnalisée

```bash
python3 tshark2hashcat.py capture.pcap \
  --output resultats/audit-01.txt
```

### Analyse verbeuse

```bash
python3 tshark2hashcat.py capture.pcapng --verbose
```

### Utiliser un Tshark spécifique

```bash
python3 tshark2hashcat.py capture.pcap \
  --tshark /usr/bin/tshark
```

### Analyser tous les paquets

```bash
python3 tshark2hashcat.py capture.pcapng --full-packets
```

Cette option désactive le filtre de sélection par défaut. Elle est utile pour le dépannage ou lorsque la capture contient un protocole encapsulé de façon inhabituelle, mais elle peut multiplier le volume JSON produit par Tshark.

### Lire un export JSON existant

```bash
tshark -r capture.pcapng -T json -x > capture.json
python3 tshark2hashcat.py capture.json
```

Lorsqu'un JSON est fourni en entrée, le script le lit directement et ne relance pas Tshark.

### Captures `.bz2` et `.xz`

Les captures compressées avec `.bz2` ou `.xz` sont décompressées temporairement, transmises à Tshark, puis supprimées automatiquement.

---

## 🖥️ Référence de la ligne de commande

```text
usage: tshark2hashcat.py [-h] [-o OUTPUT] [--tshark TSHARK]
                         [--full-packets] [-v] pcap
```

| Argument | Description | Valeur par défaut |
|---|---|---|
| `pcap` | Capture `.pcap`, `.pcapng`, `.bz2`, `.xz` ou export JSON Tshark | Obligatoire |
| `-o`, `--output` | Fichier global de sortie | `hashes.txt` |
| `--tshark` | Chemin complet vers Tshark | Détection automatique |
| `--full-packets` | Désactive le filtre Tshark optimisé | Désactivé |
| `-v`, `--verbose` | Affiche les candidats acceptés en temps réel | Désactivé |
| `-h`, `--help` | Affiche l'aide | — |

---

## 📁 Fichiers générés

Avec la commande :

```bash
python3 tshark2hashcat.py capture.pcapng -o hashes.txt
```

le programme produit :

| Fichier | Contenu |
|---|---|
| `hashes.txt` | Tous les hashes acceptés, tous modes confondus |
| `hashes_m5500.txt` | Hashes NetNTLMv1/ESS |
| `hashes_m5600.txt` | Hashes NetNTLMv2 |
| `hashes_m7500.txt` | Kerberos AS-REQ RC4 |
| `hashes_m18200.txt` | Kerberos AS-REP RC4 |
| `hashes_m22000.txt` | WPA/WPA2 PMKID et EAPOL |
| `hashes_m25000.txt` | SNMPv3 USM |
| `hashes_credentials.txt` | Identifiants transmis en clair, si détectés |

Les fichiers par mode sont les fichiers à privilégier avec Hashcat : ils évitent de mélanger des formats incompatibles.

### Convention de nommage

Si la sortie est `resultats/audit.txt`, les fichiers associés sont créés ainsi :

```text
resultats/audit.txt
resultats/audit_m5500.txt
resultats/audit_m5600.txt
resultats/audit_m22000.txt
resultats/audit_credentials.txt
```

---

## 🔥 Utilisation avec Hashcat

### NetNTLMv2

```bash
hashcat -m 5600 hashes_m5600.txt wordlist.txt
```

### NetNTLMv1 / ESS

```bash
hashcat -m 5500 hashes_m5500.txt wordlist.txt
```

### AS-REP roasting

```bash
hashcat -m 18200 hashes_m18200.txt wordlist.txt
hashcat -m 32100 hashes_m32100.txt wordlist.txt
hashcat -m 32200 hashes_m32200.txt wordlist.txt
```

### Kerberoasting

```bash
hashcat -m 13100 hashes_m13100.txt wordlist.txt
hashcat -m 19600 hashes_m19600.txt wordlist.txt
hashcat -m 19700 hashes_m19700.txt wordlist.txt
```

### WPA/WPA2

```bash
hashcat -m 22000 hashes_m22000.txt wordlist.txt
```

### SNMPv3

```bash
hashcat -m 25000 hashes_m25000.txt wordlist.txt
```

### Attaque avec règles

```bash
hashcat -m 5600 hashes_m5600.txt wordlist.txt \
  -r rules/best64.rule
```

### Attaque par masque

```bash
hashcat -m 19700 hashes_m19700.txt \
  -a 3 '?u?l?l?l?l?l?l?d'
```

### Afficher les mots de passe retrouvés

```bash
hashcat -m 5600 hashes_m5600.txt --show
```

> Vérifiez toujours le format attendu par la version de Hashcat installée. Les modules peuvent évoluer entre versions.

---

## 🔓 Identifiants transmis en clair

Le programme recherche également des identifiants qui ne nécessitent aucun cassage : ils circulent directement dans la capture.

| Source | Détection |
|---|---|
| **FTP / Telnet** | Commandes `USER` puis `PASS` |
| **Telnet interactif** | Prompts `login:`, `username:` et `Password:` |
| **HTTP Basic** | En-tête `Authorization: Basic ...` décodé en Base64 |
| **SMTP / IMAP / POP** | `AUTH PLAIN` |
| **SMTP / IMAP / POP** | `AUTH LOGIN` avec réponses Base64 |
| **Formulaires HTTP** | `user=`, `username=`, `login=`, `pass=`, `password=` et `pwd=` |
| **SNMPv1/v2c** | Community string rapportée séparément |

Les résultats sont dédupliqués et écrits dans :

```text
hashes_credentials.txt
```

Format :

```text
HTTP Basic	user=alice	pass=MotDePasseDeTest
FTP/Telnet USER/PASS	user=bob	pass=AutreMotDePasse
```

> Ce fichier doit être protégé avec le même niveau de confidentialité qu'un fichier de mots de passe.

---

## 📊 Exemple de session

```console
$ python3 tshark2hashcat.py capture.pcapng --verbose
[i] tshark : /usr/bin/tshark
[i] /usr/bin/tshark -n -2 -r capture.pcapng ... -T json -x
    [m5600] frame #18 NTLM brut (alice)
    [m32200] frame #61 Kerberos

=== RÉSULTATS ===
[i] protocoles détectés : kerberos, ntlmssp
[i] comptes AVEC pré-auth Kerberos vus : alice

=== IDENTITÉS KERBEROS VUES (diagnostic) ===
    frame #61    AS-REQ   user=alice realm=EXAMPLE.LOCAL spn=- etypes=18
    frame #62    AS-REP   user=alice realm=EXAMPLE.LOCAL spn=- etypes=18

[+]   1 hash (5600) -> hashes_m5600.txt
    hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
    hashcat -m 32200 hashes_m32200.txt wordlist.txt

[i] 2 hash(s) écrit(s) aussi dans ./hashes.txt
```

Les valeurs de cet exemple sont fictives.

---

## 🧩 Fonctionnement interne

### 1. Décodage par Tshark

Pour une capture, le programme lance Tshark une seule fois avec notamment :

```text
-n
-2
-r <capture>
-T json
-x
-o tcp.desegment_tcp_streams:true
```

Le filtre d'affichage intégré est utilisé par défaut pour éviter un export JSON inutilement volumineux. `--full-packets` le désactive.

### 2. Champs structurés et octets bruts

Les champs disséqués sont privilégiés :

```text
ntlmssp.*
kerberos.*
wlan.*
snmp.*
eapol.*
```

Les champs bruts permettent de traiter les cas où :

- l'encapsulation applicative n'est pas reconnue ;
- un message Base64 contient NTLMSSP ;
- plusieurs champs ASN.1 répétés sont perdus dans le JSON ;
- un message est réparti sur plusieurs segments ;
- la structure attendue n'est pas entièrement exposée par le dissecteur.

### 3. Réassemblage et appairage

Les charges utiles TCP/UDP sont collectées par flux et réassemblées à partir des numéros de séquence lorsque ceux-ci sont disponibles. Les retransmissions exactes sont supprimées.

Pour NTLM, le challenge est associé à la réponse en privilégiant le flux inverse, puis en utilisant un repli basé sur l'ordre des trames lorsque les adresses ne sont pas disponibles.

### 4. Validation

Chaque candidat est contrôlé avant écriture :

- nombre de champs ;
- séparateurs attendus ;
- longueurs exactes des challenges et checksums ;
- bornes de taille des blobs ;
- format hexadécimal ;
- syntaxe propre au mode Hashcat.

### 5. Sortie

Les lignes validées sont dédupliquées, classées par mode et écrites dans les fichiers correspondants.

---

## 🏛️ Kerberos et compatibilité Wireshark

Les noms de champs Kerberos ont changé entre les versions de Wireshark. Le programme accepte notamment :

- les champs spécialisés historiques tels que `encryptedKDCREPData_cipher` ;
- `encryptedTicketData_cipher` ;
- `PA_ENC_TIMESTAMP_cipher` ;
- le champ générique moderne `kerberos.cipher`.

Le contexte ASN.1 est utilisé pour distinguer :

- le ticket chiffré ;
- l'EncPart d'un AS-REP ;
- l'EncPart d'un TGS-REP ;
- la valeur chiffrée d'un PA-ENC-TIMESTAMP.

Types de chiffrement pris en charge :

```text
23  RC4-HMAC
17  AES128-CTS-HMAC-SHA1-96
18  AES256-CTS-HMAC-SHA1-96
```

Le diagnostic Kerberos affiche les identités observées, les realms, les SPN, les salts disponibles, les etypes et les numéros de trame. Cela permet de comprendre pourquoi un hash est ou n'est pas généré.

---

## ⚙️ Performances et grosses captures

Le JSON Tshark peut devenir très volumineux, notamment avec `-T json -x`. Le programme limite l'impact côté Python en lisant l'export progressivement.

Bonnes pratiques :

1. commencez sans `--full-packets` ;
2. utilisez `--full-packets` uniquement si nécessaire ;
3. utilisez un disque local suffisamment rapide ;
4. activez `--verbose` seulement pour diagnostiquer ;
5. travaillez sur une copie de la capture ;
6. si possible, analysez une fenêtre temporelle ou une copie préfiltrée autorisée.

Le traitement JSON est progressif côté Python, mais Tshark peut malgré tout générer un volume important de données pour une capture complexe.

---

## 🧯 Données manquantes et rejets

Le programme ne complète jamais un champ par une supposition. Exemples de messages possibles :

```text
[!] Données manquantes / éléments ignorés :
    - NTLM frame #51: server challenge absent -> hash non généré
    - NTLM frame #52: NT response de longueur invalide -> ignoré
    - Kerberos frame #77: TGS-REP sans cname/realm/spn -> ignoré
    - Kerberos frame #80: AS-REP etype inconnu (1) -> ignoré
    - APOP (alice): challenge introuvable -> ignoré
```

Cela garantit que les fichiers de hash ne sont pas pollués par des lignes incomplètes ou ambiguës.

---

## 🌍 Compatibilité

| Élément | Compatibilité |
|---|---|
| Systèmes | Windows, Linux, macOS |
| Python | 3.10+ |
| Entrées | PCAP, PCAPNG, `.bz2`, `.xz`, export JSON Tshark |
| Décodage réseau | Tshark |
| Dépendances Python | Aucune, bibliothèque standard uniquement |
| Résolution Tshark | Chemins Windows courants ou `PATH` |

La disponibilité exacte de certains champs peut varier selon la version de Wireshark/Tshark utilisée.

---

## 🚧 Limites connues

- Une capture tronquée ou incomplète ne fournit pas toujours assez de données pour générer un hash.
- Une capture ne contenant qu'une seule direction peut empêcher l'appariement d'un challenge et d'une réponse.
- Des flux fortement entrelacés peuvent rendre le dernier recours par ordre de trame ambigu.
- Les etypes Kerberos non listés sont ignorés.
- Les tickets `krbtgt` sont volontairement exclus des TGS-REP.
- PKINIT et FAST ne produisent pas automatiquement un des formats supportés.
- Un handshake WPA incomplet ou sans SSID exploitable ne produit pas de ligne.
- Les identifiants en clair sont rapportés, mais ne sont pas transformés en hash.
- OSPF n'est pas couvert : Hashcat ne propose pas de mode natif correspondant à cette extraction.
- Le script ne remplace pas Tshark et ne décode pas lui-même les protocoles réseau.

---

## 🛠️ Dépannage

### Tshark est introuvable

```bash
tshark --version
```

Si la commande échoue, installez Wireshark/Tshark ou indiquez son chemin :

```bash
python3 tshark2hashcat.py capture.pcap \
  --tshark /chemin/vers/tshark
```

### Aucun protocole détecté

Essayez une analyse complète et verbeuse :

```bash
python3 tshark2hashcat.py capture.pcapng \
  --full-packets --verbose
```

Vous pouvez également vérifier la présence de protocoles dans Tshark :

```bash
tshark -r capture.pcapng -q -z io,phs
```

### Aucun hash produit

Consultez la section `Données manquantes / éléments ignorés`. Les causes fréquentes sont :

- challenge non capturé ;
- réponse d'authentification tronquée ;
- capture filtrée ;
- handshake WPA incomplet ;
- realm, SPN ou utilisateur Kerberos absent ;
- etype non supporté ;
- SSID non disponible.

### Erreur `Separator unmatched` dans Hashcat

Utilisez le fichier correspondant au mode exact :

```bash
hashcat -m 5600 hashes_m5600.txt wordlist.txt
```

Ne mélangez pas manuellement des lignes provenant de plusieurs modes et ne modifiez pas les séparateurs générés.

### JSON Tshark vide ou invalide

Régénérez l'export :

```bash
tshark -r capture.pcapng -T json -x > capture.json
```

Pour une analyse directe, laissez le script lancer Tshark afin de conserver les messages d'erreur associés à la capture.

---

## 🤝 Contribution

Les contributions sont les bienvenues, notamment pour :

- ajouter des alias de champs Tshark ;
- prendre en charge de nouvelles encapsulations ;
- améliorer la compatibilité entre versions de Wireshark ;
- ajouter des fixtures JSON anonymisées ;
- documenter de nouveaux modes Hashcat ;
- améliorer les diagnostics et la portabilité.

### Règles de contribution

1. Conserver la compatibilité Python 3.10+.
2. Préserver l'absence de dépendances tierces, sauf nécessité justifiée.
3. Ne jamais publier de capture réelle ni de secret dans le dépôt.
4. Ajouter un exemple reproductible pour toute modification de parsing.
5. Valider chaque nouveau format avant écriture.
6. Documenter le mode Hashcat et les champs Tshark utilisés.
7. Anonymiser les captures et sorties avant partage.

Un rapport de bug utile contient :

- système d'exploitation ;
- version de Python ;
- version de Tshark ;
- version de Hashcat le cas échéant ;
- commande utilisée ;
- sortie diagnostique nettoyée ;
- fixture JSON minimale et anonymisée si possible.

---

## 🗺️ Évolutions possibles

- fixtures de régression pour chaque mode ;
- tests automatisés des validateurs ;
- rapports optionnels JSON/CSV ;
- filtres Tshark configurables ;
- diagnostic des trous dans les flux TCP ;
- prise en charge de nouveaux champs Wireshark ;
- intégration CI pour la syntaxe et les exemples JSON ;
- documentation dédiée aux formats Hashcat par version.

---

## 📄 Licence

`tshark2hashcat` est distribué sous licence [Apache License 2.0](LICENSE).

Le dépôt doit contenir un fichier `LICENSE` correspondant avant publication. Les mentions de copyright et de licence doivent être conservées dans les copies redistribuées.

---

<div align="center">

### 🦈 Capturer proprement. Valider strictement. Analyser avec méthode.

</div>
