<div align="center">

# 🦈 tshark2hashcat

**Extraction de hashes prêts pour Hashcat depuis des captures réseau, via Tshark.**

[![Python](https://img.shields.io/badge/python-%E2%89%A5%203.10-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#)
[![Dependencies](https://img.shields.io/badge/python%20dependencies-none-success)](#prérequis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

English version: [README_EN.md](README_EN.md)

</div>

---

## Présentation

`tshark2hashcat` analyse des fichiers `.pcap` et `.pcapng` avec **Tshark comme unique source de données**, détecte différentes authentifications réseau, puis reconstruit les lignes dans les formats exacts attendus par [Hashcat](https://hashcat.net/hashcat/).

Le programme :

- utilise un seul appel à Tshark avec `-T json -x` ;
- exploite les champs disséqués et les octets bruts fournis par Tshark ;
- valide chaque ligne avant son écriture ;
- déduplique les résultats ;
- produit un fichier global et un fichier par mode Hashcat ;
- signale les données manquantes au lieu de générer des lignes invalides ;
- détecte également certains identifiants transmis en clair.

L'outil est destiné aux pentesters, analystes forensic, administrateurs et participants à des CTF dans un cadre autorisé.

> **Avertissement légal** — Utilisez cet outil uniquement sur des captures que vous êtes autorisé à analyser : laboratoire, CTF, audit contractuel ou environnement de test. Les identifiants en clair peuvent contenir des données personnelles et des secrets sensibles.

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Formats supportés](#formats-supportés)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Fichiers produits](#fichiers-produits)
- [Cassage avec Hashcat](#cassage-avec-hashcat)
- [Identifiants transmis en clair](#identifiants-transmis-en-clair)
- [Architecture](#architecture)
- [Limites connues](#limites-connues)
- [Dépannage](#dépannage)
- [Contribution](#contribution)
- [Licence](#licence)

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| NetNTLM | Extraction de NetNTLMv1/ESS et NetNTLMv2, y compris depuis des flux Base64 |
| Kerberos | AS-REQ avec PA-ENC-TIMESTAMP, AS-REP et TGS-REP en RC4, AES128 et AES256 |
| WPA/WPA2 | Extraction des PMKID et des handshakes EAPOL au format unifié 22000 |
| SNMPv3 | Extraction des authentifications USM au format Hashcat 25000 |
| APOP | Appairage de la bannière POP3 et de la commande `APOP` |
| Identifiants en clair | FTP, Telnet, HTTP Basic, formulaires HTTP et `AUTH PLAIN/LOGIN` SMTP/IMAP/POP |
| Validation stricte | Vérification des séparateurs, longueurs et bornes avant écriture |
| Repli sur octets bruts | Analyse de `frame_raw` et des charges utiles lorsque le dissecteur ne suffit pas |
| Réassemblage | Reconstruction des charges utiles TCP/UDP à partir des paquets fournis par Tshark |
| Sortie normalisée | Déduplication, fichier global, fichiers par mode et commandes Hashcat |
| Portabilité | Windows, Linux et macOS ; bibliothèque standard Python uniquement |

## Formats supportés

| Protocole / authentification | Condition | Mode Hashcat | Format produit |
|---|---|:---:|---|
| NetNTLMv2 | Réponse NT supérieure à 24 octets | `5600` | `user::domain:challenge:NTProofStr:blob` |
| NetNTLMv1 / ESS | Réponses LM et NT de 24 octets | `5500` | `user::domain:LM:NT:challenge` |
| Kerberos AS-REP, RC4 | Etype `23` | `18200` | `$krb5asrep$23$...` |
| Kerberos AS-REP, AES128 | Etype `17` | `32100` | `$krb5asrep$17$...` |
| Kerberos AS-REP, AES256 | Etype `18` | `32200` | `$krb5asrep$18$...` |
| Kerberos AS-REQ, RC4 | PA-ENC-TIMESTAMP, etype `23` | `7500` | `$krb5pa$23$...` |
| Kerberos AS-REQ, AES128 | PA-ENC-TIMESTAMP, etype `17` | `19800` | `$krb5pa$17$...` |
| Kerberos AS-REQ, AES256 | PA-ENC-TIMESTAMP, etype `18` | `19900` | `$krb5pa$18$...` |
| Kerberos TGS-REP, RC4 | Etype `23` | `13100` | `$krb5tgs$23$...` |
| Kerberos TGS-REP, AES128 | Etype `17` | `19600` | `$krb5tgs$17$...` |
| Kerberos TGS-REP, AES256 | Etype `18` | `19700` | `$krb5tgs$18$...` |
| APOP | Bannière `<challenge>` et commande `APOP` | `20` | `digest:challenge` |
| SNMPv3 USM | Authentification USM | `25000` | `$SNMPv3$0$...` |
| WPA/WPA2 PMKID | PMKID RSN disponible | `22000` | `WPA*01*...` |
| WPA/WPA2 EAPOL | Handshake 4-way M1 + M2 disponible | `22000` | `WPA*02*...` |

### Particularités prises en charge

- **NetNTLMv2** : séparation automatique du `NTProofStr` et du blob.
- **Kerberos RC4** : checksum placé au début du cipher selon le format du module.
- **Kerberos AES** : checksum extrait des 12 derniers octets.
- **Kerberos moderne** : prise en charge du champ générique `kerberos.cipher` avec analyse du contexte ASN.1.
- **PA-ENC-TIMESTAMP** : repli sur les octets DER bruts quand les champs répétés ne sont pas conservés dans le JSON.
- **TGS `krbtgt`** : tickets ignorés, car ils ne correspondent pas à un hash de service utile au Kerberoasting.
- **APOP** : le digest n'est produit que si le challenge de la bannière a été capturé.
- **WPA** : le MIC est remis à zéro dans la trame EAPOL avant génération de la ligne `WPA*02*`.

## Prérequis

| Composant | Version / remarque |
|---|---|
| Python | **3.10 ou supérieur** ; aucun paquet tiers requis |
| Tshark | Fourni avec [Wireshark](https://www.wireshark.org/download.html) |
| Hashcat | Optionnel, uniquement pour le cassage des hashes |

Le script recherche automatiquement Tshark dans cet ordre :

```text
C:\Program Files\Wireshark\tshark.exe
C:\Program Files (x86)\Wireshark\tshark.exe
tshark  # PATH
```

## Installation

```bash
git clone https://github.com/<organisation>/tshark2hashcat.git
cd tshark2hashcat
```

Aucune installation Python supplémentaire n'est nécessaire :

```bash
python3 tshark2hashcat.py --help
```

Sous Windows, utilisez `python` au lieu de `python3` si nécessaire.

## Utilisation

### Analyse standard

```bash
python3 tshark2hashcat.py capture.pcapng
```

### Choisir le fichier de sortie

```bash
python3 tshark2hashcat.py capture.pcap \
  --output resultats/hashes.txt
```

### Indiquer le chemin de Tshark

```bash
python3 tshark2hashcat.py capture.pcap \
  --tshark /usr/bin/tshark
```

Sous Windows PowerShell :

```powershell
python tshark2hashcat.py capture.pcap `
  --tshark "C:\Program Files\Wireshark\tshark.exe"
```

### Analyser un export JSON Tshark

Le script accepte directement un export JSON produit par Tshark :

```bash
tshark -r capture.pcapng -T json -x > export_tshark.json
python3 tshark2hashcat.py export_tshark.json
```

Dans ce cas, Tshark n'est pas relancé.

### Captures compressées

Les fichiers `.bz2` et `.xz` sont décompressés temporairement avant l'appel à Tshark. Le fichier temporaire est supprimé automatiquement après traitement.

### Filtre de sélection et grosses captures

Par défaut, Tshark reçoit un filtre ciblant les protocoles et signatures utiles afin de limiter le volume du JSON produit. Pour analyser tous les paquets :

```bash
python3 tshark2hashcat.py capture.pcapng --full-packets
```

Cette option peut augmenter fortement la durée d'analyse et l'utilisation mémoire.

### Mode verbeux

```bash
python3 tshark2hashcat.py capture.pcapng --verbose
```

### Aide

```bash
python3 tshark2hashcat.py --help
```

## Fichiers produits

Avec `--output hashes.txt`, le programme génère :

| Fichier | Contenu |
|---|---|
| `hashes.txt` | Tous les hashes, tous modes confondus |
| `hashes_m<mode>.txt` | Un fichier par mode Hashcat, directement exploitable avec `-m` |
| `hashes_credentials.txt` | Identifiants transmis en clair, lorsqu'ils sont détectés |

Exemples :

```text
hashes.txt
hashes_m20.txt
hashes_m5600.txt
hashes_m18200.txt
hashes_m22000.txt
hashes_credentials.txt
```

Les fichiers de hashes sont dédupliqués. Le fichier d'identifiants en clair est un rapport TSV contenant le protocole, l'utilisateur et le mot de passe.

## Exemple de session

```console
$ python3 tshark2hashcat.py capture.pcapng -v
[i] tshark : /usr/bin/tshark
[i] /usr/bin/tshark -n -2 -r capture.pcapng ... -T json -x
    [m5600] frame #18 NTLM brut (j.dupont)
    [m32200] frame #61 Kerberos

=== RÉSULTATS ===
[i] protocoles détectés : kerberos, ntlmssp
[i] comptes AVEC pré-auth Kerberos vus : j.dupont

[+]   1 hash (5600) -> hashes_m5600.txt
    hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
    hashcat -m 32200 hashes_m32200.txt wordlist.txt

[i] 2 hash(s) écrit(s) aussi dans ./hashes.txt
```

Les valeurs affichées dans cet exemple sont fictives.

## Cassage avec Hashcat

### NetNTLMv2

```bash
hashcat -m 5600 hashes_m5600.txt wordlist.txt
```

### AS-REP roasting RC4

```bash
hashcat -m 18200 hashes_m18200.txt wordlist.txt
```

### Kerberoasting AES256

```bash
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

Avec des règles :

```bash
hashcat -m 5600 hashes_m5600.txt wordlist.txt \
  -r rules/best64.rule
```

Afficher les résultats déjà trouvés :

```bash
hashcat -m 5600 hashes_m5600.txt --show
```

> Vérifiez le format attendu par la version de Hashcat installée. Les modules et formats peuvent évoluer entre versions.

## Identifiants transmis en clair

En complément des hashes, le programme recherche des couples utilisateur/mot de passe transmis sans chiffrement :

| Source | Détection |
|---|---|
| FTP / Telnet | Commandes `USER` puis `PASS` |
| Telnet | Prompts `login:` / `username:` puis `Password:` |
| HTTP Basic | En-tête `Authorization: Basic` décodé en Base64 |
| SMTP / IMAP / POP | `AUTH PLAIN` |
| SMTP / IMAP / POP | `AUTH LOGIN` avec valeurs Base64 |
| Formulaires HTTP | Paramètres `user=`, `username=`, `login=`, `pass=` ou `password=` |
| SNMPv1/v2c | Community string rapportée comme donnée en clair |

Les résultats sont dédupliqués et enregistrés dans :

```text
hashes_credentials.txt
```

Exemple de contenu :

```text
HTTP Basic	user=alice	pass=ExempleTemporaire!
FTP/Telnet USER/PASS	user=bob	pass=MotDePasseDeTest
```

Ces valeurs ne nécessitent aucun cassage. Traitez ce fichier comme un secret.

## Gestion des données manquantes

Le programme n'extrapole pas les champs absents. Toute donnée inexploitable est signalée dans le rapport final, par exemple :

```text
[!] Données manquantes / éléments ignorés :
    - NTLM frame #51: server challenge absent -> hash non généré
    - Kerberos frame #77: TGS-REP sans cname/realm/spn -> ignoré
    - Kerberos frame #80: AS-REP etype inconnu (1) -> ignoré
    - APOP (alice): challenge introuvable -> ignoré
```

Une capture valide peut donc ne produire aucun hash si elle ne contient pas tous les éléments nécessaires : challenge, réponse, handshake complet, SSID, realm, SPN, etc.

## Architecture

```text
capture.pcapng
      │
      ▼
┌────────────────────────────────────┐
│ tshark -n -2 -r capture -T json -x │  Appel unique
└────────────────────────────────────┘
      │
      ├── Champs disséqués
      │   ntlmssp.*, kerberos.*, wlan.*, snmp.*
      │
      └── Octets bruts (-x)
          frame_raw, payload_raw, champs *_raw
      │
      ▼
Réassemblage, scans de signatures et appariement
      │
      ▼
Validateurs propres à chaque mode Hashcat
      │
      ▼
hashes.txt + hashes_m<mode>.txt + hashes_credentials.txt
```

1. **Tshark** décode la capture et fournit les champs structurés ainsi que les octets bruts.
2. **Les champs disséqués** sont privilégiés lorsqu'ils sont disponibles.
3. **Les octets bruts** servent de repli pour NTLMSSP, APOP, Kerberos PA-ENC-TIMESTAMP et les identifiants encapsulés ou Base64.
4. **Les flux** sont réassemblés à partir des charges utiles capturées.
5. **Les candidats** sont validés puis dédupliqués avant écriture.

Pour les captures très volumineuses, l'export JSON est parcouru progressivement afin de limiter la mémoire utilisée par Python.

## Limites connues

- Une authentification incomplète, tronquée ou filtrée ne produit pas de hash.
- Le rapprochement NTLM repose prioritairement sur le tuple IP/port et, en dernier recours, sur l'ordre des trames.
- Des flux fortement entrelacés ou des paquets manquants peuvent empêcher l'appariement challenge/réponse.
- Les protocoles et etypes non listés dans [Formats supportés](#formats-supportés) sont ignorés.
- PKINIT, FAST et les échanges Kerberos sans matériel exploitable ne produisent pas de hash.
- Les tickets `krbtgt` sont volontairement ignorés pour les TGS-REP.
- WPA/WPA2 nécessite les éléments suffisants du handshake et, selon le cas, le SSID.
- Les données transmises en clair sont seulement rapportées ; elles ne sont pas converties en hash.
- OSPF n'est pas pris en charge : Hashcat ne fournit pas de mode natif correspondant à cette authentification.
- Le script ne lit jamais directement un fichier PCAP avec une bibliothèque Python : le décodage est effectué par Tshark.

## Dépannage

| Symptôme | Cause probable | Résolution |
|---|---|---|
| `tshark introuvable` | Tshark n'est pas installé ou absent du `PATH` | Installer Wireshark ou utiliser `--tshark` |
| `aucun hash produit` | Aucun échange complet ou filtre trop restrictif | Essayer `--full-packets` et `--verbose` |
| JSON Tshark invalide ou vide | Export interrompu ou Tshark incompatible | Régénérer l'export avec `tshark -T json -x` |
| Challenge NTLM absent | Capture incomplète ou challenge dans un paquet non capturé | Capturer le début complet de l'échange |
| Handshake WPA absent | M1/M2, SSID ou données EAPOL manquants | Capturer l'association complète |
| `Separator unmatched` dans Hashcat | Hash modifié manuellement ou format non supporté | Utiliser exclusivement les fichiers générés par le script |
| Aucun identifiant en clair | Protocole non couvert ou flux incomplet | Vérifier les charges utiles avec Wireshark/Tshark |

## Contribution

Les contributions sont bienvenues :

- nouveaux alias de champs Tshark ;
- nouvelles encapsulations ou signatures ;
- nouveaux modes Hashcat ;
- tests sur des exports JSON anonymisés ;
- corrections de documentation et de compatibilité multiplateforme.

Avant une pull request :

1. conservez la compatibilité avec Python 3.10+ ;
2. n'ajoutez pas de dépendance externe sans nécessité ;
3. ajoutez un cas de test ou un exemple reproductible ;
4. anonymisez les captures et supprimez tous les secrets réels.

Les rapports de bugs devraient préciser les versions de Python, Tshark et Hashcat, le système d'exploitation, la commande utilisée et le message obtenu.

## Licence

Distribué sous [Apache License 2.0](LICENSE).

Ajoutez le fichier `LICENSE` correspondant au dépôt avant publication si ce n'est pas déjà fait.
