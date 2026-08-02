<div align="center">

<img src="docs/logo.png" alt="tshark2hashcat" width="360">

# tshark2hashcat

**Extraction de hachés prêts pour Hashcat depuis des captures réseau, via Tshark.**

[![Python](https://img.shields.io/badge/python-%E2%89%A5%203.7-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#)
[![Dependencies](https://img.shields.io/badge/python%20dependencies-none-success)](#)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

English version: [README_EN.md](README_EN.md)

</div>

---

## Présentation

`tshark2hashcat` analyse un fichier `.pcap` / `.pcapng` à l'aide de **Tshark** — son
unique source de données —, détecte les authentifications **NetNTLM** et **Kerberos**,
reconstruit les empreintes cassables dans le **format exact attendu par Hashcat**,
les **valide individuellement** contre la grammaire des modules officiels, puis
génère les fichiers de sortie accompagnés de la **commande de cassage** correspondante.

L'outil s'adresse aux pentesters, analystes forensique et joueurs de CTF. Il
élimine les deux sources d'erreur classiques de ce workflow : la reconstruction
manuelle d'empreintes (checksum mal positionné, séparateurs incorrects) et le
choix du mauvais mode Hashcat parmi les onze variantes concernées.

> **Avertissement légal.** Cet outil est destiné exclusivement à un usage
> autorisé : laboratoires, environnements de test, CTF et missions d'audit
> contractuelles. L'utilisateur est seul responsable de la conformité de son
> usage avec la législation applicable.

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Formats de hachés supportés](#formats-de-hachés-supportés)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Exemple de session](#exemple-de-session)
- [Cassage avec Hashcat](#cassage-avec-hashcat)
- [Gestion des données manquantes](#gestion-des-données-manquantes)
- [Architecture](#architecture)
- [Limites connues](#limites-connues)
- [Dépannage](#dépannage)
- [Contribution](#contribution)
- [Licence](#licence)

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Détection automatique | NTLMSSP et Kerberos identifiés sans configuration, y compris en présence des deux protocoles dans la même capture |
| Couverture étendue | 11 modes Hashcat : NetNTLMv1/v2, AS-REP roasting, pré-authentification Kerberos, Kerberoasting — en RC4 **et** AES 128/256 |
| Validation stricte | Chaque ligne est vérifiée contre les contraintes exactes du tokenizer Hashcat (séparateurs, longueurs, bornes) **avant** écriture sur disque |
| Rapport d'anomalies | Toute trame incomplète est journalisée avec la cause précise du rejet ; aucune empreinte bancale n'est produite |
| Repli sur octets bruts | Scan de la signature `NTLMSSP\0` — en clair ou encodée Base64 — lorsque le dissecteur n'a pas reconnu l'encapsulation (HTTP, IMAP, SMTP, RPC…) |
| Diagnostic Kerberos | Inventaire des identités observées : utilisateur, realm, SPN, salt ETYPE-INFO2, etype, type de message, numéro de trame |
| Sortie normalisée | Déduplication, fichier global + un fichier par mode Hashcat, commandes `hashcat` prêtes à l'emploi |
| Portabilité | Windows, Linux, macOS — bibliothèque standard Python uniquement, aucune dépendance tierce |

## Formats de hachés supportés

| Protocole / attaque | Condition dans la capture | Mode Hashcat | Format produit |
|---|---|:---:|---|
| NetNTLMv2 | Réponse NT > 24 octets | `5600` | `user::domaine:challenge:NTProofStr:blob` |
| NetNTLMv1 (±ESS) | Réponse NT = 24 octets | `5500` | `user::domaine:challenge:LM:NT` |
| AS-REP roasting | AS-REP, etype 23 (RC4) | `18200` | `$krb5asrep$23$user@realm:chk$edata2` |
| AS-REP roasting | AS-REP, etype 17 / 18 (AES) | `32100` / `32200` | `$krb5asrep$18$user$realm$chk$edata2` |
| Pré-authentification | AS-REQ, etype 23 | `7500` | `$krb5pa$23$user$realm$timestamp` |
| Pré-authentification | AS-REQ, etype 17 / 18 | `19800` / `19900` | `$krb5pa$18$user$realm$timestamp` |
| Kerberoasting | TGS-REP, etype 23 (RC4) | `13100` | `$krb5tgs$23$*user$realm$spn*$chk$edata2` |
| Kerberoasting | TGS-REP, etype 17 / 18 | `19600` / `19700` | `$krb5tgs$18$service$realm$chk$edata2` |

Les subtilités de format sont gérées nativement :

- **Position du checksum** — 16 premiers octets pour RC4 (etype 23), 12 **derniers**
  octets pour AES (etypes 17/18) ;
- **Découpe NetNTLMv2** — séparation `NTProofStr` (16 octets) / blob ;
- **Formats TGS** — astérisques présents en RC4 (`$krb5tgs$23$*…$…$…*$`), absents en AES ;
- **Tickets `krbtgt` ignorés** — chiffrés avec la clé du KDC, donc non cassables ;
  leur émission comme empreinte serait sans valeur.

## Prérequis

| Composant | Version / remarque |
|---|---|
| Python | ≥ 3.7 — aucun paquet tiers requis |
| Tshark | Installé avec [Wireshark](https://www.wireshark.org/download.html) (composant *TShark* à cocher) |

Chemins détectés automatiquement, par ordre de priorité :

```
1. C:\Program Files\Wireshark\tshark.exe
2. C:\Program Files (x86)\Wireshark\tshark.exe
3. tshark (résolution via le PATH)
```

Un chemin différent peut être fourni explicitement avec `--tshark`.

## Installation

```bash
git clone https://github.com/<organisation>/tshark2hashcat.git
cd tshark2hashcat
```

Aucune étape supplémentaire : pas de `pip install`, pas de compilation.

## Utilisation

```
usage: tshark2hashcat.py [-h] [-o SORTIE] [--tshark CHEMIN] [-v] pcap
```

| Argument | Description | Défaut |
|---|---|---|
| `pcap` | Capture `.pcap` / `.pcapng`, ou export JSON de Tshark (analyse hors-ligne) | — |
| `-o`, `--output` | Fichier global agrégeant toutes les empreintes | `hashes.txt` |
| `--tshark` | Chemin complet vers l'exécutable Tshark | détection automatique |
| `-v`, `--verbose` | Journalisation détaillée | désactivé |

```bash
# Analyse standard
python tshark2hashcat.py capture.pcapng

# Sortie personnalisée, Tshark hors des chemins standards
python tshark2hashcat.py capture.pcap -o empreintes.txt --tshark "D:\Outils\Wireshark\tshark.exe"

# Rejeu d'un export JSON Tshark (tests, intégration continue)
python tshark2hashcat.py export_tshark.json
```

**Windows — glisser-déposer.** Créer `run.bat` à côté du script permet de
déposer une capture directement sur le raccourci :

```bat
@echo off
python "%~dp0tshark2hashcat.py" %*
pause
```

## Exemple de session

```console
C:\outils> python tshark2hashcat.py capture.pcapng
[i] tshark : C:\Program Files\Wireshark\tshark.exe
[i] tshark -r capture.pcapng -T json -x
    [m5600]  frame #18 NTLM (j.dupont)
    [m32200] frame #61 Kerberos

=== RÉSULTATS ===
[i] protocoles détectés : kerberos, ntlmssp
[i] comptes AVEC pré-auth Kerberos vus : j.dupont

=== IDENTITÉS KERBEROS VUES (diagnostic) ===
    frame #61    AS-REQ   user=j.dupont realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL salt=EXAMPLE.LOCALj.dupont etypes=18
    frame #62    AS-REP   user=j.dupont realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL etypes=18

[+]   1 hash (5600)  -> hashes_m5600.txt
      hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
      hashcat -m 32200 hashes_m32200.txt wordlist.txt

[i] 2 empreintes également écrites dans .\hashes.txt
```

Fichiers produits à côté de la capture :

| Fichier | Contenu |
|---|---|
| `hashes.txt` | Toutes les empreintes, tous modes confondus |
| `hashes_m<mode>.txt` | Un fichier par mode Hashcat, directement exploitable avec `-m` |

## Cassage avec Hashcat

```bash
# Attaque par dictionnaire
hashcat -m 5600  hashes_m5600.txt  rockyou.txt
hashcat -m 32200 hashes_m32200.txt rockyou.txt

# Dictionnaire + règles
hashcat -m 32200 hashes_m32200.txt rockyou.txt -r rules/best64.rule

# Attaque par masque (politique de mot de passe connue)
hashcat -m 19700 hashes_m19700.txt -a 3 ?u?l?l?l?l?l?l?d

# Consultation des résultats
hashcat -m 32200 hashes_m32200.txt --show
```

Les empreintes sont également compatibles avec **John the Ripper jumbo**
(formats `netntlm`, `netntlmv2`, `krb5asrep`, `krb5pa-sha1`, `krb5tgs`).

> **Note — modes 19600/19700 (TGS AES).** Le salt Kerberos AES est construit comme
> `REALM + sAMAccountName` du **compte de service**. Le script retient par défaut
> la première composante du SPN (convention des comptes machine : `HOST/srv` →
> salt `REALMHOST$`). En cas d'échec du cassage, identifier le véritable compte de
> service dans la section *Identités Kerberos vues* et ajuster le champ `user` de
> la ligne en conséquence.

## Gestion des données manquantes

Le programme ne procède à aucune extrapolation. Chaque trame inexploitable est
rapportée dans un récapitulatif final indiquant la cause exacte :

```console
[!] Données manquantes / éléments ignorés :
    - NTLM frame #51: 'server_challenge' manquant -> hash non généré
    - Kerberos frame #77: TGS-REP mais cname/realm/spn manquant (user=j.dupont, realm=EXAMPLE.LOCAL, spn=None) -> ignoré
    - Kerberos frame #80: AS-REP etype inconnu (1) -> ignoré
```

Cette politique garantit qu'aucune ligne du fichier de sortie ne peut être rejetée
par Hashcat pour motif de format (`Separator unmatched`, `Token length exception`).

## Architecture

```
capture.pcapng
      │
      ▼
┌──────────────────────────────────┐
│ tshark -r capture -T json -x     │   Appel unique : champs disséqués
└──────────────────────────────────┘   + octets bruts de chaque couche
        │                    │
        ▼                    ▼
  Champs disséqués      Octets bruts (-x)
  ntlmssp.* /           Scan de la signature
  kerberos.*            NTLMSSP\0 (clair, Base64)
        │                    │
        ▼                    │
  Appairage challenge/       │
  réponse par tuple IP:port  │
        └──────────┬─────────┘
                   ▼
       Validateurs par mode Hashcat
        (grammaire officielle)
                   ▼
    hashes.txt  +  hashes_m<mode>.txt
```

1. **Champs disséqués prioritaires** — voie privilégiée : types de message,
   etypes et security buffers sont déjà interprétés par Tshark.
2. **Scan brut en repli** — indispensable lorsque l'encapsulation n'a pas été
   reconnue (en-tête HTTP `Authorization: NTLM …`, commande `AUTH NTLM`, RPC…).
3. **Validation avant écriture** — chaque ligne candidate est confrontée aux
   contraintes des modules Hashcat officiels (longueurs, séparateurs, bornes :
   `user` ≤ 60 caractères, domaine ≤ 45, tailles de checksum…).

## Limites connues

- Un échange d'authentification **incomplet ou tronqué** ne produit aucune
  empreinte — comportement voulu, signalé dans le récapitulatif des anomalies.
- Kerberos **PKINIT / FAST** ne fournit pas de matériel cassable : l'absence de
  résultat est cryptographiquement attendue.
- L'appairage NetNTLM challenge/réponse repose sur le tuple IP:port, puis sur
  l'ordre d'apparition en dernier recours ; des flux fortement entrelacés peuvent
  nécessiter un filtrage préalable de la capture.

## Dépannage

| Symptôme | Cause probable | Résolution |
|---|---|---|
| `tshark introuvable` | Tshark hors des chemins standards | `--tshark "C:\chemin\vers\tshark.exe"` |
| `protocoles détectés : aucun` | Capture sans authentification NTLM/Kerberos | Vérifier : `tshark -q -r capture.pcapng -z io,phs` |
| `tshark a échoué` | Fichier corrompu ou format inattendu | Ouvrir la capture dans Wireshark pour validation |
| Hashcat : `Separator unmatched` | Ligne écrite manuellement dans le fichier | Régénérer le fichier avec le script exclusivement |
| Mode 19700 sans résultat | Compte de service incorrect (salt) | Voir la note des modes [19600/19700](#cassage-avec-hashcat) |

## Contribution

Les contributions sont les bienvenues : nouveaux formats d'empreintes, prise en
charge d'encapsulations supplémentaires, jeux de tests. Merci d'ouvrir une
*issue* pour discuter de tout nouveau validateur avant son implémentation, et de
joindre une capture de test (anonymisée) ainsi que la sortie Hashcat attendue.

## Licence

Distribué sous [Apache License 2.0](LICENSE) — © 2026 tshark2hashcat contributors.

Utilisation, modification et redistribution libres, y compris à des fins
commerciales, avec protection expresse contre les litiges de brevets. Les
mentions de copyright et la licence doivent être conservées dans toute copie.
