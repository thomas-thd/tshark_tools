<div align="center">

# 🦈 tshark2hashcat

**Des captures réseau → des hashes Hashcat valides. Automatiquement.**

![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.7-3776AB?logo=python&logoColor=white)
![Plateforme](https://img.shields.io/badge/Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-supported-brightgreen)
![Dépendances](https://img.shields.io/badge/dépendances%20Python-0-blue)
![Licence](https://img.shields.io/badge/licence-Apache%202.0-blue)

*[English translation below](#-english-summary) · Outil offensif — usage strictement légal (labos, CTF, audits autorisés)*

</div>

---

**tshark2hashcat** analyse un fichier `.pcap` / `.pcapng` avec **Tshark** (et uniquement
Tshark), détecte les authentifications **NetNTLM** et **Kerberos**, reconstruit les
empreintes cassables **au format exact attendu par Hashcat**, les **valide une par
une** et affiche la **commande de cassage** correspondante.

Plus une seule ligne rejetée par `Separator unmatched`. Plus de devinettes sur le
bon `-m`. Tu captures, tu extrais, tu casses.

```console
C:\outils> python tshark2hashcat.py capture.pcapng
[+]   1 hash (5600)  -> hashes_m5600.txt
      hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
      hashcat -m 32200 hashes_m32200.txt wordlist.txt
```

---

## 📑 Sommaire

- [Pourquoi cet outil ?](#-pourquoi-cet-outil-)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Exemple de sortie complet](#-exemple-de-sortie-complet)
- [Modes Hashcat supportés](#-modes-hashcat-supportés)
- [Cassage avec Hashcat](#-cassage-avec-hashcat)
- [Données manquantes : zéro hash bancal](#-données-manquantes--zéro-hash-bancal)
- [Fonctionnement interne](#-fonctionnement-interne)
- [Limites connues](#-limites-connues)
- [Dépannage](#-dépannage)
- [Contribuer](#-contribuer)
- [Licence](#-licence)

---

## 🎯 Pourquoi cet outil ?

Extraire un hash Kerberos ou NetNTLM « à la main » depuis une capture, c'est :

1. ouvrir Wireshark, fouiller les bons paquets, copier de l'hexadécimal ;
2. reconstruire la ligne au bon format (un `:` ou un `$` de travers et Hashcat refuse tout) ;
3. choisir le bon mode parmi **11 possibles** (RC4 vs AES, AS-REQ vs AS-REP vs TGS-REP, NetNTLMv1 vs v2…) ;
4. découvrir au cassage que le checksum est au mauvais endroit (16 premiers octets en RC4, **12 derniers** en AES).

**tshark2hashcat fait tout ça pour toi**, avec un garde-fou à chaque étape : aucune
ligne n'est écrite si elle ne respecte pas à la lettre la grammaire du module
Hashcat correspondant.

---

## ✨ Fonctionnalités

| | |
|---|---|
| 🔍 **Détection automatique** | NTLMSSP et/ou Kerberos, aucun paramètre à régler |
| 🔐 **11 modes Hashcat** | NetNTLMv1/v2, AS-REP, AS-REQ (pré-auth), Kerberoast — RC4 **et** AES 128/256 |
| ✅ **Validation stricte** | chaque ligne vérifiée contre le tokenizer officiel Hashcat **avant** écriture |
| ⚠️ **Rapport des manques** | trame incomplète ? le script dit *exactement* ce qui bloque, au lieu de produire un hash invalide |
| 🧹 **Sortie propre** | déduplication, `hashes.txt` + un fichier par mode + commande `hashcat` prête à coller |
| 🪪 **Diagnostic Kerberos** | identités vues : utilisateur, realm, SPN, salt ETYPE-INFO2, etype — pour vérifier la casse exacte d'un UPN |
| 🕸️ **NTLMSSP caché ? trouvé** | scan par signature binaire (clair **ou Base64**) quand le dissecteur n'a pas reconnu l'encapsulation (HTTP, IMAP, SMTP, RPC…) |
| 📦 **Zéro dépendance** | bibliothèque standard Python uniquement |

---

## 🧰 Prérequis

| Composant | Détail |
|---|---|
| **Python** | ≥ 3.7 (aucun paquet à installer) |
| **Tshark** | installé avec [Wireshark](https://www.wireshark.org/download.html) — cocher *TShark* à l'installation |

Chemins détectés automatiquement :

```
C:\Program Files\Wireshark\tshark.exe        (Windows)
C:\Program Files (x86)\Wireshark\tshark.exe  (Windows)
tshark                                       (si présent dans le PATH)
```

Sinon, indique-le toi-même avec `--tshark`.

---

## 📥 Installation

```bash
git clone https://github.com/<vous>/tshark2hashcat.git
cd tshark2hashcat
```

C'est tout. Pas de `pip install`, pas de compilation.

---

## 🚀 Utilisation

```
usage: tshark2hashcat.py [-h] [-o SORTIE] [--tshark CHEMIN] pcap
```

| Argument | Rôle | Défaut |
|---|---|---|
| `pcap` | Fichier `.pcap` / `.pcapng` — ou export `.json` de tshark (debug) | — |
| `-o, --output` | Fichier global regroupant tous les hashes | `hashes.txt` |
| `--tshark` | Chemin complet vers `tshark.exe` | auto-détection |

```bash
# Cas typique
python tshark2hashcat.py capture.pcapng

# Sortie personnalisée + tshark hors du PATH
python tshark2hashcat.py capture.pcap -o mon_hashes.txt --tshark "D:\Outils\Wireshark\tshark.exe"

# Rejouer un export JSON tshark (hors-ligne, tests, debug)
python tshark2hashcat.py export_tshark.json
```

> **Sous Windows** : glisse-dépose la capture sur un raccourci du script, ou crée
> `run.bat` à côté :
> ```bat
> @echo off
> python "%~dp0tshark2hashcat.py" %*
> pause
> ```

---

## 🖥️ Exemple de sortie complet

```
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

[i] 2 hash écrit(s) aussi dans .\hashes.txt
```

Fichiers produits à côté de la capture :

| Fichier | Contenu |
|---|---|
| `hashes.txt` | toutes les empreintes, tous modes confondus |
| `hashes_m<mode>.txt` | un fichier par mode Hashcat, prêt pour `-m` |

---

## 🔢 Modes Hashcat supportés

| Protocole | Condition dans la capture | Mode Hashcat | Format de la ligne |
|---|---|:---:|---|
| **NetNTLMv2** | NT response > 24 octets | `5600` | `user::domaine:challenge:NTProofStr:blob` |
| **NetNTLMv1** (+ESS) | NT response = 24 octets | `5500` | `user::domaine:challenge:LM:NT` |
| **AS-REP Roasting** | AS-REP, etype 23 (RC4) | `18200` | `$krb5asrep$23$user@realm:chk$edata2` |
| **AS-REP Roasting** | AS-REP, etype 17 / 18 (AES) | `32100` / `32200` | `$krb5asrep$18$user$realm$chk$edata2` |
| **Pré-auth Kerberos** | AS-REQ, etype 23 | `7500` | `$krb5pa$23$user$realm$timestamp` |
| **Pré-auth Kerberos** | AS-REQ, etype 17 / 18 | `19800` / `19900` | `$krb5pa$18$user$realm$timestamp` |
| **Kerberoasting** | TGS-REP, etype 23 (RC4) | `13100` | `$krb5tgs$23$*user$realm$spn*$chk$edata2` |
| **Kerberoasting** | TGS-REP, etype 17 / 18 | `19600` / `19700` | `$krb5tgs$18$service$realm$chk$edata2` |

Subtilités gérées pour toi :

- 🧂 **Position du checksum** : 16 premiers octets en RC4-etype 23, **12 derniers** octets en AES etype 17/18 ;
- ✂️ **Découpe NetNTLMv2** : `NTProofStr` (16 o) séparé du blob ;
- ⭐ **Étoiles RC4 vs pas d'étoiles AES** dans les formats `$krb5tgs$` ;
- 🚫 **Tickets `krbtgt` ignorés** (chiffrés avec la clé du KDC : non cassables, ligne inutile).

---

## 💥 Cassage avec Hashcat

```bash
# Dictionnaire
hashcat -m 5600  hashes_m5600.txt  rockyou.txt
hashcat -m 32200 hashes_m32200.txt rockyou.txt

# Dictionnaire + règles
hashcat -m 32200 hashes_m32200.txt rockyou.txt -r rules/best64.rule

# Masque (mot de passe court à politique connue)
hashcat -m 19700 hashes_m19700.txt -a 3 ?u?l?l?l?l?l?l?d

# Résultats
hashcat -m 32200 hashes_m32200.txt --show
```

Compatible **John the Ripper jumbo** (formats `netntlmv2`, `netntlm`, `krb5asrep`,
`krb5tgs`, `krb5pa-sha1`).

> 💡 **Astuce mode 19600/19700 (TGS AES)** : le salt Kerberos AES vaut
> `REALM + sAMAccountName` du **compte de service**. Le script met la 1ʳᵉ partie
> du SPN (défaut des comptes machine : `HOST/srv` → salt `REALMHOST$`). Si le
> cassage échoue, vérifie le vrai nom du compte dans la section *IDENTITÉS
> KERBEROS VUES* et ajuste le champ `user` de la ligne.

---

## ⚠️ Données manquantes : zéro hash bancal

Le script ne *devine* jamais. Toute trame inexploitable est rapportée avec la
cause exacte :

```
[!] Données manquantes / éléments ignorés :
    - NTLM frame #51: 'server_challenge' manquant -> hash non généré
    - Kerberos frame #77: TGS-REP mais cname/realm/spn manquant (user=j.dupont, realm=EXAMPLE.LOCAL, spn=None) -> ignoré
    - Kerberos frame #80: AS-REP etype inconnu (1) -> ignoré
```

---

## ⚙️ Fonctionnement interne

```
capture.pcapng
      │
      ▼
┌───────────────────────────────┐
│ tshark -r capture -T json -x  │   ← UN seul appel : champs disséqués + octets bruts
└───────────────────────────────┘
      │                    │
      ▼                    ▼
 champs disséqués      octets bruts (-x)
 ntlmssp.* /           scan signature NTLMSSP\0
 kerberos.*            (clair + Base64 : HTTP,
      │                IMAP, SMTP, …)
      ▼                    │
 appairage challenge/      │
 auth par IP:port          │
      └────────┬───────────┘
               ▼
     validateurs par mode
  (grammaire exacte hashcat)
               ▼
   hashes.txt + hashes_m*.txt
```

1. **Champs disséqués d'abord** — c'est la voie fiable (types de message, etypes,
   security buffers déjà découpés par Tshark).
2. **Scan brut en filet de sécurité** — indispensable quand le dissecteur n'a pas
   reconnu l'encapsulation (NTLMSSP dans un en-tête `Authorization: NTLM …`, une
   commande `AUTH NTLM`, du RPC…).
3. **Validation avant écriture** — longueurs, séparateurs, hexadécimal, bornes
   (`user` ≤ 60 car., domaine ≤ 45, tailles de checksum…) rejouées comme dans le
   code des modules Hashcat officiels.

---

## 🚧 Limites connues

- Un échange **incomplet** (challenge sans réponse, capture tronquée) ne produit
  rien — par conception (signalement dans la section *Données manquantes*).
- Kerberos **PKINIT / FAST** ne produit pas d'empreinte cassable : c'est cryptographiquement attendu.
- L'appairage NTLM challenge/réponse se fait par tuple IP:port, et à défaut par
  ordre d'apparition (un flux très imbriqué peut nécessiter un filtrage préalable).

---

## 🩹 Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `tshark introuvable` | Tshark hors PATH | `--tshark "C:\chemin\vers\tshark.exe"` |
| `protocoles détectés : aucun` | Pas d'auth NTLM/Kerberos dans la capture | vérifier avec `tshark -q -r capture.pcapng -z io,phs` |
| `tshark a échoué` | Fichier corrompu ou pas une capture | ouvrir le fichier dans Wireshark pour valider |
| Hashcat : `Separator unmatched` | Ancienne ligne écrite à la main dans le fichier | regénérer le fichier avec ce script |
| Mode 19700 ne casse pas | Mauvais compte de service (salt) | voir l'astuce [ci-dessus](#-cassage-avec-hashcat) |

---

## 🤝 Contribuer

Les PR sont bienvenues : nouveaux formats, supports d'encapsulations exotiques,
tests. Ouvre une *issue* pour discuter d'un format avant de coder son validateur.

---

## 📜 Licence

Distribué sous licence **Apache License 2.0** — voir [LICENSE](LICENSE).

En résumé : utilisation, modification et redistribution libres (même commerciales),
avec protection expresse contre les litiges de brevets ; les mentions de copyright
et la licence doivent être conservées dans les copies.

---

<div align="center">

## 🇬🇧 English summary

**tshark2hashcat** turns `.pcap`/`.pcapng` captures into **ready-to-crack Hashcat
hashes**, using Tshark as its only data source. It auto-detects NetNTLM (v1/v2)
and Kerberos traffic (AS-REQ pre-auth, AS-REP roasting, Kerberoasting — RC4 and
AES128/256), rebuilds each hash in the **exact format expected by Hashcat** (11
modes supported: 5500, 5600, 7500, 13100, 18200, 19600, 19700, 19800, 19900,
32100, 32200), **validates every line** against the official Hashcat tokenizers
before writing it, reports missing data instead of emitting broken hashes, and
prints the matching `hashcat -m` command. Pure standard-library Python ≥ 3.7,
Windows/Linux/macOS. Usage: `python tshark2hashcat.py capture.pcapng`.
**For legal, authorized use only (labs, CTFs, pentests).**

</div>
