# tshark2hashcat

Extraction automatique de **hashes prêts pour Hashcat** depuis des captures réseau
(`.pcap` / `.pcapng`), en utilisant **Tshark comme unique source de données**.

Outil conçu pour le pentest, les CTF et l'analyse forensique : il détecte le
protocole, reconstruit les empreintes NetNTLM et Kerberos **au format exact
attendu par Hashcat**, les valide une par une, et affiche la commande de
cassage correspondante.

> ⚠️ **Usage légal uniquement** : vos propres réseaux, labos, CTF ou missions
> autorisées. Vous êtes responsable de l'usage que vous en faites.

---

## Fonctionnalités

- 🔍 **Détection automatique du protocole** : NTLMSSP et/ou Kerberos, aucun
  paramètre à régler.
- 🔐 **11 modes Hashcat couverts** (voir table ci-dessous), y compris les
  variantes AES de Kerberos 5 (etypes 17/18) souvent ignorées par les autres
  outils.
- ✅ **Aucun hash invalide** : chaque ligne est validée contre la grammaire
  exacte du tokenizer Hashcat (longueurs, séparateurs, hexadécimal, positions
  du checksum) **avant** d'être écrite. Fini les `Separator unmatched`.
- ⚠️ **Signalement des données manquantes** : si une trame est incomplète
  (challenge absent, realm manquant, etype inconnu…), le script le dit au lieu
  de produire une ligne bancale.
- 🧹 **Une seule ligne par utilisateur/mode** (déduplication) et sortie propre :
  `hashes.txt` + un fichier par mode (`hashes_m5600.txt`, …) + la commande
  `hashcat` prête à copier-coller.
- 🪪 **Diagnostic Kerberos** : liste des identités vues (utilisateur, realm,
  SPN, salt ETYPE-INFO2, etype, type de message) — indispensable pour vérifier
  la casse exacte d'un UPN ou le salt d'un compte de service.
- 🪟 **Windows / Linux / macOS**, **zéro dépendance Python** (bibliothèque
  standard uniquement).

## Prérequis

| Composant | Détail |
|---|---|
| Python | ≥ 3.7 |
| Tshark | installé avec [Wireshark](https://www.wireshark.org/) (cocher « TShark ») |
| | chemins détectés automatiquement : `C:\Program Files\Wireshark\tshark.exe`, `C:\Program Files (x86)\Wireshark\tshark.exe`, ou `tshark` dans le `PATH` |

## Installation

```bash
git clone https://github.com/<vous>/tshark2hashcat.git
cd tshark2hashcat
```

Aucune dépendance à installer (`pip install` inutile).

## Utilisation

```bash
# Le plus simple : un fichier en argument
python tshark2hashcat.py capture.pcapng

# Options
python tshark2hashcat.py capture.pcap -o hashes.txt --tshark "D:\Outils\Wireshark\tshark.exe"

# Rejouer un export JSON tshark (debug / tests hors-ligne)
python tshark2hashcat.py export.json
```

Sous Windows, on peut aussi **glisser-déposer** la capture sur le script via un
raccourci, ou créer un `run.bat` :

```bat
@echo off
python "%~dp0tshark2hashcat.py" %1
pause
```

## Exemple de sortie

```
[i] tshark : C:\Program Files\Wireshark\tshark.exe
[i] tshark -r capture.pcapng -T json -x
    [m5600] frame #18 NTLM (j.dupont)
    [m32200] frame #61 Kerberos

=== RÉSULTATS ===
[i] protocoles détectés : kerberos, ntlmssp
[i] comptes AVEC pré-auth Kerberos vus : j.dupont

=== IDENTITÉS KERBEROS VUES (diagnostic) ===
    frame #61    AS-REQ   user=j.dupont realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL salt=EXAMPLE.LOCALj.dupont etypes=18
    frame #62    AS-REP   user=j.dupont realm=EXAMPLE.LOCAL spn=krbtgt/EXAMPLE.LOCAL etypes=18

[+]   1 hash (5600) -> hashes_m5600.txt
    hashcat -m 5600 hashes_m5600.txt wordlist.txt
[+]   1 hash (32200) -> hashes_m32200.txt
    hashcat -m 32200 hashes_m32200.txt wordlist.txt
```

## Modes Hashcat supportés

| Protocole | Condition dans la capture | Mode | Format produit |
|---|---|---|---|
| NetNTLMv2 | NT response > 24 octets | **5600** | `user::domaine:challenge:NTProofStr:blob` |
| NetNTLMv1 (+ESS) | NT response = 24 octets | **5500** | `user::domaine:challenge:LM:NT` |
| Kerberos AS-REP (Roasting) | etype 23 (RC4) | **18200** | `$krb5asrep$23$user@realm:chk$edata2` |
| Kerberos AS-REP | etype 17 / 18 (AES128/256) | **32100 / 32200** | `$krb5asrep$18$user$realm$chk$edata2` |
| Kerberos AS-REQ (pré-auth) | etype 23 | **7500** | `$krb5pa$23$user$realm$timestamp` |
| Kerberos AS-REQ (pré-auth) | etype 17 / 18 | **19800 / 19900** | `$krb5pa$18$user$realm$timestamp` |
| Kerberos TGS-REP (Kerberoast) | etype 23 (RC4) | **13100** | `$krb5tgs$23$*user$realm$spn*$chk$edata2` |
| Kerberos TGS-REP | etype 17 / 18 | **19600 / 19700** | `$krb5tgs$18$service$realm$chk$edata2` |

Les lignes sont **dédupliquées** et écrites en ASCII, une par ligne, selon les
contraintes exactes des modules Hashcat (`user` ≤ 60 car., domaine ≤ 45 car.,
checksum de 12 derniers octets en AES vs 16 premiers en RC4, etc.).

## Cassage

```bash
# Dictionnaire classique
hashcat -m 5600 hashes_m5600.txt rockyou.txt

# Avec règles
hashcat -m 32200 hashes_m32200.txt rockyou.txt -r rules/best64.rule

# Afficher les mots de passe trouvés
hashcat -m 32200 hashes_m32200.txt --show
```

John the Ripper (jumbo) lit aussi ces formats (`netntlmv2`, `krb5asrep`, …).

> 💡 **Mode 19600/19700 (TGS AES)** : le salt Kerberos AES est
> `REALM + nom_du_compte_de_service`. Le script utilise la 1ʳᵉ partie du SPN
> (comportement par défaut des comptes machine : `HOST/monserveur` → `HOST$`).
> Si le cassage échoue, vérifiez le vrai `sAMAccountName` du service dans la
> section *IDENTITÉS KERBEROS VUES* et ajustez le champ `user` de la ligne.

## Données manquantes

Le script ne devine jamais : il rapporte précisément ce qui bloque, par ex. :

```
[!] Données manquantes / éléments ignorés :
    - NTLM frame #51: 'server_challenge' manquant -> hash non généré
    - Kerberos frame #77: TGS-REP mais cname/realm/spn manquant -> ignoré
    - Kerberos frame #80: AS-REP etype inconnu (1) -> ignoré
```

## Fonctionnement interne

1. **Un seul appel Tshark** : `tshark -r capture.pcapng -T json -x`
   (champs disséqués + octets bruts de chaque couche).
2. Les champs disséqués (`ntlmssp.*`, `kerberos.*`) sont utilisés **en
   priorité**, avec appairage challenge/auth par tuple IP:port.
3. **Filet de sécurité** : si le dissecteur n'a pas reconnu un encapsulage
   (NTLMSSP dans HTTP/IMAP/SMTP, encapsulation exotique…), les octets bruts du
   `-x` sont parcourus à la recherche de la signature `NTLMSSP\0` — en clair
   **ou encodée en Base64** (en-têtes `Authorization`, `AUTH NTLM`, …).
4. Chaque empreinte candidate passe un **validateur dédié** qui rejoue les
   contraintes du module Hashcat officiel ; seules les lignes conformes sont
   écrites.

## Limites connues

- Nécessite que les échanges d'authentification soient **complets** dans la
  capture (un challenge sans réponse, ou l'inverse, ne suffit pas — ils sont
  appairés dans l'ordre d'apparition en dernier recours).
- Les tickets `krbtgt` (clé du KDC, non cassable) sont volontairement ignorés.
- Kerberos avec pré-authentification sans données réseau exploitables (FAST,
  PKINIT) ne produit rien — c'est attendu.

## Licence

MIT — voir [LICENSE](LICENSE).
