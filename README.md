████████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗██████╗
╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝╚════██╗
██║   ███████╗███████║███████║██████╔╝█████╔╝  █████╔╝
██║   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██╔═══╝
██║   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗
╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ █████╗ ████████╗
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝
███████║███████║███████╗███████║██║     ███████║   ██║
██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██║   ██║
██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝

```
                TSHARK2HASHCAT
          PCAP -> HASHCAT + AUDIT SÉCURITÉ
```

## DESCRIPTION

tshark2hashcat est un outil Python permettant d'analyser des captures
réseau PCAP, PCAPNG et CAP avec TShark.

L'outil extrait automatiquement les éléments d'authentification, les hashes,
les identifiants, les secrets et différentes informations réseau présentes
dans les captures.

Il génère également un rapport d'audit permettant d'identifier les
expositions de sécurité, les chemins d'attaque et les techniques
MITRE ATT&CK associées.

## FONCTIONNALITÉS

* Analyse de fichiers PCAP / PCAPNG / CAP
* Analyse basée sur TShark
* Extraction NetNTLMv1
* Extraction NetNTLMv2
* Extraction Kerberos AS-REQ
* Extraction Kerberos AS-REP
* Détection du Kerberoasting
* Extraction WPA PMKID
* Extraction APOP
* Extraction SIP Digest
* Extraction CHAP
* Détection des JWT
* Détection d'identifiants en clair
* Détection FTP / Telnet
* Détection HTTP Basic Authentication
* Analyse SMTP / IMAP / POP
* Analyse LDAP
* Détection des communautés SNMP
* Analyse SMB et SYSVOL
* Extraction DNS / DHCP / NetBIOS
* Extraction TLS SNI et HTTP Host
* Détection des cookies et tokens
* Génération d'un rapport Excel
* Génération de fichiers compatibles Hashcat
* Cartographie MITRE ATT&CK
* Reconstruction de chemins d'attaque
* Évaluation du niveau de risque

## MODES HASHCAT

Mode       Type

20         APOP
4800       CHAP
5500       NetNTLMv1
5600       NetNTLMv2
7500       Kerberos AS-REQ RC4
11400      SIP Digest
13100      Kerberoast RC4
16500      JWT
18200      AS-REP RC4
19600      Kerberoast AES128
19700      Kerberoast AES256
19800      AS-REQ AES128
19900      AS-REQ AES256
22000      WPA-PBKDF2-PMKID
32100      AS-REP AES128
32200      AS-REP AES256

## PRÉREQUIS

* Python 3
* Wireshark / TShark
* openpyxl
* rich

Optionnel :

* editcap

## INSTALLATION

Installation des dépendances Python :

```
pip install openpyxl rich
```

Vérification de TShark :

```
tshark --version
```

## UTILISATION

Lancer le programme :

```
python tshark2hashcat.py
```

Menu principal :

```
[1] Analyser un PCAP
[2] Analyser un dossier
[0] Quitter
```

## ANALYSE D'UN PCAP

L'option 1 permet d'analyser une capture réseau.

Fichiers générés :

```
tshark2hashcat-rapport.xlsx
tshark2hashcat-rapport_m5500.txt
tshark2hashcat-rapport_m5600.txt
tshark2hashcat-rapport_m18200.txt
tshark2hashcat-rapport_m22000.txt
...
```

## ANALYSE D'UN DOSSIER

L'option 2 recherche récursivement les fichiers :

```
.pcap
.pcapng
.cap
.dmp
```

Les captures sont analysées puis regroupées dans un seul rapport Excel.

Les gros fichiers peuvent être découpés avec editcap.

L'analyse d'un dossier peut utiliser jusqu'à quatre workers en parallèle.

## SORTIES

Le rapport principal est :

```
tshark2hashcat-rapport.xlsx
```

Le classeur contient notamment :

```
Couverture
Findings
Expositions
Cartographie
MITRE
Chemins
Écarts
Analyse
OSINT
Identités
Hôtes
Secrets
Hashes
Wi-Fi
Fichiers
Captures
```

## EXTRACTION DES HASHES

Les hashes extraits sont automatiquement validés avant d'être écrits dans
les fichiers de sortie Hashcat.

Exemple :

```
tshark2hashcat-rapport_m32200.txt
```

Commande Hashcat :

```
hashcat -m 32200 -a 0 tshark2hashcat-rapport_m32200.txt wordlist.txt
```

La commande correspondante est également disponible dans le rapport Excel.

## DÉTECTION DES IDENTIFIANTS

L'outil recherche notamment les informations d'authentification visibles
dans les protocoles suivants :

```
FTP
Telnet
HTTP
SMTP
IMAP
POP
LDAP
PAP
TACACS+
NTLM
```

Les mécanismes HTTP Basic Authentication et Bearer Token sont également
analysés.

## INFORMATIONS RÉSEAU

L'outil peut extraire :

```
DNS
DHCP
NetBIOS
SMB
SYSVOL
TLS SNI
HTTP Host
URI
Hôtes
Adresses IP
Partages réseau
Fichiers
Identités Kerberos
```

## CLASSIFICATION

Les éléments extraits sont classés selon leur nature :

```
secret
identity
host
wifi
file
meta
noise
```

Plusieurs filtres permettent de limiter les faux positifs.

Exemples :

```
Les cookies Cloudflare sont filtrés.
Les comptes machine terminés par "$" ne sont pas considérés comme humains.
Les realms Active Directory ne sont pas considérés comme des personnes.
Les empreintes JA3 ne sont pas considérées comme des numéros de téléphone.
Les codes FTP sont considérés comme des métadonnées.
Les tickets TGS normaux ne sont pas automatiquement considérés comme du
Kerberoasting.
```

## KERBEROS

Les échanges Kerberos sont distingués :

```
AS-REQ
AS-REP
TGS-REP
```

L'outil différencie également le véritable Kerberoasting du trafic normal
lié aux services Active Directory.

Exemples de services qui ne sont pas automatiquement considérés comme du
Kerberoasting :

```
cifs/DC
ldap/DC
host/PC
netlogon/...
```

## AUDIT DE SÉCURITÉ

Le moteur d'audit génère des findings uniquement lorsqu'une preuve est
présente dans la capture.

Exemples :

```
Mot de passe en clair
NetNTLMv1
NetNTLMv2
AS-REP Roasting
Kerberoasting
LLMNR / NBNS
WPAD
LDAP en clair
Communauté SNMP
APOP
PMKID Wi-Fi
Cookies applicatifs
Exposition de données personnelles
Fichiers sensibles
```

Chaque finding contient :

```
ID
Gravité
Titre
Actifs concernés
Description
Preuve
Impact
Remédiation
Technique MITRE ATT&CK
```

## RAPPORT EXCEL

Le fichier :

```
tshark2hashcat-rapport.xlsx
```

contient plusieurs onglets permettant de consulter les résultats de
l'analyse.

COUVERTURE
Résumé exécutif, score, niveau de risque et périmètre observé.

FINDINGS
Détail des vulnérabilités et expositions détectées.

EXPOSITIONS
Vue synthétique des principales expositions.

CARTOGRAPHIE
Domaines, contrôleurs, utilisateurs, machines, partages et fichiers.

MITRE
Techniques MITRE ATT&CK déclenchées par les preuves observées.

CHEMINS
Chemins d'attaque reconstruits à partir des éléments présents.

ÉCARTS
Comparaison entre contrôles attendus et éléments observés.

ANALYSE
Statistiques et informations techniques sur la capture.

OSINT
Personnes, organisations, e-mails, machines, sites et IP.

IDENTITÉS
Identités Kerberos, NTLM et DHCP.

HÔTES
Hôtes détectés via DNS, SNI, NetBIOS et HTTP.

SECRETS
Secrets et identifiants détectés.

HASHES
Hashes extraits et commandes Hashcat correspondantes.

WI-FI
SSID, BSSID et PMKID.

FICHIERS
Partages SMB, chemins SYSVOL et fichiers détectés.

CAPTURES
Résumé des captures analysées lors d'une analyse de dossier.

## SCORING

Le score de sécurité ne repose pas simplement sur le nombre de paquets
ou de protocoles détectés.

Les findings sont regroupés par familles d'attaque.

La formule utilise ensuite des pondérations décroissantes afin d'éviter
qu'une même faiblesse soit comptée plusieurs fois.

Le rapport fournit :

```
Score
Niveau de risque
Findings
Familles d'attaque
Chemins d'attaque
```

## LIMITES

L'outil ne peut analyser que les informations présentes dans la capture.

Limites importantes :

* Une information absente du PCAP ne peut pas être récupérée.
* "Non observé" ne signifie pas "conforme".
* Un handshake WPA incomplet ne permet pas de fabriquer un hash valide.
* Certaines structures JSON de TShark peuvent rendre les statistiques
  incomplètes.
* L'onglet Hôtes peut contenir du trafic légitime et du bruit réseau.
* Un TGS vers un contrôleur de domaine ne prouve pas que son mot de passe
  est faible.
* L'outil n'exécute pas Hashcat.
* L'outil n'exécute pas Responder.
* L'outil n'exécute pas BloodHound.

## ARCHITECTURE

Le script principal contient notamment :

```
tshark2hashcat.py

Hashcat validators
Hashcat modes
Hashcat commands

Extracteur NTLM
Extracteur Kerberos
Extracteur APOP
Extracteur WPA
Extracteur de credentials
Extracteur de secrets
Autres extracteurs

Classification des résultats
Rapport réseau
Rapport OSINT

Rapport d'audit
Rapport Excel
Briefing terminal
```

## VERSION

Version documentée :

```
2.7.0
```

## AUTEUR

Thomas Thedie

Administration systèmes et réseaux
Cybersécurité

## UTILISATION

Projet destiné notamment à :

```
CTF
Laboratoires de sécurité
Pentest
Analyse réseau
Forensic réseau
Audit de sécurité
Formation cybersécurité
```

Utiliser uniquement cet outil sur des captures réseau pour lesquelles
vous disposez d'une autorisation.

## DOCUMENTATION

La documentation technique détaillée décrit le fonctionnement interne,
les extracteurs, les règles de classification, le scoring et les onglets
du rapport Excel. Le fonctionnement général documenté est basé sur
l'analyse TShark puis l'extraction et la validation des éléments détectés.
