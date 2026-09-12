<p align="center">
  <img src="banner.png" alt="tshark2hashcat" width="100%">
</p>

<h1 align="center">tshark2hashcat</h1>

<p align="center">
  <b>Analyse de captures réseau avec TShark, extraction de hashes et analyse des identifiants.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/TShark-Wireshark-1679a7?style=for-the-badge&logo=wireshark&logoColor=white">
  <img src="https://img.shields.io/badge/Hashcat-ready-d75fff?style=for-the-badge">
  <img src="https://img.shields.io/badge/license-Apache--2.0-5fd75f?style=for-the-badge">
</p>

<p align="center">
  <code>v1.2.0</code>
</p>

> Audit, pentest, CTF et recherche. Utilisez uniquement des captures que vous êtes autorisé à analyser.

---

# Utilisation

Le moyen le plus simple d'utiliser `tshark2hashcat` est le **menu interactif**.

```bash
python tshark2hashcat.py
```

Le programme affiche :

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

Le type d'entrée est automatiquement détecté pour l'option `3`. Il suffit donc de choisir le numéro puis de fournir le chemin demandé.

---

# 1. MOTEUR : nouveau projet

L'option **1** lance le moteur complet sur un dossier contenant les captures.

```text
Votre choix : 1

Dossier du projet (captures .pcap / .pcapng / .cap / .json) :
```

Le programme demande ensuite où écrire les résultats :

```text
OÙ ÉCRIRE LES FICHIERS DE SORTIE ? (rapports, hashes, journaux)

  défaut (Entrée) : <dossier de sortie>

  autre dossier   : tapez son chemin complet

  Dossier de sortie :
```

Puis éventuellement un fichier de connaissances :

```text
Fichier de connaissances — lignes type:valeur ou JSON (Entrée = aucun) :
```

Et le mode profond :

```text
Mode profond — échelles complètes, sans budget temps ? [o/N] :
```

Ces questions correspondent directement au parcours du wizard.

Une fois l'analyse terminée :

```text
TOUT EST DANS : <dossier de sortie>

ouvrez d'abord GUIDE.txt (le guide), puis
RAPPORT.txt (rapport texte) ou rapport.html
(double-clic → navigateur)
```

### Ce mode est destiné à l'analyse complète

Le moteur projet regroupe notamment :

```text
Captures
   ↓
Analyse
   ↓
Extraction
   ↓
Solveurs
   ↓
Post-crack
   ↓
Rapports
```

Il peut ensuite être rouvert avec l'option `2`.

---

# 2. MOTEUR : ouvrir un projet

L'option **2** permet de reprendre un projet existant.

```text
Votre choix : 2

Dossier projet (celui qui contient data.json) :
```

Le programme ouvre ensuite le sous-menu du projet :

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

Ce sous-menu correspond directement aux fonctions présentes dans le code.

## 2.1 Poursuivre

```text
Votre choix : 1
```

Permet de reprendre l'analyse du projet et d'effectuer de nouveaux rounds.

Le programme demande éventuellement un fichier de connaissances :

```text
Fichier de connaissances à importer avant les rounds (Entrée = aucun) :
```

---

## 2.2 Knowledge Base

```text
Votre choix : 2
```

Le programme demande éventuellement :

```text
Filtrer par statut (VALIDATED / CORRELATED / OBSERVED…, Entrée = tous) :
Filtrer par type (password / secret / pmk / hash…, Entrée = tous) :
Fichier de connaissances à importer (Entrée = aucun) :
```

---

## 2.3 Graphe

```text
Votre choix : 3
```

Lance le graphe de connaissances du projet.

```text
graph.dot
```

est généré par la commande correspondante.

---

## 2.4 Hashes Hashcat

```text
Votre choix : 4
```

Le programme demande éventuellement une wordlist :

```text
Wordlist à associer aux commandes hashcat (Entrée = aucune) :
```

Puis traite les cibles Hashcat du projet.

Les commandes générées peuvent notamment utiliser :

```text
Dictionnaire
Rules
Combinator
Mask
Hybrid
```

Par exemple, le code génère des commandes de type :

```bash
hashcat -m <mode> -a 1 -O -w 3 <hashfile> <wordlist> <wordlist>
```

ou :

```bash
hashcat -m <mode> -a 3 -O -w 3 <hashfile> ?l?l?l?l?l?l?l?l
```

et :

```bash
hashcat -m <mode> --show <hashfile>
```

---

## 2.5 Rapport HTML

```text
Votre choix : 5
```

Le rapport HTML du projet est ouvert automatiquement dans le navigateur lorsqu'il existe.

Si le navigateur ne peut pas être ouvert automatiquement :

```text
aucun navigateur trouvé — ouvrez manuellement : <rapport.html>
```

---

## 2.6 Inventaire réseau

```text
Votre choix : 6
```

Cette fonction permet d'extraire les informations réseau d'une capture.

Elle peut produire notamment :

```text
secrets
tokens
SNI
e-mails
identités
PII
métadonnées
protocoles
```

Les sorties d'inventaire sont écrites en TXT, JSON et CSV dans la version actuelle du code.

---

# 3. Mode classique

L'option **3** est le mode le plus simple pour analyser rapidement une capture.

```text
Votre choix : 3

Fichier OU dossier de captures
(.pcap / .pcapng / .cap / .json) :
```

Le programme détecte automatiquement si le chemin fourni correspond à un fichier ou à un dossier.

### Fichier

```text
Votre choix : 3

Fichier OU dossier de captures :
C:\captures\capture.pcapng
```

Le programme lance automatiquement :

```text
auto
```

### Dossier

```text
Votre choix : 3

Fichier OU dossier de captures :
C:\captures\
```

Le programme lance automatiquement :

```text
folder
```

---

# Exemple : analyse classique d'une capture

```text
◆ tshark2hashcat

Votre choix : 3

Fichier OU dossier de captures :
C:\CTF\capture.pcapng

[INFO] Analyse de la capture...
[INFO] Extraction TShark...
[INFO] Analyse des protocoles...
[INFO] Extraction des hashes...
[INFO] Génération des rapports...
```

Les messages exacts dépendent naturellement du contenu de la capture. Mettre une sortie avec `NTLM : 4`, `Kerberos : 12` et `password : 2` dans un README serait très joli, mais ce serait aussi inventer des résultats. L'outil, lui, n'a malheureusement pas la délicatesse de produire toujours la même capture pour nous arranger.

---

# Formats générés

Le mode classique peut générer différents formats d'analyse, notamment :

```text
TXT
CSV
JSON
XLSX
HTML
Markdown
```

Le code déclare ces formats dans ses constantes d'export et dans la CLI.

Les fichiers Hashcat sont également séparés par mode lorsque l'extraction produit plusieurs types de hashes.

Exemples de noms :

```text
*_m5600.txt
*_m5500.txt
*_m22000.txt
```

---

# Hashcat

Le programme associe les hashes extraits aux modes Hashcat correspondants.

Quelques modes présents dans le catalogue du code :

|    Mode | Type            |
| ------: | --------------- |
|    `20` | APOP            |
|  `4800` | CHAP            |
|  `5500` | NetNTLMv1       |
|  `5600` | NetNTLMv2       |
|  `7500` | Kerberos        |
| `11400` | SIP Digest      |
| `13100` | Kerberos TGS    |
| `16500` | JWT             |
| `18200` | Kerberos AS-REP |
| `22000` | WPA             |
| `32100` | Kerberos AS-REP |
| `32200` | Kerberos AS-REP |

Le catalogue du code contient également de nombreux autres modes Hashcat génériques.

---

# Exemple de fichier Hashcat

Pour un hash associé au mode `5600`, le projet peut générer un fichier de cible accompagné de commandes.

```text
hash.txt
hashcat.txt
```

Une commande peut prendre la forme :

```bash
hashcat -m 5600 -a 0 -O -w 3 hash.txt wordlist.txt
```

Et pour afficher les résultats déjà récupérés :

```bash
hashcat -m 5600 --show hash.txt
```

Le code génère également des variantes par masque et hybride.

---

# Diagnostic

Avant de commencer :

```bash
python tshark2hashcat.py doctor
```

Le diagnostic vérifie la présence des outils et dépendances nécessaires au fonctionnement du programme.

---

# Utilisation directe

Le menu n'est pas obligatoire.

Une capture peut être passée directement :

```bash
python tshark2hashcat.py capture.pcap
```

Un dossier :

```bash
python tshark2hashcat.py ./captures
```

Le programme détecte alors automatiquement le type d'entrée et l'oriente vers le traitement correspondant.

---

# Résumé du menu

```text
┌──────────────────────────────────────────────────────────────┐
│                    tshark2hashcat                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. MOTEUR                                                   │
│     Nouveau projet complet                                   │
│                                                              │
│  2. MOTEUR                                                   │
│     Ouvrir un projet existant                                │
│                                                              │
│  3. CLASSIQUE                                                │
│     Fichier OU dossier → analyse automatique                 │
│                                                              │
│  0. Quitter                                                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Le parcours typique

```text
Pour une analyse complète :

python tshark2hashcat.py
        │
        └── 1
             │
             ├── dossier de captures
             ├── dossier de sortie
             ├── knowledge optionnel
             └── mode profond optionnel
                    │
                    ▼
                 PROJET
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       solve    knowledge   graph
          │
          ▼
       targets
          │
          ▼
       rapports
```

### Pour une analyse rapide

```text
python tshark2hashcat.py
        │
        └── 3
             │
             ├── fichier → auto
             │
             └── dossier → folder
```

---

# Licence

Le code fourni indique la licence :

```text
Apache-2.0
```

Version actuelle du fichier :

```text
1.2.0
```
