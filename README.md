# tshark2hashcat

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Wireshark](https://img.shields.io/badge/Wireshark-Tshark-orange)
![Hashcat](https://img.shields.io/badge/Hashcat-Compatible-red)
![License](https://img.shields.io/badge/Usage-Security%20Research-green)

## Description

`tshark2hashcat` est un outil Python permettant d'extraire automatiquement des hashes d'authentification crackables depuis des captures réseau **PCAP/PCAPNG**.

Le script utilise uniquement **Tshark** pour analyser les paquets et transforme les authentifications détectées en formats directement compatibles avec **Hashcat**.

Il supporte principalement les environnements **Active Directory**, les analyses réseau, les laboratoires cybersécurité et les challenges CTF.

---

# Fonctionnalités

## Protocoles supportés

### NTLMSSP

Extraction :

| Type | Hashcat Mode |
|------|--------------|
| NetNTLMv2 | 5600 |
| NetNTLMv1 | 5500 |

Fonctions :

- Analyse NTLMSSP via les champs Tshark
- Association Challenge / Response
- Détection NTLMSSP dans les données brutes
- Support des encapsulations Base64 (HTTP, IMAP, SMTP)

---

### Kerberos

Extraction :

| Attaque | Type | Hashcat Mode |
|-|-|-|
| AS-REQ | Kerberos Pre-Authentication | 7500 / 19800 / 19900 |
| AS-REP Roast | Kerberos AS-REP | 18200 / 32100 / 32200 |
| Kerberoasting | TGS-REP | 13100 / 19600 / 19700 |

Support :

- RC4-HMAC
- AES128
- AES256
- Extraction utilisateur
- Extraction Realm
- Extraction SPN
- Extraction des salts Kerberos

---

# Fonctionnement
