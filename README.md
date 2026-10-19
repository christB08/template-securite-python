# TP1 — IDS/IPS en Python avec Scapy

## Présentation du projet

Ce projet a été réalisé dans le cadre du TP1 de sécurité réseau.

L'objectif est de développer un outil d'analyse de trafic réseau en Python, utilisant la bibliothèque **Scapy**, afin d'identifier les protocoles présents dans une capture PCAP et de détecter plusieurs comportements suspects.

L'outil fonctionne hors ligne à partir d'un fichier PCAP et génère un rapport JSON contenant les résultats de l'analyse.

## Fonctionnalités

### 1. Analyse des protocoles réseau

L'application identifie et comptabilise les paquets associés aux protocoles suivants :

- Ethernet
- ARP
- IP
- TCP
- UDP
- ICMP
- DNS
- HTTP

Un même paquet peut être comptabilisé dans plusieurs protocoles selon les couches réseau qu'il contient.

### 2. Détection des attaques

**ARP Spoofing**

Identification des conflits d'association IP/MAC dans les réponses ARP. Lorsqu'une même adresse IP est annoncée par plusieurs adresses MAC, l'outil utilise une heuristique basée sur le nombre de réponses ARP pour sélectionner une adresse MAC suspecte.

**Scan de ports SYN**

Analyse des paquets TCP SYN pour identifier une source qui tente de contacter plusieurs ports de destination distincts.

**Injection SQL**

Analyse des requêtes HTTP afin de rechercher des motifs caractéristiques d'injections SQL, notamment `OR 1=1` et `UNION SELECT`.

### 3. Extraction du flag

L'outil recherche un flag au format `ESGI{...}` dans les paramètres des requêtes HTTP de la capture.

### 4. Génération du rapport

L'analyse produit un fichier JSON contenant :

- Les statistiques des protocoles.
- Les attaques détectées.
- Les adresses IP ou MAC des attaquants présumés.
- Le flag extrait de la capture.

## Technologies utilisées

- Python
- Scapy
- Poetry
- Git
- Pre-commit
- Ruff

## Installation

### Prérequis

- Python compatible avec la version indiquée dans `pyproject.toml`
- Poetry
- Un terminal Linux ou WSL

### Étapes

Cloner le dépôt :

```bash
git clone <URL_DU_DEPOT>
cd <DOSSIER_DU_PROJET>
```

Installer les dépendances :

```bash
poetry install
```

## Utilisation

Lancer l'analyse d'un fichier PCAP :

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

**Arguments :**

| Argument | Description |
|---|---|
| `--pcap` | Chemin du fichier PCAP à analyser |
| `--out` | Chemin du fichier JSON à générer |

L'analyse fonctionne hors ligne et ne nécessite pas de connexion réseau.

## Exemple de rapport JSON

```json
{
  "protocols": {
    "TCP": 95,
    "UDP": 12,
    "ARP": 20,
    "ICMP": 16,
    "Ethernet": 143,
    "IP": 123,
    "DNS": 12,
    "HTTP": 13
  },
  "attacks": [
    {
      "type": "arp_spoofing",
      "attacker": "02:34:5b:f0:b3:a8"
    },
    {
      "type": "port_scan",
      "attacker": "192.168.213.66"
    },
    {
      "type": "sql_injection",
      "attacker": "192.168.213.77"
    }
  ],
  "flag": "ESGI{exemple}"
}
```

Les résultats dépendent du contenu du fichier PCAP analysé.

## Organisation du projet

Le code principal se trouve dans le répertoire `src/tp1/`.

- `main.py` : point d'entrée de l'application et gestion des arguments.
- `utils/capture.py` : lecture des PCAP, analyse des protocoles et détection des attaques.
- `utils/report.py` : génération du rapport JSON.
- `utils/config.py` : configuration de la journalisation.

## Limites

La détection ARP repose sur une heuristique : la MAC qui émet le plus de réponses pour une IP en conflit n'est pas nécessairement l'attaquant dans toutes les situations.

La détection SQLi repose sur des motifs connus et ne garantit pas l'identification de toutes les variantes d'injection SQL.

L'outil est destiné à l'analyse pédagogique de captures réseau et ne constitue pas un système de prévention en temps réel.

## Auteur

Projet réalisé dans le cadre du TP1 de cybersécurité — ESGI.