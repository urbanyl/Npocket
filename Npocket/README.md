# Npocket

**Npocket** est un clone moderne, léger, et modulaire de Nmap écrit entièrement en Python, conçu pour des scans réseau performants, avec une architecture propre et lisible.

## Fonctionnalités Clés
- **Ultra Rapide (Asyncio)** : Scan complet de ports propulsé par la boucle événementielle `asyncio`, permettant d'analyser des milliers de ports par seconde sans surcharger la mémoire.
- **Découverte d'Hôtes** : Vérification de la disponibilité asynchrone (ICMP ping via subprocess asynchrones).
- **Scan de Ports** : Scans TCP Connect et UDP gérés de façon asynchrone pour une performance maximale.
- **Détection de Services (Améliorée)** : Envoi de multiples payloads (sondes HTTP, FTP, raw) pour maximiser les chances de récupérer la bannière du service en cours d'exécution.
- **Fingerprinting OS** : Détection basique du système d'exploitation en analysant les valeurs TTL.
- **Rapports Modernes et Interface Riche** : Affichage console esthétique (couleurs ANSI), barres de progression en temps réel, et export des résultats en JSON, CSV, et Markdown.

## Structure de l'Architecture

Le projet suit des principes stricts de séparation des responsabilités :
- `cli/` : Gère les arguments et le point d'entrée. Exécute la boucle asynchrone.
- `parse/` : Responsable du parsing intelligent des IPs (CIDR, plages) et des ports.
- `scan/` : Cœur de la logique (découverte, scan TCP/UDP, fingerprinting, services). Totalement refactorisé avec `asyncio`.
- `report/` : Gère le rendu visuel (UI) et l'export dans différents formats.
- `utils/` : Fournit les configurations globales, couleurs UI, et le système de logging.

## Prérequis
Npocket fonctionne avec **Python 3.7+** et n'a besoin d'**aucune dépendance externe** (il utilise les modules standard : `asyncio`, `socket`, `subprocess`, `ipaddress`).

## Exemples d'Utilisation

> **Note pour les utilisateurs Windows :** Si la commande `python` vous renvoie une erreur (Microsoft Store), utilisez `py` à la place (ex: `py Npocket/cli/main.py ...`).

Depuis la racine du projet, lancez Npocket via le module `cli.main` :

1. **Scan Simple TCP (Top 100 ports)**
```bash
python Npocket/cli/main.py 192.168.1.1
```

2. **Découverte d'Hôtes Uniquement (Ping Sweep) sur un sous-réseau**
```bash
python Npocket/cli/main.py 192.168.1.0/24 -sn
```

3. **Scan Complet avec Détection d'OS et Services**
```bash
python Npocket/cli/main.py 192.168.1.1-50 -p 22,80,443 -sV -O
```

4. **Scan Ultra Rapide (Asyncio) sur les 65535 ports avec Export JSON**
```bash
python Npocket/cli/main.py 10.0.0.1 -p all -c 1000 -oJ resultats.json
```

5. **Scan UDP**
```bash
python Npocket/cli/main.py 192.168.1.1 -sU -p 53,161
```

## Choix Techniques
- **Asyncio (Moteur Principal)** : Plutôt que d'utiliser de coûteux threads système (`ThreadPoolExecutor`), Npocket utilise `asyncio.open_connection` avec un système de sémaphore pour réguler le nombre de connexions concurrentes (par défaut 500, configurable via `-c`). Cela permet de scanner l'ensemble des 65535 ports TCP en quelques secondes.
- **Sans Privilèges Spéciaux** : Contrairement à Nmap ou Scapy qui nécessitent les droits root pour forger des paquets bruts (Raw Sockets), Npocket utilise des sockets standards (TCP Connect) pour être utilisable par n'importe quel utilisateur.
- **Sondes Multiples** : La détection de service ne se contente pas d'attendre passivement une bannière ; elle envoie des sondes HTTP ou génériques si le port reste silencieux, imitant ainsi le comportement des signatures Nmap.

---
Développé avec ❤️ pour l'analyse réseau moderne.
