# RustGuard

**Pare-feu Applicatif Minimaliste en Rust**

Un pare-feu applicatif en mode utilisateur écrit en Rust qui filtre les connexions sortantes basées sur des règles personnalisables. Comprend un système de journalisation pour suivre les tentatives de connexion suspectes et le blocage dynamique d'adresses IP ou de ports spécifiques.

## Auteurs

Développé par **Guillaume**, **Theo**, **Mohamed** et **Youness**

## Fonctionnalités

- **Pare-feu en Mode Utilisateur** : Aucun module noyau ou modification système requis
- **Filtrage des Connexions Sortantes** : Contrôlez quelles applications peuvent accéder au réseau
- **Filtrage Basé sur des Règles** : Définissez des règles personnalisées pour autoriser ou bloquer les connexions
- **Journalisation Complète** : Suivez toutes les tentatives de connexion avec des informations détaillées
- **Blocage Dynamique IP/Port** : Bloquez automatiquement les adresses IP ou ports suspects
- **Faible Utilisation des Ressources** : Empreinte mémoire et CPU minimale
- **Support IPv4 et IPv6** : Support complet pour IPv4 et IPv6
- **Liste Blanche Configurable** : Protection des IPs critiques contre le blocage automatique
- **Seuils de Blocage Automatique** : Blocage automatique après un nombre défini de tentatives

## Prérequis

- **Rust et Cargo** (version 1.70.0 ou plus récente)
- **Système d'exploitation Linux** (pour la fonctionnalité de capture de paquets)
- **Privilèges administrateur** (pour la capture de paquets réseau)

## Installation

### Compilation depuis les sources

```bash
# Cloner le dépôt
git clone https://github.com/votre-repo/rustguard.git
cd rustguard

# Compiler le projet
cargo build --release

# Le binaire sera disponible dans target/release/rustguard
```

### Vérification de la compilation

```bash
# Vérifier que la compilation s'est bien passée
ls -la target/release/rustguard

# Vérifier la version
./target/release/rustguard --version
```

## Configuration

RustGuard utilise un fichier de configuration TOML. La configuration par défaut est incluse dans `config.toml`.

### Exemple de configuration

```toml
# Configuration de RustGuard

[general]
interface = "default"  # Utilise "default" pour l'interface système par défaut
default_action = "block"  # Action par défaut si aucune règle ne correspond

# Définition des règles de pare-feu
[[rules]]
name = "Allow HTTP"
action = "allow"
direction = "outbound"
protocol = "tcp"
dst_port = 80
enabled = true

[[rules]]
name = "Allow HTTPS"
action = "allow"
direction = "outbound"
protocol = "tcp"
dst_port = 443
enabled = true

[[rules]]
name = "Allow DNS"
action = "allow"
direction = "outbound"
protocol = "udp"
dst_port = 53
enabled = true

[blocklist]
enabled = true
auto_block_threshold = 5  # Bloque après ce nombre de tentatives
block_duration = 3600  # Durée du blocage en secondes (1 heure)
whitelist = ["127.0.0.1", "::1"]  # Toujours autoriser ces IPs
```

## Utilisation

### Commandes de base

```bash
# Exécuter avec les paramètres par défaut
sudo ./target/release/rustguard

# Exécuter avec un fichier de configuration personnalisé
sudo ./target/release/rustguard -c ma_config.toml

# Exécuter en mode verbeux pour le débogage
sudo ./target/release/rustguard -v

# Spécifier un fichier de log personnalisé
sudo ./target/release/rustguard -l rustguard_personnalise.log
```

### Options de ligne de commande

- `-c, --config-file <FILE>` : Chemin vers le fichier de configuration (défaut : config.toml)
- `-l, --log-file <FILE>` : Chemin vers le fichier de log (défaut : rustguard.log)
- `-v, --verbose` : Activer la journalisation verbeuse
- `-f, --foreground` : Exécuter au premier plan (ne pas daemoniser)
- `-h, --help` : Afficher les informations d'aide
- `-V, --version` : Afficher les informations de version

### Exemples d'utilisation pratiques

#### 1. Configuration restrictive (par défaut)
```bash
# Bloque tout sauf HTTP, HTTPS et DNS
sudo ./target/release/rustguard
```

#### 2. Configuration permissive pour développement
Modifiez `config.toml` :
```toml
[general]
default_action = "allow"  # Autoriser par défaut
```

#### 3. Blocage spécifique d'un service
Ajoutez dans `config.toml` :
```toml
[[rules]]
name = "Block SSH"
action = "block"
direction = "outbound"
protocol = "tcp"
dst_port = 22
enabled = true
```

## Règles de Pare-feu

RustGuard utilise un système basé sur des règles pour décider quelles connexions autoriser ou bloquer :

- **Name** : Nom descriptif de la règle
- **Action** : Action à effectuer avec les paquets correspondants (`allow`, `block`, `log`)
- **Direction** : Direction du paquet (`outbound`, `inbound`, `any`)
- **Protocol** : Protocole réseau (`tcp`, `udp`, `icmp`, `any`)
- **Source IP** : Adresse IP source ou réseau CIDR
- **Destination IP** : Adresse IP de destination ou réseau CIDR
- **Source Port** : Numéro de port source
- **Destination Port** : Numéro de port de destination
- **Enabled** : Si la règle est active

Les règles sont évaluées dans l'ordre, et la première règle correspondante détermine l'action.

## Journalisation

RustGuard enregistre toutes les tentatives de connexion, incluant :

- Horodatage
- Adresses IP source et destination
- Ports source et destination
- Protocole
- Taille du paquet
- Action prise (autorisé, bloqué, enregistré)

Les logs sont stockés dans le fichier spécifié (défaut : `rustguard.log`).

### Exemple de logs

```
INFO ALLOW TCP 192.168.1.100:45234 -> 93.184.216.34:443 (1024 bytes)
INFO BLOCK TCP 192.168.1.100:45235 -> 142.250.191.14:22 (512 bytes)
INFO Auto-blocked IP 10.0.0.50 for excessive connection attempts
```

## Blocage Dynamique

RustGuard peut automatiquement bloquer les adresses IP qui présentent un comportement suspect :

- Tentatives de connexion excessives
- Scan de ports
- Tentatives de connexion échouées

Les IPs bloquées sont temporairement ajoutées à la liste noire pour la durée configurée.

## Résolution des Problèmes

### Erreurs communes

1. **"Privilèges insuffisants"**
   ```bash
   # Solution : Exécuter avec sudo
   sudo ./target/release/rustguard
   ```

2. **"Impossible de créer le fichier de log"**
   ```bash
   # Vérifier les permissions du répertoire
   chmod 755 .
   ```

3. **"Interface réseau non trouvée"**
   ```bash
   # Lister les interfaces disponibles
   ip link show
   # Modifier config.toml avec le bon nom d'interface
   ```

##⚠️ AVERTISSEMENT - UTILISATION RESPONSABLE

**IMPORTANT : Cet outil doit être utilisé de manière responsable et légale.**

### Utilisation Autorisée
- Protection de vos propres systèmes et réseaux
- Tests de sécurité avec autorisation explicite
- Recherche académique dans un environnement contrôlé
- Administration de systèmes dont vous êtes responsable

### Utilisation Interdite
- ❌ **Ne PAS utiliser sur des réseaux ou systèmes qui ne vous appartiennent pas**
- ❌ **Ne PAS utiliser pour des activités malveillantes ou illégales**
- ❌ **Ne PAS utiliser pour intercepter ou bloquer le trafic d'autres utilisateurs sans autorisation**
- ❌ **Ne PAS utiliser dans un environnement de production sans tests préalables**

### Responsabilités de l'Utilisateur
- Vous êtes entièrement responsable de l'utilisation de cet outil
- Assurez-vous de respecter les lois locales et internationales
- Obtenez toujours une autorisation écrite avant de tester sur des systèmes tiers
- Documentez vos activités de test de sécurité

### Déni de Responsabilité
Les auteurs de RustGuard ne sont pas responsables de l'utilisation abusive de cet outil. L'utilisation de cet outil implique l'acceptation de ces conditions et la responsabilité complète de l'utilisateur.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à soumettre une Pull Request.

### Comment contribuer
1. Fork le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Commitez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## Licence

Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.

## Support

Pour signaler des bugs ou demander des fonctionnalités, veuillez ouvrir une issue sur le dépôt GitHub.

---

**RustGuard** - Un pare-feu moderne et sécurisé pour protéger vos connexions réseau.
