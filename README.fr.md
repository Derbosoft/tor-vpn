# Tor-VPN Manager — v3.6.1

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.6.1-blue)
![Systemd](https://img.shields.io/badge/Systemd-service-lightgrey?logo=linux)

> [English documentation](README.md)

Daemon + interface graphique pour router **tout le trafic réseau via OpenVPN tunnelé dans Tor** sur Ubuntu/Debian. Le daemon tourne en arrière-plan en tant que service systemd et gère automatiquement Tor, OpenVPN, le blocage IPv6, le partage LAN et la surveillance de connectivité.

---

## Table des matières

1. [Architecture globale](#architecture-globale)
2. [Prérequis](#prérequis)
3. [Installation](#installation)
4. [Structure du projet](#structure-du-projet)
5. [Interface graphique](#interface-graphique)
6. [CLI `tor-vpn`](#cli-tor-vpn)
7. [Fonctionnement détaillé du daemon](#fonctionnement-détaillé-du-daemon)
8. [Chaînes iptables](#chaînes-iptables)
9. [Failover et watchdog](#failover-et-watchdog)
10. [Partage LAN](#partage-lan)
11. [DNS split — Domaines locaux](#dns-split--domaines-locaux)
12. [Configuration Tor (torrc)](#configuration-tor-torrc)
13. [Réparation réseau automatique](#réparation-réseau-automatique)
14. [Format config.json](#format-configjson)
15. [Tests](#tests)
16. [Sécurité](#sécurité)
17. [Premiers pas](#premiers-pas)
18. [Désinstallation](#désinstallation)

---

## Architecture globale

```
Utilisateur
    │
    ├── tor-vpn gui          ──►  GUI (main.py → gui/app.py)
    │                              • Lit/écrit config.json et torrc
    │                              • Appelle systemctl via pkexec
    │                              • Ne touche jamais aux processus réseau
    │
    ├── tor-vpn <commande>   ──►  CLI wrapper (/usr/local/bin/tor-vpn)
    │                              • Appelle systemctl
    │
    └── systemd              ──►  tor-vpn-manager.service
                                   │
                                   └── daemon/  (root)
                                         │
                                         ├── Tor  (subprocess, port 9050/9051)
                                         │         └── torrc optionnel
                                         │
                                         ├── OpenVPN ──► SOCKS5 127.0.0.1:9050 ──► Tor ──► Internet
                                         │              (tunX, redirect-gateway)
                                         │
                                         ├── iptables  (IPv6 block, LAN sharing)
                                         │
                                         └── Watchdog  (connectivité)


Flux réseau complet :
  Application → tunX → OpenVPN → SOCKS5:9050 → Tor → Relais Tor → Serveur VPN → Internet
```

Le GUI et le daemon sont **entièrement découplés** : le GUI écrit uniquement des fichiers de configuration et invoque systemd. Il ne surveille aucun processus et ne peut pas interférer avec la connexion active.

---

## Prérequis

| Composant | Version minimale | Rôle |
|-----------|-----------------|------|
| Ubuntu / Debian | 20.04 / 11 | Système de base |
| Python | 3.8+ | Daemon + GUI |
| python3-tk | — | Interface graphique |
| tor | — | Proxy SOCKS5 et réseau Tor |
| openvpn | 2.4+ | Tunnel chiffré vers le fournisseur VPN |
| dnsmasq | — | **Optionnel** — serveur DHCP, uniquement pour le partage LAN |
| curl | — | Mesure de débit et tests de connectivité |
| systemd + systemd-resolved | — | Gestion du service et DNS |

---

## Installation

```bash
sudo bash install.sh
```

L'installateur effectue **6 étapes** :

**1. Dépendances**
```bash
apt install tor openvpn python3 python3-tk curl
```
`dnsmasq` ne sert qu'au partage LAN (désactivé par défaut) : depuis la v3.6.1 il n'est installé que s'il est déjà présent ou si le partage est configuré, plutôt qu'installé puis désactivé aussitôt. Pour l'ajouter plus tard : `sudo apt install dnsmasq`.

**2. Répertoire de configuration**
- Crée `/etc/tor-vpn-manager/` en `root:torvpn 2770` (groupe torvpn : GUI sans root)
- Écrit `/etc/tor-vpn-manager/install_dir` contenant le chemin d'installation (utilisé par le CLI)
- Installe un **torrc par défaut** (circuits longs et stables) s'il n'en existe pas déjà un — un torrc personnalisé n'est jamais écrasé
- Migration automatique si une config existe dans `/root/.config/tor-vpn-manager/` ou `/opt/tor-vpn-manager/`

**3. Services système**
- Active et démarre `systemd-resolved`
- **Désactive** et **arrête** le service `tor` système — le daemon gère Tor directement en subprocess pour contrôler précisément son démarrage, ses logs et son redémarrage

**4. Service systemd**
Crée `/etc/systemd/system/tor-vpn-manager.service` :
- `ExecStartPre` : script de nettoyage iptables (efface les règles orphelines d'une session précédente)
- `ExecStart` : `python3 -m daemon` lancé depuis le répertoire d'installation
- `ExecStopPost` : même script de nettoyage
- `Restart=on-failure` avec un délai de 20s, tentatives illimitées (`StartLimitIntervalSec=0`)
- `Type=notify` + `WatchdogSec=90` : le daemon signale sa vivacité toutes les ~3s ; s'il gèle (deadlock), systemd le tue et le relance
- `KillMode=control-group` : systemd tue tout le groupe (Tor, OpenVPN, dnsmasq inclus)
- `TimeoutStopSec=30`

**5. Hook veille/réveil**
Installe `/lib/systemd/system-sleep/tor-vpn-sleep` : redémarre automatiquement le daemon 3 secondes après chaque réveil de veille ou hibernation. Sans ce hook, les circuits Tor sont périmés au réveil mais le port 9050 reste ouvert, ce qui amène OpenVPN à se reconnecter sans passer par Tor.

**6. CLI et lanceur GUI**
- Installe `/usr/local/bin/tor-vpn` (copie de `tor-vpn-cli.sh`)
- Crée `/etc/xdg/autostart/tor-vpn-gui.desktop` (apparaît dans les applications)

---

## Structure du projet

```
tor-vpn-manager/
├── main.py              Point d'entrée GUI — vérifie les droits root, lance ConfigApp
├── constants.py         Constantes partagées GUI + daemon (chemins, palette, config par défaut)
├── install.sh           Script d'installation Ubuntu/Debian
├── repair_network.sh    Script de réparation réseau (nettoyage iptables, routes, DNS)
├── tor-vpn-cli.sh       Source du CLI — copié dans /usr/local/bin/tor-vpn par install.sh
├── template.ovpn        Modèle commenté pour créer un fichier .ovpn compatible
├── run-tests.sh         Lanceur de la suite de tests (+ empreinte réseau avant/après)
│
├── daemon/              Package daemon (lancé par systemd via python3 -m daemon)
│   ├── __init__.py      Classe Daemon (agrège tous les mixins) + fonction main()
│   ├── __main__.py      Point d'entrée python3 -m daemon
│   ├── core.py          DaemonCore — état partagé, config, log, signaux, orchestration
│   ├── tor.py           TorMixin — démarrage/arrêt Tor, torrc optionnel, ControlPort
│   ├── network.py       NetworkMixin — gateway, SOCKS, protection routes Tor /32
│   ├── firewall.py      FirewallMixin — iptables/ip6tables, blocage IPv6, partage LAN, dnsmasq
│   ├── dns.py           DNSMixin — split DNS via systemd-resolved drop-in
│   ├── openvpn.py       OpenVPNMixin — boucle OpenVPN, failover fournisseurs
│   └── watchdog.py      WatchdogMixin — surveillance connectivité, redémarrage complet
│
├── gui/                 Package interface graphique
│   ├── __init__.py
│   └── app.py           ConfigApp — interface tkinter complète (6 onglets)
│
├── tests/               Suite de tests (unittest, aucune dépendance externe)
│   ├── helpers.py       Daemon factice + interception des commandes système
│   ├── test_network.py      routes exclues, passerelle, protection des guards
│   ├── test_tor.py          parsing ControlPort, bootstrap, NEWNYM
│   ├── test_dns.py          DNS du VPN, split DNS, revérification périodique
│   ├── test_firewall.py     blocage IPv6, partage LAN, plage DHCP
│   ├── test_openvpn.py      identifiants, qualité de circuit, reconnexion
│   ├── test_watchdog.py     connectivité, filet anti-inertie, redémarrage
│   ├── test_config_status.py  chargement de config, socket de statut
│   ├── test_core_lifecycle.py ControlPort réel, nettoyage, arrêt propre
│   ├── test_gui.py          validation des saisies, torrc, obfuscation
│   ├── test_scripts.py      syntaxe shell, unité systemd, cohérence des versions
│   └── test_safety.py       garde-fou : la suite ne touche pas au système
│
└── providers/           Dossier des fichiers .ovpn par fournisseur (non versionné)
    └── <NomFournisseur>/
        └── <fichier>.ovpn
```

**Fichiers générés à l'installation / à l'usage :**
```
/etc/tor-vpn-manager/
├── config.json               Configuration principale (mode 600, root:root)
├── torrc                     Configuration Tor personnalisée (mode 600, optionnel)
├── install_dir               Chemin d'installation (lu par le CLI)
├── auth.tmp                  Credentials OpenVPN temporaires (créé/supprimé à chaque connexion)
├── tor-vpn-routes.txt        Routes /32 Tor actives (persistance inter-redémarrages)
└── tor_data/                 Données persistantes de Tor (descripteurs, clés, cache)

/etc/systemd/system/tor-vpn-manager.service
/etc/systemd/resolved.conf.d/tor-vpn-split.conf   (si DNS split activé)
/lib/systemd/system-sleep/tor-vpn-sleep
/usr/local/bin/tor-vpn
/usr/local/lib/tor-vpn-cleanup.sh
/etc/xdg/autostart/tor-vpn-gui.desktop
```

---

## Interface graphique

### Lancement

```bash
tor-vpn gui          # Méthode recommandée — tourne avec votre utilisateur (groupe torvpn)
python3 main.py      # Lancement direct — actions privilégiées via pkexec
```

### Onglet Fournisseurs

Gère la liste des fournisseurs VPN et leurs comptes. L'ordre de la liste définit la priorité de connexion et de failover.

**Fournisseur :**
- Nom libre (ex : ProtonVPN, Mullvad)
- Fichier `.ovpn` associé — copié dans `providers/<NomFournisseur>/` lors de la sélection
- Boutons ↑ ↓ pour réordonner la priorité

**Comptes par fournisseur :**
- Chaque fournisseur peut avoir plusieurs comptes (identifiant + mot de passe)
- Stockés en base64 dans `config.json` (obfuscation simple, voir [Sécurité](#sécurité))
- Boutons ↑ ↓ pour réordonner ; le daemon tente les comptes dans l'ordre

**Failover automatique :** si les identifiants d'un compte sont refusés, le daemon passe au compte suivant du même fournisseur. Sur une coupure réseau, il réessaie le même compte avant de changer de fournisseur — voir [Failover et watchdog](#failover-et-watchdog).

**Import / Export `.tvpn` :** archive ZIP contenant `config.json` + tous les fichiers `.ovpn`. Permet de transférer la configuration complète entre machines.

### Onglet Exclusions

#### DNS split — domaines locaux

Permet de router les requêtes DNS pour des domaines spécifiques vers votre serveur DNS local, tout en laissant le reste passer par le DNS du VPN.

| Champ | Description |
|-------|-------------|
| **Serveur DNS local** | IP de votre serveur DNS (ex : `10.0.50.253`) |
| **Domaines** | Domaines à router vers ce DNS (ex : `.derbo`, `.local`, `.home`) |

> **Important :** le réseau contenant votre serveur DNS doit figurer dans les **IPs/Réseaux exclus** ci-dessous.

#### IPs / Réseaux exclus du tunnel

CIDRs et IPs qui contournent le tunnel et passent par la passerelle locale. Le daemon injecte `--route <ip> <mask> net_gateway` dans la commande OpenVPN.

> **IPv4 uniquement.** `--route` est une option IPv4 ; une entrée IPv6 serait acceptée puis ignorée par OpenVPN, en laissant croire à tort que le réseau est exclu. Depuis la v3.6.1, le GUI refuse la saisie et le daemon écarte ces entrées avec un avertissement dans le journal.

**Cas d'usage typiques :**
- Réseaux joignables **via un routeur** (autres VLAN, sites distants : `10.0.20.0/24`…)
- Sous-réseau du serveur DNS s'il est derrière un routeur — **obligatoire si DNS split activé**
- **Sous-réseau d'un VPN d'accès distant** (WireGuard/OpenVPN d'administration) : sans cette exclusion, les réponses vers votre client partiraient dans le tunnel Tor et **votre session SSH/RDP serait coupée** dès l'activation du service
- NAS, imprimante réseau, serveurs locaux situés derrière le routeur

> **Les réseaux directement connectés n'ont pas à être exclus — et ne doivent pas l'être.**
>
> Le réseau de votre propre carte (ex. `10.0.50.0/24` sur `ens18`) possède déjà une route kernel `scope link` en `/24`, plus spécifique que le `redirect-gateway` du VPN (`0.0.0.0/1`) : par *longest prefix match*, il reste **de toute façon hors tunnel**.
>
> L'exclure superposerait une route `via <passerelle>` de métrique 0 qui **supplanterait la route directe** : tout le trafic vers votre propre LAN ferait alors un détour par le routeur (*hairpin*), souvent refusé — ce qui casse notamment l'accès à un serveur VPN hébergé sur ce même segment.
>
> Le daemon **détecte et ignore automatiquement** ces exclusions inutiles, avec un message dans le journal.

### Onglet Paramètres

| Paramètre | Valeur par défaut | Description |
|-----------|------------------|-------------|
| **Bloquer IPv6** | désactivé | DROP ip6tables sur OUTPUT + FORWARD |
| **Reconnexion auto** | activé | Relance le tunnel automatiquement |
| **Qualité du circuit Tor** | activé | Mesure le débit à la connexion, re-tire un circuit s'il est trop lent |
| **Débit minimum** | 250 KB/s | Seuil sous lequel le circuit est re-tiré (≈ 2 Mbps ; l'équivalent Mbps est affiché à côté du champ) |
| **Essais maximum** | 3 | Nombre de re-tirages avant de conserver le circuit tel quel |
| **Démarrage auto** | désactivé | `systemctl enable/disable tor-vpn-manager` |

**Bouton "Réparer le réseau" :** lance `repair_network.sh` manuellement — arrête le service, nettoie toutes les règles iptables, routes et DNS bloqués, puis invite à redémarrer le service. Utile quand la connexion est totalement bloquée malgré un redémarrage du service.

### Onglet Partage LAN

Partage le tunnel Tor+VPN avec des appareils connectés sur une deuxième interface réseau.

| Paramètre | Description |
|-----------|-------------|
| **Interface** | Carte réseau à utiliser (filtre automatiquement lo, tun*, docker*, etc.) |
| **IP de la carte** | IP passerelle assignée à cette interface (ex : `10.0.0.1`) |
| **Sous-réseau CIDR** | Plage DHCP (ex : `10.0.0.0/24`) |
| **Serveur DHCP** | Lance dnsmasq automatiquement |
| **Activer au démarrage** | Démarre le partage dès que le tunnel est actif |

### Onglet Tor (torrc)

Permet de personnaliser la configuration de Tor via un fichier `torrc` dédié. `install.sh` en installe un par défaut (valeurs ci-dessous) ; s'il est supprimé, Tor démarre avec les paramètres minimaux intégrés au daemon.

Les valeurs par défaut privilégient des circuits longs et stables, adaptés à
un tunnel OpenVPN persistant. Chaque option reste ajustable individuellement
ci-dessous, ou via le mode expert (édition directe du torrc).

**Options configurables :**

| Option | Description |
|--------|-------------|
| `LongLivedPorts 1194,443` | Préfère des relais stables pour les ports OpenVPN |
| `LearnCircuitBuildTimeout 0` | Timeout de circuit fixe (plus prévisible) |
| `MaxCircuitDirtiness` | Durée max d'un circuit avant renouvellement (s) |
| `CircuitBuildTimeout` | Délai max de construction d'un circuit (s) |
| `NewCircuitPeriod` | Fréquence de construction de nouveaux circuits (s) |
| `KeepalivePeriod` | Envoi de cellules keepalive pour maintenir les circuits NAT |
| `NumEntryGuards` | Nombre de nœuds d'entrée (guards) |
| `GuardLifetime` | Durée de conservation des guards |
| `AvoidDiskWrites 1` | Réduit les écritures disque |
| `SafeLogging 1` | Masque les IPs dans les logs Tor |
| `ClientUseIPv6 0` | Désactive IPv6 pour Tor |
| `TestSocks 1` | Avertit si une requête DNS locale est détectée |
| `ConnectionPadding 1` | Résistance à l'analyse de trafic (↑ bande passante) |
| `ExcludeExitNodes` | Exclure des nœuds de sortie par pays (format `{us},{gb}`) |
| `StrictNodes` | Strict sur les exclusions (peut couper si aucun nœud disponible) |

**Mode expert :** zone de texte éditable affichant le torrc complet. Se met à jour en temps réel quand les options changent. Peut être édité directement pour des paramètres avancés.

**Bouton Appliquer** → écrit `/etc/tor-vpn-manager/torrc` + redémarre le service.
**Bouton Réinitialiser** → supprime le torrc + redémarre avec la config minimale du daemon.

> Les paramètres obligatoires (`SocksPort`, `ControlPort`, `CookieAuthentication`, `DataDirectory`) sont toujours garantis à l'application.

---

## CLI `tor-vpn`

```bash
# Contrôle du service (requiert root)
sudo tor-vpn start       # Démarre le daemon
sudo tor-vpn stop        # Arrête le daemon
sudo tor-vpn restart     # Redémarre le daemon
sudo tor-vpn enable      # Active le démarrage automatique au boot
sudo tor-vpn disable     # Désactive le démarrage automatique

# Interface graphique
tor-vpn gui

# Surveillance
tor-vpn status           # État complet : service, Tor, VPN, DNS split, IP publique
tor-vpn logs [n]         # n dernières lignes de journal (défaut : 60)
tor-vpn follow           # Logs en direct (Ctrl+C pour quitter)
tor-vpn ip               # IP publique actuelle
```

---

## Fonctionnement détaillé du daemon

### Séquence de démarrage complète

```
1.  Nettoyage des règles iptables orphelines (session précédente)
2.  Démarrage de Tor en subprocess (avec torrc si présent)
3.  Attente du bootstrap Tor 100% (timeout 240s max)
4.  Démarrage de la boucle OpenVPN dans un thread dédié
5.  Démarrage de la boucle de monitoring dans le thread principal
```

### Gestion de Tor

Tor est lancé directement en subprocess (pas via le service système).

**Sans torrc personnalisé** (config minimale intégrée) :
```
--SocksPort 9050  --ControlPort 9051  --CookieAuthentication 1
--DataDirectory /etc/tor-vpn-manager/tor_data  --Log notice stdout
```

**Avec torrc personnalisé** (créé via l'onglet Tor du GUI) :
```
tor --torrc-file /etc/tor-vpn-manager/torrc --Log notice stdout
```
Le `--Log notice stdout` est toujours ajouté en ligne de commande pour que le daemon puisse détecter le bootstrap, quelle que soit la configuration du torrc.

Si Tor crash, il est redémarré automatiquement (jusqu'à 5 fois avec délai de 15s).

### Gestion d'OpenVPN

```
openvpn
  --config            <fichier.ovpn>
  --auth-user-pass    /etc/tor-vpn-manager/auth.tmp
  --verb              3          ← requis pour net_addr_v4_add dans les logs
  --ping              10
  --ping-exit         60
  --connect-timeout   60         ← allongé car les circuits Tor peuvent être lents
  --connect-retry     1
  --connect-retry-max 1
  --socks-proxy       127.0.0.1 9050
  [--route <ip> <mask> net_gateway ...]
```

> **Depuis la v3.6.1 : plus de `--script-security 2`.** Aucun fichier `.ovpn` n'a besoin de scripts — le daemon applique lui-même le DNS du VPN via `resolvectl`. Autoriser l'exécution de scripts permettait en revanche à quiconque peut écrire un `.ovpn` (le groupe `torvpn`) de faire exécuter du code **par le daemon, en root**, via une simple directive `up`.
>
> Les exécutables **intégrés** d'OpenVPN restent autorisés au niveau 1 : sur OpenVPN 2.6+, le hook natif `/usr/libexec/openvpn/dns-updown` continue donc de fonctionner normalement. Seuls les scripts définis dans le `.ovpn` sont bloqués — et le daemon avertit désormais dans le journal si un `.ovpn` en contient un (`up`, `down`, `route-up`, `ipchange`, `tls-verify`…), qu'il existe sur le disque ou non.

**Protection des routes Tor :**
Dès qu'OpenVPN assigne une IP au tunnel (`net_addr_v4_add`, visible grâce à `--verb 3`), le daemon ajoute de façon **synchrone** des routes `/32` statiques vers toutes les IP de guards Tor actifs via la passerelle locale originale. Cela doit s'exécuter *avant* que le script `up` n'installe les routes `redirect-gateway`. Sans cette protection, Tor tenterait de joindre ses guards via le tunnel, créant une boucle qui coupe la connexion. Les routes sont persistées dans `/etc/tor-vpn-manager/tor-vpn-routes.txt` et supprimées proprement à chaque arrêt.

**DNS split timing :**
Le DNS du VPN est géré nativement par le daemon : les serveurs poussés par le VPN (`PUSH_REPLY`, `dhcp-option DNS`) sont extraits de la sortie d'OpenVPN et appliqués sur l'interface tunnel via `resolvectl` (aucun script `update-resolv-conf` requis). Le DNS split est ensuite appliqué **après** `Initialization Sequence Completed` ; son drop-in systemd-resolved garde la priorité sur les domaines exclus.

**Robustesse du DNS :**
- Au démarrage, le daemon vérifie que `resolvectl` est présent et que `systemd-resolved` est actif — sinon il avertit clairement dans le journal (sans lui, la résolution DNS peut échouer ou fuir hors Tor).
- Toutes les ~30 s, il **revérifie** que la configuration DNS de l'interface tunnel est toujours en place. Si un outil tiers a redémarré `systemd-resolved` (ce qui efface la config *runtime* par interface), elle est **réappliquée automatiquement**. En temps normal c'est une simple lecture : aucune réécriture, aucun `reload` inutile.

  Depuis la v3.6.1, le contrôle porte sur les **trois** attributs posés (serveurs DNS, domaine `~.`, `default-route`) et non plus sur les seuls serveurs. Motif : lors d'une reconnexion interne (`SIGUSR1`), le hook natif `dns-updown` d'OpenVPN 2.6+ réinstalle les serveurs mais pas nécessairement le reste — et sans `~.`, l'interface tunnel cesse d'être la destination DNS par défaut, si bien que les requêtes publiques peuvent repartir vers le DNS local, hors tunnel, sans que rien ne le signale.

**Séquence à la connexion :**
Quand `Initialization Sequence Completed` est détecté :
1. DNS split appliqué (après le script up d'OpenVPN)
2. Blocage IPv6 activé (si configuré)
3. Partage LAN démarré (si `lan_auto = true`)

### Hook veille/réveil

`/lib/systemd/system-sleep/tor-vpn-sleep` est appelé par le noyau à chaque événement de veille/réveil. Au réveil (`post`), il attend 3 secondes puis exécute `systemctl restart tor-vpn-manager`. Ce délai laisse le temps aux interfaces réseau de se reconnecter avant que le daemon ne relance Tor.

---

## Chaînes iptables

Le daemon crée des **chaînes nommées dédiées** pour un nettoyage propre sans interférer avec d'autres règles.

### Blocage IPv6 — `TORVPN_KS6` / `TORVPN_KS6_FWD`

```
OUTPUT/FORWARD :
RETURN  → lo
RETURN  → tunX
RETURN  → ESTABLISHED,RELATED
DROP    → tout le reste (IPv6)
```

Protège contre les fuites IPv6 quand le fournisseur VPN ne le supporte pas.

### Partage LAN — `TORVPN_LAN_FWD` (FORWARD)

```
RETURN  → ESTABLISHED,RELATED
RETURN  → <iface_lan> → tunX
DROP    → <iface_lan> → tout le reste

NAT POSTROUTING : MASQUERADE source=<subnet_lan> out=tunX
```

---

## Failover et watchdog

### Reconnexion : deux causes, deux réponses

Quand le processus OpenVPN se termine, le daemon distingue **la nature de la rupture** avant de décider (comportement de la v3.6.1) :

| Cause détectée | Réponse | Délai |
|----------------|---------|-------|
| **Identifiants refusés** (`AUTH_FAILED` ou `SIGTERM[soft,auth-failure]`) | Compte suivant du même fournisseur | 3 s |
| **Tout le reste** (coupure réseau, TLS expiré, `ping-exit`) | **Même compte**, jusqu'à `RECONNECT_MAX` (5) fois | 15 s |
| Le même compte échoue 5 fois de suite | **Fournisseur suivant**, compte 1 | 3 s |
| Plus aucun fournisseur de secours | Abandon → filet anti-inertie → relance systemd | — |

Le point clé : **changer de compte ne sert que si le compte est en cause.** Tous les comptes d'un fournisseur partagent le même fichier `.ovpn`, donc la même liste de serveurs — en changer n'a aucun effet sur une panne réseau ou côté serveur. Seul le changement de *fournisseur* en a.

> **Avant la v3.6.1**, toute rupture déclenchait un failover de compte. Une simple coupure réseau brûlait les dix comptes iVPN puis ceux de ProtonVPN en une trentaine de secondes (3 s d'écart), sans que la temporisation de 15 s n'entre jamais en jeu : jusqu'à 65 tentatives d'authentification en rafale sur une panne prolongée. La logique actuelle en fait 12, espacées de 15 s — moins agressif pour le fournisseur, et bien plus susceptible de réussir puisqu'une coupure réseau se répare d'elle-même.

Un défaut qui touche le fournisseur entier (`.ovpn` introuvable) fait aussi passer directement au fournisseur suivant, sans parcourir ses comptes un à un.

### Détection de panne

Le watchdog vérifie la connectivité toutes les **9 secondes** (après un délai de grâce de **30 secondes** post-connexion) :

1. `ip link show tunX` — l'interface existe-t-elle ?
2. Connexion TCP via `SO_BINDTODEVICE tunX` (timeout 5s) vers `1.1.1.1:443`, puis `9.9.9.9:443` en second avis — le tunnel route-t-il vraiment ? Deux endpoints indépendants : la panne ponctuelle de l'un ne déclenche pas de redémarrage pour rien.

Si la vérification échoue **2 fois de suite** (~28s max) : `_full_restart()` — arrêt complet Tor + OpenVPN, nettoyage des routes `/32` orphelines, redémarrage complet.

**Filet anti-inertie :** les boucles Tor/OpenVPN abandonnent après un nombre borné de tentatives. Si plus aucune boucle VPN ne tourne pendant **2 minutes** (reconnexion auto active), le daemon quitte volontairement (`exit 1`) : systemd le relance intégralement (`Restart=on-failure`, tentatives illimitées). Aucune panne, même longue, ne laisse le daemon dans un état inerte définitif.

**Watchdog systemd :** la boucle de monitoring envoie `WATCHDOG=1` à systemd toutes les ~3s (`sd_notify`, également pendant l'attente du bootstrap Tor). Si le processus Python lui-même gèle — deadlock, appel système suspendu — les pings cessent et systemd tue puis relance le daemon après 90s (`WatchdogSec=90`). Chaîne de survie complète : boucles internes → filet anti-inertie → watchdog systemd.

Si la connectivité revient après un redémarrage, le compteur est remis à zéro.

### Réparation automatique d'urgence

Si **3 redémarrages complets consécutifs** échouent tous (compteur `_full_restart_count`), le watchdog déclenche `_emergency_repair()` :

```
1. Lance repair_network.sh --internal
   → nettoie iptables (IPv6 + LAN), routes OpenVPN bloquées, DNS systemd-resolved
   → ne touche pas au service systemd (le daemon reste maître)
2. sys.exit(1)
   → systemd détecte le crash et relance automatiquement le daemon (Restart=on-failure)
```

**Séquence type en cas de blocage total :**
```
[WARN] Watchdog : pas de connectivité (1/2) …
[WARN] Watchdog : pas de connectivité (2/2) …
[ERROR] Watchdog : redémarrage complet (1/3) …
[WARN] Watchdog : pas de connectivité (1/2) …
[ERROR] Watchdog : redémarrage complet (2/3) …
[WARN] Watchdog : pas de connectivité (1/2) …
[ERROR] Watchdog : redémarrage complet (3/3) …
[ERROR] 3 redémarrages échoués — lancement de repair_network.sh …
[WARN]  Réparation terminée — sortie pour relance systemd.
← systemd relance le daemon automatiquement
```

### Contrôle qualité du circuit Tor

Le circuit Tor est **tiré au sort à chaque connexion** : sa qualité varie fortement d'un tirage à l'autre (de ~100 KB/s à plusieurs Mo/s). Juste après l'établissement du tunnel, le daemon effectue **une mesure unique** du débit réel (téléchargement de 2 Mo *à travers* le tunnel) :

```
Tunnel actif → 5 s de stabilisation → mesure du débit
   ├─ ≥ seuil  → circuit conservé, aucune autre mesure
   └─ < seuil  → SIGNAL NEWNYM  (force un circuit neuf)
                 → reconnexion OpenVPN (même fournisseur/compte)
                 → nouvelle mesure … jusqu'à « essais maximum »
                 → au-delà : circuit conservé (jamais de boucle)
```

Deux points de conception importants :

- **La mesure crée elle-même la demande qu'elle mesure.** Une lecture passive des compteurs d'interface serait ininterprétable : un débit faible signifierait aussi bien « le lien est lent » que « rien n'est demandé ». Ici, un résultat faible signifie sans ambiguïté que le circuit est mauvais.
- **`NEWNYM` est envoyé *avant* la reconnexion.** Il ne change pas le circuit d'une connexion déjà établie — il garantit que la *prochaine* connexion partira sur un circuit neuf. Sans lui, `MaxCircuitDirtiness` ferait réutiliser le même circuit, donc les mêmes relais lents.

**Aucune surveillance continue** : ce test ne tourne pas en tâche de fond et ne consomme rien après la connexion.

Exemple réel :
```
[WARN] [circuit] Débit faible : 127 KB/s (~1.0 Mbps) < 250 KB/s — nouveau tirage (1/3) …
[OK  ] [tor] Nouveau circuit demandé (NEWNYM).
[WARN] Reconnexion sur un circuit Tor neuf …
[OK  ] [circuit] Débit OK : 568 KB/s (~4.5 Mbps).
```

### Logique de failover

```
Fournisseur 1, Compte 1 → Fournisseur 1, Compte 2 → ... → Fournisseur 2, Compte 1 → ...
Tous épuisés → retour au début → abandon après 5 tentatives
```

### Arrêt propre (SIGTERM / SIGINT)

```
1. SIGTERM → OpenVPN
2. SIGTERM → Tor
3. Suppression des routes /32 Tor
4. Démontage partage LAN + arrêt dnsmasq
5. Suppression chaînes ip6tables
6. Suppression drop-in DNS split
7. Suppression auth.tmp
```

---

## Partage LAN

Quand le partage LAN est activé :

1. IP passerelle assignée à l'interface LAN (`ip addr add`)
2. Routage IP activé (`sysctl net.ipv4.ip_forward=1`)
3. NAT MASQUERADE pour que le trafic LAN sorte par le tunnel
4. Chaîne `TORVPN_LAN_FWD` : bloque tout trafic LAN n'allant pas vers le tunnel
5. dnsmasq en mode `--no-daemon` : DHCP dans le sous-réseau, DNS `1.1.1.1` via tunnel

Si le tunnel tombe, le trafic LAN est bloqué — aucune fuite par la connexion directe.

Les règles des étapes 3 et 4 figent le **nom de l'interface tunnel**. Comme les `.ovpn` utilisent `dev tun` (premier device libre), ce nom peut changer au remontage du tunnel. Depuis la v3.6.1, le daemon compare l'interface mémorisée à l'interface courante et **reconstruit les règles** si elles diffèrent (avec une trace en `WARN`) : sans cela, elles pointaient dans le vide et le trafic LAN tombait sur la règle `DROP` finale — coupure totale et silencieuse jusqu'au redémarrage du service.

---

## DNS split — Domaines locaux

Permet d'accéder à des services hébergés sur votre réseau local avec un nom de domaine personnalisé **pendant que le VPN est actif**.

### Pourquoi c'est nécessaire

Sans DNS split, le `redirect-gateway def1` du VPN route tout le trafic via le tunnel — y compris les paquets vers votre DNS local, qui devient inaccessible.

Avec DNS split :
- `.derbo` → votre DNS local (`10.0.50.253`)
- Tout le reste → DNS du VPN via Tor

### Configuration

**Dans l'onglet Exclusions du GUI :**

1. Saisir l'IP du serveur DNS local
2. Ajouter les domaines locaux (ex : `.derbo`)
3. Ajouter le sous-réseau du DNS dans les IPs exclues (ex : `10.0.50.0/24`) — **étape critique**
4. Sauvegarder + Redémarrer

Le daemon génère automatiquement :

```ini
# /etc/systemd/resolved.conf.d/tor-vpn-split.conf
[Resolve]
DNS=10.0.50.253
Domains=~derbo
```

### Vérification

```bash
resolvectl status            # voir les domaines routés
dig serveur.derbo            # doit résoudre via 10.0.50.253
tor-vpn status               # affiche "DNS split : actif (→ 10.0.50.253)"
```

---

## Configuration Tor (torrc)

`install.sh` installe `/etc/tor-vpn-manager/torrc` avec les valeurs par défaut (sans écraser un fichier existant), et l'onglet **Tor (torrc)** du GUI permet de le modifier. Si ce fichier existe, le daemon le passe à Tor via `--torrc-file`. S'il est absent, Tor démarre avec les arguments minimaux intégrés.

### Paramètres obligatoires (toujours présents)

```ini
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /etc/tor-vpn-manager/tor_data
```

### Valeurs par défaut (circuits longs et stables)

```ini
LongLivedPorts 1194,443
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 3600
CircuitBuildTimeout 60
NewCircuitPeriod 60
KeepalivePeriod 60
NumEntryGuards 3
GuardLifetime 2 months
AvoidDiskWrites 1
SafeLogging 1
ClientUseIPv6 0
TestSocks 1
```

Pour un anonymat renforcé, activez par exemple `ConnectionPadding 1` et
`ExcludeExitNodes {us},{gb},{ca},{au},{nz}` — toutes les options sont
ajustables dans l'onglet ou en mode expert.

### Réinitialisation

Le bouton **Réinitialiser** supprime le fichier torrc. Au prochain démarrage du service, Tor tourne avec les paramètres minimaux sans fichier de configuration externe.

---

## Réparation réseau automatique

`repair_network.sh` est le script de récupération d'urgence. Il peut être déclenché de **trois façons** :

| Déclencheur | Mode | Comportement |
|-------------|------|--------------|
| Bouton GUI "Réparer le réseau" | manuel | Arrête le service, nettoie tout, invite à redémarrer |
| `sudo bash repair_network.sh` | manuel CLI | Identique au bouton GUI |
| Watchdog (3 redémarrages échoués) | automatique | `--internal` : nettoie sans `systemctl stop`, puis `sys.exit(1)` pour relance systemd |

**Ce que le script nettoie :**

1. Processus OpenVPN et Tor résiduels (`pkill`)
2. Chaînes ip6tables `TORVPN_KS6` / `TORVPN_KS6_FWD` (blocage IPv6)
3. Chaîne iptables `TORVPN_LAN_FWD`, dnsmasq du partage, et la règle NAT `MASQUERADE` associée
4. DNS systemd-resolved — `resolvectl revert` sur `tun0` et `tun1`, suppression du drop-in, redémarrage de `systemd-resolved`
5. Routes `/32` des relais Tor, lues dans `tor-vpn-routes.txt` — sans quoi le trafic vers ces IPs continuerait de contourner le tunnel après la réparation
6. Routes OpenVPN def1 bloquées (`0.0.0.0/1`, `128.0.0.0/1`, `default`) sur `tun0` et `tun1`
7. Vérification de connectivité finale (`ip route get 1.1.1.1`, `getent ahosts`)

> Les points 3, 5 et l'extension à `tun1` datent de la v3.6.1 : le script laissait auparavant des routes `/32` et une règle NAT orphelines, et ne traitait que `tun0` alors que les `.ovpn` utilisent `dev tun`.

---

## Format config.json

`/etc/tor-vpn-manager/config.json` — mode `660 root:torvpn`.

```json
{
  "providers": [
    {
      "name": "ProtonVPN",
      "ovpn_file": "providers/ProtonVPN/server.ovpn",
      "accounts": [
        { "u": "dXNlcm5hbWU=", "p": "cGFzc3dvcmQ=" }
      ]
    }
  ],
  "auto_reconnect": true,
  "block_ipv6": false,
  "excluded_ips": ["192.168.1.0/24", "10.0.50.0/24"],
  "excluded_domains": [".derbo"],
  "local_dns": "10.0.50.253",
  "circuit_check": true,
  "circuit_min_kbs": 250,
  "circuit_max_retries": 3,
  "lan_iface": "",
  "lan_gateway": "10.0.0.1",
  "lan_subnet": "10.0.0.0/24",
  "lan_dhcp": true,
  "lan_auto": false,
  "autostart": false
}
```

| Clé | Type | Description |
|-----|------|-------------|
| `providers[].ovpn_file` | string | Chemin relatif au répertoire d'installation |
| `providers[].accounts[].u` | string | Identifiant en base64 |
| `providers[].accounts[].p` | string | Mot de passe en base64 |
| `excluded_ips` | liste | CIDRs/IPs passant par la passerelle locale |
| `excluded_domains` | liste | Domaines routés vers le DNS local |
| `local_dns` | string | IP du serveur DNS local |
| `circuit_check` | bool | Mesure du débit à la connexion + re-tirage si circuit lent |
| `circuit_min_kbs` | int | Seuil en KB/s (250 ≈ 2 Mbps ; 0 = désactivé) |
| `circuit_max_retries` | int | Re-tirages max avant de conserver le circuit |

---

## Tests

Le projet est couvert par une suite de **285 tests** (`unittest`, aucune dépendance externe) :

```bash
bash run-tests.sh                 # tout
bash run-tests.sh -v              # détail test par test
bash run-tests.sh tests.test_openvpn   # un module
```

**La suite ne touche jamais au système.** `iptables`, `ip`, `resolvectl`, `systemctl`, `curl`, `openvpn` et `tor` sont interceptés et enregistrés au lieu d'être exécutés : les tests vérifient *quelles commandes auraient été lancées*, avec quels arguments et dans quel ordre. On peut donc lancer la suite sur la machine de production, tunnel monté, sans risque. `run-tests.sh` relève une empreinte réseau avant et après pour le prouver, et `tests/test_safety.py` interdit à un futur test de contourner cette règle.

Ce qui est couvert, au-delà des chemins nominaux :

| Domaine | Exemples de cas vérifiés |
|---------|--------------------------|
| Routes exclues | IPv6 refusé, réseau directement connecté ignoré (piège scope-link), CIDR normalisé |
| ControlPort | consensus microdesc (8 champs) *et* ns (9 champs), une seule connexion pour N requêtes, plafond de 32 relais |
| DNS | serveur/domaine `~.`/default-route contrôlés séparément, abstention si l'état est illisible |
| Pare-feu | `DROP` toujours en dernière règle, refus de flusher l'uplink, reconstruction si le tunnel change de nom |
| Qualité de circuit | seuil exact, plafond d'essais, thread périmé qui ne doit pas tuer le tunnel suivant |
| Reconnexion | identifiants refusés vs coupure réseau, nombre de tentatives borné |
| Sécurité | `auth.tmp` en 0600 même sous umask permissif, aucun identifiant dans le socket de statut, anti-path-traversal de l'import |
| Cohérence | version identique dans `constants.py` et les deux READMEs, `--script-security` absent du code |

Plusieurs tests exercent aussi le système en **lecture seule** pour valider les parseurs contre la réalité plutôt que contre un échantillon figé (format de `/proc/net/dev`, sortie de `resolvectl status`).

---

## Sécurité

**Credentials VPN :** stockés en base64 dans `config.json`. C'est de l'obfuscation, **pas du chiffrement**. Le fichier est en mode `660 root:torvpn`, dans un répertoire `2770 root:torvpn`.

**auth.tmp :** créé directement en mode `600` (jamais exposé à l'umask) juste avant de lancer OpenVPN, supprimé dans le bloc `finally` dès qu'OpenVPN a lu le fichier.

**torrc :** mode `660 root:torvpn`.

**Portée du groupe `torvpn` :** ce groupe existe pour que le GUI tourne **sans root**. Il donne en contrepartie l'accès en écriture à des fichiers que le daemon consomme en root (`config.json`, `torrc`, `providers/*.ovpn`) — ses membres doivent donc être considérés comme des administrateurs de la machine. N'y ajoutez que des comptes de confiance. La v3.6.1 ferme le vecteur le plus direct en retirant `--script-security 2` (voir *Gestion d'OpenVPN*), mais le principe reste : `torvpn` ≈ privilèges élevés.

**Scripts `.ovpn` :** l'exécution de scripts définis dans un `.ovpn` est désactivée. Un `.ovpn` qui en contient est signalé dans le journal et échouera à se connecter — supprimez la directive, le daemon gère le DNS lui-même.

**Tor comme proxy :** le serveur VPN voit l'IP d'un nœud de sortie Tor, jamais votre IP réelle. Votre FAI voit que vous utilisez Tor, mais ne sait pas que vous utilisez un VPN ni quelle destination vous atteignez.

---

## Premiers pas

```bash
# 1. Installer
sudo bash install.sh

# 2. Ouvrir l'interface de configuration
tor-vpn gui

# 3. Onglet Fournisseurs :
#    a. "+ Ajouter" → nom du fournisseur
#    b. "Choisir / Changer" → sélectionner votre fichier .ovpn
#    c. "+ Ajouter compte" → identifiant + mot de passe

# 4. (Optionnel) Onglet Tor (torrc) :
#    - Ajuster les options si besoin (défauts adaptés à l'usage courant)
#    - Cliquer "Appliquer + Redémarrer"

# 5. (Optionnel) Onglet Exclusions :
#    - DNS local + domaines + sous-réseau DNS dans les IPs exclues

# 6. Sauvegarder

# 7. Démarrer
sudo tor-vpn start

# 8. Suivre le démarrage
tor-vpn follow
# Attendre "Tunnel VPN actif." (Tor bootstrap = 1-3 minutes)

# 9. Vérifier
tor-vpn status
```

---

## Désinstallation

```bash
sudo tor-vpn stop
sudo systemctl disable tor-vpn-manager
sudo rm /etc/systemd/system/tor-vpn-manager.service
sudo rm /lib/systemd/system-sleep/tor-vpn-sleep
sudo rm /usr/local/bin/tor-vpn
sudo rm /usr/local/lib/tor-vpn-cleanup.sh
sudo rm /etc/xdg/autostart/tor-vpn-gui.desktop
sudo rm -f /etc/systemd/resolved.conf.d/tor-vpn-split.conf
sudo rm -rf /etc/tor-vpn-manager
sudo systemctl daemon-reload
sudo resolvectl reload
```
