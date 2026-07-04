#!/usr/bin/env bash
# Tor-VPN Manager — Installation (Ubuntu/Debian)
# Usage : sudo bash install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$SCRIPT_DIR'); from constants import VERSION; print(VERSION)" 2>/dev/null || echo "?")"
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
SERVICE_FILE="/etc/systemd/system/tor-vpn-manager.service"
CLEANUP_SCRIPT="/usr/local/lib/tor-vpn-cleanup.sh"
SLEEP_HOOK="/lib/systemd/system-sleep/tor-vpn-sleep"
CLI_BIN="/usr/local/bin/tor-vpn"
CONFIG_DIR="/etc/tor-vpn-manager"
DESKTOP_FILE="/etc/xdg/autostart/tor-vpn-gui.desktop"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Tor-VPN Manager v$VERSION — Installation              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Répertoire : $SCRIPT_DIR"
echo "  Utilisateur: $REAL_USER"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERREUR : ce script doit être lancé en root."
    echo "  sudo bash install.sh"
    exit 1
fi

# ── [1/6] Dépendances ────────────────────────────────────────────────────────
echo "[1/6] Installation des dépendances …"
apt-get update -qq
apt-get install -y tor openvpn python3 python3-tk dnsutils dnsmasq curl

# ── [2/6] Répertoire de configuration ───────────────────────────────────────
echo "[2/6] Répertoire de configuration …"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
echo "$SCRIPT_DIR" > "$CONFIG_DIR/install_dir"
echo "    Créé : $CONFIG_DIR"

mkdir -p "$SCRIPT_DIR/providers"

# Migration depuis une installation précédente
for OLD in "/root/.config/tor-vpn-manager" "/home/$REAL_USER/.config/tor-vpn-manager" \
           "/opt/tor-vpn-manager"; do
    if [ -f "$OLD/config.json" ] && [ ! -f "$CONFIG_DIR/config.json" ]; then
        echo "    Migration config : $OLD → $CONFIG_DIR"
        cp "$OLD/config.json" "$CONFIG_DIR/config.json"
    fi
done

# ── [3/6] Services système ───────────────────────────────────────────────────
echo "[3/6] Configuration des services système …"

systemctl enable systemd-resolved
systemctl start  systemd-resolved

# Tor géré en subprocess par le daemon — évite le conflit sur le port 9050
systemctl disable tor 2>/dev/null || true
systemctl stop    tor 2>/dev/null || true

# dnsmasq système désactivé (lancé à la demande par le daemon pour le partage LAN)
systemctl disable dnsmasq 2>/dev/null || true
systemctl stop    dnsmasq 2>/dev/null || true

# ── [4/6] Service systemd ────────────────────────────────────────────────────
echo "[4/6] Création du service systemd …"

# Script de nettoyage des règles iptables (appelé avant démarrage et après arrêt)
cat > "$CLEANUP_SCRIPT" << 'CLEANUP_EOF'
#!/bin/bash
ip6tables -D OUTPUT  -j TORVPN_KS6      2>/dev/null
ip6tables -F TORVPN_KS6                 2>/dev/null
ip6tables -X TORVPN_KS6                 2>/dev/null
ip6tables -D FORWARD -j TORVPN_KS6_FWD  2>/dev/null
ip6tables -F TORVPN_KS6_FWD            2>/dev/null
ip6tables -X TORVPN_KS6_FWD            2>/dev/null
iptables  -D FORWARD -j TORVPN_LAN_FWD  2>/dev/null
iptables  -F TORVPN_LAN_FWD            2>/dev/null
iptables  -X TORVPN_LAN_FWD            2>/dev/null
pkill -x dnsmasq                         2>/dev/null
# NAT masquerade du partage LAN
CONFIG_JSON="/etc/tor-vpn-manager/config.json"
if [ -f "$CONFIG_JSON" ]; then
    LAN_SUBNET=$(python3 -c "import json; d=json.load(open('$CONFIG_JSON')); print(d.get('lan_subnet',''))" 2>/dev/null)
    if [ -n "$LAN_SUBNET" ]; then
        iptables -t nat -D POSTROUTING -s "$LAN_SUBNET" -o tun0 -j MASQUERADE 2>/dev/null
        iptables -t nat -D POSTROUTING -s "$LAN_SUBNET" -o tun1 -j MASQUERADE 2>/dev/null
    fi
fi
# DNS split drop-in
rm -f /etc/systemd/resolved.conf.d/tor-vpn-split.conf
resolvectl reload 2>/dev/null || systemctl reload systemd-resolved 2>/dev/null || true
exit 0
CLEANUP_EOF
chmod +x "$CLEANUP_SCRIPT"

cat > "$SERVICE_FILE" << SERVICE_EOF
[Unit]
Description=Tor-VPN Manager — Daemon (Tor + OpenVPN headless)
After=network-online.target
Wants=network-online.target
# Pas de plafond de redémarrage : le daemon doit toujours retenter
# (sinon une série d'échecs au boot laisserait le service mort).
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStartPre=$CLEANUP_SCRIPT
ExecStart=/usr/bin/python3 -m daemon
ExecStopPost=$CLEANUP_SCRIPT
Restart=on-failure
RestartSec=20
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tor-vpn
KillMode=control-group
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable tor-vpn-manager
echo "    Service  : $SERVICE_FILE"
echo "    Activé   : démarrage automatique au boot"

# ── [5/6] Hook veille/réveil ─────────────────────────────────────────────────
echo "[5/6] Hook veille/réveil (résolution VPN-sans-Tor après suspend) …"

# Après un réveil, les circuits Tor sont périmés mais le port 9050 peut rester
# ouvert → OpenVPN se reconnecte sans passer par Tor. Le hook force un redémarrage
# complet du daemon après chaque réveil pour reconstruire les circuits Tor.
cat > "$SLEEP_HOOK" << 'SLEEP_EOF'
#!/bin/bash
# Tor-VPN Manager — hook systemd-sleep
# Redémarre le daemon après chaque réveil de veille/hibernation
case "$1" in
    post)
        sleep 3
        systemctl restart tor-vpn-manager 2>/dev/null || true
        ;;
esac
exit 0
SLEEP_EOF
chmod +x "$SLEEP_HOOK"
echo "    Hook     : $SLEEP_HOOK"

# ── [6/6] CLI + Lanceur GUI ──────────────────────────────────────────────────
echo "[6/6] Création du CLI tor-vpn et du lanceur GUI …"

cp "$SCRIPT_DIR/tor-vpn-cli.sh" "$CLI_BIN"
chmod +x "$CLI_BIN"
echo "    CLI : $CLI_BIN"

cat > "$DESKTOP_FILE" << DESKTOP_EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Tor-VPN Manager
Comment=Configuration du daemon Tor-VPN
Exec=pkexec python3 $SCRIPT_DIR/main.py
Icon=network-vpn
Terminal=false
Categories=Network;Security;
DESKTOP_EOF
echo "    Lanceur : $DESKTOP_FILE"

# ── Vérification ──────────────────────────────────────────────────────────────
echo ""
echo "── Vérification ────────────────────────────────────────"
all_ok=true

for bin in tor openvpn python3 curl dnsmasq; do
    if command -v "$bin" &>/dev/null; then
        echo "  OK  $bin"
    else
        echo "  KO  $bin  MANQUANT"
        all_ok=false
    fi
done

python3 -c "import tkinter" 2>/dev/null \
    && echo "  OK  python3-tk" \
    || { echo "  KO  python3-tk  MANQUANT"; all_ok=false; }

if systemctl is-active systemd-resolved &>/dev/null; then
    echo "  OK  systemd-resolved actif"
else
    echo "  KO  systemd-resolved inactif"
    all_ok=false
fi

systemctl is-enabled tor &>/dev/null 2>&1 \
    && echo "  KO  tor.service encore activé (conflit port 9050)" \
    || echo "  OK  tor.service désactivé"

[ -f "$SERVICE_FILE" ]             && echo "  OK  service systemd créé"
[ -x "$SLEEP_HOOK" ]               && echo "  OK  hook veille/réveil installé"
systemctl is-enabled tor-vpn-manager &>/dev/null && echo "  OK  démarrage auto activé"
[ -x "$CLI_BIN" ]                  && echo "  OK  commande tor-vpn disponible"
[ -f "$CONFIG_DIR/install_dir" ]   && echo "  OK  install_dir : $(cat $CONFIG_DIR/install_dir)"

echo "────────────────────────────────────────────────────────"
echo ""

if [ "$all_ok" = true ]; then
    echo "  Installation terminée avec succès."
else
    echo "  Installation terminée avec des avertissements (voir ci-dessus)."
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PROCHAINE ÉTAPE                                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Ouvrir l'interface de configuration :"
echo ""
echo "       tor-vpn gui"
echo "    ou sudo python3 $SCRIPT_DIR/main.py"
echo ""
echo "  Démarrer le service :"
echo ""
echo "       sudo tor-vpn start"
echo ""
echo "  Surveillance :"
echo "    tor-vpn status    # état complet"
echo "    tor-vpn follow    # logs en direct"
echo ""
