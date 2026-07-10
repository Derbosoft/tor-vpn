#!/bin/bash
# Tor-VPN Manager — CLI wrapper
SERVICE="tor-vpn-manager"
DAEMON_DIR=$(cat /etc/tor-vpn-manager/install_dir 2>/dev/null)

_need_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Cette commande nécessite les droits root."
        echo "Utilisez : sudo tor-vpn $*"
        exit 1
    fi
}

case "${1:-help}" in

    start)
        _need_root "$@"
        systemctl reset-failed "$SERVICE" 2>/dev/null || true
        systemctl start "$SERVICE" && echo "Service démarré."
        ;;

    stop)
        _need_root "$@"
        systemctl stop "$SERVICE" && echo "Service arrêté."
        ;;

    restart)
        _need_root "$@"
        systemctl reset-failed "$SERVICE" 2>/dev/null || true
        systemctl restart "$SERVICE" && echo "Service redémarré."
        ;;

    enable)
        _need_root "$@"
        systemctl enable "$SERVICE" && echo "Démarrage automatique activé."
        ;;

    disable)
        _need_root "$@"
        systemctl disable "$SERVICE" && echo "Démarrage automatique désactivé."
        ;;

    gui)
        if [ -z "$DAEMON_DIR" ]; then
            echo "ERREUR : répertoire d'installation introuvable." >&2
            exit 1
        fi
        # Le GUI tourne en utilisateur normal (groupe torvpn) ; les actions
        # privilégiées (systemctl) passent par pkexec depuis le GUI lui-même.
        exec python3 "$DAEMON_DIR/main.py"
        ;;

    status)
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║  Tor-VPN Manager — État                              ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo ""
        if systemctl is-active "$SERVICE" &>/dev/null; then
            SINCE=$(systemctl show "$SERVICE" \
                --property=ActiveEnterTimestamp --value 2>/dev/null \
                | sed 's/ [A-Z]*$//')
            echo "  Service    : actif  (depuis $SINCE)"
        else
            STATE=$(systemctl show "$SERVICE" --property=SubState --value 2>/dev/null)
            echo "  Service    : $STATE"
        fi
        if systemctl is-enabled "$SERVICE" &>/dev/null; then
            echo "  Boot auto  : activé"
        else
            echo "  Boot auto  : désactivé"
        fi
        echo ""
        # État précis via le socket du daemon ; repli sur pgrep si absent.
        DSTATUS=$(python3 - << 'PYEOF' 2>/dev/null
import json, socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.5)
    s.connect("/run/tor-vpn-manager.sock")
    d = json.loads(s.makefile().readline())
    tor = "actif (bootstrap OK)" if d["tor_ready"] else \
          ("bootstrap en cours" if d["tor_running"] else "inactif")
    if d["tunnel_up"]:
        up = d["tunnel_uptime"]
        vpn = (f"actif ({d['tunnel_iface']} UP, {d['provider']}, "
               f"{d['rx_kbs']:.0f} KB/s, depuis {up//3600}h{(up%3600)//60:02d})")
    else:
        vpn = "connexion en cours" if d["tor_ready"] else "en attente de Tor"
    print(f"  Tor        : {tor}")
    print(f"  VPN        : {vpn}")
    if d["lan_sharing"]:  print("  Partage LAN: actif")
    if d["ipv6_blocked"]: print("  IPv6       : bloqué")
except Exception:
    pass
PYEOF
)
        if [ -n "$DSTATUS" ]; then
            echo "$DSTATUS"
        else
            if pgrep -x tor &>/dev/null; then
                echo "  Tor        : actif  (PID $(pgrep -x tor | head -1))"
            else
                echo "  Tor        : inactif"
            fi
            if pgrep -x openvpn &>/dev/null; then
                if ip link show tun0 &>/dev/null 2>&1; then
                    echo "  VPN        : actif  (tun0 UP)"
                else
                    echo "  VPN        : connexion en cours"
                fi
            else
                echo "  VPN        : inactif"
            fi
        fi
        if [ -f /etc/systemd/resolved.conf.d/tor-vpn-split.conf ]; then
            DNS_SERVER=$(grep '^DNS=' /etc/systemd/resolved.conf.d/tor-vpn-split.conf | cut -d= -f2)
            echo "  DNS split  : actif  (→ $DNS_SERVER)"
        else
            echo "  DNS split  : inactif"
        fi
        echo ""
        IP=$(curl -s --max-time 6 https://api.ipify.org 2>/dev/null)
        echo "  IP publique: ${IP:-(inaccessible)}"
        echo ""
        echo "── Derniers logs ────────────────────────────────────────"
        journalctl -u "$SERVICE" -n 15 --no-pager --output=short-precise 2>/dev/null \
            || echo "  (journalctl non disponible)"
        echo "────────────────────────────────────────────────────────"
        ;;

    logs)
        N="${2:-60}"
        journalctl -u "$SERVICE" -n "$N" --no-pager
        ;;

    follow)
        echo "Suivi des logs en temps réel (Ctrl+C pour quitter) …"
        journalctl -u "$SERVICE" -f
        ;;

    ip)
        IP=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null)
        if [ -n "$IP" ]; then echo "$IP"; else echo "Impossible de récupérer l'IP."; fi
        ;;

    help|--help|-h|*)
        echo "Usage : tor-vpn <commande>"
        echo ""
        echo "  Contrôle (nécessitent sudo) :"
        echo "    start    Démarrer le daemon"
        echo "    stop     Arrêter le daemon"
        echo "    restart  Redémarrer le daemon"
        echo "    enable   Activer au démarrage"
        echo "    disable  Désactiver au démarrage"
        echo ""
        echo "  Interface graphique :"
        echo "    gui      Ouvrir le panneau de configuration"
        echo ""
        echo "  Surveillance :"
        echo "    status   État complet"
        echo "    logs [n] n dernières lignes (défaut : 60)"
        echo "    follow   Logs en direct (Ctrl+C)"
        echo "    ip       IP publique actuelle"
        ;;
esac
