#!/usr/bin/env bash
set -euo pipefail

# ── Mode d'appel ──────────────────────────────────────────────────────────────
# Sans argument  : usage manuel — arrête le service, répare, affiche conseils
# --internal     : appelé par le daemon — skip systemctl stop, le daemon
#                  se charge de son propre arrêt puis de sys.exit(1) pour
#                  que systemd le relance via Restart=on-failure

INTERNAL=0
if [[ "${1:-}" == "--internal" ]]; then
  INTERNAL=1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Relancez avec : sudo bash repair_network.sh"
  exit 1
fi

KS6_CHAIN="TORVPN_KS6"
RESOLVED_DROP_IN="/etc/systemd/resolved.conf.d/tor-vpn-split.conf"

if [[ $INTERNAL -eq 0 ]]; then
  echo "[1/7] Arrêt du service tor-vpn-manager si actif..."
  systemctl stop tor-vpn-manager.service 2>/dev/null || true
  sleep 1
fi

echo "[2/7] Arrêt des processus OpenVPN/Tor restants..."
pkill -x openvpn 2>/dev/null || true
pkill -x tor     2>/dev/null || true

echo "[3/7] Nettoyage règles iptables IPv6 (TORVPN_KS6)..."
while ip6tables -D OUTPUT  -j "${KS6_CHAIN}" 2>/dev/null; do :; done
while ip6tables -D FORWARD -j "${KS6_CHAIN}" 2>/dev/null; do :; done
ip6tables -F "${KS6_CHAIN}" 2>/dev/null || true
ip6tables -X "${KS6_CHAIN}" 2>/dev/null || true

echo "[4/7] Nettoyage règles iptables LAN (TORVPN_LAN_FWD)..."
while iptables -D FORWARD -j TORVPN_LAN_FWD 2>/dev/null; do :; done
iptables -F TORVPN_LAN_FWD 2>/dev/null || true
iptables -X TORVPN_LAN_FWD 2>/dev/null || true

echo "[5/7] Nettoyage DNS systemd-resolved..."
resolvectl revert tun0 2>/dev/null || true
rm -f "${RESOLVED_DROP_IN}"
systemctl restart systemd-resolved 2>/dev/null || true

echo "[6/7] Suppression des routes OpenVPN def1 bloquées sur tun0..."
ip route del 0.0.0.0/1   dev tun0 2>/dev/null || true
ip route del 128.0.0.0/1 dev tun0 2>/dev/null || true
ip route del default      dev tun0 2>/dev/null || true

echo "[7/7] Vérification rapide de la connectivité..."
ip route get 1.1.1.1 2>/dev/null || true
getent ahosts example.com 2>/dev/null | head -n 3 || true

echo
echo "=== Réparation réseau terminée. ==="

if [[ $INTERNAL -eq 0 ]]; then
  echo
  echo "Le service tor-vpn-manager est arrêté."
  echo "Relancez-le avec :  sudo tor-vpn start"
  echo
  echo "Si Internet ne revient toujours pas :"
  echo "  sudo systemctl restart NetworkManager"
fi
