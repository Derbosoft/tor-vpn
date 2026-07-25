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
KS6_FWD_CHAIN="TORVPN_KS6_FWD"
RESOLVED_DROP_IN="/etc/systemd/resolved.conf.d/tor-vpn-split.conf"
CONFIG_JSON="/etc/tor-vpn-manager/config.json"
TOR_ROUTES_FILE="/etc/tor-vpn-manager/tor-vpn-routes.txt"
# Les .ovpn utilisent « dev tun » : le tunnel peut être tun0 comme tun1.
TUNS=(tun0 tun1)

if [[ $INTERNAL -eq 0 ]]; then
  echo "[1/8] Arrêt du service tor-vpn-manager si actif..."
  systemctl stop tor-vpn-manager.service 2>/dev/null || true
  sleep 1
fi

echo "[2/8] Arrêt des processus OpenVPN/Tor restants..."
pkill -x openvpn 2>/dev/null || true
pkill -x tor     2>/dev/null || true

echo "[3/8] Nettoyage règles iptables IPv6 (TORVPN_KS6, TORVPN_KS6_FWD)..."
while ip6tables -D OUTPUT  -j "${KS6_CHAIN}" 2>/dev/null; do :; done
ip6tables -F "${KS6_CHAIN}" 2>/dev/null || true
ip6tables -X "${KS6_CHAIN}" 2>/dev/null || true
# Le jump FORWARD pointe vers la chaîne _FWD (pas KS6_CHAIN)
while ip6tables -D FORWARD -j "${KS6_FWD_CHAIN}" 2>/dev/null; do :; done
ip6tables -F "${KS6_FWD_CHAIN}" 2>/dev/null || true
ip6tables -X "${KS6_FWD_CHAIN}" 2>/dev/null || true

echo "[4/8] Nettoyage règles iptables LAN (TORVPN_LAN_FWD + NAT)..."
while iptables -D FORWARD -j TORVPN_LAN_FWD 2>/dev/null; do :; done
iptables -F TORVPN_LAN_FWD 2>/dev/null || true
iptables -X TORVPN_LAN_FWD 2>/dev/null || true
# dnsmasq du partage LAN uniquement (jamais « pkill dnsmasq » : libvirt en dépend)
pkill -f /etc/tor-vpn-manager/tor-vpn-dnsmasq.pid 2>/dev/null || true
# MASQUERADE du partage LAN : sous-réseau lu dans la config, les deux tun testés
if [[ -f "${CONFIG_JSON}" ]]; then
  LAN_SUBNET=$(python3 -c "import json;print(json.load(open('${CONFIG_JSON}')).get('lan_subnet',''))" 2>/dev/null || true)
  if [[ -n "${LAN_SUBNET}" ]]; then
    for T in "${TUNS[@]}"; do
      while iptables -t nat -D POSTROUTING -s "${LAN_SUBNET}" -o "$T" -j MASQUERADE 2>/dev/null; do :; done
    done
  fi
fi

echo "[5/8] Nettoyage DNS systemd-resolved..."
for T in "${TUNS[@]}"; do
  resolvectl revert "$T" 2>/dev/null || true
done
rm -f "${RESOLVED_DROP_IN}"
systemctl restart systemd-resolved 2>/dev/null || true

echo "[6/8] Suppression des routes /32 des relais Tor..."
# Sans cela, le trafic vers ces IPs continue de contourner le tunnel après
# la réparation.  Le daemon les nettoie à son démarrage, mais ce script doit
# pouvoir rendre la main sur un système sain sans le relancer.
if [[ -f "${TOR_ROUTES_FILE}" ]]; then
  N=0
  while read -r IP; do
    [[ -z "$IP" ]] && continue
    ip route del "${IP}/32" 2>/dev/null && N=$((N+1))
  done < "${TOR_ROUTES_FILE}"
  rm -f "${TOR_ROUTES_FILE}"
  echo "    ${N} route(s) /32 supprimée(s)."
else
  echo "    Aucune route persistée."
fi

echo "[7/8] Suppression des routes OpenVPN def1 bloquées..."
for T in "${TUNS[@]}"; do
  ip route del 0.0.0.0/1   dev "$T" 2>/dev/null || true
  ip route del 128.0.0.0/1 dev "$T" 2>/dev/null || true
  ip route del default     dev "$T" 2>/dev/null || true
done

echo "[8/8] Vérification rapide de la connectivité..."
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
