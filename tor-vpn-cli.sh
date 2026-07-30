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
    kbs = d.get("last_circuit_kbs", 0)
    if kbs:
        age = d.get("last_circuit_age", 0)
        quand = f"il y a {age//3600}h{(age%3600)//60:02d}" if age >= 3600 \
                else f"il y a {age//60} min" if age >= 60 else "à l'instant"
        print(f"  Circuit    : {kbs:.0f} KB/s (~{kbs*8/1000:.1f} Mbps) "
              f"mesuré {quand}")
    elif d["tunnel_up"]:
        print("  Circuit    : non mesuré")
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

    doctor)
        # Diagnostic complet, en LECTURE SEULE et sans root : vérifie les
        # invariants qui doivent tenir quand la connexion est saine.
        # Code de sortie : 0 si aucun KO, 1 sinon.
        python3 - "$DAEMON_DIR" << 'PYEOF'
import json, os, socket, subprocess, sys, time

DAEMON_DIR = sys.argv[1] if len(sys.argv) > 1 else ""
OK, WARN, KO = "OK  ", "WARN", "KO  "
resultats = []

def note(niveau, titre, detail=""):
    resultats.append((niveau, titre, detail))

def sh(*cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception:
        return 1, ""

# ── 1. Service ────────────────────────────────────────────────────────────────
rc, _ = sh("systemctl", "is-active", "tor-vpn-manager")
if rc != 0:
    note(KO, "Service", "tor-vpn-manager n'est pas actif — sudo tor-vpn start")
    for n, t, d in resultats:
        print(f"  [{n}] {t:22} {d}")
    sys.exit(1)
note(OK, "Service", "actif")

# ── 2. État du daemon ─────────────────────────────────────────────────────────
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect("/run/tor-vpn-manager.sock")
    st = json.loads(s.makefile().readline())
except Exception as e:
    note(KO, "Socket de statut", f"injoignable ({e})")
    st = {}

if st:
    note(OK, "Version du daemon", st["version"])
    note(OK if st.get("tor_ready") else KO, "Tor",
         "bootstrap terminé" if st.get("tor_ready") else "pas prêt")
    if st.get("tunnel_up"):
        up = st["tunnel_uptime"]
        note(OK, "Tunnel", f"{st['tunnel_iface']} depuis {up//3600}h{(up%3600)//60:02d} "
                           f"({st['provider']}, compte {st['account_index']+1})")
    else:
        note(KO, "Tunnel", "fermé")
    kbs, age = st.get("last_circuit_kbs", 0), st.get("last_circuit_age", 0)
    if kbs:
        vieux = age > 6 * 3600
        note(WARN if vieux else OK, "Qualité du circuit",
             f"{kbs:.0f} KB/s (~{kbs*8/1000:.1f} Mbps), mesuré il y a "
             f"{age//3600}h{(age%3600)//60:02d}"
             + (" — mesure ancienne, le circuit a pu se dégrader" if vieux else ""))
    elif st.get("tunnel_up"):
        note(WARN, "Qualité du circuit", "aucune mesure pour ce tunnel")

    # Comptes écartés temporairement : ni une panne ni un état normal, une
    # information.  Un refus d'authentification ne distingue pas un mot de
    # passe invalide d'un quota de connexions simultanées atteint.
    quar = st.get("accounts_cooldown") or {}
    if quar:
        detail = ", ".join(f"compte {n} ({s//60} min)"
                           for n, s in sorted(quar.items(), key=lambda kv: int(kv[0])))
        note(WARN, "Comptes en quarantaine", detail + " — essayés en dernier")
    else:
        note(OK, "Comptes", "aucun écarté")

tun = st.get("tunnel_iface", "tun0")

# ── 3. Routage ────────────────────────────────────────────────────────────────
_, routes = sh("ip", "-4", "route", "show")
lignes = routes.splitlines()

defauts = [l for l in lignes if l.startswith("default")]
if not defauts:
    note(KO, "Route par défaut", "absente")
elif f"dev {tun}" in defauts[0]:
    note(KO, "Route par défaut", f"pointe sur {tun} — boucle de routage probable")
else:
    note(OK, "Route par défaut", defauts[0].split("proto")[0].strip() + " (hors tunnel)")

guards = [l for l in lignes
          if l[:1].isdigit() and "/" not in l.split()[0] and " via " in l]
if guards:
    note(OK, "Protection des guards Tor", f"{len(guards)} route(s) /32 hors tunnel")
else:
    note(KO, "Protection des guards Tor",
         "aucune route /32 — Tor risque de joindre ses relais par le tunnel")

redirect = [l for l in lignes if l.startswith(("0.0.0.0/1", "128.0.0.0/1"))]
note(OK if len(redirect) == 2 else WARN, "Redirection du trafic",
     f"{len(redirect)}/2 routes def1 présentes")

# Piège scope-link : un réseau directement connecté ne doit jamais être
# supplanté par une route « via » de métrique 0.
_, liens = sh("ip", "-4", "route", "show", "scope", "link")
connectes = {l.split()[0] for l in liens.splitlines() if "/" in l.split()[0]}
detournes = [c for c in connectes
             if any(l.startswith(c + " ") and " via " in l for l in lignes)]
if detournes:
    note(KO, "Réseaux locaux", f"détourné(s) par une route via : {', '.join(detournes)} "
                               "— casse l'accès aux machines du segment")
else:
    note(OK, "Réseaux locaux", f"{len(connectes)} réseau(x) en accès direct")

# ── 4. DNS ────────────────────────────────────────────────────────────────────
rc, sortie = sh("resolvectl", "status", tun)
attrs = {}
for ligne in sortie.splitlines():
    label, sep, val = ligne.partition(":")
    if sep:
        attrs[label.strip()] = val.strip()
# default-route : le format varie selon la version de systemd.  Le drapeau de
# « Protocols » est présent partout ; l'étiquette « Default Route » n'existe
# pas sur systemd 255.  None = format non reconnu, on ne conclut pas.
def etat_default_route(attrs):
    proto = attrs.get("Protocols", "")
    if "+DefaultRoute" in proto:
        return True
    if "-DefaultRoute" in proto:
        return False
    for label in ("Default Route", "DefaultRoute setting"):
        if label in attrs:
            return attrs[label].strip().lower() in ("yes", "true")
    return None

route_dns = etat_default_route(attrs)
manquants = []
if not attrs.get("DNS Servers"):
    manquants.append("serveur")
if "~." not in attrs.get("DNS Domain", "").split():
    manquants.append("domaine ~.")
if route_dns is False:
    manquants.append("default-route")
if manquants:
    note(KO, "DNS du tunnel", f"incomplet ({', '.join(manquants)}) — "
                              "risque de requêtes hors tunnel")
elif route_dns is None:
    note(WARN, "DNS du tunnel",
         f"{attrs.get('DNS Servers','?')} · ~. — default-route non vérifiable "
         "(format resolvectl inconnu)")
else:
    note(OK, "DNS du tunnel", f"{attrs['DNS Servers']} · ~. · default-route")

if os.path.exists("/etc/systemd/resolved.conf.d/tor-vpn-split.conf"):
    note(OK, "DNS split", "drop-in en place")

# Où part réellement une requête publique ? Le résolveur local répond en
# ~0 ms, celui du tunnel en dizaines/centaines de ms.
uplink = ""
if defauts:
    champs = defauts[0].split()
    if "dev" in champs:
        uplink = champs[champs.index("dev") + 1]

t0 = time.monotonic()
sh("resolvectl", "query", "--cache=no", "wikipedia.org", timeout=20)
lat_defaut = time.monotonic() - t0
lat_locale = None
if uplink:
    t0 = time.monotonic()
    sh("resolvectl", "query", "--cache=no", "-i", uplink, "wikipedia.org", timeout=20)
    lat_locale = time.monotonic() - t0

if lat_defaut < 0.02 and (lat_locale is None or lat_locale < 0.02):
    note(WARN, "Chemin des requêtes DNS",
         "trop rapide pour passer par Tor — vérifiez une éventuelle fuite")
else:
    ref = f" (résolveur local via {uplink} : {lat_locale*1000:.0f} ms)" \
          if lat_locale is not None else ""
    note(OK, "Chemin des requêtes DNS", f"{lat_defaut*1000:.0f} ms{ref}")

# ── 5. IPv6 ───────────────────────────────────────────────────────────────────
if st.get("ipv6_blocked"):
    note(OK, "IPv6", "bloqué")
else:
    note(WARN, "IPv6", "non bloqué (option désactivée dans les paramètres)")

# ── 6. Connectivité réelle à travers le tunnel ────────────────────────────────
rc, ip = sh("curl", "-s", "--max-time", "20", "--interface", tun,
            "https://api.ipify.org", timeout=25)
ip = ip.strip()
if rc == 0 and ip:
    prive = ip.startswith(("10.", "192.168.", "172.16.", "127."))
    note(KO if prive else OK, "Sortie Internet",
         f"IP publique {ip}" + (" — adresse privée, sortie anormale" if prive else ""))
else:
    note(KO, "Sortie Internet", f"aucune réponse via {tun}")

# ── Verdict ───────────────────────────────────────────────────────────────────
print()
print("  ╔══════════════════════════════════════════════════════╗")
print("  ║  Diagnostic Tor-VPN Manager                          ║")
print("  ╚══════════════════════════════════════════════════════╝")
print()
for niveau, titre, detail in resultats:
    print(f"  [{niveau}] {titre:26} {detail}")
print()
n_ko = sum(1 for n, _, _ in resultats if n == KO)
n_warn = sum(1 for n, _, _ in resultats if n == WARN)
if n_ko:
    print(f"  {n_ko} problème(s) bloquant(s), {n_warn} avertissement(s).")
    print("  Piste : sudo tor-vpn restart  (3 s de coupure), puis relancez ce diagnostic.")
elif n_warn:
    print(f"  Aucun problème bloquant, {n_warn} avertissement(s) à surveiller.")
else:
    print("  Tout est conforme.")
print()
sys.exit(1 if n_ko else 0)
PYEOF
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
        echo "    doctor   Diagnostic des invariants (routage, DNS, fuites)"
        echo "    logs [n] n dernières lignes (défaut : 60)"
        echo "    follow   Logs en direct (Ctrl+C)"
        echo "    ip       IP publique actuelle"
        ;;
esac
