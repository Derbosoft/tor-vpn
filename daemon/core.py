"""
Daemon core : constantes, helpers, initialisation, run(), handle_signal().
"""

import base64
import copy
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

# ── Imports projet ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from constants import CONFIG_DIR, CONFIG_FILE, AUTH_TMP, PROVIDERS_DIR, SCRIPT_DIR, DEFAULT_CONFIG, TORRC_FILE, VERSION

# ── Constantes daemon ─────────────────────────────────────────────────────────
TOR_DATA_DIR      = CONFIG_DIR / "tor_data"
TOR_COOKIE        = TOR_DATA_DIR / "control_auth_cookie"
RESOLVED_DROP_IN  = Path("/etc/systemd/resolved.conf.d/tor-vpn-split.conf")
LAN_DNSMASQ_PID   = CONFIG_DIR / "tor-vpn-dnsmasq.pid"
TOR_ROUTES_FILE   = CONFIG_DIR / "tor-vpn-routes.txt"

KS6_CHAIN         = "TORVPN_KS6"
KS6_FWD_CHAIN     = "TORVPN_KS6_FWD"
KS_LAN_CHAIN      = "TORVPN_LAN_FWD"

TOR_CTRL_PORT     = 9051
RECONNECT_DELAY   = 15
RECONNECT_MAX     = 5
CONN_FAIL_MAX     = 2
REPAIR_THRESHOLD  = 3   # full_restarts consécutifs avant réparation d'urgence


# ── Helpers module-level (importables par les autres modules daemon) ───────────

def _run(*cmd) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True)

def _deobf(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s

def _sd_notify(msg: str):
    """Notification systemd (READY=1, WATCHDOG=1, STOPPING=1) sans dépendance.
    No-op silencieux hors systemd (NOTIFY_SOCKET absent) — le daemon reste
    lançable à la main pour le debug."""
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return
    try:
        if path.startswith("@"):          # socket abstrait
            path = "\0" + path[1:]
        # « with » plutôt qu'un close() en fin de bloc : sur exception, la
        # fermeture ne dépend plus du ramasse-miettes.  Appelé toutes les 3 s.
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(path)
            s.send(msg.encode())
    except Exception:
        pass


# ── DaemonCore ────────────────────────────────────────────────────────────────

class DaemonCore:
    """État partagé et méthodes d'orchestration principale."""

    def __init__(self):
        self.config = self._load_config()

        self.tor_process     = None
        self.openvpn_process = None
        self._tor_thread     = None

        self._tor_ready          = threading.Event()
        self._vpn_lock           = threading.Lock()
        self._vpn_loop_active    = False
        self._stop_flag          = False
        self._stop_vpn           = False
        self._stop_tor_flag      = False
        self._ipv6_blocked       = False
        self._lan_active         = False
        self._lan_tun            = ""    # interface tunnel figée dans les règles LAN
        self._dnsmasq_proc       = None

        self._current_provider_idx = 0
        self._current_account_idx  = 0
        self._reconnect_vpn_count  = 0
        self._reconnect_tor_count  = 0

        self._conn_fail_count      = 0
        self._conn_restart_pending = False
        self._full_restart_count   = 0
        self._inert_ticks          = 0

        self._circuit_attempts = 0      # essais de re-tirage du circuit Tor
        self._circuit_retry    = False  # reconnexion pour circuit (pas un failover)
        self._auth_failed      = False  # dernière rupture = refus d'identifiants

        self._vpn_dns_ips    = []

        self._tun_iface      = "tun0"
        self._tunnel_up      = False
        self._tunnel_up_time = 0.0

        self._orig_gw    = None
        self._orig_iface = None

        self._protected_routes: set = set()

        # deque bornée : l'ajout chasse le plus ancien, sans recopier la liste
        # à chaque tick du watchdog (toutes les 3 s).
        self._rx_history = deque([0.0] * 60, maxlen=60)
        self._last_rx    = 0

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        # deepcopy et non dict() : les valeurs par défaut contiennent des
        # listes (providers, excluded_ips…).  Une copie superficielle les
        # partagerait avec DEFAULT_CONFIG, si bien qu'un ajout en place —
        # le GUI fait « providers.append(...) » — muterait la constante du
        # module pour tout le processus.
        defaults = copy.deepcopy(DEFAULT_CONFIG)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    loaded = json.load(f)
                if not isinstance(loaded, dict):
                    raise ValueError("config.json ne contient pas un objet JSON")
                return {**defaults, **loaded}
            except Exception as e:
                # config corrompue : la mettre de côté plutôt que de la perdre,
                # et le signaler dans le journal (sinon démarrage en défauts muet).
                bad = CONFIG_FILE.with_name(CONFIG_FILE.name + ".bad")
                try:
                    CONFIG_FILE.replace(bad)
                    self._log(f"config.json illisible ({e}) — sauvegardé dans {bad}, "
                              "démarrage avec les valeurs par défaut.", "ERROR")
                except Exception:
                    pass
        return defaults

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level:5s}] {msg}", flush=True)

    # ── Signal ────────────────────────────────────────────────────────────────

    def handle_signal(self, signum, _frame):
        _sd_notify("STOPPING=1")
        self._log(f"Signal {signum} reçu — arrêt propre …", "WARN")
        self._stop_flag     = True
        self._stop_vpn      = True
        self._stop_tor_flag = True
        self._stop_openvpn()
        self._stop_tor()
        self._revert_vpn_dns()
        self._cleanup_tor_routes()
        self._teardown_lan_sharing()
        self._ipv6_block_off()
        self._remove_dns_split()
        self._stop_status_server()
        if AUTH_TMP.exists():
            AUTH_TMP.unlink()
        self._log("Daemon arrêté proprement.", "OK")
        sys.exit(0)

    # ── Nettoyage au démarrage ────────────────────────────────────────────────

    def cleanup_stale_rules(self):
        """Supprime toutes les règles/routes orphelines d'une session précédente."""
        self._log("Nettoyage des règles orphelines …")

        def _purge_jumps(tool, parent, chain, limit=25):
            # Des crashs répétés peuvent empiler plusieurs jumps identiques :
            # on supprime en boucle jusqu'à épuisement (comme repair_network.sh).
            for _ in range(limit):
                if _run(tool, "-D", parent, "-j", chain).returncode != 0:
                    break

        _purge_jumps("ip6tables", "OUTPUT",  KS6_CHAIN)
        _purge_jumps("ip6tables", "FORWARD", KS6_FWD_CHAIN)
        _purge_jumps("iptables",  "FORWARD", KS_LAN_CHAIN)
        for args in [
            ("ip6tables", "-F", KS6_CHAIN),
            ("ip6tables", "-X", KS6_CHAIN),
            ("ip6tables", "-F", KS6_FWD_CHAIN),
            ("ip6tables", "-X", KS6_FWD_CHAIN),
            ("iptables",  "-F", KS_LAN_CHAIN),
            ("iptables",  "-X", KS_LAN_CHAIN),
        ]:
            _run(*args)

        lan_subnet = self.config.get("lan_subnet", "")
        if lan_subnet:
            try:
                import ipaddress as _ip
                net = _ip.ip_network(lan_subnet, strict=False)
                for tun in {self._tun_iface, "tun0", "tun1"}:
                    _run("iptables", "-t", "nat", "-D", "POSTROUTING",
                         "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            except Exception:
                pass

        # dnsmasq orphelin du partage LAN : ciblé via son argument --pid-file
        # unique (jamais « pkill dnsmasq » : cela tuerait ceux de libvirt).
        _run("pkill", "-f", str(LAN_DNSMASQ_PID))
        LAN_DNSMASQ_PID.unlink(missing_ok=True)

        self._cleanup_tor_routes()
        self._log("Nettoyage terminé.", "OK")

    # ── Démarrage des services ────────────────────────────────────────────────

    def _wait_tor_ready(self, timeout: float) -> bool:
        """Attend le bootstrap Tor : événement posé par le parsing stdout,
        doublé d'un sondage du ControlPort (GETINFO status/bootstrap-phase),
        plus fiable que la seule détection de « Bootstrapped 100% »."""
        deadline  = time.time() + timeout
        last_prog = -1
        while time.time() < deadline and not self._stop_flag:
            # Le bootstrap peut durer plusieurs minutes : on maintient le
            # watchdog systemd pendant cette attente (sinon WatchdogSec
            # tuerait un démarrage parfaitement sain).
            _sd_notify("WATCHDOG=1")
            if self._tor_ready.wait(2):
                return True
            prog = self._tor_bootstrap_progress()
            if prog >= 100:
                self._tor_ready.set()
                self._log("[tor-ctrl] Bootstrap 100 % (ControlPort).", "OK")
                return True
            if prog > last_prog >= 0 or (prog >= 0 and last_prog < 0):
                self._log(f"[tor-ctrl] Bootstrap {prog} % …")
            last_prog = max(last_prog, prog)
        return self._tor_ready.is_set()

    def _start_services(self) -> bool:
        self._start_tor()
        self._log("Attente du bootstrap Tor (max 240s) …")
        ready = self._wait_tor_ready(90)
        if not ready and self.tor_process and self.tor_process.poll() is None:
            self._log("Tor encore en bootstrap — attente prolongée (150s) …", "WARN")
            ready = self._wait_tor_ready(150)
        if not ready:
            self._log("Tor n'a pas démarré dans les temps.", "ERROR")
            return False
        threading.Thread(target=self._openvpn_loop, daemon=True).start()
        return True

    # ── Point d'entrée ────────────────────────────────────────────────────────

    def run(self):
        self._log(f"Tor-VPN Manager daemon v{VERSION} démarré (PID {os.getpid()}).", "OK")
        # READY tout de suite (Type=notify) : le « prêt » systemd signifie
        # « le daemon orchestre », pas « le tunnel est monté ».
        _sd_notify("READY=1")
        if not self.config.get("providers"):
            self._log(
                "Aucun fournisseur configuré.\n"
                "Configurez via :  sudo python3 main.py\n"
                "Puis relancez :   tor-vpn restart", "ERROR")
            sys.exit(1)
        self._check_dns_stack()
        self.cleanup_stale_rules()
        self._start_status_server()
        if not self._start_services():
            sys.exit(1)
        self._monitor_loop()
        self._log("Daemon terminé.")
