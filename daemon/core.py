"""
Daemon core : constantes, helpers, initialisation, run(), handle_signal().
"""

import base64
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

# ── Imports projet ────────────────────────────────────────────────────────────
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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


# ── DaemonCore ────────────────────────────────────────────────────────────────

class DaemonCore:
    """État partagé et méthodes d'orchestration principale."""

    def __init__(self):
        self.config = self._load_config()

        self.tor_process     = None
        self.openvpn_process = None

        self._tor_ready          = threading.Event()
        self._vpn_lock           = threading.Lock()
        self._vpn_loop_active    = False
        self._stop_flag          = False
        self._stop_vpn           = False
        self._stop_tor_flag      = False
        self._ipv6_blocked       = False
        self._lan_active         = False
        self._dnsmasq_proc       = None

        self._current_provider_idx = 0
        self._current_account_idx  = 0
        self._reconnect_vpn_count  = 0
        self._reconnect_tor_count  = 0
        self._failover_in_progress = False
        self._vpn_slow_count       = 0
        self._tor_slow_count       = 0

        self._conn_fail_count      = 0
        self._conn_restart_pending = False
        self._full_restart_count   = 0

        self._tun_iface      = "tun0"
        self._tunnel_up      = False
        self._tunnel_up_time = 0.0

        self._orig_gw    = None
        self._orig_iface = None

        self._protected_routes: set = set()

        self._rx_history = [0.0] * 60
        self._last_rx    = 0

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    return {**DEFAULT_CONFIG, **json.load(f)}
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
        return dict(DEFAULT_CONFIG)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level:5s}] {msg}", flush=True)

    # ── Signal ────────────────────────────────────────────────────────────────

    def handle_signal(self, signum, _frame):
        self._log(f"Signal {signum} reçu — arrêt propre …", "WARN")
        self._stop_flag     = True
        self._stop_vpn      = True
        self._stop_tor_flag = True
        self._stop_openvpn()
        self._stop_tor()
        self._cleanup_tor_routes()
        self._teardown_lan_sharing()
        self._ipv6_block_off()
        self._remove_dns_split()
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

        if LAN_DNSMASQ_PID.exists():
            try:
                pid = int(LAN_DNSMASQ_PID.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
            LAN_DNSMASQ_PID.unlink(missing_ok=True)

        self._cleanup_tor_routes()
        self._log("Nettoyage terminé.", "OK")

    # ── Démarrage des services ────────────────────────────────────────────────

    def _start_services(self) -> bool:
        self._start_tor()
        self._log("Attente du bootstrap Tor (max 240s) …")
        ready = self._tor_ready.wait(90)
        if not ready and self.tor_process and self.tor_process.poll() is None:
            self._log("Tor encore en bootstrap — attente prolongée (150s) …", "WARN")
            ready = self._tor_ready.wait(150)
        if not ready:
            self._log("Tor n'a pas démarré dans les temps.", "ERROR")
            return False
        threading.Thread(target=self._openvpn_loop, daemon=True).start()
        return True

    # ── Point d'entrée ────────────────────────────────────────────────────────

    def run(self):
        self._log(f"Tor-VPN Manager daemon v{VERSION} démarré (PID {os.getpid()}).", "OK")
        if not self.config.get("providers"):
            self._log(
                "Aucun fournisseur configuré.\n"
                "Configurez via :  sudo python3 main.py\n"
                "Puis relancez :   tor-vpn restart", "ERROR")
            sys.exit(1)
        self.cleanup_stale_rules()
        if not self._start_services():
            sys.exit(1)
        self._monitor_loop()
        self._log("Daemon terminé.")
