"""
Watchdog : surveillance de connectivité, débit, redémarrage automatique.
"""

import socket
import subprocess
import sys
import threading
import time

from .core import _run, CONN_FAIL_MAX, REPAIR_THRESHOLD, SCRIPT_DIR


class WatchdogMixin:

    def _vpn_is_active(self) -> bool:
        if self.openvpn_process and self.openvpn_process.poll() is None:
            return True
        return _run("pgrep", "-x", "openvpn").returncode == 0

    _CONN_GRACE = 30  # secondes de grâce après tunnel up avant de vérifier la connectivité

    def _check_connectivity(self) -> bool:
        tun = self._tun_iface
        if _run("ip", "link", "show", tun).returncode != 0:
            return False
        if time.time() - self._tunnel_up_time < self._CONN_GRACE:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, 25, tun.encode() + b"\0")  # SO_BINDTODEVICE
            s.settimeout(5)
            s.connect(("1.1.1.1", 443))
            s.close()
            return True
        except Exception:
            return False

    def _read_tun0_rx(self) -> int:
        tun = self._tun_iface
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    name, _, rest = line.partition(":")
                    if name.strip() == tun:
                        return int(rest.split()[0])
        except Exception:
            pass
        return 0

    def _emergency_repair(self):
        """Lance repair_network.sh --internal puis quitte : systemd relance le service."""
        self._log(
            f"Watchdog : {REPAIR_THRESHOLD} redémarrages échoués — "
            "lancement de repair_network.sh …", "ERROR")
        script = SCRIPT_DIR / "repair_network.sh"
        try:
            subprocess.run(["bash", str(script), "--internal"],
                           timeout=60, check=False)
        except Exception as e:
            self._log(f"repair_network.sh : {e}", "ERROR")
        self._log("Réparation terminée — sortie pour relance systemd.", "WARN")
        sys.exit(1)

    def _full_restart(self):
        self._full_restart_count += 1
        self._log(
            f"Watchdog : redémarrage complet "
            f"({self._full_restart_count}/{REPAIR_THRESHOLD}) …", "ERROR")
        if self._full_restart_count >= REPAIR_THRESHOLD:
            self._emergency_repair()
        self._stop_vpn      = True
        self._stop_tor_flag = True
        self._stop_openvpn()
        self._stop_tor()
        self._wait_vpn_loop_exit()
        self._cleanup_tor_routes()
        self._ipv6_block_off()
        time.sleep(6)
        self._stop_vpn             = False
        self._stop_tor_flag        = False
        self._conn_fail_count      = 0
        self._conn_restart_pending = False
        self._reconnect_vpn_count  = 0
        self._reconnect_tor_count  = 0
        self._tunnel_up            = False
        self._tunnel_up_time       = 0.0
        self._tun_iface            = "tun0"
        self._tor_ready.clear()
        self._log("Relance des services …", "WARN")
        if not self._start_services():
            self._log("Watchdog : relance échouée (Tor ne démarre pas).", "ERROR")

    _GUARD_REFRESH_TICKS = 10   # ~30s (10 × 3s)

    def _monitor_loop(self):
        conn_tick  = 0
        guard_tick = 0
        while not self._stop_flag:
            time.sleep(3)
            if self._stop_flag:
                break

            rx   = self._read_tun0_rx()
            d_rx = max(0, rx - self._last_rx) if self._last_rx else 0
            self._last_rx    = rx
            self._rx_history = self._rx_history[1:] + [float(d_rx)]

            # Rafraîchit les routes /32 des guards Tor : si Tor change de
            # garde en cours de session, son IP doit rester routée hors
            # tunnel, sinon boucle de routage (le tunnel dépend du guard).
            guard_tick += 1
            if self._tunnel_up and guard_tick >= self._GUARD_REFRESH_TICKS:
                guard_tick = 0
                self._protect_tor_routes()

            conn_tick += 1
            if conn_tick < 3:   # vérifier toutes les 9s (3 × 3s)
                continue
            conn_tick = 0

            vpn_up = self._vpn_is_active()
            if not vpn_up or not self._tunnel_up:
                self._conn_fail_count = 0
                self._vpn_slow_count  = 0
                continue

            if not self.config.get("auto_reconnect", True) or self._conn_restart_pending:
                continue

            ok = self._check_connectivity()
            if ok:
                self._conn_fail_count    = 0
                self._full_restart_count = 0
            else:
                self._conn_fail_count += 1
                self._log(
                    f"Watchdog : pas de connectivité "
                    f"({self._conn_fail_count}/{CONN_FAIL_MAX}) …", "WARN")
                if self._conn_fail_count >= CONN_FAIL_MAX and not self._stop_vpn:
                    self._conn_restart_pending = True
                    self._full_restart()
                continue

            vpn_min = self.config.get("vpn_min_speed_kbs", 0)
            if vpn_min > 0 and not self._failover_in_progress:
                bw_bps = (self._rx_history[-1] if self._rx_history else 0) / 3
                if 0 < bw_bps < vpn_min * 1024:
                    self._vpn_slow_count += 1
                    if self._vpn_slow_count >= self.config.get("speed_fail_count", 3):
                        self._vpn_slow_count = 0
                        if self._try_failover():
                            # _try_failover a déjà avancé les index : on les
                            # capture pour relancer la boucle DESSUS (sinon
                            # _openvpn_loop les remettrait à 0).
                            target_p = self._current_provider_idx
                            target_a = self._current_account_idx
                            self._log(
                                f"Débit VPN faible ({bw_bps/1024:.0f} KB/s) — failover …",
                                "WARN")
                            self._failover_in_progress = True

                            def _do_fo(tp=target_p, ta=target_a):
                                self._stop_vpn = True
                                self._stop_openvpn()
                                # Attendre la fin réelle de l'ancienne boucle
                                # avant d'en démarrer une nouvelle.
                                self._wait_vpn_loop_exit()
                                self._failover_in_progress = False
                                threading.Thread(
                                    target=self._openvpn_loop,
                                    kwargs={"start_provider_idx": tp,
                                            "start_account_idx": ta},
                                    daemon=True).start()
                            threading.Thread(target=_do_fo, daemon=True).start()
                else:
                    self._vpn_slow_count = 0

            tor_min = self.config.get("tor_min_speed_kbs", 0)
            if tor_min > 0:
                bw_bps = (self._rx_history[-1] if self._rx_history else 0) / 3
                if 0 < bw_bps < tor_min * 1024:
                    self._tor_slow_count += 1
                    if self._tor_slow_count >= self.config.get("speed_fail_count", 3):
                        self._tor_slow_count = 0
                        self._log(
                            f"Débit Tor faible ({bw_bps/1024:.0f} KB/s) — nouveau circuit …",
                            "WARN")
                        self._new_tor_circuit()
                else:
                    self._tor_slow_count = 0
