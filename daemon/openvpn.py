"""
OpenVPN : gestion du processus, failover, boucle de reconnexion.

Corrections critiques appliquées :
  - --verb 3  : requis pour que net_addr_v4_add apparaisse dans les logs
  - --connect-timeout 60 : évite les faux échecs lors d'un circuit Tor lent
  - _protect_tor_routes() synchrone à net_addr_v4_add : évite la boucle de routage
  - _apply_dns_split() après "Initialization Sequence Completed" : évite que le
    script up d'OpenVPN écrase la config DNS split appliquée au démarrage
"""

import os
import subprocess
import threading
import time
from pathlib import Path

from .core import (
    _run, _deobf, AUTH_TMP, SCRIPT_DIR, RECONNECT_DELAY, RECONNECT_MAX,
)


class OpenVPNMixin:

    def _write_auth_tmp(self, username: str, password: str):
        # Création directe en 0600 — évite la fenêtre où le fichier de
        # credentials existerait avec les permissions par défaut de l'umask.
        fd = os.open(str(AUTH_TMP), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{username}\n{password}\n")

    def _stop_openvpn(self):
        self._stop_vpn = True
        if self.openvpn_process and self.openvpn_process.poll() is None:
            self.openvpn_process.terminate()
            try:
                self.openvpn_process.wait(timeout=5)   # reape, évite le zombie
            except Exception:
                self.openvpn_process.kill()            # SIGTERM ignoré → SIGKILL
                try:
                    self.openvpn_process.wait(timeout=3)
                except Exception:
                    pass
        else:
            _run("pkill", "-x", "openvpn")
        if AUTH_TMP.exists():
            AUTH_TMP.unlink()

    def _get_active_creds(self):
        providers = self.config.get("providers", [])
        if not providers or self._current_provider_idx >= len(providers):
            return None
        p    = providers[self._current_provider_idx]
        ovpn = p.get("ovpn_file", "")
        if not ovpn:
            return None
        path = Path(ovpn)
        if not path.is_absolute():
            path = SCRIPT_DIR / path
        if not path.exists():
            self._log(f"[provider] Fichier .ovpn introuvable : {path}", "ERROR")
            return None
        accounts = p.get("accounts", [])
        if not accounts or self._current_account_idx >= len(accounts):
            return None
        acc = accounts[self._current_account_idx]
        return (
            str(path),
            _deobf(acc.get("u", "")),
            _deobf(acc.get("p", "")),
            p["name"],
            self._current_account_idx,
        )

    def _try_failover(self) -> bool:
        providers = self.config.get("providers", [])
        if not providers:
            return False
        cur_p    = providers[self._current_provider_idx]
        accounts = cur_p.get("accounts", [])
        if self._current_account_idx + 1 < len(accounts):
            self._current_account_idx += 1
            self._log(
                f"Failover : compte {self._current_account_idx+1}/{len(accounts)} "
                f"chez {cur_p['name']}", "WARN")
            return True
        if self._current_provider_idx + 1 < len(providers):
            self._current_provider_idx += 1
            self._current_account_idx  = 0
            next_p = providers[self._current_provider_idx]
            self._log(f"Failover : {cur_p['name']} épuisé → {next_p['name']}", "WARN")
            return True
        self._current_provider_idx = 0
        self._current_account_idx  = 0
        self._log("Failover : tous les fournisseurs et comptes épuisés.", "ERROR")
        return False

    def _dns_script_args(self, cur_conf: str) -> list:
        """Arguments --up/--down pour configurer le DNS du VPN.

        OpenVPN n'accepte qu'un seul script up : on n'ajoute le nôtre que si
        le .ovpn n'en définit pas déjà un.  Le script update-resolv-conf est
        fourni par les paquets « resolvconf » ou « openvpn-systemd-resolved »
        (pas par « openvpn » lui-même sur les distributions récentes)."""
        script = Path("/etc/openvpn/update-resolv-conf")
        conf_has_updown = False
        try:
            for ln in Path(cur_conf).read_text(errors="ignore").splitlines():
                w = ln.strip().split()
                if w and w[0] in ("up", "down"):
                    conf_has_updown = True
                    break
        except Exception:
            pass
        if conf_has_updown:
            if not script.exists() and f"{script}" in Path(cur_conf).read_text(errors="ignore"):
                self._log(
                    f"Le .ovpn référence {script} qui est absent — la connexion "
                    "échouera. Installez : sudo apt install resolvconf "
                    "(ou openvpn-systemd-resolved).", "ERROR")
            return []          # le .ovpn gère lui-même ses scripts up/down
        if script.exists():
            return ["--up", str(script), "--down", str(script)]
        self._log(
            "Aucun script DNS : /etc/openvpn/update-resolv-conf absent et le "
            ".ovpn ne définit pas de script up → DNS du VPN non configuré "
            "(risque de fuite/panne DNS). Installez : sudo apt install "
            "resolvconf  (ou openvpn-systemd-resolved).", "WARN")
        return []

    def _wait_vpn_loop_exit(self, timeout: float = 15.0) -> bool:
        """Attend que la boucle OpenVPN en cours se termine (utilisé avant
        d'en relancer une — évite deux boucles/processus concurrents)."""
        for _ in range(int(timeout * 10)):
            with self._vpn_lock:
                if not self._vpn_loop_active:
                    return True
            time.sleep(0.1)
        return False

    def _openvpn_loop(self, start_provider_idx: int = 0, start_account_idx: int = 0):
        # Garde-fou : une seule boucle OpenVPN active à la fois.
        with self._vpn_lock:
            if self._vpn_loop_active:
                self._log("Boucle OpenVPN déjà active — second démarrage ignoré.", "WARN")
                return
            self._vpn_loop_active = True
        try:
            self._openvpn_loop_body(start_provider_idx, start_account_idx)
        finally:
            with self._vpn_lock:
                self._vpn_loop_active = False

    def _openvpn_loop_body(self, start_provider_idx: int, start_account_idx: int):
        self._current_provider_idx = start_provider_idx
        self._current_account_idx  = start_account_idx
        self._reconnect_vpn_count  = 0
        self._stop_vpn             = False

        while not self._stop_vpn and not self._stop_flag:
            result = self._get_active_creds()
            if not result:
                self._log("Aucun fournisseur/compte disponible.", "ERROR")
                break
            cur_conf, username, password, prov_name, acc_idx = result
            self._log(f"Fournisseur : {prov_name}  (compte {acc_idx+1})", "INFO")

            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible — attente (60s max) …", "WARN")
                for _ in range(60):
                    if self._stop_flag or self._stop_vpn:
                        return
                    if self._check_socks_port():
                        break
                    time.sleep(1)
            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible après attente — abandon.", "ERROR")
                break
            self._log("Proxy SOCKS5 127.0.0.1:9050 OK.", "OK")

            self._orig_gw, self._orig_iface = self._get_default_gateway()
            if self._orig_gw:
                self._log(f"Passerelle : {self._orig_gw} via {self._orig_iface}")

            self._write_auth_tmp(username, password)

            route_args = self._build_route_args()
            cmd = [
                "openvpn",
                "--config",            cur_conf,
                "--auth-user-pass",    str(AUTH_TMP),
                "--script-security",   "2",
                "--verb",              "3",   # requis pour net_addr_v4_add
                "--ping",              "10",
                "--ping-exit",         "60",
                "--connect-timeout",   "60",  # Tor peut être lent à établir un circuit
                "--connect-retry",     "1",
                "--connect-retry-max", "1",
                "--socks-proxy",       "127.0.0.1", "9050",
            ]
            cmd += route_args

            cmd += self._dns_script_args(cur_conf)

            self._log(f"OpenVPN : {os.path.basename(cur_conf)} via Tor …")
            tunnel_up = False
            self._tunnel_up = False
            try:
                self.openvpn_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                for line in self.openvpn_process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()

                    if "tun/tap device" in low and "opened" in low:
                        for word in line.split():
                            if word.startswith("tun") and word != "tun/tap":
                                self._tun_iface = word
                                self._log(f"[openvpn] Interface tunnel : {self._tun_iface}", "INFO")
                                break

                    # Synchrone — doit s'exécuter avant que le script up
                    # installe redirect-gateway.
                    elif "net_addr_v4_add" in low:
                        self._protect_tor_routes()

                    if "error" in low or "failed" in low:
                        self._log(f"[openvpn] {line}", "ERROR")
                    elif "initialization sequence completed" in low:
                        if not tunnel_up:
                            # Filet de sécurité si net_addr_v4_add a été manqué.
                            threading.Thread(
                                target=self._protect_tor_routes, daemon=True).start()
                            tunnel_up = True
                            self._tunnel_up      = True
                            self._tunnel_up_time = time.time()
                            self._reconnect_vpn_count = 0
                            self._log("Tunnel VPN actif.", "OK")
                            # Appliquer le DNS split APRÈS que le script up d'OpenVPN
                            # ait tourné, pour éviter qu'il écrase notre config.
                            self._apply_dns_split()
                            if self.config.get("block_ipv6"):
                                self._ipv6_block_on()
                            if self.config.get("lan_auto") and self.config.get("lan_iface"):
                                self._setup_lan_sharing()
                        self._log(f"[openvpn] {line}", "OK")
                    elif "warning" in low:
                        self._log(f"[openvpn] {line}", "WARN")
                    else:
                        self._log(f"[openvpn] {line}")

                self._tunnel_up = False
                self._log("Processus OpenVPN terminé.", "WARN")

            except FileNotFoundError:
                self._log("openvpn introuvable : sudo apt install openvpn", "ERROR")
                break
            except Exception as e:
                self._log(f"OpenVPN : {e}", "ERROR")
            finally:
                if AUTH_TMP.exists():
                    AUTH_TMP.unlink()

            if self._stop_vpn or self._stop_flag:
                self._ipv6_block_off()
                break

            if not self.config.get("auto_reconnect", True):
                self._ipv6_block_off()
                break

            if self._try_failover():
                self._log("Failover — reconnexion immédiate …", "WARN")
                time.sleep(3)
                continue

            self._reconnect_vpn_count += 1
            if self._reconnect_vpn_count > RECONNECT_MAX:
                self._log(
                    f"OpenVPN : {RECONNECT_MAX} tentatives échouées, abandon.", "ERROR")
                break

            self._log(
                f"OpenVPN : reconnexion dans {RECONNECT_DELAY}s "
                f"({self._reconnect_vpn_count}/{RECONNECT_MAX}) …", "WARN")
            for _ in range(RECONNECT_DELAY):
                if self._stop_flag or self._stop_vpn:
                    return
                time.sleep(1)
