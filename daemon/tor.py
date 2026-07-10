"""
Gestion du processus Tor : démarrage, arrêt, nouveau circuit (NEWNYM).
"""

import shutil
import socket
import threading
import time

from .core import (
    _run, TOR_DATA_DIR, TOR_COOKIE, TOR_CTRL_PORT, TORRC_FILE,
    RECONNECT_DELAY, RECONNECT_MAX,
)


class TorMixin:

    def _start_tor(self):
        if self.tor_process and self.tor_process.poll() is None:
            return
        if not shutil.which("tor"):
            self._log("Tor non installé — lancez : sudo apt install tor", "ERROR")
            return

        # Libérer le port 9050 si le service tor système tourne encore
        try:
            s = socket.socket()
            s.settimeout(1)
            busy = s.connect_ex(("127.0.0.1", 9050)) == 0
            s.close()
        except OSError:
            busy = False
        if busy:
            self._log("[tor] Port 9050 occupé — arrêt service tor système …", "WARN")
            _run("systemctl", "stop", "tor")
            _run("pkill", "-x", "tor")
            time.sleep(2)

        # Attendre la sortie de l'ancien thread _run_tor AVANT de remettre
        # _stop_tor_flag à False : sinon l'ancien thread, encore dans son
        # attente de reconnexion, repartirait → deux processus Tor.
        if self._tor_thread and self._tor_thread.is_alive():
            self._tor_thread.join(timeout=10)
            if self._tor_thread.is_alive():
                self._log("[tor] Ancien thread Tor toujours actif — "
                          "démarrage annulé.", "ERROR")
                return

        TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._tor_ready.clear()
        self._stop_tor_flag = False

        if TORRC_FILE.exists():
            cmd = ["tor", "--torrc-file", str(TORRC_FILE), "--Log", "notice stdout"]
        else:
            cmd = [
                "tor",
                "--SocksPort",            "9050",
                "--ControlPort",          str(TOR_CTRL_PORT),
                "--CookieAuthentication", "1",
                "--DataDirectory",        str(TOR_DATA_DIR),
                "--Log",                  "notice stdout",
            ]

        def _run_tor():
            import subprocess
            self._reconnect_tor_count = 0
            while True:
                self._log("Démarrage de Tor …")
                try:
                    self.tor_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    for line in self.tor_process.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        low = line.lower()
                        if "bootstrapped 100%" in low:
                            self._tor_ready.set()
                            self._reconnect_tor_count = 0
                            self._log("[tor] Réseau Tor prêt (100%).", "OK")
                        elif "err" in low:
                            self._log(f"[tor] {line}", "ERROR")
                        elif "warn" in low:
                            self._log(f"[tor] {line}", "WARN")
                        else:
                            self._log(f"[tor] {line}")
                    self._tor_ready.clear()
                    self._log("Processus Tor terminé.", "WARN")
                except FileNotFoundError:
                    self._log("tor introuvable.", "ERROR")
                    break
                except Exception as e:
                    self._log(f"Tor : {e}", "ERROR")

                if self._stop_tor_flag or self._stop_flag:
                    break
                if not self.config.get("auto_reconnect", True):
                    break
                self._reconnect_tor_count += 1
                if self._reconnect_tor_count > RECONNECT_MAX:
                    self._log(f"Tor : {RECONNECT_MAX} tentatives échouées.", "ERROR")
                    break
                self._log(
                    f"Tor : reconnexion dans {RECONNECT_DELAY}s "
                    f"({self._reconnect_tor_count}/{RECONNECT_MAX}) …", "WARN")
                for _ in range(RECONNECT_DELAY):
                    if self._stop_flag or self._stop_tor_flag:
                        return
                    time.sleep(1)

        self._tor_thread = threading.Thread(target=_run_tor, daemon=True)
        self._tor_thread.start()


    # ── ControlPort ───────────────────────────────────────────────────────────

    def _tor_ctrl(self, *commands, timeout: float = 3.0) -> str:
        """Envoie une ou plusieurs commandes au ControlPort (auth cookie)
        et renvoie la réponse brute.  Lève OSError en cas d'échec réseau."""
        auth = b"AUTHENTICATE\r\n"
        try:
            if TOR_COOKIE.exists():
                auth = b"AUTHENTICATE " + TOR_COOKIE.read_bytes().hex().encode() + b"\r\n"
        except Exception:
            pass
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect(("127.0.0.1", TOR_CTRL_PORT))
            s.sendall(auth)
            if b"250" not in s.recv(256):
                raise OSError("authentification ControlPort refusée")
            out = []
            for cmd in commands:
                s.sendall(cmd.encode() + b"\r\n")
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Fin de réponse : ligne de statut « 250 … » ou « 5xx … »
                    if b"\r\n250 " in buf or buf.endswith(b"250 OK\r\n") \
                       or b"\r\n5" in buf[-64:]:
                        break
                out.append(buf.decode(errors="ignore"))
            s.sendall(b"QUIT\r\n")
            return "\n".join(out)

    def _tor_bootstrap_progress(self) -> int:
        """Progression du bootstrap (0-100) via GETINFO, -1 si indisponible."""
        try:
            resp = self._tor_ctrl("GETINFO status/bootstrap-phase")
            for tok in resp.split():
                if tok.startswith("PROGRESS="):
                    return int(tok.split("=", 1)[1])
        except Exception:
            pass
        return -1

    def _tor_relay_ips(self) -> set:
        """IPs IPv4 des relais auxquels Tor est connecté, via le ControlPort
        (orconn-status → ns/id/<fingerprint>).  Ensemble vide en cas d'échec :
        l'appelant peut alors se replier sur l'inspection des sockets (ss)."""
        ips = set()
        try:
            resp = self._tor_ctrl("GETINFO orconn-status")
            fps = []
            for line in resp.splitlines():
                line = line.strip().lstrip("250+-").strip()
                if line.startswith("$") and "CONNECTED" in line:
                    fps.append(line[1:].split("~")[0].split("=")[0].split()[0])
            for fp in fps[:32]:                      # borne de sécurité
                ns = self._tor_ctrl(f"GETINFO ns/id/${fp}")
                # Ligne « r … <IP> <ORPort> <DirPort> » : l'IP est le 3e champ
                # en partant de la fin — valable pour les deux formats de
                # consensus (ns : 9 champs avec digest ; microdesc : 8 champs
                # sans digest, le défaut des clients Tor).
                for line in ns.splitlines():
                    w = line.strip().split()
                    if len(w) >= 8 and w[0] == "r":
                        ips.add(w[-3])
                        break
        except Exception as e:
            self._log(f"[tor-ctrl] relais indisponibles via ControlPort : {e}", "WARN")
        return ips

    def _stop_tor(self):
        self._stop_tor_flag = True
        if self.tor_process and self.tor_process.poll() is None:
            self.tor_process.terminate()
            try:
                self.tor_process.wait(timeout=5)   # reape le process, évite le zombie
            except Exception:
                self.tor_process.kill()            # SIGTERM ignoré → SIGKILL
                try:
                    self.tor_process.wait(timeout=3)
                except Exception:
                    pass
            self._tor_ready.clear()
        else:
            _run("pkill", "-x", "tor")
