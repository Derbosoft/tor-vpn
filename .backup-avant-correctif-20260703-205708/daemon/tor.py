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

        threading.Thread(target=_run_tor, daemon=True).start()

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

    def _new_tor_circuit(self):
        try:
            # Authentification par cookie si disponible (CookieAuthentication 1),
            # sinon repli sur l'authentification nulle (torrc personnalisé).
            auth = b"AUTHENTICATE\r\n"
            try:
                if TOR_COOKIE.exists():
                    auth = b"AUTHENTICATE " + TOR_COOKIE.read_bytes().hex().encode() + b"\r\n"
            except Exception:
                pass
            with socket.socket() as s:
                s.settimeout(3)
                s.connect(("127.0.0.1", TOR_CTRL_PORT))
                s.sendall(auth + b"SIGNAL NEWNYM\r\n")
                resp = s.recv(256).decode(errors="ignore")
                if "250" in resp:
                    self._log("Tor : nouveau circuit (NEWNYM).", "OK")
                else:
                    self._log(
                        f"Tor NEWNYM : réponse inattendue ({resp.strip()[:40]})", "WARN")
        except Exception as e:
            self._log(f"Tor NEWNYM : {e}", "WARN")
