"""
DNS : split DNS via drop-in systemd-resolved, et DNS du VPN appliqué
nativement par resolvectl (sans dépendre du script update-resolv-conf).
"""

import shutil
import subprocess

from .core import _run, RESOLVED_DROP_IN


class DNSMixin:

    # ── Contrôle de l'environnement DNS ──────────────────────────────────────

    def _check_dns_stack(self):
        """Vérifie au démarrage que systemd-resolved est disponible et actif.
        Sans lui, le DNS du VPN et le split DNS ne peuvent pas s'appliquer :
        le trafic reste tunnelé, mais les requêtes DNS peuvent échouer ou
        fuir hors Tor.  On avertit tôt (au lieu d'attendre la 1re connexion)."""
        if not shutil.which("resolvectl"):
            self._log(
                "resolvectl introuvable — systemd-resolved requis pour la "
                "protection DNS (DNS du VPN + split DNS). Sans lui, la "
                "résolution DNS peut échouer ou fuir hors Tor. "
                "Installez systemd-resolved.", "WARN")
            return
        if _run("systemctl", "is-active", "systemd-resolved").stdout \
                .decode().strip() != "active":
            self._log(
                "systemd-resolved n'est pas actif — la protection DNS ne "
                "pourra pas s'appliquer. Lancez : "
                "systemctl enable --now systemd-resolved.", "WARN")

    def _ensure_dns_config(self):
        """Réapplique le DNS s'il a disparu (ex. systemd-resolved redémarré
        par un autre outil).  Appelé périodiquement par le watchdog quand le
        tunnel est actif.  Léger : en temps normal, une simple lecture ;
        réapplication uniquement si la config a effectivement été perdue."""
        if not self._tunnel_up:
            return
        # 1. DNS du VPN (config runtime par interface — perdue si resolved
        #    redémarre, contrairement au drop-in qui est persistant).
        if self._vpn_dns_ips:
            try:
                r = subprocess.run(["resolvectl", "dns", self._tun_iface],
                                   capture_output=True, text=True, timeout=5)
                if not any(ip in r.stdout for ip in self._vpn_dns_ips):
                    self._log("[dns] DNS du VPN absent de l'interface — "
                              "réapplication.", "WARN")
                    self._apply_vpn_dns()
            except Exception:
                pass
        # 2. Drop-in split DNS (persistant, mais un autre outil a pu le
        #    supprimer) : le réécrire s'il devrait exister et manque.
        if (self.config.get("local_dns", "").strip()
                and self.config.get("excluded_domains")
                and not RESOLVED_DROP_IN.exists()):
            self._log("[dns] Drop-in split DNS disparu — réapplication.", "WARN")
            self._apply_dns_split()

    # ── DNS du VPN (poussé par le serveur, appliqué via resolvectl) ──────────

    def _apply_vpn_dns(self):
        """Applique les serveurs DNS poussés par le VPN (PUSH_REPLY
        dhcp-option DNS) sur l'interface tunnel via systemd-resolved.
        « ~. » fait de ces serveurs la destination DNS par défaut ; le
        drop-in du split DNS garde la priorité sur les domaines exclus."""
        ips = list(dict.fromkeys(self._vpn_dns_ips))   # dédup, ordre conservé
        if not ips:
            self._log(
                "Aucun DNS poussé par le VPN (dhcp-option DNS absent du "
                "PUSH_REPLY) — DNS système inchangé, risque de fuite ou de "
                "panne DNS derrière redirect-gateway.", "WARN")
            return
        tun = self._tun_iface
        try:
            r = subprocess.run(["resolvectl", "dns", tun, *ips],
                               capture_output=True, timeout=10)
            if r.returncode != 0:
                self._log(
                    f"resolvectl dns {tun} : "
                    f"{r.stderr.decode(errors='ignore').strip() or 'échec'} — "
                    "systemd-resolved est-il actif ?", "ERROR")
                return
            subprocess.run(["resolvectl", "domain", tun, "~."],
                           capture_output=True, timeout=10)
            subprocess.run(["resolvectl", "default-route", tun, "true"],
                           capture_output=True, timeout=10)
            self._log(f"DNS du VPN appliqué sur {tun} : {', '.join(ips)}", "OK")
        except FileNotFoundError:
            self._log("resolvectl introuvable — DNS du VPN non appliqué. "
                      "Installez systemd-resolved.", "ERROR")
        except Exception as e:
            self._log(f"DNS du VPN : {e}", "ERROR")

    def _revert_vpn_dns(self):
        """Retire la config DNS de l'interface tunnel (sans toucher au
        split DNS).  Sans effet si l'interface a déjà disparu."""
        try:
            subprocess.run(["resolvectl", "revert", self._tun_iface],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        self._vpn_dns_ips = []

    def _apply_dns_split(self):
        dns     = self.config.get("local_dns", "").strip()
        domains = self.config.get("excluded_domains", [])
        if not dns or not domains:
            self._remove_dns_split()
            return
        domain_str = " ".join(f"~{d.lstrip('.')}" for d in domains)
        try:
            RESOLVED_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
            RESOLVED_DROP_IN.write_text(f"[Resolve]\nDNS={dns}\nDomains={domain_str}\n")
            # « resolvectl reload » n'existe pas, et « systemctl reload »
            # échoue sur les systemd sans ExecReload : reload-or-restart
            # applique le drop-in de manière fiable partout.
            subprocess.run(["systemctl", "reload-or-restart", "systemd-resolved"],
                           capture_output=True, timeout=15)
            self._log(f"DNS split actif : {len(domains)} domaine(s) → {dns}", "OK")
        except Exception as e:
            self._log(f"DNS split : {e}", "WARN")

    def _remove_dns_split(self):
        if RESOLVED_DROP_IN.exists():
            try:
                RESOLVED_DROP_IN.unlink()
                subprocess.run(["systemctl", "reload-or-restart", "systemd-resolved"],
                               capture_output=True, timeout=15)
                self._log("DNS split désactivé.", "OK")
            except Exception:
                pass
