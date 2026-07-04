"""
Pare-feu : blocage IPv6 iptables/ip6tables, partage LAN.
"""

import shutil
import subprocess
import threading

from .core import (
    _run,
    KS6_CHAIN, KS6_FWD_CHAIN, KS_LAN_CHAIN,
    LAN_DNSMASQ_PID,
)


class FirewallMixin:

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_libvirt_bridges() -> list:
        import glob as _gl
        from pathlib import Path
        try:
            return sorted(
                Path(p).name
                for p in _gl.glob("/sys/class/net/virbr*")
                if not Path(p).name.endswith("-nic")
            )
        except Exception:
            return []

    # ── Blocage IPv6 ──────────────────────────────────────────────────────────

    def _ipv6_block_on(self):
        if self._ipv6_blocked:
            return
        tun = self._tun_iface
        try:
            _run("ip6tables", "-N", KS6_CHAIN)
            _run("ip6tables", "-F", KS6_CHAIN)
            _run("ip6tables", "-A", KS6_CHAIN, "-o", "lo",  "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN, "-o", tun,   "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN, "-j", "DROP")
            r = _run("ip6tables", "-I", "OUTPUT", "-j", KS6_CHAIN)
            if r.returncode != 0:
                self._log("ip6tables OUTPUT : échec.", "ERROR")
                return

            _run("ip6tables", "-N", KS6_FWD_CHAIN)
            _run("ip6tables", "-F", KS6_FWD_CHAIN)
            _run("ip6tables", "-A", KS6_FWD_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_FWD_CHAIN, "-i", "virbr+", "-o", "virbr+", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_FWD_CHAIN, "-i", "virbr+", "-j", "DROP")
            _run("ip6tables", "-I", "FORWARD", "-j", KS6_FWD_CHAIN)

            self._ipv6_blocked = True
            self._log("IPv6 bloqué — host + VMs.", "OK")
        except Exception as e:
            self._log(f"IPv6 block : {e}", "ERROR")

    def _ipv6_block_off(self):
        if not self._ipv6_blocked:
            return
        try:
            _run("ip6tables", "-D", "OUTPUT",  "-j", KS6_CHAIN)
            _run("ip6tables", "-F", KS6_CHAIN)
            _run("ip6tables", "-X", KS6_CHAIN)
            _run("ip6tables", "-D", "FORWARD", "-j", KS6_FWD_CHAIN)
            _run("ip6tables", "-F", KS6_FWD_CHAIN)
            _run("ip6tables", "-X", KS6_FWD_CHAIN)
            self._ipv6_blocked = False
        except Exception:
            pass

    # ── Partage LAN ───────────────────────────────────────────────────────────

    def _setup_lan_sharing(self) -> bool:
        if self._lan_active:
            return True
        import ipaddress as _ip
        iface  = self.config.get("lan_iface",   "").strip()
        gw     = self.config.get("lan_gateway", "10.0.0.1").strip()
        subnet = self.config.get("lan_subnet",  "10.0.0.0/24").strip()
        if not iface:
            self._log("Partage LAN : aucune interface configurée.", "ERROR")
            return False
        # Refus catégorique : ne jamais flush l'interface qui porte la route
        # par défaut (uplink Internet) — cela couperait toute connectivité.
        _, uplink = self._get_default_gateway()
        if uplink and iface == uplink:
            self._log(
                f"Partage LAN : '{iface}' porte la route par défaut (uplink) — "
                "configuration refusée pour ne pas couper le réseau.", "ERROR")
            return False
        try:
            net = _ip.ip_network(subnet, strict=False)
        except ValueError:
            self._log(f"Partage LAN : sous-réseau invalide : {subnet}", "ERROR")
            return False
        try:
            _run("ip", "addr", "flush", "dev", iface)
            r = _run("ip", "addr", "add", f"{gw}/{net.prefixlen}", "dev", iface)
            if r.returncode != 0:
                self._log(f"Partage LAN : ip addr add : {r.stderr.decode().strip()}", "ERROR")
                return False
            _run("ip", "link", "set", iface, "up")
            tun = self._tun_iface
            _run("sysctl", "-w", "net.ipv4.ip_forward=1")
            r = _run("iptables", "-t", "nat", "-C", "POSTROUTING",
                     "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            if r.returncode != 0:
                _run("iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            _run("iptables", "-N", KS_LAN_CHAIN)
            _run("iptables", "-F", KS_LAN_CHAIN)
            _run("iptables", "-A", KS_LAN_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("iptables", "-A", KS_LAN_CHAIN, "-i", iface, "-o", tun, "-j", "RETURN")
            _run("iptables", "-A", KS_LAN_CHAIN, "-i", iface, "-j", "DROP")
            _run("iptables", "-I", "FORWARD", "-j", KS_LAN_CHAIN)
            self._lan_active = True
            self._log(f"Partage LAN actif : {iface} ({gw}/{net.prefixlen}) → {tun}.", "OK")
            if self.config.get("lan_dhcp", True):
                self._start_lan_dnsmasq(iface, gw, net)
            return True
        except Exception as e:
            self._log(f"Partage LAN : {e}", "ERROR")
            return False

    def _teardown_lan_sharing(self):
        if not self._lan_active:
            return
        import ipaddress as _ip
        iface  = self.config.get("lan_iface",  "").strip()
        subnet = self.config.get("lan_subnet", "10.0.0.0/24").strip()
        self._stop_lan_dnsmasq()
        try:
            net = _ip.ip_network(subnet, strict=False)
        except ValueError:
            net = None
        try:
            _run("iptables", "-D", "FORWARD", "-j", KS_LAN_CHAIN)
            _run("iptables", "-F", KS_LAN_CHAIN)
            _run("iptables", "-X", KS_LAN_CHAIN)
            if net:
                _run("iptables", "-t", "nat", "-D", "POSTROUTING",
                     "-s", str(net), "-o", self._tun_iface, "-j", "MASQUERADE")
            if iface:
                _run("ip", "addr", "flush", "dev", iface)
            self._lan_active = False
            self._log("Partage LAN désactivé.", "OK")
        except Exception as e:
            self._log(f"Partage LAN (désactivation) : {e}", "ERROR")

    def _start_lan_dnsmasq(self, iface: str, gw: str, net):
        if not shutil.which("dnsmasq"):
            self._log("dnsmasq non installé — DHCP inactif.", "WARN")
            return
        hosts = list(net.hosts())
        n = len(hosts)
        if n >= 200:
            dhcp_start, dhcp_end = str(hosts[99]), str(hosts[199])
        elif n >= 10:
            dhcp_start = str(hosts[n // 4])
            dhcp_end   = str(hosts[3 * n // 4])
        else:
            dhcp_start, dhcp_end = str(hosts[0]), str(hosts[-1])
        cmd = [
            "dnsmasq",
            f"--interface={iface}",
            "--bind-interfaces",
            "--no-daemon",
            f"--dhcp-range={dhcp_start},{dhcp_end},24h",
            f"--dhcp-option=3,{gw}",
            "--dhcp-option=6,1.1.1.1",
            "--no-resolv",
            f"--pid-file={LAN_DNSMASQ_PID}",
        ]

        def _run_dns():
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._dnsmasq_proc = proc
                self._log(f"dnsmasq DHCP démarré : {iface} ({dhcp_start}–{dhcp_end}).", "OK")
                proc.wait()
                self._log("dnsmasq terminé.", "WARN")
                LAN_DNSMASQ_PID.unlink(missing_ok=True)
            except Exception as ex:
                self._log(f"dnsmasq : {ex}", "ERROR")

        threading.Thread(target=_run_dns, daemon=True).start()

    def _stop_lan_dnsmasq(self):
        proc = self._dnsmasq_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        self._dnsmasq_proc = None
        LAN_DNSMASQ_PID.unlink(missing_ok=True)
