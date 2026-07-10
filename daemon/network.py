"""
Réseau : gateway, SOCKS, routes Tor, routes exclues.
"""

import ipaddress
import socket

from .core import _run, TOR_ROUTES_FILE


class NetworkMixin:

    def _get_default_gateway(self):
        try:
            r = _run("ip", "route", "show", "default")
            for line in r.stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
                    return parts[2], parts[4]
        except Exception:
            pass
        return None, None

    def _check_socks_port(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 9050), timeout=3):
                return True
        except OSError:
            return False

    def _build_route_args(self) -> list:
        args = []
        for entry in self.config.get("excluded_ips", []):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                args += ["--route", str(net.network_address), str(net.netmask), "net_gateway"]
            except ValueError:
                self._log(f"Route ignorée (invalide) : {entry}", "WARN")
        return args

    def _add_protected_routes(self, ips, source: str):
        """Route en /32 via la gateway originale chaque IP IPv4 valide et
        nouvelle de `ips`, journalise et persiste l'ensemble."""
        added = []
        for ip in sorted(ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or ip.startswith(("127.", "0.")):
                continue
            if ip in self._protected_routes:
                continue
            _run("ip", "route", "replace", f"{ip}/32",
                 "via", self._orig_gw, "dev", self._orig_iface)
            self._protected_routes.add(ip)
            added.append(ip)
        if added:
            self._log(
                f"[route] {len(added)} IP(s) Tor protégée(s) via {source} "
                f"(total {len(self._protected_routes)}).", "INFO")
            try:
                TOR_ROUTES_FILE.write_text(
                    "\n".join(sorted(self._protected_routes)) + "\n")
            except Exception:
                pass

    def _protect_tor_routes(self):
        """Ajoute des routes /32 statiques via la gateway originale pour chaque
        IP de relais Tor actif.  Appel SYNCHRONE depuis le thread stdout
        d'OpenVPN, avant l'installation de redirect-gateway.
        Source primaire : ControlPort (orconn-status) ; repli : ss -tnp."""
        if not self._orig_gw or not self.tor_process:
            return

        # Source primaire : le ControlPort (fiable, indépendant du format
        # de sortie de ss).  Repli : inspection des sockets établies.
        ctrl_ips = self._tor_relay_ips()
        if ctrl_ips:
            self._add_protected_routes(ctrl_ips, "ControlPort")
            return

        pid = self.tor_process.pid
        try:
            # ss -tnp state established → colonnes :
            #   Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
            # On extrait l'adresse pair (relais Tor), colonne d'index 3.
            r = _run("ss", "-tnp", "state", "established")
            peers = set()
            for line in r.stdout.decode().splitlines():
                if f"pid={pid}" not in line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                peer = parts[3]
                # IPv6 entre crochets ([2001:db8::1]:443) → ignoré (tunnel IPv4).
                if peer.startswith("["):
                    continue
                peers.add(peer.rsplit(":", 1)[0])
            self._add_protected_routes(peers, "ss")
        except Exception as e:
            self._log(f"[route] {e}", "WARN")

    def _cleanup_tor_routes(self):
        """Supprime les routes /32 Tor (session courante + fichier persistant)."""
        routes = set(self._protected_routes)
        if TOR_ROUTES_FILE.exists():
            try:
                routes.update(
                    ln.strip()
                    for ln in TOR_ROUTES_FILE.read_text().splitlines()
                    if ln.strip()
                )
            except Exception:
                pass
        for ip in routes:
            _run("ip", "route", "del", f"{ip}/32")
        self._protected_routes.clear()
        TOR_ROUTES_FILE.unlink(missing_ok=True)
        if routes:
            self._log(f"[route] {len(routes)} route(s) /32 Tor supprimée(s).", "INFO")
