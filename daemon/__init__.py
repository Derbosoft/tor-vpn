"""
Package daemon — point d'entrée pour le daemon Tor-VPN.

La classe Daemon hérite de tous les mixins :
  DaemonCore   — état, config, log, signaux, orchestration
  TorMixin     — processus Tor
  NetworkMixin — routes, SOCKS, protection guards Tor
  FirewallMixin — iptables / ip6tables, partage LAN, dnsmasq
  DNSMixin     — split DNS systemd-resolved
  OpenVPNMixin — boucle OpenVPN, failover
  WatchdogMixin — surveillance connectivité/débit, redémarrage
"""

import os
import signal
import sys

from .core      import DaemonCore
from .tor       import TorMixin
from .network   import NetworkMixin
from .firewall  import FirewallMixin
from .dns       import DNSMixin
from .openvpn   import OpenVPNMixin
from .watchdog  import WatchdogMixin


class Daemon(
    DaemonCore,
    TorMixin,
    NetworkMixin,
    FirewallMixin,
    DNSMixin,
    OpenVPNMixin,
    WatchdogMixin,
):
    """Daemon Tor-VPN : réunit tous les mixins."""


def main():
    if os.geteuid() != 0:
        print("Ce daemon doit être lancé en root.", file=sys.stderr)
        print("Utilisez :  sudo python3 -m daemon  ou  tor-vpn start")
        sys.exit(1)
    d = Daemon()
    signal.signal(signal.SIGTERM, d.handle_signal)
    signal.signal(signal.SIGINT,  d.handle_signal)
    d.run()


if __name__ == "__main__":
    main()
