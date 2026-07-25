"""Watchdog : lecture des compteurs, test de connectivité, filet anti-inertie."""

import socket
import time
import unittest

import daemon.watchdog as m_watchdog
from tests.helpers import FakeDaemon, FakeProc, Recorder, patched_run


PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes
    lo:   12345     100    0    0    0     0          0         0
  ens18: 999888     500    0    0    0     0          0         0
   tun0: 4242424    3000    0    0    0     0          0         0
"""


class ReadRxTest(unittest.TestCase):

    def _read(self, iface, content=PROC_NET_DEV):
        from unittest.mock import mock_open, patch
        d = FakeDaemon(_tun_iface=iface)
        with patch("builtins.open", mock_open(read_data=content)):
            return d._read_tun0_rx()

    def test_lit_les_octets_recus_de_la_bonne_interface(self):
        self.assertEqual(self._read("tun0"), 4242424)

    def test_ne_confond_pas_les_interfaces(self):
        self.assertEqual(self._read("ens18"), 999888)

    def test_interface_absente_renvoie_zero(self):
        self.assertEqual(self._read("tun9"), 0)

    def test_fichier_illisible_renvoie_zero(self):
        from unittest.mock import patch
        d = FakeDaemon(_tun_iface="tun0")
        with patch("builtins.open", side_effect=OSError("pas de /proc")):
            self.assertEqual(d._read_tun0_rx(), 0)

    def test_sur_le_vrai_proc_net_dev(self):
        """Intégration (lecture seule) : le parseur doit tenir sur la sortie
        réelle du noyau, pas seulement sur un échantillon figé."""
        import pathlib
        proc = pathlib.Path("/proc/net/dev")
        if not proc.exists():
            self.skipTest("/proc/net/dev absent")
        ifaces = [ln.split(":", 1)[0].strip()
                  for ln in proc.read_text().splitlines() if ":" in ln]
        self.assertIn("lo", ifaces, "format de /proc/net/dev inattendu")
        d = FakeDaemon(_tun_iface="lo")
        octets = d._read_tun0_rx()
        self.assertIsInstance(octets, int)
        self.assertGreater(octets, 0, "loopback à 0 octet reçu : parsing suspect")


class VpnIsActiveTest(unittest.TestCase):

    def test_process_vivant(self):
        d = FakeDaemon()
        p = FakeProc(returncode=None)
        p._rc = None
        d.openvpn_process = p
        with patched_run(Recorder({"pgrep": (1, "")})):
            self.assertTrue(d._vpn_is_active())

    def test_repli_sur_pgrep(self):
        d = FakeDaemon()
        d.openvpn_process = None
        with patched_run(Recorder({"pgrep": (0, "1234")})):
            self.assertTrue(d._vpn_is_active())

    def test_aucun_openvpn(self):
        d = FakeDaemon()
        d.openvpn_process = None
        with patched_run(Recorder({"pgrep": (1, "")})):
            self.assertFalse(d._vpn_is_active())


class ConnectivityTest(unittest.TestCase):
    """Le double endpoint évite un redémarrage complet sur une panne ponctuelle."""

    def _check(self, link_rc=0, echecs=(), grace=False):
        """`echecs` : indices des endpoints qui doivent échouer."""
        d = FakeDaemon(_tun_iface="tun0")
        d._tunnel_up_time = time.time() if grace else time.time() - 3600
        tentes = []

        class FakeSock:
            def __init__(self, *a, **k):
                pass

            def setsockopt(self, *a):
                pass

            def settimeout(self, t):
                pass

            def connect(self, addr):
                tentes.append(addr)
                if (len(tentes) - 1) in echecs:
                    raise OSError("injoignable")

            def close(self):
                pass

        saved = m_watchdog.socket.socket
        m_watchdog.socket.socket = FakeSock
        try:
            with patched_run(Recorder({"ip link show": (link_rc, "")})):
                return d._check_connectivity(), tentes
        finally:
            m_watchdog.socket.socket = saved

    def test_interface_absente(self):
        ok, tentes = self._check(link_rc=1)
        self.assertFalse(ok)
        self.assertEqual(tentes, [], "connexion tentée sans interface")

    def test_delai_de_grace(self):
        ok, tentes = self._check(grace=True)
        self.assertTrue(ok)
        self.assertEqual(tentes, [], "test réseau pendant le délai de grâce")

    def test_premier_endpoint_repond(self):
        ok, tentes = self._check()
        self.assertTrue(ok)
        self.assertEqual(len(tentes), 1, "second endpoint sollicité inutilement")
        self.assertEqual(tentes[0], ("1.1.1.1", 443))

    def test_second_avis_quand_le_premier_echoue(self):
        ok, tentes = self._check(echecs=(0,))
        self.assertTrue(ok, "un endpoint en panne suffit à déclarer la panne")
        self.assertEqual([a[0] for a in tentes], ["1.1.1.1", "9.9.9.9"])

    def test_les_deux_endpoints_en_panne(self):
        ok, tentes = self._check(echecs=(0, 1))
        self.assertFalse(ok)
        self.assertEqual(len(tentes), 2)

    def test_endpoints_independants(self):
        """Deux opérateurs distincts : pas deux résolveurs du même fournisseur."""
        hotes = [h for h, _ in m_watchdog.WatchdogMixin._CONN_ENDPOINTS]
        self.assertEqual(len(set(hotes)), 2)
        self.assertNotIn("1.0.0.1", hotes, "1.0.0.1 est le même opérateur que 1.1.1.1")


class InertNetTest(unittest.TestCase):
    """Filet anti-inertie : aucune impasse ne doit être définitive."""

    def test_seuils_coherents(self):
        W = m_watchdog.WatchdogMixin
        self.assertLess(W._INERT_WARN_TICKS, W._INERT_EXIT_TICKS)
        self.assertEqual(W._INERT_EXIT_TICKS * 3, 120, "le seuil de sortie doit rester à 2 min")

    def test_rafraichissement_des_guards_toutes_les_30s(self):
        self.assertEqual(m_watchdog.WatchdogMixin._GUARD_REFRESH_TICKS * 3, 30)

    def test_delai_de_grace_de_30s(self):
        self.assertEqual(m_watchdog.WatchdogMixin._CONN_GRACE, 30)


class FullRestartTest(unittest.TestCase):

    def _daemon(self):
        d = FakeDaemon(config={"auto_reconnect": True})
        d._tunnel_up, d._tun_iface = True, "tun0"
        d.appels = []
        for nom in ("_stop_openvpn", "_stop_tor", "_cleanup_tor_routes",
                    "_ipv6_block_off"):
            setattr(d, nom, (lambda n: lambda: d.appels.append(n))(nom))
        d._wait_vpn_loop_exit = lambda timeout=15.0: d.appels.append("_wait") or True
        d._start_services = lambda: d.appels.append("_start") or True
        return d

    def test_sequence_d_arret_puis_relance(self):
        import types
        d = self._daemon()
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        for attendu in ("_stop_openvpn", "_stop_tor", "_wait",
                        "_cleanup_tor_routes", "_ipv6_block_off", "_start"):
            self.assertIn(attendu, d.appels, f"{attendu} non appelé")
        self.assertLess(d.appels.index("_stop_openvpn"), d.appels.index("_start"))

    def test_etat_reinitialise(self):
        import types
        d = self._daemon()
        d._conn_fail_count, d._reconnect_vpn_count = 5, 4
        d._conn_restart_pending = True
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertEqual(d._conn_fail_count, 0)
        self.assertEqual(d._reconnect_vpn_count, 0)
        self.assertFalse(d._conn_restart_pending)
        self.assertFalse(d._tunnel_up)
        self.assertFalse(d._stop_vpn, "_stop_vpn resté armé : la boucle ne repartirait pas")
        self.assertFalse(d._stop_tor_flag)

    def test_reparation_d_urgence_au_seuil(self):
        import types
        d = self._daemon()
        d._full_restart_count = m_watchdog.REPAIR_THRESHOLD - 1
        appele = []
        d._emergency_repair = lambda: appele.append(1)
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertEqual(appele, [1], "réparation d'urgence non déclenchée au seuil")


if __name__ == "__main__":
    unittest.main()
