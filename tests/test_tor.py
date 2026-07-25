"""Tor : parsing du ControlPort, bootstrap, NEWNYM, batching des requêtes."""

import unittest

from tests.helpers import FakeDaemon, Recorder, patched_run


# Consensus « microdesc » (défaut des clients Tor) : 8 champs, pas de digest.
NS_MICRODESC = (
    "250+ns/id/$AAAA=\r\n"
    "r Relay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-07-25 10:00:00 77.1.2.3 9001 0\r\n"
    "s Fast Guard Running Stable Valid\r\n"
    ".\r\n250 OK\r\n"
)
# Consensus « ns » complet : 9 champs (digest supplémentaire).
NS_FULL = (
    "250+ns/id/$BBBB=\r\n"
    "r Relay2 BBBBBBBBBBBBBBBBBBBBBBBBBBB CCCCCCCCCCCCCCCCCCCCCCCCCCC "
    "2026-07-25 10:00:00 88.4.5.6 443 0\r\n"
    "s Fast Running Valid\r\n"
    ".\r\n250 OK\r\n"
)


class TorRelayIpsTest(unittest.TestCase):
    """_tor_relay_ips alimente la protection /32 : un parsing faux = boucle de routage."""

    def _run_with(self, ctrl_responses):
        d = FakeDaemon()
        seen = []

        def fake_ctrl(*commands, timeout=3.0):
            seen.append(list(commands))
            return ctrl_responses.pop(0) if ctrl_responses else ""

        d._tor_ctrl = fake_ctrl
        return d, d._tor_relay_ips(), seen

    def test_format_microdesc_8_champs(self):
        orcon = "250+orcon-status=\r\n$AAAA~Relay1 CONNECTED\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, NS_MICRODESC])
        self.assertEqual(ips, {"77.1.2.3"})

    def test_format_ns_9_champs(self):
        orcon = "250+orcon-status=\r\n$BBBB~Relay2 CONNECTED\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, NS_FULL])
        self.assertEqual(ips, {"88.4.5.6"})

    def test_les_deux_formats_melanges(self):
        orcon = ("250+orcon-status=\r\n$AAAA~R1 CONNECTED\r\n"
                 "$BBBB~R2 CONNECTED\r\n.\r\n250 OK\r\n")
        _, ips, _ = self._run_with([orcon, NS_MICRODESC + NS_FULL])
        self.assertEqual(ips, {"77.1.2.3", "88.4.5.6"})

    def test_batching_une_seule_connexion(self):
        """Correctif des timeouts ControlPort : toutes les requêtes ns/id en UN appel."""
        orcon = ("250+orcon-status=\r\n"
                 + "".join(f"$FP{i}~R{i} CONNECTED\r\n" for i in range(12))
                 + ".\r\n250 OK\r\n")
        _, _, seen = self._run_with([orcon, ""])
        self.assertEqual(len(seen), 2, "plus de 2 connexions au ControlPort")
        self.assertEqual(len(seen[1]), 12, "les requêtes ns/id ne sont pas groupées")

    def test_plafonne_a_32_relais(self):
        orcon = ("250+orcon-status=\r\n"
                 + "".join(f"$FP{i}~R{i} CONNECTED\r\n" for i in range(50))
                 + ".\r\n250 OK\r\n")
        _, _, seen = self._run_with([orcon, ""])
        self.assertEqual(len(seen[1]), 32, "le plafond de 32 requêtes n'est pas respecté")

    def test_relais_non_connectes_ignores(self):
        orcon = ("250+orcon-status=\r\n$AAAA~R1 LAUNCHED\r\n"
                 "$BBBB~R2 CLOSED\r\n.\r\n250 OK\r\n")
        d = FakeDaemon()
        calls = []
        d._tor_ctrl = lambda *c, timeout=3.0: (calls.append(c), orcon)[1]
        self.assertEqual(d._tor_relay_ips(), set())
        self.assertEqual(len(calls), 1, "requête ns/id émise sans relais connecté")

    def test_controlport_en_erreur_renvoie_ensemble_vide(self):
        """Doit permettre le repli sur ss, pas propager l'exception."""
        d = FakeDaemon()

        def boom(*c, timeout=3.0):
            raise OSError("connexion refusée")

        d._tor_ctrl = boom
        self.assertEqual(d._tor_relay_ips(), set())
        self.assertTrue(d.has_log("relais indisponibles", "WARN"))

    def test_lignes_trop_courtes_ignorees(self):
        orcon = "250+orcon-status=\r\n$AAAA~R1 CONNECTED\r\n.\r\n250 OK\r\n"
        ns = "250+ns/id/$AAAA=\r\nr Relay1 AAA 9001 0\r\ns Fast\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, ns])
        self.assertEqual(ips, set())


class BootstrapProgressTest(unittest.TestCase):

    def _prog(self, response):
        d = FakeDaemon()
        d._tor_ctrl = lambda *c, **k: response
        return d._tor_bootstrap_progress()

    # Format réel de la réponse : PROGRESS= est un jeton séparé par des
    # espaces (« NOTICE BOOTSTRAP PROGRESS=n TAG=… SUMMARY="…" »).  Le
    # parseur a bien atteint 100 % par cette voie en production.
    def test_progression_lue(self):
        self.assertEqual(
            self._prog('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=75 '
                       'TAG=loading_status SUMMARY="Loading networkstatus"'), 75)

    def test_cent_pour_cent(self):
        self.assertEqual(
            self._prog('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 '
                       'TAG=done SUMMARY="Done"'), 100)

    def test_absent_renvoie_moins_un(self):
        self.assertEqual(self._prog("250 OK"), -1)

    def test_exception_renvoie_moins_un(self):
        d = FakeDaemon()

        def boom(*c, **k):
            raise OSError("nope")

        d._tor_ctrl = boom
        self.assertEqual(d._tor_bootstrap_progress(), -1)


class NewCircuitTest(unittest.TestCase):

    def test_succes(self):
        d = FakeDaemon()
        sent = []
        d._tor_ctrl = lambda *c, **k: (sent.extend(c), "250 OK")[1]
        d._new_tor_circuit()
        self.assertEqual(sent, ["SIGNAL NEWNYM"])
        self.assertTrue(d.has_log("Nouveau circuit demandé", "OK"))

    def test_reponse_inattendue(self):
        d = FakeDaemon()
        d._tor_ctrl = lambda *c, **k: "515 Command not recognized"
        d._new_tor_circuit()
        self.assertTrue(d.has_log("réponse inattendue", "WARN"))

    def test_exception_journalisee_sans_lever(self):
        d = FakeDaemon()

        def boom(*c, **k):
            raise OSError("socket fermé")

        d._tor_ctrl = boom
        d._new_tor_circuit()          # ne doit pas lever
        self.assertTrue(d.has_log("NEWNYM", "WARN"))


class StopTorTest(unittest.TestCase):

    def test_terminate_puis_reap(self):
        from tests.helpers import FakeProc
        d = FakeDaemon()
        proc = FakeProc(returncode=None)
        proc._rc = None                      # process vivant
        d.tor_process = proc
        with patched_run(Recorder()):
            d._stop_tor()
        self.assertTrue(proc.terminated)
        self.assertTrue(d._stop_tor_flag)

    def test_pkill_si_pas_de_process(self):
        d = FakeDaemon()
        d.tor_process = None
        r = Recorder()
        with patched_run(r):
            d._stop_tor()
        self.assertTrue(r.ran("pkill -x tor"))


if __name__ == "__main__":
    unittest.main()
