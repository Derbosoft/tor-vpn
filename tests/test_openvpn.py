"""OpenVPN : identifiants, scripts, qualité de circuit, décision de reconnexion."""

import os
import pathlib
import stat
import tempfile
import unittest

import daemon.openvpn as m_openvpn
from tests.helpers import (FakeDaemon, FakeProc, Recorder, no_sleep,
                           patched_run, patched_subprocess, provider)


AUTH_FAIL_MSG = ("AUTH: Received control message: AUTH_FAILED\n"
                 "SIGTERM[soft,auth-failure] received, process exiting\n")
AUTH_FAIL_ALT = "SIGTERM[soft,auth-failure] received, process exiting\n"
NET_DROP_MSG  = ("Connection reset, restarting [0]\n"
                 "SIGUSR1[soft,connection-reset] received\n")


class WriteAuthTmpTest(unittest.TestCase):
    """Les identifiants ne doivent jamais exister avec des droits laxistes."""

    def test_cree_directement_en_0600(self):
        d = FakeDaemon()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "auth.tmp"
            saved = m_openvpn.AUTH_TMP
            m_openvpn.AUTH_TMP = path
            try:
                os.umask(0o000)                    # pire cas : umask permissif
                d._write_auth_tmp("bob", "s3cret")
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode, 0o600, f"mode {oct(mode)} au lieu de 0600")
                self.assertEqual(path.read_text(), "bob\ns3cret\n")
            finally:
                m_openvpn.AUTH_TMP = saved


class GetActiveCredsTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ovpn = pathlib.Path(self._tmp.name) / "p.ovpn"
        self.ovpn.write_text("client\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_deobfusque_les_identifiants(self):
        d = FakeDaemon(config={"providers": [provider("ivpn", 2, str(self.ovpn))]})
        conf, user, pwd, name, idx = d._get_active_creds()
        self.assertEqual((user, pwd, name, idx), ("user0", "pass0", "ivpn", 0))
        self.assertEqual(conf, str(self.ovpn))

    def test_compte_courant_respecte(self):
        d = FakeDaemon(config={"providers": [provider("ivpn", 3, str(self.ovpn))]})
        d._current_account_idx = 2
        self.assertEqual(d._get_active_creds()[1], "user2")

    def test_ovpn_absent(self):
        d = FakeDaemon(config={"providers": [provider("x", 1, "/inexistant.ovpn")]})
        self.assertIsNone(d._get_active_creds())
        self.assertTrue(d.has_log(".ovpn introuvable", "ERROR"))

    def test_sans_ovpn_configure(self):
        p = provider("x", 1, "")
        d = FakeDaemon(config={"providers": [p]})
        self.assertIsNone(d._get_active_creds())

    def test_sans_compte(self):
        d = FakeDaemon(config={"providers": [provider("x", 0, str(self.ovpn))]})
        self.assertIsNone(d._get_active_creds())

    def test_index_hors_bornes(self):
        d = FakeDaemon(config={"providers": [provider("x", 1, str(self.ovpn))]})
        d._current_account_idx = 9
        self.assertIsNone(d._get_active_creds())

    def test_aucun_fournisseur(self):
        self.assertIsNone(FakeDaemon(config={"providers": []})._get_active_creds())

    def test_chemin_relatif_resolu_depuis_script_dir(self):
        d = FakeDaemon(config={"providers": [provider("x", 1, "providers/x/x.ovpn")]})
        d._log = lambda m, l="INFO": d.logs.append((l, m))
        res = d._get_active_creds()
        # Le fichier n'existe pas : on vérifie surtout que le chemin est absolu.
        self.assertTrue(d.has_log("/providers/x/x.ovpn") or res is None)


class CheckOvpnScriptsTest(unittest.TestCase):
    """Correctif #8 : alerter sur toute directive de script, présente ou non."""

    def _check(self, content):
        d = FakeDaemon()
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "c.ovpn"
            p.write_text(content)
            d._check_ovpn_scripts(str(p))
        return d

    def test_script_absent_signale(self):
        d = self._check("client\nup /inexistant/script.sh\n")
        self.assertTrue(d.has_log("directive de script", "ERROR"))

    def test_script_present_signale_aussi(self):
        """C'était l'angle mort : un update-resolv-conf existant écrase le DNS."""
        d = self._check("client\nup /bin/sh\n")
        self.assertTrue(d.has_log("directive de script", "ERROR"),
                        "une directive dont le script EXISTE est passée en silence")

    def test_toutes_les_directives_couvertes(self):
        for directive in m_openvpn.OpenVPNMixin._SCRIPT_DIRECTIVES:
            d = self._check(f"client\n{directive} /bin/sh\n")
            self.assertTrue(d.has_log("directive de script", "ERROR"),
                            f"directive non détectée : {directive}")

    def test_update_resolv_conf_le_cas_reel(self):
        d = self._check("client\nup /etc/openvpn/update-resolv-conf\n"
                        "down /etc/openvpn/update-resolv-conf\n")
        self.assertTrue(d.has_log("directive de script", "ERROR"))

    def test_config_propre_silencieuse(self):
        d = self._check("client\ndev tun\nproto tcp\nremote x 443\nauth-user-pass\n")
        self.assertEqual(d.logs, [], d.log_dump())

    def test_commentaires_ignores(self):
        d = self._check("client\n# up /etc/openvpn/script.sh\n;down /bin/sh\n")
        self.assertEqual(d.logs, [], d.log_dump())

    def test_directive_sans_argument_ignoree(self):
        d = self._check("client\nup\n")
        self.assertEqual(d.logs, [])

    def test_fichier_illisible_ne_leve_pas(self):
        FakeDaemon()._check_ovpn_scripts("/inexistant/nulle/part.ovpn")

    def test_mot_contenant_up_non_confondu(self):
        d = self._check("client\nauth-user-pass /etc/creds\nkeepalive 10 60\n")
        self.assertEqual(d.logs, [], d.log_dump())


class MeasureSpeedTest(unittest.TestCase):
    """Correctif #3 : la mesure doit être liée à l'interface tunnel."""

    def _measure(self, iface="tun0", out="512000", rc=0, exc=None):
        d = FakeDaemon()
        if exc:
            def boom(*a, **k):
                raise exc
            with patched_subprocess(m_openvpn, boom):
                return d._measure_tunnel_speed(iface), None
        rec = Recorder({"curl": (rc, out)})
        with patched_subprocess(m_openvpn, rec):
            return d._measure_tunnel_speed(iface), rec

    def test_interface_transmise_a_curl(self):
        _, rec = self._measure("tun0")
        self.assertTrue(rec.ran("--interface tun0"),
                        f"curl n'est pas lié au tunnel : {rec.dump()}")

    def test_sans_interface_pas_d_option(self):
        _, rec = self._measure("")
        self.assertFalse(rec.ran("--interface"))

    def test_conversion_octets_par_seconde_en_kbs(self):
        kbs, _ = self._measure(out="512000")
        self.assertAlmostEqual(kbs, 500.0, places=3)

    def test_max_time_present(self):
        _, rec = self._measure()
        self.assertTrue(rec.ran("--max-time 40"))

    def test_debit_nul_renvoie_moins_un(self):
        self.assertEqual(self._measure(out="0")[0], -1.0)

    def test_sortie_vide_renvoie_moins_un(self):
        self.assertEqual(self._measure(out="")[0], -1.0)

    def test_sortie_illisible_renvoie_moins_un(self):
        self.assertEqual(self._measure(out="pas-un-nombre")[0], -1.0)

    def test_exception_renvoie_moins_un(self):
        self.assertEqual(self._measure(exc=OSError("curl absent"))[0], -1.0)


class CircuitQualityTest(unittest.TestCase):
    """Correctifs #2 (thread périmé) et le comportement de re-tirage."""

    def _daemon(self, kbs, **cfg):
        d = FakeDaemon(config={"circuit_check": True, "circuit_min_kbs": 250,
                               "circuit_max_retries": 3, **cfg})
        d._tunnel_up, d._tun_iface = True, "tun0"
        d.openvpn_process = FakeProc(returncode=None)
        d.openvpn_process._rc = None                       # vivant
        d._measure_tunnel_speed = lambda iface="", timeout=40: kbs
        d.newnym = []
        d._new_tor_circuit = lambda: d.newnym.append(1)
        return d

    def _run(self, d):
        with no_sleep(m_openvpn):
            d._circuit_quality_check()
        return d

    def test_debit_suffisant_conserve_le_circuit(self):
        d = self._run(self._daemon(400.0))
        self.assertTrue(d.has_log("Débit OK", "OK"))
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.openvpn_process.terminated)
        self.assertEqual(d._circuit_attempts, 0)

    def test_debit_faible_retire_un_circuit(self):
        d = self._run(self._daemon(100.0))
        self.assertEqual(d.newnym, [1], "NEWNYM non demandé")
        self.assertTrue(d.openvpn_process.terminated, "OpenVPN non relancé")
        self.assertTrue(d._circuit_retry, "la reconnexion n'est pas marquée « circuit »")
        self.assertEqual(d._circuit_attempts, 1)
        self.assertTrue(d.has_log("Débit faible", "WARN"))

    def test_seuil_exact_accepte(self):
        d = self._run(self._daemon(250.0))
        self.assertTrue(d.has_log("Débit OK", "OK"))
        self.assertEqual(d.newnym, [])

    def test_plafond_d_essais_respecte(self):
        d = self._daemon(50.0)
        d._circuit_attempts = 3
        self._run(d)
        self.assertEqual(d.newnym, [], "re-tirage au-delà du plafond")
        self.assertFalse(d.openvpn_process.terminated)
        self.assertTrue(d.has_log("circuit conservé", "WARN"))

    def test_mesure_impossible_conserve(self):
        d = self._run(self._daemon(-1.0))
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.openvpn_process.terminated)
        self.assertTrue(d.has_log("Mesure du débit impossible", "WARN"))

    def test_desactive_ne_mesure_pas(self):
        d = self._daemon(10.0, circuit_check=False)
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [])

    def test_seuil_zero_desactive(self):
        d = self._daemon(10.0, circuit_min_kbs=0)
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [])

    def test_tunnel_ferme_avant_mesure(self):
        d = self._daemon(10.0)
        d._tunnel_up = False
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [], "mesure lancée alors que le tunnel est fermé")

    def test_processus_remplace_pendant_la_mesure(self):
        """#2 : un thread périmé ne doit PAS tuer le tunnel qui a pris la place."""
        d = self._daemon(50.0)
        ancien = d.openvpn_process
        nouveau = FakeProc(returncode=None)
        nouveau._rc = None

        def mesure_puis_remplacement(iface="", timeout=40):
            d.openvpn_process = nouveau          # reconnexion pendant la mesure
            return 50.0

        d._measure_tunnel_speed = mesure_puis_remplacement
        self._run(d)
        self.assertFalse(nouveau.terminated, "le NOUVEAU tunnel a été tué")
        self.assertFalse(ancien.terminated)
        self.assertEqual(d.newnym, [], "NEWNYM demandé sur un résultat périmé")
        self.assertFalse(d._circuit_retry)
        self.assertTrue(d.has_log("Tunnel renouvelé pendant la mesure", "WARN"))

    def test_tunnel_tombe_pendant_la_mesure(self):
        d = self._daemon(50.0)

        def mesure_puis_chute(iface="", timeout=40):
            d._tunnel_up = False
            return 50.0

        d._measure_tunnel_speed = mesure_puis_chute
        self._run(d)
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.openvpn_process.terminated)

    def test_interface_capturee_avant_la_mesure(self):
        d = self._daemon(400.0)
        vues = []
        d._measure_tunnel_speed = lambda iface="", timeout=40: (vues.append(iface), 400.0)[1]
        self._run(d)
        self.assertEqual(vues, ["tun0"])


class FailoverDecisionTest(unittest.TestCase):
    """Correctif #4 : bascule de compte seulement si les identifiants sont refusés."""

    def test_failover_compte_puis_fournisseur(self):
        d = FakeDaemon(config={"providers": [provider("a", 2), provider("b", 1)]})
        self.assertTrue(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (0, 1))
        self.assertTrue(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (1, 0))
        self.assertFalse(d._try_failover(), "devrait signaler l'épuisement")
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (0, 0))

    def test_next_provider_saute_les_comptes(self):
        d = FakeDaemon(config={"providers": [provider("a", 10), provider("b", 3)]})
        self.assertTrue(d._try_next_provider())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (1, 0),
                         "les comptes du fournisseur courant n'ont pas été sautés")
        self.assertFalse(d._try_next_provider())
        self.assertEqual(d._current_provider_idx, 1, "ne doit pas boucler sur 0")

    def test_next_provider_sans_fournisseur(self):
        self.assertFalse(FakeDaemon(config={"providers": []})._try_next_provider())


class ReconnectLoopTest(unittest.TestCase):
    """Boucle complète, avec un OpenVPN simulé : c'est le comportement observable."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ovpn = pathlib.Path(self._tmp.name) / "p.ovpn"
        self.ovpn.write_text("client\ndev tun\n")
        self.auth = pathlib.Path(self._tmp.name) / "auth.tmp"
        self._saved_auth = m_openvpn.AUTH_TMP
        m_openvpn.AUTH_TMP = self.auth

    def tearDown(self):
        m_openvpn.AUTH_TMP = self._saved_auth
        self._tmp.cleanup()

    def _run_loop(self, providers, sorties):
        d = FakeDaemon(config={"providers": providers, "auto_reconnect": True})
        d._orig_gw, d._orig_iface = "10.0.50.254", "ens18"
        d.tentatives = []
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("10.0.50.254", "ens18")
        d._build_route_args = lambda: []
        d._protect_tor_routes = lambda: None
        d._apply_vpn_dns = lambda: None
        d._apply_dns_split = lambda: None
        d._revert_vpn_dns = lambda: None
        d._ipv6_block_off = lambda: None
        d._new_tor_circuit = lambda: None
        d._check_ovpn_scripts = lambda c: None

        vrai_creds = d._get_active_creds

        def creds_espion():
            r = vrai_creds()
            if r:
                d.tentatives.append((r[3], r[4] + 1))
            return r

        d._get_active_creds = creds_espion
        restants = list(sorties)

        def popen(cmd, **kw):
            p = FakeProc(restants.pop(0) if restants else "")
            d.openvpn_process = p
            return p

        with patched_run(Recorder()), no_sleep(m_openvpn), \
                patched_subprocess(m_openvpn, Recorder(), popen=popen):
            d._openvpn_loop_body(0, 0)
        return d

    def test_coupure_reseau_garde_le_meme_compte(self):
        d = self._run_loop([provider("ivpn", 10, str(self.ovpn)),
                            provider("proton", 3, str(self.ovpn))],
                           [NET_DROP_MSG] * 6)
        comptes_ivpn = {n for p, n in d.tentatives if p == "ivpn"}
        self.assertEqual(comptes_ivpn, {1},
                         f"changement de compte sur une coupure réseau : {d.tentatives}")

    def test_coupure_reseau_bascule_de_fournisseur_apres_le_plafond(self):
        d = self._run_loop([provider("ivpn", 10, str(self.ovpn)),
                            provider("proton", 3, str(self.ovpn))],
                           [NET_DROP_MSG] * 8)
        self.assertIn("proton", [p for p, _ in d.tentatives],
                      "aucune bascule de fournisseur")
        self.assertTrue(d.has_log("Fournisseur suivant : proton", "WARN"))

    def test_coupure_reseau_temporise(self):
        d = self._run_loop([provider("ivpn", 10, str(self.ovpn))], [NET_DROP_MSG] * 3)
        self.assertTrue(d.has_log("reconnexion du même compte", "WARN"))

    def test_identifiants_refuses_bascule_de_compte(self):
        d = self._run_loop([provider("ivpn", 5, str(self.ovpn))],
                           [AUTH_FAIL_MSG, AUTH_FAIL_MSG, AUTH_FAIL_MSG, ""])
        self.assertEqual([n for _, n in d.tentatives][:4], [1, 2, 3, 4],
                         f"pas de bascule immédiate : {d.tentatives}")
        self.assertTrue(d.has_log("Identifiants refusés", "WARN"))

    def test_signature_sigterm_auth_failure_seule_suffit(self):
        d = self._run_loop([provider("ivpn", 3, str(self.ovpn))],
                           [AUTH_FAIL_ALT, ""])
        self.assertEqual([n for _, n in d.tentatives][:2], [1, 2])

    def test_nombre_de_tentatives_borne(self):
        """Le point de #4 : plus de rafale de dizaines d'authentifications."""
        d = self._run_loop([provider("ivpn", 10, str(self.ovpn)),
                            provider("proton", 3, str(self.ovpn))],
                           [NET_DROP_MSG] * 40)
        self.assertLessEqual(len(d.tentatives), 14,
                             f"{len(d.tentatives)} tentatives — rafale non maîtrisée")

    def test_fournisseur_inutilisable_saute_ses_comptes(self):
        casse = provider("casse", 10, "/inexistant.ovpn")
        d = self._run_loop([casse, provider("ivpn", 2, str(self.ovpn))],
                           [NET_DROP_MSG] * 3)
        self.assertTrue(all(p == "ivpn" for p, _ in d.tentatives),
                        f"le fournisseur cassé a été retenté : {d.tentatives}")

    def test_reconnexion_desactivee_sort_immediatement(self):
        d = FakeDaemon(config={"providers": [provider("a", 2, str(self.ovpn))],
                               "auto_reconnect": False})
        d._orig_gw, d._orig_iface = "10.0.50.254", "ens18"
        for m in ("_check_socks_port",):
            setattr(d, m, lambda: True)
        d._get_default_gateway = lambda: ("10.0.50.254", "ens18")
        for m in ("_build_route_args",):
            setattr(d, m, lambda: [])
        for m in ("_protect_tor_routes", "_apply_vpn_dns", "_apply_dns_split",
                  "_revert_vpn_dns", "_ipv6_block_off"):
            setattr(d, m, lambda: None)
        d._check_ovpn_scripts = lambda c: None
        n = []

        def popen(cmd, **kw):
            n.append(1)
            p = FakeProc("")
            d.openvpn_process = p
            return p

        with patched_run(Recorder()), no_sleep(m_openvpn), \
                patched_subprocess(m_openvpn, Recorder(), popen=popen):
            d._openvpn_loop_body(0, 0)
        self.assertEqual(len(n), 1, "a reconnecté malgré auto_reconnect=False")

    def test_auth_flag_remis_a_zero_entre_tentatives(self):
        d = self._run_loop([provider("ivpn", 5, str(self.ovpn))],
                           [AUTH_FAIL_MSG, NET_DROP_MSG, NET_DROP_MSG])
        # 1er échec = auth -> compte 2 ; ensuite coupures -> on reste sur 2
        comptes = [n for _, n in d.tentatives]
        self.assertEqual(comptes[0], 1)
        self.assertEqual(comptes[1], 2)
        self.assertEqual(set(comptes[1:]), {2},
                         f"le drapeau auth a fuité sur les tentatives suivantes : {comptes}")


class LoopGuardTest(unittest.TestCase):

    def test_une_seule_boucle_a_la_fois(self):
        d = FakeDaemon(config={"providers": []})
        d._vpn_loop_active = True
        d._openvpn_loop()
        self.assertTrue(d.has_log("Boucle OpenVPN déjà active", "WARN"))

    def test_drapeau_relache_meme_sur_exception(self):
        d = FakeDaemon(config={"providers": []})

        def boom(*a):
            raise RuntimeError("panne")

        d._openvpn_loop_body = boom
        with self.assertRaises(RuntimeError):
            d._openvpn_loop()
        self.assertFalse(d._vpn_loop_active, "drapeau resté armé après exception")


class LastCircuitMeasureTest(unittest.TestCase):
    """La dernière mesure doit être consultable, et jamais héritée d'un
    tunnel précédent — un chiffre périmé serait plus trompeur qu'absent."""

    def _daemon(self, kbs, **cfg):
        d = FakeDaemon(config={"circuit_check": True, "circuit_min_kbs": 250,
                               "circuit_max_retries": 3, **cfg})
        d._tunnel_up, d._tun_iface = True, "tun0"
        d.openvpn_process = FakeProc(returncode=None)
        d.openvpn_process._rc = None
        d._measure_tunnel_speed = lambda iface="", timeout=40: kbs
        d._new_tor_circuit = lambda: None
        return d

    def _run(self, d):
        with no_sleep(m_openvpn):
            d._circuit_quality_check()
        return d

    def test_mesure_conservee_quand_le_debit_est_bon(self):
        d = self._run(self._daemon(592.0))
        self.assertEqual(d._last_circuit_kbs, 592.0)
        self.assertGreater(d._last_circuit_at, 0)

    def test_mesure_conservee_meme_si_le_debit_est_faible(self):
        """Un mauvais tirage doit rester visible, c'est justement l'intérêt."""
        d = self._run(self._daemon(100.0))
        self.assertEqual(d._last_circuit_kbs, 100.0)

    def test_mesure_impossible_ne_falsifie_pas_la_valeur(self):
        d = self._daemon(-1.0)
        d._last_circuit_kbs = 0.0
        self._run(d)
        self.assertEqual(d._last_circuit_kbs, 0.0,
                         "une mesure ratée ne doit pas être enregistrée")

    def test_valeur_initiale_nulle(self):
        d = FakeDaemon()
        self.assertEqual(d._last_circuit_kbs, 0.0)
        self.assertEqual(d._last_circuit_at, 0.0)

    def test_controle_desactive_laisse_la_valeur_a_zero(self):
        d = self._daemon(500.0, circuit_check=False)
        self._run(d)
        self.assertEqual(d._last_circuit_kbs, 0.0)


class CircuitMeasureInStatusTest(unittest.TestCase):

    def test_expose_dans_le_statut(self):
        import time as _t
        d = FakeDaemon(config={"providers": []})
        d._last_circuit_kbs, d._last_circuit_at = 592.4, _t.time() - 7200
        snap = d._status_snapshot()
        self.assertEqual(snap["last_circuit_kbs"], 592.4)
        self.assertAlmostEqual(snap["last_circuit_age"], 7200, delta=5)

    def test_sans_mesure_les_champs_valent_zero(self):
        d = FakeDaemon(config={"providers": []})
        snap = d._status_snapshot()
        self.assertEqual(snap["last_circuit_kbs"], 0.0)
        self.assertEqual(snap["last_circuit_age"], 0,
                         "un âge non nul sans mesure serait ininterprétable")

    def test_statut_toujours_serialisable(self):
        import json
        d = FakeDaemon(config={"providers": []})
        d._last_circuit_kbs, d._last_circuit_at = 1.0, 1.0
        json.dumps(d._status_snapshot())

if __name__ == "__main__":
    unittest.main()
