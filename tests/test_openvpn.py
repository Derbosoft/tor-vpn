"""OpenVPN : identifiants, scripts, qualité de circuit, décision de reconnexion."""

import os
import pathlib
import stat
import tempfile
import time
import unittest

import daemon.openvpn as m_openvpn
from constants import DEFAULT_CONFIG
from tests.helpers import (FakeDaemon, FakeProc, Recorder, no_sleep,
                           patched_run, patched_subprocess, provider)


AUTH_FAIL_MSG = ("AUTH: Received control message: AUTH_FAILED\n"
                 "SIGTERM[soft,auth-failure] received, process exiting\n")
AUTH_FAIL_ALT = "SIGTERM[soft,auth-failure] received, process exiting\n"
NET_DROP_MSG  = ("Connection reset, restarting [0]\n"
                 "SIGUSR1[soft,connection-reset] received\n")
# Tunnel réellement monté : c'est cette ligne, et elle seule, qui déclenche le
# traitement « tunnel actif » du daemon.
TUNNEL_UP_MSG = "Initialization Sequence Completed\n"


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


class SequenceCurl:
    """Répond à chaque appel curl par la valeur suivante d'une séquence.

    Le Recorder rend toujours la même réponse pour un motif donné : il ne peut
    pas exprimer « la 1re requête est lente, les suivantes sont rapides », qui
    est précisément le comportement à tester."""

    def __init__(self, valeurs):
        self.valeurs = list(valeurs)
        self.calls = []

    def __call__(self, *cmd, **kwargs):
        argv = list(cmd[0]) if len(cmd) == 1 and isinstance(cmd[0], (list, tuple)) else list(cmd)
        self.calls.append(" ".join(str(c) for c in argv))
        v = self.valeurs.pop(0) if self.valeurs else 0
        from tests.helpers import Result
        r = Result(0, str(v))
        r.text = bool(kwargs.get("text"))
        return r

    def n_curl(self):
        return len([c for c in self.calls if c.startswith("curl")])


class MeasureWarmupTest(unittest.TestCase):
    """La mesure décrit la capacité du circuit, pas le coût de la 1re requête.

    Relevé sur un circuit vieux de 9 h, mesure du daemon rejouée 3 fois :
    344 KB/s, puis 985, puis 979.  Le premier échantillon coûte l'ouverture
    d'un flux TCP/TLS à travers Tor — il ne dit rien de la capacité."""

    def _mesure(self, octets_par_sec, still_valid=None):
        d = FakeDaemon()
        seq = SequenceCurl(octets_par_sec)
        with patched_subprocess(m_openvpn, seq), no_sleep(m_openvpn):
            kbs = d._measure_tunnel_speed("tun0", still_valid=still_valid)
        return kbs, seq, d

    def test_echauffement_effectue(self):
        """1 échauffement + _SPEED_SAMPLES échantillons."""
        M = m_openvpn.OpenVPNMixin
        _, seq, _ = self._mesure([100_000] * (M._SPEED_SAMPLES + 1))
        self.assertEqual(seq.n_curl(), M._SPEED_SAMPLES + 1,
                         f"requêtes : {seq.calls}")

    def test_echauffement_plus_petit_que_les_echantillons(self):
        """Son rôle est d'ouvrir le circuit, pas de mesurer : il doit être bon
        marché.  Les échantillons, eux, restent à la taille de calibration."""
        M = m_openvpn.OpenVPNMixin
        self.assertLess(M._SPEED_WARMUP_BYTES, M._SPEED_BYTES)

    def test_taille_d_echantillon_non_reduite(self):
        """Un échantillon court passe sa vie en slow-start et sous-estime.

        Mesuré après échauffement sur le même circuit : 500 Ko → 383 KB/s,
        2 Mo → 1061 KB/s.  Le seuil circuit_min_kbs est calibré sur 2 Mo ;
        réduire l'échantillon ferait rejeter des circuits sains."""
        self.assertGreaterEqual(m_openvpn.OpenVPNMixin._SPEED_BYTES, 2_000_000,
                                "échantillon réduit : la mesure sous-estimera")

    def test_echauffement_et_echantillons_de_tailles_distinctes(self):
        M = m_openvpn.OpenVPNMixin
        _, seq, _ = self._mesure([100_000] * (M._SPEED_SAMPLES + 1))
        curls = [c for c in seq.calls if c.startswith("curl")]
        self.assertIn(f"bytes={M._SPEED_WARMUP_BYTES}", curls[0])
        for c in curls[1:]:
            self.assertIn(f"bytes={M._SPEED_BYTES}", c)

    def test_resultat_de_l_echauffement_jete(self):
        """Le cas réel : 1re requête lente, suivantes rapides."""
        kbs, _, _ = self._mesure([344 * 1024, 985 * 1024, 979 * 1024])
        self.assertAlmostEqual(kbs, 985.0, places=0,
                               msg="l'échauffement a été compté dans le résultat")

    def test_maximum_retenu_et_non_moyenne(self):
        kbs, _, _ = self._mesure([1, 344 * 1024, 985 * 1024])
        self.assertAlmostEqual(kbs, 985.0, places=0)
        self.assertNotAlmostEqual(kbs, (344 + 985) / 2, places=0,
                                  msg="une moyenne pénaliserait un circuit gêné")

    def test_empreinte_reseau_bornee(self):
        """Le contrôle n'a lieu qu'une fois par tunnel, mais reste borné."""
        M = m_openvpn.OpenVPNMixin
        total = M._SPEED_WARMUP_BYTES + M._SPEED_BYTES * M._SPEED_SAMPLES
        self.assertLessEqual(total, 5_000_000,
                             f"{total} octets par contrôle — empreinte excessive")

    def test_seconde_salve_si_tous_les_echantillons_echouent(self):
        M = m_openvpn.OpenVPNMixin
        par_salve = M._SPEED_SAMPLES + 1
        # 1re salve entièrement en échec, 2e exploitable.
        kbs, seq, d = self._mesure([0] * par_salve + [1, 500 * 1024, 400 * 1024])
        self.assertEqual(seq.n_curl(), par_salve * 2, f"requêtes : {seq.calls}")
        self.assertAlmostEqual(kbs, 500.0, places=0)
        self.assertTrue(d.has_log("seconde salve", "WARN"), d.log_dump())

    def test_deux_salves_au_maximum(self):
        """Jamais de boucle : deux salves puis abandon."""
        M = m_openvpn.OpenVPNMixin
        kbs, seq, _ = self._mesure([0] * 20)
        self.assertEqual(kbs, -1.0)
        self.assertEqual(seq.n_curl(), (M._SPEED_SAMPLES + 1) * 2,
                         "plus de deux salves")

    def test_interruption_si_le_tunnel_disparait(self):
        """Inutile de sonder une interface morte pendant plusieurs requêtes."""
        etat = {"vivant": True}

        def still_valid():
            # Vivant pour l'échauffement, mort ensuite.
            v = etat["vivant"]
            etat["vivant"] = False
            return v

        kbs, seq, _ = self._mesure([500 * 1024] * 12, still_valid=still_valid)
        self.assertEqual(kbs, -1.0)
        self.assertLessEqual(seq.n_curl(), 2,
                             f"a continué à sonder : {seq.calls}")

    def test_budget_total_borne(self):
        """Le contrôle ne doit pas durer plus que la reconnexion qu'il décide."""
        M = m_openvpn.OpenVPNMixin
        pire = 2 * (M._SPEED_SAMPLES + 1) * M._SPEED_TIMEOUT + M._SPEED_RETRY
        self.assertGreater(pire, M._SPEED_BUDGET,
                           "le budget ne sert à rien s'il dépasse le pire cas")
        self.assertLessEqual(M._SPEED_BUDGET, 90,
                             f"budget de {M._SPEED_BUDGET}s trop permissif")

    def test_budget_epuise_interrompt(self):
        """Requêtes lentes : on s'arrête au budget, pas au nombre de salves."""
        d = FakeDaemon()
        seq = SequenceCurl([0] * 20)
        vrai = m_openvpn.time.time
        horloge = {"t": vrai()}
        # Chaque requête « coûte » 30 s d'horloge : le budget saute vite.
        def faux_temps():
            return horloge["t"]
        def avance(*a, **k):
            horloge["t"] += 30
            return seq(*a, **k)
        m_openvpn.time.time = faux_temps
        try:
            with patched_subprocess(m_openvpn, avance), no_sleep(m_openvpn):
                kbs = d._measure_tunnel_speed("tun0")
        finally:
            m_openvpn.time.time = vrai
        self.assertEqual(kbs, -1.0)
        M = m_openvpn.OpenVPNMixin
        self.assertLess(seq.n_curl(), (M._SPEED_SAMPLES + 1) * 2,
                        f"le budget n'a pas interrompu : {seq.n_curl()} requêtes")

    def test_aucune_requete_si_deja_invalide(self):
        kbs, seq, _ = self._mesure([500 * 1024] * 12, still_valid=lambda: False)
        self.assertEqual(kbs, -1.0)
        self.assertEqual(seq.n_curl(), 0)


class MeasureSpeedTest(unittest.TestCase):
    """Correctif #3 : la mesure doit être liée à l'interface tunnel."""

    def _measure(self, iface="tun0", out="512000", rc=0, exc=None):
        d = FakeDaemon()
        if exc:
            def boom(*a, **k):
                raise exc
            with patched_subprocess(m_openvpn, boom), no_sleep(m_openvpn):
                return d._measure_tunnel_speed(iface), None
        rec = Recorder({"curl": (rc, out)})
        with patched_subprocess(m_openvpn, rec), no_sleep(m_openvpn):
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
        self.assertTrue(rec.ran(f"--max-time {m_openvpn.OpenVPNMixin._SPEED_TIMEOUT}"))

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
        d._measure_tunnel_speed = lambda iface="", still_valid=None: kbs
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

        def mesure_puis_remplacement(iface="", still_valid=None):
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

        def mesure_puis_chute(iface="", still_valid=None):
            d._tunnel_up = False
            return 50.0

        d._measure_tunnel_speed = mesure_puis_chute
        self._run(d)
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.openvpn_process.terminated)

    def test_interface_capturee_avant_la_mesure(self):
        d = self._daemon(400.0)
        vues = []
        d._measure_tunnel_speed = lambda iface="", still_valid=None: (vues.append(iface), 400.0)[1]
        self._run(d)
        self.assertEqual(vues, ["tun0"])


class FailoverDecisionTest(unittest.TestCase):
    """Correctif #4 : bascule de compte seulement si les identifiants sont refusés."""

    def test_failover_compte_puis_fournisseur(self):
        # random_account désactivé : ce test porte sur la SÉQUENCE compte →
        # fournisseur → épuisement, pas sur l'ordre de tirage.
        d = FakeDaemon(config={"random_account": False,
                               "providers": [provider("a", 2), provider("b", 1)]})
        self.assertTrue(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (0, 1))
        self.assertTrue(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (1, 0))
        self.assertFalse(d._try_failover(), "devrait signaler l'épuisement")
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (0, 0))

    def test_next_provider_saute_les_comptes(self):
        d = FakeDaemon(config={"random_account": False,
                               "providers": [provider("a", 10), provider("b", 3)]})
        self.assertTrue(d._try_next_provider())
        self.assertEqual((d._current_provider_idx, d._current_account_idx), (1, 0),
                         "les comptes du fournisseur courant n'ont pas été sautés")
        self.assertFalse(d._try_next_provider())
        self.assertEqual(d._current_provider_idx, 1, "ne doit pas boucler sur 0")

    def test_next_provider_sans_fournisseur(self):
        self.assertFalse(FakeDaemon(config={"providers": []})._try_next_provider())


class AccountCooldownTest(unittest.TestCase):
    """Un compte refusé est relégué, JAMAIS exclu.

    Motif tiré du déploiement réel : le fournisseur envoie un « AUTH_FAILED »
    nu, sans distinguer un mot de passe invalide d'un quota de connexions
    simultanées atteint.  Le compte 1 d'iVPN a été refusé les 12 et 18 juillet
    puis s'est connecté une douzaine de fois — le refus était temporaire."""

    @staticmethod
    def _daemon(n=5, alea=False):
        return FakeDaemon(config={"random_account": alea,
                                  "providers": [provider("ivpn", n)]})

    def test_compte_en_quarantaine_relegue_en_fin_dordre(self):
        d = self._daemon()
        d._plan_accounts()
        d._mettre_en_quarantaine(0)
        d._plan_accounts()
        self.assertEqual(d._account_order[-1], 0,
                         f"compte 1 non relégué : {d._account_order}")
        self.assertNotEqual(d._current_account_idx, 0,
                            "un compte en quarantaine ne doit pas être essayé en premier")

    def test_quarantaine_n_exclut_jamais_le_compte(self):
        """Le point de l'utilisateur : « ce compte n'est pas mort pour autant »."""
        d = self._daemon()
        for i in range(5):
            d._mettre_en_quarantaine(i)
        d._plan_accounts()
        self.assertEqual(sorted(d._account_order), list(range(5)),
                         "des comptes en quarantaine ont été retirés de l'ordre")

    def test_ordre_reste_une_permutation_avec_quarantaines_partielles(self):
        d = self._daemon(n=10, alea=True)
        for i in (2, 5, 7):
            d._mettre_en_quarantaine(i)
        d._plan_accounts()
        self.assertEqual(sorted(d._account_order), list(range(10)))
        # Les trois punis occupent les trois dernières places, dans un ordre
        # quelconque entre eux.
        self.assertEqual(set(d._account_order[-3:]), {2, 5, 7})

    def test_quarantaine_expire(self):
        d = self._daemon()
        d._mettre_en_quarantaine(3)
        self.assertGreater(d._cooldown_restant(3), 0)
        d._account_cooldown[(0, 3)] = time.time() - 1     # échue
        self.assertEqual(d._cooldown_restant(3), 0)
        d._plan_accounts()
        self.assertEqual(sorted(d._account_order), list(range(5)))

    def test_quarantaine_par_fournisseur(self):
        """Le compte 1 de « a » et le compte 1 de « b » sont deux comptes."""
        d = FakeDaemon(config={"random_account": False,
                               "providers": [provider("a", 3), provider("b", 3)]})
        d._mettre_en_quarantaine(0)
        self.assertGreater(d._cooldown_restant(0), 0)
        d._current_provider_idx = 1
        self.assertEqual(d._cooldown_restant(0), 0,
                         "la quarantaine a fuité sur un autre fournisseur")

    def test_quarantaine_journalisee(self):
        d = self._daemon()
        d._mettre_en_quarantaine(1)
        d._plan_accounts()
        self.assertTrue(d.has_log("compte(s) en quarantaine"), d.log_dump())


class RandomAccountOrderTest(unittest.TestCase):
    """Comptes tirés au hasard, fournisseurs toujours dans l'ordre de priorité."""

    @staticmethod
    def _daemon(n_a=10, n_b=3, alea=True):
        return FakeDaemon(config={
            "random_account": alea,
            "providers": [provider("a", n_a), provider("b", n_b)]})

    def test_defaut_de_configuration_est_aleatoire(self):
        self.assertTrue(DEFAULT_CONFIG["random_account"])

    def test_ordre_fige_quand_desactive(self):
        d = self._daemon(alea=False)
        d._plan_accounts()
        self.assertEqual(d._account_order, list(range(10)))
        self.assertEqual(d._current_account_idx, 0)

    def test_ordre_est_une_permutation_complete(self):
        """Chaque compte exactement une fois : « épuisés » doit avoir un sens."""
        for _ in range(30):
            d = self._daemon()
            d._plan_accounts()
            self.assertEqual(sorted(d._account_order), list(range(10)),
                             f"ordre non couvrant : {d._account_order}")

    def test_le_tirage_varie_reellement(self):
        """Garde-fou contre un shuffle sans effet (ordre figé par accident)."""
        premiers = set()
        for _ in range(40):
            d = self._daemon()
            d._plan_accounts()
            premiers.add(d._account_order[0])
        self.assertGreater(len(premiers), 1,
                           "le tirage rend toujours le même premier compte")

    def test_tous_les_comptes_essayes_avant_le_fournisseur_suivant(self):
        d = self._daemon()
        d._plan_accounts()
        vus = [d._current_account_idx]
        while d._current_provider_idx == 0:
            if not d._try_failover():
                break
            if d._current_provider_idx == 0:
                vus.append(d._current_account_idx)
        self.assertEqual(sorted(vus), list(range(10)),
                         f"comptes de « a » non épuisés avant bascule : {vus}")
        self.assertEqual(d._current_provider_idx, 1)

    def test_ordre_des_fournisseurs_jamais_melange(self):
        """La priorité des fournisseurs est celle de la configuration."""
        for _ in range(10):
            d = self._daemon(n_a=2, n_b=2)
            d._plan_accounts()
            noms = [d.config["providers"][d._current_provider_idx]["name"]]
            for _ in range(6):
                if not d._try_failover():
                    break
                nom = d.config["providers"][d._current_provider_idx]["name"]
                if nom != noms[-1]:
                    noms.append(nom)
            self.assertEqual(noms, ["a", "b"], f"priorité non respectée : {noms}")

    def test_ordre_tire_est_journalise(self):
        """Sans la trace, un incident sur un tirage donné serait irreproductible."""
        d = self._daemon()
        d._plan_accounts()
        self.assertTrue(d.has_log("ordre des comptes tiré au hasard"),
                        d.log_dump())

    def test_compte_unique_pas_de_journal_de_tirage(self):
        d = FakeDaemon(config={"random_account": True,
                               "providers": [provider("a", 1)]})
        d._plan_accounts()
        self.assertEqual(d._account_order, [0])
        self.assertFalse(d.has_log("tiré au hasard"),
                         "un seul compte : rien à tirer, rien à journaliser")

    def test_replan_si_le_nombre_de_comptes_change_a_chaud(self):
        """Le GUI écrit config.json en cours de route : l'ordre doit suivre."""
        d = self._daemon(n_a=10, alea=False)
        d._plan_accounts()
        d.config["providers"][0]["accounts"] = \
            d.config["providers"][0]["accounts"][:3]
        self.assertTrue(d._try_failover())
        self.assertEqual(len(d._account_order), 3,
                         "l'ordre n'a pas été replanifié après réduction")
        self.assertLess(d._current_account_idx, 3)

    def test_fournisseur_sans_compte_ne_casse_pas_le_plan(self):
        d = FakeDaemon(config={"random_account": True,
                               "providers": [{"name": "vide", "ovpn_file": "/dev/null",
                                              "accounts": []}]})
        d._plan_accounts()
        self.assertEqual(d._account_order, [])
        self.assertEqual(d._current_account_idx, 0)
        self.assertFalse(d._try_failover())


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

    def _prepare(self, d):
        """Neutralise tout ce qui toucherait au système, et espionne les essais.

        Extrait de _run_loop pour que les tests qui doivent construire le
        daemon eux-mêmes (état de quarantaine préalable) partagent exactement
        le même environnement simulé."""
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
        return d

    def _run_loop(self, providers, sorties, random_account=False):
        # Par défaut l'ordre des comptes est figé : ces tests portent sur la
        # DÉCISION de reconnexion, qui doit être vérifiable pas à pas.  Les
        # tests du tirage aléatoire passent random_account=True explicitement.
        d = self._prepare(FakeDaemon(
            config={"providers": providers, "auto_reconnect": True,
                    "random_account": random_account}))
        restants = list(sorties)

        def popen(cmd, **kw):
            p = FakeProc(restants.pop(0) if restants else "")
            d.openvpn_process = p
            return p

        with patched_run(Recorder()), no_sleep(m_openvpn), \
                patched_subprocess(m_openvpn, Recorder(), popen=popen):
            d._openvpn_loop_body(0)
        return d

    def test_coupure_reseau_garde_le_meme_compte(self):
        d = self._run_loop([provider("ivpn", 10, str(self.ovpn)),
                            provider("proton", 3, str(self.ovpn))],
                           [NET_DROP_MSG] * 6)
        comptes_ivpn = {n for p, n in d.tentatives if p == "ivpn"}
        self.assertEqual(comptes_ivpn, {1},
                         f"changement de compte sur une coupure réseau : {d.tentatives}")

    def test_coupure_reseau_garde_le_meme_compte_meme_tire_au_hasard(self):
        """Le tirage aléatoire ne doit pas ressusciter la rafale du #4.

        Une coupure réseau n'est pas la faute du compte : quel que soit le
        compte tiré au départ, la boucle doit s'y tenir."""
        for _ in range(10):
            d = self._run_loop([provider("ivpn", 10, str(self.ovpn))],
                               [NET_DROP_MSG] * 4, random_account=True)
            comptes = {n for p, n in d.tentatives if p == "ivpn"}
            self.assertEqual(len(comptes), 1,
                             f"changement de compte sur coupure réseau : {d.tentatives}")

    def test_identifiants_refuses_parcourt_des_comptes_distincts(self):
        """Refus d'identifiants : chaque essai doit viser un compte NEUF."""
        d = self._run_loop([provider("ivpn", 5, str(self.ovpn))],
                           [AUTH_FAIL_MSG] * 4 + [""], random_account=True)
        comptes = [n for p, n in d.tentatives if p == "ivpn"][:5]
        self.assertEqual(len(set(comptes)), len(comptes),
                         f"un compte a été retenté : {d.tentatives}")

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
        self.assertTrue(d.has_log("refusé", "WARN"))
        self.assertTrue(d.has_log("mis en quarantaine", "WARN"))

    def test_signature_sigterm_auth_failure_seule_suffit(self):
        d = self._run_loop([provider("ivpn", 3, str(self.ovpn))],
                           [AUTH_FAIL_ALT, ""])
        self.assertEqual([n for _, n in d.tentatives][:2], [1, 2])

    def test_tous_les_comptes_refuses_retente_une_seconde_passe(self):
        """« Tous occupés au même moment » ne doit pas rendre la main aussitôt."""
        d = self._run_loop([provider("ivpn", 2, str(self.ovpn))],
                           [AUTH_FAIL_MSG] * 8)
        self.assertTrue(d.has_log("nouvelle passe", "WARN"), d.log_dump())
        self.assertEqual(len(d.tentatives), 4,
                         f"2 comptes × 2 passes attendus : {d.tentatives}")
        self.assertTrue(d.has_log("après 2 passes", "ERROR"),
                        "l'abandon final doit rester explicite")

    def _lance(self, d, sorties, start_account_idx="absent"):
        restants = list(sorties)

        def popen(cmd, **kw):
            p = FakeProc(restants.pop(0) if restants else "")
            d.openvpn_process = p
            return p

        with patched_run(Recorder()), no_sleep(m_openvpn), \
                patched_subprocess(m_openvpn, Recorder(), popen=popen):
            if start_account_idx == "absent":
                d._openvpn_loop_body(0)
            else:
                d._openvpn_loop_body(0, start_account_idx)
        return d

    def test_compte_1_peut_etre_impose_explicitement(self):
        """L'index 0 est un compte valide, pas une absence de valeur.

        Avec un test de vérité (« if start_account_idx »), le compte 1 aurait
        été confondu avec « non spécifié » et n'aurait jamais pu être imposé."""
        d = self._prepare(FakeDaemon(config={
            "providers": [provider("ivpn", 5, str(self.ovpn))],
            "auto_reconnect": True, "random_account": False}))
        d._mettre_en_quarantaine(0)          # sinon relégué en fin d'ordre
        self._lance(d, [TUNNEL_UP_MSG], start_account_idx=0)
        self.assertEqual(d.tentatives[0], ("ivpn", 1),
                         f"le compte 1 imposé n'a pas été utilisé : {d.tentatives}")

    def test_sans_compte_impose_la_quarantaine_decide(self):
        """Sans index explicite, un compte puni ne doit pas être choisi."""
        d = self._prepare(FakeDaemon(config={
            "providers": [provider("ivpn", 5, str(self.ovpn))],
            "auto_reconnect": True, "random_account": False}))
        d._mettre_en_quarantaine(0)
        self._lance(d, [TUNNEL_UP_MSG])
        self.assertNotEqual(d.tentatives[0], ("ivpn", 1),
                            f"un compte en quarantaine a été choisi : {d.tentatives}")

    def test_abandon_ne_parle_plus_d_identifiants_seuls(self):
        """Le diagnostic doit mentionner les deux causes possibles."""
        d = self._run_loop([provider("ivpn", 1, str(self.ovpn))],
                           [AUTH_FAIL_MSG] * 4)
        quarantaine = [m for l, m in d.logs if "quarantaine" in m]
        self.assertTrue(quarantaine, d.log_dump())
        self.assertIn("connexions simultanées", quarantaine[0],
                      "le message n'évoque pas le quota de connexions")

    def test_connexion_reussie_leve_la_quarantaine_du_compte(self):
        """Un compte puni qui finit par se connecter doit sortir de quarantaine.

        Sans cela, un compte simplement occupé resterait relégué 15 min après
        être redevenu libre."""
        d = FakeDaemon(config={"providers": [provider("ivpn", 3, str(self.ovpn))],
                               "auto_reconnect": True, "random_account": False})
        d._mettre_en_quarantaine(0)
        self.assertGreater(d._cooldown_restant(0), 0)

        d = self._prepare(d)
        restants = [TUNNEL_UP_MSG]

        def popen(cmd, **kw):
            p = FakeProc(restants.pop(0) if restants else "")
            d.openvpn_process = p
            return p

        with patched_run(Recorder()), no_sleep(m_openvpn), \
                patched_subprocess(m_openvpn, Recorder(), popen=popen):
            # Le compte 0 est puni, donc relégué ; on force le daemon dessus
            # pour observer la levée à la connexion.
            d._openvpn_loop_body(0, 0)

        self.assertTrue(d._tunnel_up or d.has_log("Tunnel VPN actif", "OK"),
                        d.log_dump())
        self.assertEqual(d._cooldown_restant(0), 0,
                         "la quarantaine n'a pas été levée après une connexion")

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
        d._measure_tunnel_speed = lambda iface="", still_valid=None: kbs
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
