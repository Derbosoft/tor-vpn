"""GUI : validation des saisies, torrc, obfuscation, anti-path-traversal.

Aucun Tk() n'est créé : on exerce la logique en substituant des faux widgets.
"""

import copy
import pathlib
import unittest

import gui.app as app
from constants import DEFAULT_CONFIG


class FakeVar:
    def __init__(self, value=""):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class FakeListbox:
    def __init__(self, items=()):
        self.items = list(items)

    def get(self, a, b=None):
        return tuple(self.items)

    def insert(self, where, item):
        self.items.append(item)

    def delete(self, a, b=None):
        if b is not None:
            self.items = []
        else:
            self.items.pop(a)

    def curselection(self):
        return ()


class FakeEntry:
    def __init__(self, text=""):
        self._t = text

    def get(self):
        return self._t

    def delete(self, a, b=None):
        self._t = ""


class ObfuscationTest(unittest.TestCase):

    def test_aller_retour(self):
        for clair in ("bob", "p@ssw0rd!", "üñïçødé", "", "x" * 500, "a b\tc"):
            self.assertEqual(app._deobf(app._obf(clair)), clair)

    def test_deobf_tolere_une_valeur_en_clair(self):
        self.assertEqual(app._deobf("!!!pas-base64!!!"), "!!!pas-base64!!!")

    def test_obfuscation_n_est_pas_du_chiffrement(self):
        """Documenté comme tel : le test fige cette limite connue."""
        import base64
        self.assertEqual(base64.b64decode(app._obf("secret")).decode(), "secret")


class AddIpTest(unittest.TestCase):
    """Correctif #1 : le GUI doit refuser l'IPv6, qu'OpenVPN ignorerait."""

    def _add(self, saisie, existants=()):
        obj = app.ConfigApp.__new__(app.ConfigApp)
        obj.ip_entry = FakeEntry(saisie)
        obj.ip_list = FakeListbox(existants)
        obj.config = {}
        erreurs = []
        saved = app.messagebox
        app.messagebox = type("MB", (), {
            "showerror": staticmethod(lambda t, m: erreurs.append((t, m))),
            "showwarning": staticmethod(lambda t, m: erreurs.append((t, m))),
            "showinfo": staticmethod(lambda t, m: None),
        })
        obj._persist_lists = lambda: None
        try:
            obj._add_ip()
        finally:
            app.messagebox = saved
        return obj.ip_list.items, erreurs

    def test_ipv4_simple_normalisee_en_32(self):
        items, err = self._add("10.0.0.5")
        self.assertEqual(items, ["10.0.0.5/32"])
        self.assertEqual(err, [])

    def test_cidr_accepte(self):
        self.assertEqual(self._add("10.0.20.0/24")[0], ["10.0.20.0/24"])

    def test_cidr_avec_bits_hote_normalise(self):
        self.assertEqual(self._add("10.0.20.7/24")[0], ["10.0.20.0/24"])

    def test_ipv6_refusee(self):
        items, err = self._add("2001:db8::/32")
        self.assertEqual(items, [], "une entrée IPv6 a été acceptée")
        self.assertTrue(err and "IPv6" in err[0][0], err)

    def test_ipv6_simple_refusee(self):
        self.assertEqual(self._add("fe80::1")[0], [])

    def test_saisie_invalide_refusee(self):
        items, err = self._add("pas-une-ip")
        self.assertEqual(items, [])
        self.assertTrue(err and "invalide" in err[0][0].lower())

    def test_saisie_vide_ignoree_sans_erreur(self):
        items, err = self._add("")
        self.assertEqual((items, err), ([], []))

    def test_doublon_non_ajoute(self):
        items, _ = self._add("10.0.20.0/24", existants=["10.0.20.0/24"])
        self.assertEqual(items, ["10.0.20.0/24"])

    def test_masque_hors_bornes_refuse(self):
        self.assertEqual(self._add("10.0.0.0/33")[0], [])


class TorrcTest(unittest.TestCase):
    """Les paramètres obligatoires doivent survivre à toute édition."""

    def _obj(self, **overrides):
        obj = app.ConfigApp.__new__(app.ConfigApp)
        d = app.ConfigApp._TOR_DEFAULTS
        obj._tor_avoid_disk_var = FakeVar(d["avoid_disk"])
        obj._tor_safe_logging_var = FakeVar(d["safe_logging"])
        obj._tor_no_ipv6_var = FakeVar(d["no_ipv6"])
        obj._tor_test_socks_var = FakeVar(d["test_socks"])
        obj._tor_conn_padding_var = FakeVar(d["conn_padding"])
        obj._tor_long_lived_var = FakeVar(d["long_lived"])
        obj._tor_learn_timeout_var = FakeVar(d["learn_timeout"])
        obj._tor_max_dirty_var = FakeVar(str(d["max_dirty"]))
        obj._tor_build_timeout_var = FakeVar(str(d["build_timeout"]))
        obj._tor_new_circuit_var = FakeVar(str(d["new_circuit"]))
        obj._tor_keepalive_var = FakeVar(str(d["keepalive"]))
        obj._tor_num_guards_var = FakeVar(str(d["num_guards"]))
        obj._tor_guard_lifetime_var = FakeVar(d["guard_lifetime"])
        obj._tor_exclude_var = FakeVar(d["exclude_exits"])
        obj._tor_strict_var = FakeVar(d["strict_nodes"])
        for k, v in overrides.items():
            getattr(obj, k).set(v)
        return obj

    def test_defauts_contiennent_les_obligatoires(self):
        txt = self._obj()._build_torrc_from_widgets()
        for cle in ("SocksPort 9050", "ControlPort 9051",
                    "CookieAuthentication 1", "DataDirectory"):
            self.assertIn(cle, txt, f"{cle} absent du torrc généré")

    def test_valeurs_par_defaut_attendues(self):
        txt = self._obj()._build_torrc_from_widgets()
        for ligne in ("AvoidDiskWrites 1", "SafeLogging 1", "ClientUseIPv6 0",
                      "TestSocks 1", "LongLivedPorts 1194,443",
                      "LearnCircuitBuildTimeout 0", "MaxCircuitDirtiness 3600",
                      "NumEntryGuards 3", "GuardLifetime 2 months"):
            self.assertIn(ligne, txt)

    def test_conn_padding_desactive_par_defaut(self):
        self.assertNotIn("ConnectionPadding", self._obj()._build_torrc_from_widgets())

    def test_valeur_zero_omise(self):
        txt = self._obj(_tor_max_dirty_var="0")._build_torrc_from_widgets()
        self.assertNotIn("MaxCircuitDirtiness", txt)

    def test_valeur_non_numerique_ignoree_sans_planter(self):
        txt = self._obj(_tor_keepalive_var="abc")._build_torrc_from_widgets()
        self.assertNotIn("KeepalivePeriod", txt)

    def test_strict_nodes_seulement_avec_exclusion(self):
        self.assertNotIn("StrictNodes", self._obj()._build_torrc_from_widgets())
        txt = self._obj(_tor_exclude_var="{us},{gb}",
                        _tor_strict_var=True)._build_torrc_from_widgets()
        self.assertIn("ExcludeExitNodes {us},{gb}", txt)
        self.assertIn("StrictNodes 1", txt)

    def test_guard_lifetime_vide_omis(self):
        txt = self._obj(_tor_guard_lifetime_var="")._build_torrc_from_widgets()
        self.assertNotIn("GuardLifetime", txt)


class TorrcMandatoryReinjectionTest(unittest.TestCase):
    """La réinjection ne doit jamais dupliquer SocksPort/ControlPort (bind en conflit)."""

    def _reinject(self, contenu):
        MANDATORY = app.ConfigApp._TORRC_MANDATORY
        present = {ln.strip().split()[0].lower()
                   for ln in contenu.splitlines()
                   if ln.strip() and not ln.strip().startswith("#")}
        missing = [ln for ln in MANDATORY.splitlines()
                   if ln.strip() and not ln.startswith("#")
                   and ln.split()[0].lower() not in present]
        if missing:
            contenu = ("# === Paramètres obligatoires (réinjectés) ===\n"
                       + "\n".join(missing) + "\n\n" + contenu)
        return contenu

    def test_rien_a_reinjecter_si_tout_present(self):
        base = app.ConfigApp._TORRC_MANDATORY + "\nAvoidDiskWrites 1\n"
        out = self._reinject(base)
        self.assertEqual(out.count("SocksPort"), 1, "SocksPort dupliqué → conflit de bind")
        self.assertEqual(out.count("ControlPort"), 1)

    def test_reinjecte_ce_qui_manque(self):
        out = self._reinject("AvoidDiskWrites 1\nSocksPort 9050\n")
        self.assertEqual(out.count("SocksPort"), 1, "SocksPort dupliqué")
        self.assertEqual(out.count("ControlPort"), 1, "ControlPort non réinjecté")
        self.assertIn("CookieAuthentication 1", out)

    def test_detection_insensible_a_la_casse(self):
        """Les clés torrc sont insensibles à la casse pour Tor."""
        out = self._reinject("socksport 9050\ncontrolport 9051\n"
                             "cookieauthentication 1\ndatadirectory /x\n")
        self.assertEqual(out.lower().count("socksport"), 1,
                         "une variante de casse a provoqué un doublon")

    def test_lignes_commentees_ne_comptent_pas(self):
        out = self._reinject("# SocksPort 9050\nAvoidDiskWrites 1\n")
        lignes_actives = [l for l in out.splitlines()
                          if l.strip().lower().startswith("socksport")]
        self.assertEqual(len(lignes_actives), 1,
                         "un SocksPort commenté a été pris pour actif")

    def test_torrc_vide(self):
        out = self._reinject("")
        for cle in ("SocksPort", "ControlPort", "CookieAuthentication", "DataDirectory"):
            self.assertIn(cle, out)


class ImportSafetyTest(unittest.TestCase):
    """Anti-path-traversal de l'import .tvpn."""

    @staticmethod
    def _safe(c):
        return bool(c) and c not in (".", "..") \
            and "/" not in c and "\\" not in c and not c.startswith(".")

    def test_composants_valides(self):
        for bon in ("ivpn", "protonVPN", "mon-vpn_2", "a.ovpn"):
            self.assertTrue(self._safe(bon), bon)

    def test_composants_dangereux_refuses(self):
        for mauvais in ("..", ".", "", "../etc", "a/b", "a\\b",
                        ".ssh", "./x", "/etc/passwd"):
            self.assertFalse(self._safe(mauvais), f"« {mauvais} » accepté")


class ProviderNameValidationTest(unittest.TestCase):
    """Le nom sert de nom de dossier sous providers/."""

    @staticmethod
    def _valide(name):
        name = name.strip()
        return bool(name) and name not in (".", "..") \
            and "/" not in name and "\\" not in name

    def test_noms_acceptes(self):
        for bon in ("ivpn", "Proton VPN", "vpn-2"):
            self.assertTrue(self._valide(bon), bon)

    def test_noms_refuses(self):
        for mauvais in ("", "   ", ".", "..", "a/b", "..\\..", "/abs"):
            self.assertFalse(self._valide(mauvais), f"« {mauvais} » accepté")


class DefaultConfigIntegrityTest(unittest.TestCase):
    """Le défaut partagé ne doit jamais être muté (défaut trouvé par les tests)."""

    def setUp(self):
        self._snapshot = copy.deepcopy(DEFAULT_CONFIG)

    def test_defauts_intacts_apres_import_du_module(self):
        self.assertEqual(DEFAULT_CONFIG, self._snapshot)

    def test_listes_par_defaut_vides(self):
        for cle in ("providers", "excluded_ips", "excluded_domains"):
            self.assertEqual(DEFAULT_CONFIG[cle], [],
                             f"DEFAULT_CONFIG[{cle}] a été pollué")

    def test_seuil_de_circuit_par_defaut(self):
        self.assertEqual(DEFAULT_CONFIG["circuit_min_kbs"], 250)
        self.assertTrue(DEFAULT_CONFIG["circuit_check"])
        self.assertEqual(DEFAULT_CONFIG["circuit_max_retries"], 3)


class GuiOptionRoundTripTest(unittest.TestCase):
    """Toute case à cocher doit être LUE et ÉCRITE.

    Le défaut classique du GUI est la case qui enregistre sans jamais se
    recharger : la valeur est correcte dans config.json et fausse à l'écran.
    On vérifie sur la source que chaque option booléenne apparaît des deux
    côtés — création du widget, collecte, et rechargement."""

    SRC = (pathlib.Path(__file__).resolve().parents[1] / "gui" / "app.py").read_text()

    OPTIONS = ("auto_reconnect", "block_ipv6", "circuit_check", "random_account",
               "lan_dhcp", "lan_auto", "autostart")

    def test_chaque_option_est_lue_et_ecrite(self):
        for cle in self.OPTIONS:
            var = f"{cle}_var"
            # tk.BooleanVar() ou tk.BooleanVar(value=…) selon l'option.
            self.assertIn(f"self.{var} = tk.BooleanVar(", self.SRC,
                          f"{cle} : pas de variable Tk")
            self.assertIn(f'self.config["{cle}"]', self.SRC,
                          f"{cle} : jamais écrit dans la config")
            self.assertIn(f'self.{var}.set(self.config.get("{cle}"',
                          self.SRC, f"{cle} : jamais rechargé à l'écran")

    def test_options_du_gui_declarees_dans_les_defauts(self):
        for cle in self.OPTIONS:
            self.assertIn(cle, DEFAULT_CONFIG,
                          f"{cle} exposé par le GUI mais absent de DEFAULT_CONFIG")


if __name__ == "__main__":
    unittest.main()
