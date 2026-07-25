"""Configuration (chargement, corruption) et socket de statut (fuites, format)."""

import json
import pathlib
import tempfile
import unittest

import daemon.core as m_core
from constants import DEFAULT_CONFIG
from tests.helpers import FakeDaemon, provider


class LoadConfigTest(unittest.TestCase):
    """Une config illisible ne doit jamais être perdue ni ignorée en silence."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        self._saved = (m_core.CONFIG_DIR, m_core.CONFIG_FILE)
        m_core.CONFIG_DIR = self.dir
        m_core.CONFIG_FILE = self.dir / "config.json"

    def tearDown(self):
        m_core.CONFIG_DIR, m_core.CONFIG_FILE = self._saved
        self._tmp.cleanup()

    def _load(self, contenu=None):
        if contenu is not None:
            m_core.CONFIG_FILE.write_text(contenu)
        logs = []

        class Minimal(m_core.DaemonCore):
            def __init__(self):
                pass

            def _log(self, msg, level="INFO"):
                logs.append((level, msg))

        return Minimal()._load_config(), logs

    def test_absente_renvoie_les_defauts(self):
        cfg, logs = self._load()
        self.assertEqual(cfg, DEFAULT_CONFIG)
        self.assertIsNot(cfg, DEFAULT_CONFIG, "DEFAULT_CONFIG renvoyé par référence")

    def test_modification_ne_contamine_pas_les_defauts(self):
        cfg, _ = self._load()
        cfg["providers"].append({"name": "x"})
        self.assertEqual(DEFAULT_CONFIG["providers"], [],
                         "DEFAULT_CONFIG muté par une copie superficielle")

    def test_cles_manquantes_completees(self):
        cfg, _ = self._load('{"local_dns": "10.0.0.1"}')
        self.assertEqual(cfg["local_dns"], "10.0.0.1")
        for cle in DEFAULT_CONFIG:
            self.assertIn(cle, cfg, f"clé {cle} non complétée")

    def test_valeurs_du_fichier_prioritaires(self):
        cfg, _ = self._load('{"circuit_min_kbs": 999, "auto_reconnect": false}')
        self.assertEqual(cfg["circuit_min_kbs"], 999)
        self.assertFalse(cfg["auto_reconnect"])

    def test_json_corrompu_mis_de_cote(self):
        cfg, logs = self._load('{"providers": [ CASSE')
        bad = self.dir / "config.json.bad"
        self.assertTrue(bad.exists(), "config corrompue perdue au lieu d'être sauvegardée")
        self.assertIn("CASSE", bad.read_text())
        self.assertFalse(m_core.CONFIG_FILE.exists())
        self.assertEqual(cfg, DEFAULT_CONFIG)
        self.assertTrue(any("illisible" in m for _, m in logs),
                        "corruption non signalée dans le journal")

    def test_json_valide_mais_pas_un_objet(self):
        cfg, _ = self._load('["une", "liste"]')
        self.assertEqual(cfg, DEFAULT_CONFIG)


class StatusSnapshotTest(unittest.TestCase):
    """Le socket est en 0666 : il ne doit exposer AUCUN secret."""

    def _snap(self, **state):
        d = FakeDaemon(config={"providers": [provider("ivpn", 3)]}, **state)
        return d, d._status_snapshot()

    def test_serialisable_en_json(self):
        _, snap = self._snap()
        json.dumps(snap, ensure_ascii=False)      # ne doit pas lever

    def test_champs_attendus_presents(self):
        _, snap = self._snap()
        for cle in ("version", "pid", "timestamp", "tor_running", "tor_ready",
                    "tunnel_up", "tunnel_iface", "tunnel_uptime", "provider",
                    "account_index", "rx_kbs", "conn_failures", "vpn_reconnects",
                    "full_restarts", "lan_sharing", "ipv6_blocked"):
            self.assertIn(cle, snap, f"champ {cle} absent du statut")

    def test_aucun_identifiant_expose(self):
        d, snap = self._snap()
        blob = json.dumps(snap).lower()
        for interdit in ("user0", "pass0", "dXNlcjA", "cGFzczA", "password",
                         "auth", "cookie", "secret"):
            self.assertNotIn(interdit.lower(), blob,
                             f"le statut expose « {interdit} »")

    def test_nom_du_fournisseur_expose_sans_ses_comptes(self):
        _, snap = self._snap()
        self.assertEqual(snap["provider"], "ivpn")
        self.assertNotIn("accounts", snap)
        self.assertNotIn("providers", snap)

    def test_rx_kbs_calcule_depuis_la_deque(self):
        d = FakeDaemon(config={"providers": []})
        d._rx_history.append(3.0 * 1024 * 3)      # 3 KB/s sur un tick de 3 s
        _, snap = d, d._status_snapshot()
        self.assertAlmostEqual(snap["rx_kbs"], 3.0, places=1)

    def test_deque_vide_ne_plante_pas(self):
        from collections import deque
        d = FakeDaemon(config={"providers": []})
        d._rx_history = deque(maxlen=60)
        self.assertEqual(d._status_snapshot()["rx_kbs"], 0.0)

    def test_uptime_nul_si_tunnel_ferme(self):
        d = FakeDaemon(config={"providers": []})
        d._tunnel_up, d._tunnel_up_time = False, 1.0
        self.assertEqual(d._status_snapshot()["tunnel_uptime"], 0)

    def test_index_fournisseur_hors_bornes_ne_plante_pas(self):
        d = FakeDaemon(config={"providers": [provider("a", 1)]})
        d._current_provider_idx = 42
        self.assertEqual(d._status_snapshot()["provider"], "")

    def test_fournisseur_sans_nom(self):
        d = FakeDaemon(config={"providers": [{"ovpn_file": "", "accounts": []}]})
        self.assertEqual(d._status_snapshot()["provider"], "")


class SdNotifyTest(unittest.TestCase):
    """sd_notify doit rester inoffensif hors systemd (lancement manuel)."""

    def test_sans_notify_socket_ne_fait_rien(self):
        import os
        saved = os.environ.pop("NOTIFY_SOCKET", None)
        try:
            m_core._sd_notify("READY=1")           # ne doit pas lever
        finally:
            if saved is not None:
                os.environ["NOTIFY_SOCKET"] = saved

    def test_socket_injoignable_ne_leve_pas(self):
        import os
        saved = os.environ.get("NOTIFY_SOCKET")
        os.environ["NOTIFY_SOCKET"] = "/nulle/part/inexistant.sock"
        try:
            m_core._sd_notify("WATCHDOG=1")        # ne doit pas lever
        finally:
            if saved is None:
                os.environ.pop("NOTIFY_SOCKET", None)
            else:
                os.environ["NOTIFY_SOCKET"] = saved

    def test_socket_abstrait_accepte(self):
        """Un chemin « @xxx » doit être converti en \\0 (socket abstrait Linux)."""
        import os
        saved = os.environ.get("NOTIFY_SOCKET")
        os.environ["NOTIFY_SOCKET"] = "@test-inexistant"
        try:
            m_core._sd_notify("READY=1")
        finally:
            if saved is None:
                os.environ.pop("NOTIFY_SOCKET", None)
            else:
                os.environ["NOTIFY_SOCKET"] = saved


class DeobfTest(unittest.TestCase):

    def test_aller_retour(self):
        import base64
        for clair in ("bob", "mot de passe", "üñïçødé", "a" * 200, ""):
            enc = base64.b64encode(clair.encode()).decode()
            self.assertEqual(m_core._deobf(enc), clair)

    def test_valeur_non_base64_renvoyee_telle_quelle(self):
        """Compatibilité avec une config écrite à la main, en clair."""
        self.assertEqual(m_core._deobf("!!!pas-du-base64!!!"), "!!!pas-du-base64!!!")


if __name__ == "__main__":
    unittest.main()
