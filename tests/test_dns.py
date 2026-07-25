"""DNS : contrôle de l'environnement, DNS du VPN, split DNS, revérification."""

import pathlib
import tempfile
import unittest

import daemon.dns as m_dns
from tests.helpers import FakeDaemon, Recorder, patched_run, patched_subprocess


STATUS_COMPLET = """Link 6 (tun0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.20.20.1
       DNS Servers: 10.20.20.1
        DNS Domain: ~.
     Default Route: yes
"""


def status(servers="10.20.20.1", domain="~.", route="yes", link="Link 6 (tun0)"):
    """Construit une sortie « resolvectl status » ; None = ligne absente."""
    out = [link, "    Current Scopes: DNS"]
    if servers is not None:
        out.append(f"       DNS Servers: {servers}")
    if domain is not None:
        out.append(f"        DNS Domain: {domain}")
    if route is not None:
        out.append(f"     Default Route: {route}")
    return "\n".join(out) + "\n"


class LinkStatusParsingTest(unittest.TestCase):

    def _parse(self, out, rc=0):
        rec = Recorder({"resolvectl status": (rc, out)})
        with patched_subprocess(m_dns, rec):
            return m_dns.DNSMixin._resolvectl_link_status("tun0")

    def test_parse_les_trois_attributs(self):
        st = self._parse(STATUS_COMPLET)
        self.assertEqual(st["DNS Servers"], "10.20.20.1")
        self.assertEqual(st["DNS Domain"], "~.")
        self.assertEqual(st["Default Route"], "yes")

    def test_ligne_link_sans_deux_points_ignoree(self):
        st = self._parse(STATUS_COMPLET)
        self.assertNotIn("Link 6 (tun0)", st)

    def test_sortie_vide(self):
        self.assertEqual(self._parse(""), {})

    def test_plusieurs_serveurs(self):
        st = self._parse(status(servers="10.1.1.1 10.1.1.2"))
        self.assertEqual(st["DNS Servers"], "10.1.1.1 10.1.1.2")


class EnsureDnsConfigTest(unittest.TestCase):
    """Correctif #13 : les TROIS attributs sont contrôlés, pas seulement le serveur."""

    def _check(self, out, rc=0, dns_ips=("10.20.20.1",), tunnel_up=True, cfg=None):
        d = FakeDaemon(config=cfg or {})
        d._tunnel_up = tunnel_up
        d._vpn_dns_ips = list(dns_ips)
        d._tun_iface = "tun0"
        applied = []
        d._apply_vpn_dns = lambda: applied.append("vpn")
        d._apply_dns_split = lambda: applied.append("split")
        rec = Recorder({"resolvectl status": (rc, out)})
        with patched_subprocess(m_dns, rec):
            d._ensure_dns_config()
        return d, applied

    def test_config_complete_ne_fait_rien(self):
        d, applied = self._check(STATUS_COMPLET)
        self.assertEqual(applied, [], "réapplication inutile")
        self.assertEqual(d.logs, [], d.log_dump())

    def test_serveur_absent_detecte(self):
        d, applied = self._check(status(servers="9.9.9.9"))
        self.assertEqual(applied, ["vpn"])
        self.assertTrue(d.has_log("serveur", "WARN"), d.log_dump())

    def test_domaine_catchall_absent_detecte(self):
        """L'angle mort d'avant #13 : bon serveur mais « ~. » disparu."""
        d, applied = self._check(status(domain="internal"))
        self.assertEqual(applied, ["vpn"])
        self.assertTrue(d.has_log("domaine ~.", "WARN"), d.log_dump())

    def test_default_route_desactive_detecte(self):
        d, applied = self._check(status(route="no"))
        self.assertEqual(applied, ["vpn"])
        self.assertTrue(d.has_log("default-route", "WARN"))

    def test_trois_attributs_absents_listes_ensemble(self):
        d, applied = self._check(status(servers=None, domain=None, route=None))
        self.assertEqual(applied, ["vpn"])
        msg = d.logged("Config DNS")[0][1]
        for attendu in ("serveur", "domaine ~.", "default-route"):
            self.assertIn(attendu, msg)

    def test_lecture_impossible_sabstient(self):
        """Ne jamais conclure sans information : évite une boucle de réapplication."""
        d, applied = self._check("", rc=1)
        self.assertEqual(applied, [], "a agi sans pouvoir lire l'état")
        self.assertEqual(d.logs, [])

    def test_exception_sabstient(self):
        d = FakeDaemon()
        d._tunnel_up, d._vpn_dns_ips = True, ["10.0.0.1"]
        applied = []
        d._apply_vpn_dns = lambda: applied.append("vpn")
        d._apply_dns_split = lambda: applied.append("split")

        def boom(*a, **k):
            raise OSError("resolvectl absent")

        with patched_subprocess(m_dns, boom):
            d._ensure_dns_config()
        self.assertEqual(applied, [])

    def test_tunnel_ferme_sort_immediatement(self):
        d, applied = self._check(STATUS_COMPLET, tunnel_up=False)
        self.assertEqual(applied, [])

    def test_sans_dns_pousse_pas_de_controle_interface(self):
        d, applied = self._check(STATUS_COMPLET, dns_ips=())
        self.assertNotIn("vpn", applied)

    def test_dropin_split_disparu_reapplique(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_dns.RESOLVED_DROP_IN
            m_dns.RESOLVED_DROP_IN = pathlib.Path(tmp) / "absent.conf"
            try:
                d, applied = self._check(
                    STATUS_COMPLET,
                    cfg={"local_dns": "10.0.50.253", "excluded_domains": [".derbo"]})
                self.assertIn("split", applied)
                self.assertTrue(d.has_log("Drop-in split DNS disparu", "WARN"))
            finally:
                m_dns.RESOLVED_DROP_IN = saved

    def test_dropin_present_pas_de_reapplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_dns.RESOLVED_DROP_IN
            p = pathlib.Path(tmp) / "present.conf"
            p.write_text("[Resolve]\n")
            m_dns.RESOLVED_DROP_IN = p
            try:
                _, applied = self._check(
                    STATUS_COMPLET,
                    cfg={"local_dns": "10.0.50.253", "excluded_domains": [".derbo"]})
                self.assertNotIn("split", applied)
            finally:
                m_dns.RESOLVED_DROP_IN = saved


class ApplyVpnDnsTest(unittest.TestCase):

    def _apply(self, ips, rc=0):
        d = FakeDaemon()
        d._vpn_dns_ips, d._tun_iface = list(ips), "tun0"
        rec = Recorder({"resolvectl dns": (rc, "")})
        with patched_subprocess(m_dns, rec):
            d._apply_vpn_dns()
        return d, rec

    def test_pose_les_trois_reglages(self):
        d, rec = self._apply(["10.20.20.1"])
        self.assertTrue(rec.ran("resolvectl dns tun0 10.20.20.1"))
        self.assertTrue(rec.ran("resolvectl domain tun0 ~."))
        self.assertTrue(rec.ran("resolvectl default-route tun0 true"))
        self.assertTrue(d.has_log("DNS du VPN appliqué", "OK"))

    def test_deduplique_en_conservant_l_ordre(self):
        _, rec = self._apply(["10.1.1.1", "10.2.2.2", "10.1.1.1"])
        self.assertTrue(rec.ran("resolvectl dns tun0 10.1.1.1 10.2.2.2"))

    def test_aucun_dns_pousse_avertit(self):
        d, rec = self._apply([])
        self.assertTrue(d.has_log("Aucun DNS poussé par le VPN", "WARN"))
        self.assertEqual(rec.calls, [])

    def test_echec_resolvectl_signale_et_stoppe(self):
        d, rec = self._apply(["10.20.20.1"], rc=1)
        self.assertTrue(d.has_log("resolvectl dns tun0", "ERROR"))
        self.assertEqual(rec.count("resolvectl domain"), 0,
                         "a continué malgré l'échec de la 1re commande")

    def test_resolvectl_absent(self):
        d = FakeDaemon()
        d._vpn_dns_ips, d._tun_iface = ["10.0.0.1"], "tun0"

        def missing(*a, **k):
            raise FileNotFoundError()

        with patched_subprocess(m_dns, missing):
            d._apply_vpn_dns()
        self.assertTrue(d.has_log("resolvectl introuvable", "ERROR"))


class SplitDnsTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = m_dns.RESOLVED_DROP_IN
        self.dropin = pathlib.Path(self._tmp.name) / "conf.d" / "tor-vpn-split.conf"
        m_dns.RESOLVED_DROP_IN = self.dropin

    def tearDown(self):
        m_dns.RESOLVED_DROP_IN = self._saved
        self._tmp.cleanup()

    def _apply(self, dns, domains):
        d = FakeDaemon(config={"local_dns": dns, "excluded_domains": domains})
        rec = Recorder()
        with patched_subprocess(m_dns, rec):
            d._apply_dns_split()
        return d, rec

    def test_ecrit_le_dropin_et_recharge(self):
        d, rec = self._apply("10.0.50.253", [".derbo", "maison"])
        txt = self.dropin.read_text()
        self.assertIn("DNS=10.0.50.253", txt)
        self.assertIn("Domains=~derbo ~maison", txt,
                      "le préfixe ~ (domaine de routage) est indispensable")
        self.assertTrue(rec.ran("systemctl reload-or-restart systemd-resolved"))
        self.assertTrue(d.has_log("DNS split actif", "OK"))

    def test_sans_dns_supprime_le_dropin(self):
        self.dropin.parent.mkdir(parents=True, exist_ok=True)
        self.dropin.write_text("[Resolve]\nDNS=1.2.3.4\n")
        d, rec = self._apply("", [".derbo"])
        self.assertFalse(self.dropin.exists())
        self.assertTrue(d.has_log("DNS split désactivé", "OK"))

    def test_sans_domaine_supprime_le_dropin(self):
        self.dropin.parent.mkdir(parents=True, exist_ok=True)
        self.dropin.write_text("x")
        self._apply("10.0.0.1", [])
        self.assertFalse(self.dropin.exists())

    def test_remove_sans_dropin_ne_fait_rien(self):
        d = FakeDaemon()
        rec = Recorder()
        with patched_subprocess(m_dns, rec):
            d._remove_dns_split()
        self.assertEqual(rec.calls, [])


class CheckDnsStackTest(unittest.TestCase):

    def test_resolvectl_absent_avertit(self):
        d = FakeDaemon()
        saved = m_dns.shutil.which
        m_dns.shutil.which = lambda n: None
        try:
            with patched_run(Recorder()):
                d._check_dns_stack()
        finally:
            m_dns.shutil.which = saved
        self.assertTrue(d.has_log("resolvectl introuvable", "WARN"))

    def test_service_inactif_avertit(self):
        d = FakeDaemon()
        saved = m_dns.shutil.which
        m_dns.shutil.which = lambda n: "/usr/bin/resolvectl"
        try:
            with patched_run(Recorder({"is-active": (3, "inactive")})):
                d._check_dns_stack()
        finally:
            m_dns.shutil.which = saved
        self.assertTrue(d.has_log("n'est pas actif", "WARN"))

    def test_pile_saine_silencieuse(self):
        d = FakeDaemon()
        saved = m_dns.shutil.which
        m_dns.shutil.which = lambda n: "/usr/bin/resolvectl"
        try:
            with patched_run(Recorder({"is-active": (0, "active")})):
                d._check_dns_stack()
        finally:
            m_dns.shutil.which = saved
        self.assertEqual(d.logs, [], d.log_dump())


if __name__ == "__main__":
    unittest.main()
