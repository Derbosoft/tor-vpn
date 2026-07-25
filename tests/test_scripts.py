"""Scripts shell et unité systemd : syntaxe, complétude du nettoyage, cohérence.

Aucun script n'est EXÉCUTÉ : on vérifie leur syntaxe (bash -n) et leur contenu.
Lancer install.sh ou repair_network.sh couperait le réseau de la machine.
"""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
REPAIR = (ROOT / "repair_network.sh").read_text()
CLI = (ROOT / "tor-vpn-cli.sh").read_text()


class SyntaxTest(unittest.TestCase):

    def test_syntaxe_bash(self):
        for nom in ("install.sh", "repair_network.sh", "tor-vpn-cli.sh"):
            r = subprocess.run(["bash", "-n", str(ROOT / nom)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{nom} : {r.stderr}")

    def test_python_compile(self):
        import py_compile
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            fichiers = ([ROOT / "constants.py", ROOT / "main.py"]
                        + sorted((ROOT / "daemon").glob("*.py"))
                        + sorted((ROOT / "gui").glob("*.py")))
            for f in fichiers:
                py_compile.compile(str(f), cfile=f"{tmp}/x.pyc", doraise=True)


class RepairCompletenessTest(unittest.TestCase):
    """repair_network.sh doit annuler TOUT ce que le daemon installe."""

    def test_chaines_ip6tables(self):
        self.assertIn("TORVPN_KS6", REPAIR)
        self.assertIn("TORVPN_KS6_FWD", REPAIR)
        self.assertRegex(REPAIR, r"while ip6tables -D FORWARD -j \"?\$\{?KS6_FWD_CHAIN")

    def test_chaine_lan_et_nat(self):
        self.assertIn("TORVPN_LAN_FWD", REPAIR)
        self.assertIn("MASQUERADE", REPAIR,
                      "la règle NAT du partage LAN n'est pas nettoyée")

    def test_routes_32_des_relais_tor(self):
        self.assertIn("tor-vpn-routes.txt", REPAIR,
                      "les routes /32 des relais Tor ne sont pas supprimées")
        self.assertRegex(REPAIR, r'ip route del "\$\{?IP\}?/32"')

    def test_traite_tun0_et_tun1(self):
        """Les .ovpn utilisent « dev tun » : le tunnel peut être tun0 ou tun1."""
        self.assertIn("TUNS=(tun0 tun1)", REPAIR)
        for bloc in ("resolvectl revert", "ip route del 0.0.0.0/1"):
            self.assertIn(bloc, REPAIR)
        self.assertGreaterEqual(REPAIR.count('for T in "${TUNS[@]}"'), 3,
                                "la boucle sur les deux tunnels manque quelque part")

    def test_dropin_dns_supprime(self):
        self.assertIn("tor-vpn-split.conf", REPAIR)

    def test_dnsmasq_cible_par_pid_file(self):
        """« pkill dnsmasq » tuerait aussi ceux de libvirt."""
        self.assertIn("pkill -f /etc/tor-vpn-manager/tor-vpn-dnsmasq.pid", REPAIR)
        self.assertNotRegex(REPAIR, r"pkill\s+(-x\s+)?dnsmasq\s*$")

    def test_numerotation_des_etapes_coherente(self):
        etapes = re.findall(r"\[(\d+)/(\d+)\]", REPAIR)
        self.assertTrue(etapes, "aucune étape numérotée")
        total = etapes[0][1]
        self.assertTrue(all(t == total for _, t in etapes),
                        f"totaux incohérents : {etapes}")
        self.assertEqual([n for n, _ in etapes],
                         [str(i) for i in range(1, int(total) + 1)],
                         "numéros d'étapes non consécutifs")

    def test_mode_internal_saute_le_systemctl_stop(self):
        self.assertIn("--internal", REPAIR)
        self.assertRegex(REPAIR, r"if \[\[ \$INTERNAL -eq 0 \]\]")

    def test_exige_root(self):
        self.assertIn("EUID", REPAIR)

    def test_set_euo_pipefail(self):
        self.assertIn("set -euo pipefail", REPAIR)


class InstallServiceUnitTest(unittest.TestCase):
    """L'unité systemd porte la chaîne de survie : Type=notify + WatchdogSec."""

    def test_type_notify_et_watchdog(self):
        self.assertIn("Type=notify", INSTALL)
        self.assertIn("NotifyAccess=main", INSTALL)
        self.assertIn("WatchdogSec=90", INSTALL)

    def test_relance_illimitee(self):
        self.assertIn("Restart=on-failure", INSTALL)
        self.assertIn("StartLimitIntervalSec=0", INSTALL,
                      "sans cela, une série d'échecs au boot laisse le service mort")

    def test_watchdog_plus_long_que_le_pas_de_ping(self):
        """Les pings sortent toutes les ~3 s : 90 s laisse une marge confortable."""
        w = int(re.search(r"WatchdogSec=(\d+)", INSTALL).group(1))
        self.assertGreaterEqual(w, 30)

    def test_nettoyage_avant_et_apres(self):
        self.assertIn("ExecStartPre=", INSTALL)
        self.assertIn("ExecStopPost=", INSTALL)

    def test_cleanup_traite_les_deux_tunnels(self):
        cleanup = INSTALL[INSTALL.index("CLEANUP_EOF"):]
        self.assertIn("-o tun0 -j MASQUERADE", cleanup)
        self.assertIn("-o tun1 -j MASQUERADE", cleanup)

    def test_cleanup_purge_en_boucle(self):
        """Des crashs répétés peuvent empiler plusieurs jumps identiques."""
        self.assertIn("while ip6tables -D OUTPUT", INSTALL)
        self.assertIn("while iptables  -D FORWARD", INSTALL)

    def test_hook_de_reveil(self):
        self.assertIn("system-sleep", INSTALL)
        self.assertIn("systemctl restart tor-vpn-manager", INSTALL)

    def test_tor_systeme_desactive(self):
        """Sinon conflit sur le port 9050."""
        self.assertIn("systemctl disable tor", INSTALL)

    def test_groupe_torvpn_et_permissions(self):
        self.assertIn("groupadd -f torvpn", INSTALL)
        self.assertIn("chmod 2770", INSTALL)

    def test_dnsmasq_optionnel(self):
        """Ne doit plus être installé systématiquement pour être désactivé."""
        deps = re.search(r"apt-get install -y ([^\n]+)", INSTALL).group(1)
        self.assertNotIn("dnsmasq", deps,
                         "dnsmasq est encore dans les dépendances obligatoires")
        self.assertNotIn("dnsutils", deps, "dnsutils n'est utilisé nulle part")
        self.assertIn("command -v dnsmasq", INSTALL)

    def test_dnsmasq_absent_n_est_pas_un_echec(self):
        bloc = INSTALL[INSTALL.index("── Vérification"):]
        self.assertNotRegex(bloc, r"for bin in [^\n]*dnsmasq")

    def test_torrc_par_defaut_non_ecrase(self):
        self.assertIn('if [ ! -f "$TORRC_FILE" ]', INSTALL)

    def test_torrc_par_defaut_complet(self):
        for cle in ("SocksPort 9050", "ControlPort 9051",
                    "CookieAuthentication 1", "DataDirectory"):
            self.assertIn(cle, INSTALL, f"{cle} absent du torrc par défaut")


class CliTest(unittest.TestCase):

    def test_commandes_privilegiees_exigent_root(self):
        for cmd in ("start", "stop", "restart", "enable", "disable"):
            bloc = CLI[CLI.index(f"    {cmd})"):]
            self.assertIn("_need_root", bloc[:200], f"« {cmd} » ne vérifie pas root")

    def test_lecture_sans_root(self):
        for cmd in ("status", "logs", "follow", "ip"):
            bloc = CLI[CLI.index(f"    {cmd})"):]
            self.assertNotIn("_need_root", bloc[:150], f"« {cmd} » exige root sans raison")

    def test_gui_lance_sans_root(self):
        bloc = CLI[CLI.index("    gui)"):]
        self.assertNotIn("_need_root", bloc[:300])
        self.assertIn("exec python3", bloc[:400])


class VersionCoherenceTest(unittest.TestCase):

    def test_version_identique_partout(self):
        import sys
        sys.path.insert(0, str(ROOT))
        from constants import VERSION
        for nom in ("README.md", "README.fr.md"):
            txt = (ROOT / nom).read_text()
            self.assertIn(f"# Tor-VPN Manager — v{VERSION}", txt,
                          f"titre de {nom} désynchronisé de constants.py")
            self.assertIn(f"Version-{VERSION}-blue", txt,
                          f"badge de {nom} désynchronisé")

    def test_pas_de_script_security_documente(self):
        """#7 : la doc ne doit plus montrer --script-security 2."""
        for nom in ("README.md", "README.fr.md"):
            txt = (ROOT / nom).read_text()
            bloc = txt[txt.index("openvpn\n  --config"):]
            bloc = bloc[:bloc.index("```")]
            self.assertNotIn("--script-security", bloc,
                             f"{nom} documente encore --script-security dans la commande")

    def test_pas_de_script_security_dans_le_code(self):
        """On cherche l'argument littéral (entre guillemets, tel qu'il serait
        passé dans argv) : les mentions en commentaire ou docstring sont
        légitimes puisqu'elles expliquent précisément son absence."""
        code = (ROOT / "daemon" / "openvpn.py").read_text()
        for litteral in ('"--script-security"', "'--script-security'"):
            self.assertNotIn(litteral, code,
                             f"--script-security réintroduit dans argv ({litteral})")


class GitignoreTest(unittest.TestCase):
    """Les secrets ne doivent pas pouvoir être committés par accident."""

    def test_ignore_les_donnees_personnelles(self):
        ign = (ROOT / ".gitignore").read_text()
        for motif in ("providers/*/", "auth.tmp", "id.txt", "__pycache__/"):
            self.assertIn(motif, ign, f"{motif} n'est pas ignoré")

    def test_aucun_ovpn_ni_config_suivi_par_git(self):
        r = subprocess.run(["git", "ls-files"], cwd=ROOT,
                           capture_output=True, text=True)
        suivis = r.stdout.splitlines()
        for f in suivis:
            self.assertFalse(f.startswith("providers/") and f.endswith(".ovpn"),
                             f"fichier .ovpn personnel suivi par git : {f}")
            self.assertNotEqual(f, "config.json")
            self.assertFalse(f.endswith("auth.tmp"), f)


if __name__ == "__main__":
    unittest.main()
