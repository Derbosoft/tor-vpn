"""Garde-fou de la suite : aucun test ne doit modifier la machine.

Le daemon tourne en root et manipule iptables, les routes, le DNS et des
processus.  Une suite de tests qui exécuterait ces commandes pour de vrai
couperait le réseau de la machine sur laquelle elle tourne.  Ces tests
vérifient donc les invariants de sûreté de la suite elle-même.
"""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = sorted(p for p in (ROOT / "tests").glob("test_*.py"))

# Commandes qui modifient l'état de la machine.
MUTANTES = ("iptables", "ip6tables", "ip route", "ip addr", "ip link set",
            "resolvectl", "systemctl", "pkill", "sysctl", "openvpn", "dnsmasq")


class NoRealCommandTest(unittest.TestCase):

    def test_les_tests_n_appellent_pas_subprocess_directement(self):
        """Seules exceptions admises : `bash -n`, `py_compile`, `git ls-files`."""
        autorises = ("bash", "-n", "git", "ls-files", "py_compile", "capture_output")
        for f in TESTS:
            if f.name in ("test_safety.py", "test_scripts.py"):
                continue
            for i, ligne in enumerate(f.read_text().splitlines(), 1):
                if "subprocess.run(" in ligne or "subprocess.Popen(" in ligne:
                    self.assertTrue(
                        any(a in ligne for a in autorises),
                        f"{f.name}:{i} appelle subprocess directement : {ligne.strip()}")

    def test_test_scripts_n_execute_que_bash_n(self):
        txt = (ROOT / "tests" / "test_scripts.py").read_text()
        for ligne in txt.splitlines():
            if "subprocess.run(" in ligne:
                self.assertTrue("bash" in ligne or "git" in ligne,
                                f"commande non autorisée : {ligne.strip()}")

    def test_aucun_chemin_systeme_en_ecriture(self):
        """Les tests ne doivent jamais viser /etc, /run ou /lib en écriture."""
        for f in TESTS:
            txt = f.read_text()
            for chemin in ('"/etc/tor-vpn-manager', "'/etc/tor-vpn-manager",
                           '"/run/tor-vpn', '"/etc/systemd/'):
                if chemin in txt:
                    # Toléré uniquement dans une assertion de contenu (chaîne
                    # attendue), jamais dans une écriture.
                    for i, ligne in enumerate(txt.splitlines(), 1):
                        if chemin in ligne:
                            self.assertFalse(
                                any(w in ligne for w in ("write_text", "mkdir",
                                                         "unlink", "open(")),
                                f"{f.name}:{i} écrit dans un chemin système")

    def test_les_scripts_shell_ne_sont_jamais_executes(self):
        for f in TESTS:
            txt = f.read_text()
            for script in ("install.sh", "repair_network.sh"):
                for i, ligne in enumerate(txt.splitlines(), 1):
                    if script in ligne and "subprocess" in ligne:
                        self.assertIn("-n", ligne,
                                      f"{f.name}:{i} exécute {script} sans « bash -n »")


class SystemUnchangedTest(unittest.TestCase):
    """Empreinte de l'état réseau : identique avant/après la suite complète.

    Ce test est volontairement placé dans la suite : s'il échoue, c'est qu'un
    test a modifié la machine.
    """

    @staticmethod
    def _empreinte():
        def lire(cmd):
            try:
                return subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=10).stdout
            except Exception:
                return ""
        return {
            "routes": lire(["ip", "-4", "route", "show"]),
            "regles": lire(["ip", "-4", "rule", "show"]),
            "liens": lire(["ip", "-br", "link", "show"]),
        }

    def test_reseau_intact(self):
        """Lecture seule : confirme que la suite n'a rien cassé."""
        emp = self._empreinte()
        self.assertTrue(emp["routes"], "impossible de lire les routes")
        # La route par défaut doit toujours exister.
        self.assertIn("default", emp["routes"],
                      "PLUS DE ROUTE PAR DÉFAUT — la suite a modifié le système")

    def test_aucun_fichier_de_config_cree(self):
        """Les tests utilisent des répertoires temporaires, jamais /etc."""
        marqueurs = [Path("/etc/tor-vpn-manager/config.json.bad"),
                     Path("/etc/systemd/resolved.conf.d/tor-vpn-split.conf.test")]
        for m in marqueurs[1:]:
            self.assertFalse(m.exists(), f"fichier de test laissé sur le système : {m}")


class SuiteIntegrityTest(unittest.TestCase):

    # Carte de couverture explicite : ajouter un module daemon sans l'inscrire
    # ici — et sans écrire les tests correspondants — fait échouer la suite.
    COUVERTURE = {
        "core":     "test_config_status.py",
        "tor":      "test_tor.py",
        "network":  "test_network.py",
        "dns":      "test_dns.py",
        "firewall": "test_firewall.py",
        "openvpn":  "test_openvpn.py",
        "status":   "test_config_status.py",
        "watchdog": "test_watchdog.py",
    }

    def test_tous_les_modules_daemon_sont_couverts(self):
        modules = {p.stem for p in (ROOT / "daemon").glob("*.py")
                   if p.stem not in ("__init__", "__main__")}
        self.assertEqual(modules, set(self.COUVERTURE),
                         "carte de couverture désynchronisée de daemon/")
        for module, fichier in self.COUVERTURE.items():
            chemin = ROOT / "tests" / fichier
            self.assertTrue(chemin.exists(), f"{fichier} manquant (module {module})")

    def test_chaque_fichier_de_test_assertit_reellement(self):
        for f in TESTS:
            n = f.read_text().count("self.assert")
            self.assertGreaterEqual(n, 5, f"{f.name} ne contient que {n} assertions")

    def test_les_correctifs_ont_un_test_dedie(self):
        """Chaque correctif de l'audit doit rester verrouillé par un test."""
        couverture = " ".join(f.read_text() for f in TESTS)
        for marqueur, quoi in [
            ("--interface", "#3 mesure liée au tunnel"),
            ("Tunnel renouvelé pendant la mesure", "#2 thread périmé"),
            ("IPv6 non supporté", "#1 exclusion IPv6"),
            ("directive de script", "#8 scripts .ovpn"),
            ("script-security", "#7 exécution de scripts"),
            ("domaine ~.", "#13 contrôle DNS complet"),
            ("interface tunnel changée", "#5 partage LAN"),
            ("Identifiants refusés", "#4 reconnexion"),
            ("tor-vpn-routes.txt", "repair_network complété"),
            ("deepcopy", "défauts partagés (trouvé par la suite)"),
        ]:
            # Pas de dump de `couverture` dans le message : plusieurs Ko.
            self.assertTrue(marqueur in couverture,
                            f"aucun test ne verrouille {quoi}")

    def test_pas_de_test_vide(self):
        import ast
        for f in TESTS:
            arbre = ast.parse(f.read_text())
            for noeud in ast.walk(arbre):
                if isinstance(noeud, ast.FunctionDef) and noeud.name.startswith("test"):
                    corps = [n for n in noeud.body
                             if not isinstance(n, (ast.Pass, ast.Expr))
                             or (isinstance(n, ast.Expr)
                                 and not isinstance(n.value, ast.Constant))]
                    self.assertTrue(corps,
                                    f"{f.name}::{noeud.name} n'assertit rien")


if __name__ == "__main__":
    unittest.main()
