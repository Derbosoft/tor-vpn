from pathlib import Path

VERSION       = "3.6.2"
SCRIPT_DIR    = Path(__file__).resolve().parent
PROVIDERS_DIR = SCRIPT_DIR / "providers"
CONFIG_DIR    = Path("/etc/tor-vpn-manager")
CONFIG_FILE   = CONFIG_DIR / "config.json"
AUTH_TMP      = CONFIG_DIR / "auth.tmp"
TORRC_FILE    = CONFIG_DIR / "torrc"

SERVICE_NAME  = "tor-vpn-manager"
STATUS_SOCKET = Path("/run/tor-vpn-manager.sock")

DEFAULT_CONFIG = {
    "providers":         [],
    "auto_reconnect":    True,
    # Ordre de passage des comptes d'un fournisseur.  True : tiré au hasard à
    # chaque entrée dans le fournisseur.  False : ordre de la liste, utile pour
    # reproduire un incident (un refus d'identifiants intermittent devient
    # déterministe).  L'ordre des FOURNISSEURS n'est jamais mélangé : il reste
    # l'ordre de priorité défini dans la configuration.
    "random_account":    True,
    "block_ipv6":        False,
    "excluded_ips":      [],
    "excluded_domains":  [],
    "local_dns":         "",
    # Contrôle qualité du circuit Tor, une seule fois après l'établissement
    # du tunnel : si le débit mesuré est sous le seuil, on force un circuit
    # neuf (NEWNYM) et on retente, dans la limite de circuit_max_retries.
    "circuit_check":      True,
    "circuit_min_kbs":    250,   # 250 KB/s ≈ 2 Mbps
    "circuit_max_retries": 3,
    "lan_iface":         "",
    "lan_gateway":       "10.0.0.1",
    "lan_subnet":        "10.0.0.0/24",
    "lan_dhcp":          True,
    "lan_auto":          False,
    "autostart":         False,
}

# ── Palette ───────────────────────────────────────────────────────────────────
BG        = "#1e1e2e"
BG2       = "#2a2a3e"
BG3       = "#313244"
FG        = "#cdd6f4"
GRAY      = "#585b70"
ACCENT    = "#89b4fa"
GREEN     = "#a6e3a1"
RED       = "#f38ba8"
YELLOW    = "#f9e2af"

FONT      = ("Segoe UI", 10)
FONT_MONO = ("Monospace", 9)
