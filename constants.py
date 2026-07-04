from pathlib import Path

VERSION       = "3.4.0"
SCRIPT_DIR    = Path(__file__).resolve().parent
PROVIDERS_DIR = SCRIPT_DIR / "providers"
CONFIG_DIR    = Path("/etc/tor-vpn-manager")
CONFIG_FILE   = CONFIG_DIR / "config.json"
AUTH_TMP      = CONFIG_DIR / "auth.tmp"
TORRC_FILE    = CONFIG_DIR / "torrc"

SERVICE_NAME  = "tor-vpn-manager"

DEFAULT_CONFIG = {
    "providers":         [],
    "mode":              "tor+vpn",
    "auto_reconnect":    True,
    "block_ipv6":        False,
    "excluded_ips":      [],
    "excluded_domains":  [],
    "local_dns":         "",
    "tor_min_speed_kbs": 50,
    "vpn_min_speed_kbs": 100,
    "speed_fail_count":  3,
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
