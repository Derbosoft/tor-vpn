# Tor-VPN Manager — v3.6.1

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.6.1-blue)
![Systemd](https://img.shields.io/badge/Systemd-service-lightgrey?logo=linux)

> [Documentation en français](README.fr.md)

Route **all your network traffic through OpenVPN tunneled inside Tor** on Ubuntu/Debian. A systemd daemon runs in the background and automatically manages Tor, OpenVPN, IPv6 blocking, LAN sharing, and connectivity monitoring — with a full GUI and CLI.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Project Structure](#project-structure)
5. [Graphical Interface](#graphical-interface)
6. [CLI `tor-vpn`](#cli-tor-vpn)
7. [Daemon Internals](#daemon-internals)
8. [iptables Chains](#iptables-chains)
9. [Failover & Watchdog](#failover--watchdog)
10. [LAN Sharing](#lan-sharing)
11. [Split DNS — Local Domains](#split-dns--local-domains)
12. [Tor Configuration (torrc)](#tor-configuration-torrc)
13. [Automatic Network Repair](#automatic-network-repair)
14. [config.json Format](#configjson-format)
15. [Tests](#tests)
16. [Security](#security)
17. [Getting Started](#getting-started)
18. [Uninstallation](#uninstallation)

---

## Architecture

```
User
    │
    ├── tor-vpn gui          ──►  GUI (main.py → gui/app.py)
    │                              • Reads/writes config.json and torrc
    │                              • Calls systemctl via pkexec
    │                              • Never touches network processes
    │
    ├── tor-vpn <command>    ──►  CLI wrapper (/usr/local/bin/tor-vpn)
    │                              • Calls systemctl
    │
    └── systemd              ──►  tor-vpn-manager.service
                                   │
                                   └── daemon/  (root)
                                         │
                                         ├── Tor  (subprocess, port 9050/9051)
                                         │         └── optional torrc
                                         │
                                         ├── OpenVPN ──► SOCKS5 127.0.0.1:9050 ──► Tor ──► Internet
                                         │              (tunX, redirect-gateway)
                                         │
                                         ├── iptables  (IPv6 block, LAN sharing)
                                         │
                                         └── Watchdog  (connectivity)


Full network flow:
  App → tunX → OpenVPN → SOCKS5:9050 → Tor → Tor relays → VPN server → Internet
```

The GUI and the daemon are **fully decoupled**: the GUI only writes config files and calls systemd. It never monitors processes and cannot interfere with an active connection.

---

## Requirements

| Component | Min version | Role |
|-----------|-------------|------|
| Ubuntu / Debian | 20.04 / 11 | Base system |
| Python | 3.8+ | Daemon + GUI |
| python3-tk | — | GUI toolkit |
| tor | — | SOCKS5 proxy and Tor network |
| openvpn | 2.4+ | Encrypted tunnel to VPN provider |
| dnsmasq | — | **Optional** — DHCP server, only for LAN sharing |
| curl | — | Throughput measurement and connectivity tests |
| systemd + systemd-resolved | — | Service management and DNS |

---

## Installation

```bash
sudo bash install.sh
```

The installer runs **6 steps**:

**1. Dependencies**
```bash
apt install tor openvpn python3 python3-tk curl
```
`dnsmasq` is only used by LAN sharing (disabled by default): since v3.6.1 it is installed only if already present or if sharing is configured, rather than installed and immediately disabled. To add it later: `sudo apt install dnsmasq`.

**2. Configuration directory**
- Creates `/etc/tor-vpn-manager/` as `root:torvpn 2770` (torvpn group: root-less GUI)
- Writes `/etc/tor-vpn-manager/install_dir` (path used by the CLI)
- Installs a **default torrc** (long, stable circuits) if none exists yet — a customized torrc is never overwritten
- Auto-migrates any existing config from `/root/.config/tor-vpn-manager/` or `/opt/tor-vpn-manager/`

**3. System services**
- Enables and starts `systemd-resolved`
- **Disables and stops** the system `tor` service — the daemon manages Tor directly as a subprocess for precise control over startup, logs, and restarts

**4. Systemd service**
Creates `/etc/systemd/system/tor-vpn-manager.service`:
- `ExecStartPre`: iptables cleanup script (removes orphan rules from the previous session)
- `ExecStart`: `python3 -m daemon` from the install directory
- `ExecStopPost`: same cleanup script
- `Restart=on-failure` with a 20s delay, unlimited attempts (`StartLimitIntervalSec=0`)
- `Type=notify` + `WatchdogSec=90`: the daemon reports liveness every ~3s; if it freezes (deadlock), systemd kills and relaunches it
- `KillMode=control-group`: systemd kills the entire cgroup (Tor, OpenVPN, dnsmasq included)
- `TimeoutStopSec=30`

**5. Sleep/wake hook**
Installs `/lib/systemd/system-sleep/tor-vpn-sleep`: automatically restarts the daemon 3 seconds after each wake from sleep or hibernation. Without this hook, Tor circuits are stale after wake but port 9050 is still open, causing OpenVPN to reconnect without going through Tor.

**6. CLI and GUI launcher**
- Installs `/usr/local/bin/tor-vpn` (copy of `tor-vpn-cli.sh`)
- Creates `/etc/xdg/autostart/tor-vpn-gui.desktop` (appears in app menus)

---

## Project Structure

```
tor-vpn-manager/
├── main.py              GUI entry point — checks root rights, launches ConfigApp
├── constants.py         Shared constants for GUI + daemon (paths, palette, defaults)
├── install.sh           Ubuntu/Debian installation script
├── repair_network.sh    Network repair script (iptables, routes, DNS cleanup)
├── tor-vpn-cli.sh       CLI source — copied to /usr/local/bin/tor-vpn by install.sh
├── run-tests.sh         Test-suite runner (+ network fingerprint before/after)
├── template.ovpn        Annotated template to create a compatible .ovpn file
│
├── daemon/              Daemon package (launched by systemd via python3 -m daemon)
│   ├── __init__.py      Daemon class (aggregates all mixins) + main()
│   ├── __main__.py      python3 -m daemon entry point
│   ├── core.py          DaemonCore — shared state, config, logging, signals, orchestration
│   ├── tor.py           TorMixin — Tor start/stop, optional torrc, ControlPort
│   ├── network.py       NetworkMixin — gateway, SOCKS, Tor /32 route protection
│   ├── firewall.py      FirewallMixin — iptables/ip6tables, IPv6 block, LAN sharing, dnsmasq
│   ├── dns.py           DNSMixin — split DNS via systemd-resolved drop-in
│   ├── openvpn.py       OpenVPNMixin — OpenVPN loop, provider failover
│   └── watchdog.py      WatchdogMixin — connectivity monitoring, full restart
│
├── gui/                 GUI package
│   ├── __init__.py
│   └── app.py           ConfigApp — full tkinter interface (6 tabs)
│
└── providers/           .ovpn files per provider (not versioned)
    └── <ProviderName>/
        └── <file>.ovpn
```

**Files generated at install / runtime:**
```
/etc/tor-vpn-manager/
├── config.json               Main config (mode 600, root:root)
├── torrc                     Custom Tor config (mode 600, optional)
├── install_dir               Install path (read by CLI)
├── auth.tmp                  Temporary OpenVPN credentials (created/deleted each session)
├── tor-vpn-routes.txt        Active Tor /32 routes (persisted across restarts)
└── tor_data/                 Tor persistent data (descriptors, keys, cache)

/etc/systemd/system/tor-vpn-manager.service
/etc/systemd/resolved.conf.d/tor-vpn-split.conf   (if split DNS is enabled)
/lib/systemd/system-sleep/tor-vpn-sleep
/usr/local/bin/tor-vpn
/usr/local/lib/tor-vpn-cleanup.sh
/etc/xdg/autostart/tor-vpn-gui.desktop
```

---

## Graphical Interface

### Launch

```bash
tor-vpn gui          # Recommended — runs as your user (torvpn group)
python3 main.py      # Direct launch — privileged actions go through pkexec
```

### Providers Tab

Manages VPN providers and their accounts. List order defines connection and failover priority.

**Provider:**
- Free name (e.g. ProtonVPN, Mullvad)
- Associated `.ovpn` file — copied to `providers/<Name>/` on selection
- ↑ ↓ buttons to reorder priority

**Accounts per provider:**
- Each provider can have multiple accounts (username + password)
- Stored as base64 in `config.json` (simple obfuscation, see [Security](#security))
- ↑ ↓ buttons to reorder; the daemon tries accounts in order

**Automatic failover:** if an account's credentials are refused, the daemon moves to the next account of the same provider. On a network drop it retries the same account before switching provider — see [Failover & Watchdog](#failover--watchdog).

**Import / Export `.tvpn`:** ZIP archive containing `config.json` + all `.ovpn` files. Transfers the complete configuration between machines.

### Exclusions Tab

#### Split DNS — Local domains

Routes DNS queries for specific domains to your local DNS server, while everything else goes through the VPN's DNS.

| Field | Description |
|-------|-------------|
| **Local DNS server** | IP of your DNS server (e.g. `10.0.50.253`) |
| **Domains** | Domains to route to this DNS (e.g. `.local`, `.home`) |

> **Important:** the network containing your DNS server must appear in the **Excluded IPs/Networks** below.

#### IPs / Networks excluded from tunnel

CIDRs and IPs that bypass the tunnel and go through the local gateway. The daemon injects `--route <ip> <mask> net_gateway` into the OpenVPN command.

> **IPv4 only.** `--route` is an IPv4 option; an IPv6 entry would be accepted then ignored by OpenVPN, wrongly suggesting the network is excluded. Since v3.6.1 the GUI rejects such input and the daemon discards these entries with a warning in the journal.

**Typical use cases:**
- Local network (`192.168.1.0/24`)
- DNS server subnet — **required if split DNS is enabled**
- NAS, network printers, local servers

> **Directly-connected networks must NOT be excluded — and don't need to be.**
>
> Your own NIC's network (e.g. `10.0.50.0/24` on `ens18`) already has a kernel `scope link` route in `/24`, which is more specific than the VPN's `redirect-gateway` (`0.0.0.0/1`): by *longest prefix match* it stays **outside the tunnel anyway**.
>
> Excluding it would overlay a `via <gateway>` route with metric 0 that **supersedes the direct route**: all traffic to your own LAN would then detour through the router (*hairpin*), which is often refused — breaking, in particular, access to a VPN server hosted on that same segment.
>
> The daemon **detects and skips** such useless exclusions automatically, with a message in the journal.

Also worth excluding: the **subnet of a remote-admin VPN** (WireGuard/OpenVPN you connect through). Without it, replies to your client would be swallowed by the Tor tunnel and **your SSH/RDP session would drop** the moment the service starts.

### Settings Tab

| Setting | Default | Description |
|---------|---------|-------------|
| **Block IPv6** | disabled | DROP ip6tables on OUTPUT + FORWARD |
| **Auto-reconnect** | enabled | Automatically restarts the tunnel |
| **Tor circuit quality** | enabled | Measures throughput on connect, re-draws a circuit if too slow |
| **Minimum throughput** | 250 KB/s | Threshold below which the circuit is re-drawn (≈ 2 Mbps; the Mbps equivalent is shown next to the field) |
| **Maximum attempts** | 3 | Re-draws allowed before keeping the circuit as-is |
| **Autostart** | disabled | `systemctl enable/disable tor-vpn-manager` |

**"Repair Network" button:** runs `repair_network.sh` manually — stops the service, clears all iptables rules, routes and DNS blocks, then prompts to restart. Useful when the connection is completely stuck despite a service restart.

### LAN Sharing Tab

Shares the Tor+VPN tunnel with devices on a second network interface.

| Setting | Description |
|---------|-------------|
| **Interface** | Network card to use (auto-filters lo, tun*, docker*, etc.) |
| **Card IP** | Gateway IP assigned to this interface (e.g. `10.0.0.1`) |
| **CIDR subnet** | DHCP range (e.g. `10.0.0.0/24`) |
| **DHCP server** | Automatically starts dnsmasq |
| **Enable at start** | Starts sharing as soon as the tunnel is active |

### Tor (torrc) Tab

Customizes Tor configuration via a dedicated `torrc` file. `install.sh` installs one by default (values below); if it is deleted, Tor starts with the minimal parameters built into the daemon.

The defaults favor long, stable circuits — well suited to a persistent
OpenVPN tunnel. Every option remains individually adjustable below, or via
expert mode (direct torrc editing).

**Configurable options:**

| Option | Description |
|--------|-------------|
| `LongLivedPorts 1194,443` | Prefers stable relays for OpenVPN ports |
| `LearnCircuitBuildTimeout 0` | Fixed circuit timeout (more predictable) |
| `MaxCircuitDirtiness` | Max circuit lifetime before renewal (s) |
| `CircuitBuildTimeout` | Max circuit build time (s) |
| `NewCircuitPeriod` | How often new circuits are built (s) |
| `KeepalivePeriod` | Keepalive cells to maintain circuits across NAT |
| `NumEntryGuards` | Number of entry guard nodes |
| `GuardLifetime` | How long to keep guards |
| `AvoidDiskWrites 1` | Reduces disk writes |
| `SafeLogging 1` | Masks IPs in Tor logs |
| `ClientUseIPv6 0` | Disables IPv6 for Tor |
| `TestSocks 1` | Warns on local DNS leak via SOCKS |
| `ConnectionPadding 1` | Traffic analysis resistance (↑ bandwidth) |
| `ExcludeExitNodes` | Exclude exit nodes by country (e.g. `{us},{gb}`) |
| `StrictNodes` | Strict exclusions (may disconnect if no node available) |

**Expert mode:** editable text area showing the full torrc. Updates in real time as options change. Can be edited directly for advanced parameters.

**Apply button** → writes `/etc/tor-vpn-manager/torrc` + restarts the service.  
**Reset button** → deletes the torrc + restarts with the daemon's minimal config.

> Mandatory parameters (`SocksPort`, `ControlPort`, `CookieAuthentication`, `DataDirectory`) are always enforced at apply time.

---

## CLI `tor-vpn`

```bash
# Service control (requires root)
sudo tor-vpn start       # Start the daemon
sudo tor-vpn stop        # Stop the daemon
sudo tor-vpn restart     # Restart the daemon
sudo tor-vpn enable      # Enable autostart at boot
sudo tor-vpn disable     # Disable autostart

# Graphical interface
tor-vpn gui

# Monitoring
tor-vpn status           # Full state: service, Tor, VPN, split DNS, public IP
tor-vpn logs [n]         # Last n lines of journal (default: 60)
tor-vpn follow           # Live logs (Ctrl+C to exit)
tor-vpn ip               # Current public IP
```

---

## Daemon Internals

### Full startup sequence

```
1.  Clean up orphan iptables rules (from previous session)
2.  Start Tor as a subprocess (with torrc if present)
3.  Wait for Tor 100% bootstrap (240s timeout)
4.  Start the OpenVPN loop in a dedicated thread
5.  Start the monitoring loop in the main thread
```

### Tor management

Tor is launched directly as a subprocess (not via the system service).

**Without custom torrc** (minimal built-in config):
```
--SocksPort 9050  --ControlPort 9051  --CookieAuthentication 1
--DataDirectory /etc/tor-vpn-manager/tor_data  --Log notice stdout
```

**With custom torrc** (created via the GUI Tor tab):
```
tor --torrc-file /etc/tor-vpn-manager/torrc --Log notice stdout
```
`--Log notice stdout` is always appended on the command line so the daemon can detect the bootstrap regardless of torrc settings.

If Tor crashes, it is automatically restarted (up to 5 times with a 15s delay).

### OpenVPN management

```
openvpn
  --config            <file.ovpn>
  --auth-user-pass    /etc/tor-vpn-manager/auth.tmp
  --verb              3          ← required for net_addr_v4_add in logs
  --ping              10
  --ping-exit         60
  --connect-timeout   60         ← extended because Tor circuits can be slow
  --connect-retry     1
  --connect-retry-max 1
  --socks-proxy       127.0.0.1 9050
  [--route <ip> <mask> net_gateway ...]
```

> **Since v3.6.1: no more `--script-security 2`.** No `.ovpn` file needs scripts — the daemon applies the VPN DNS itself via `resolvectl`. Allowing script execution, on the other hand, let anyone able to write an `.ovpn` (the `torvpn` group) have code executed **by the daemon, as root**, through a plain `up` directive.
>
> OpenVPN's **built-in** executables remain allowed at level 1: on OpenVPN 2.6+, the native `/usr/libexec/openvpn/dns-updown` hook keeps working normally. Only scripts declared in the `.ovpn` are blocked — and the daemon now warns in the journal when an `.ovpn` contains one (`up`, `down`, `route-up`, `ipchange`, `tls-verify`…), whether or not the file exists on disk.

**Tor route protection:**
As soon as OpenVPN assigns an IP to the tunnel (`net_addr_v4_add`, visible via `--verb 3`), the daemon **synchronously** adds static `/32` routes for all active Tor guard IPs via the original local gateway. This must happen *before* the `up` script installs `redirect-gateway` routes. Without this protection, Tor would try to reach its guards through the tunnel, creating a loop that kills the connection. Routes are persisted in `/etc/tor-vpn-manager/tor-vpn-routes.txt` and cleanly removed at shutdown.

**Split DNS timing:**
VPN DNS is handled natively by the daemon: the servers pushed by the VPN (`PUSH_REPLY`, `dhcp-option DNS`) are parsed from the OpenVPN output and applied to the tunnel interface via `resolvectl` (no `update-resolv-conf` script needed). Split DNS is then applied **after** `Initialization Sequence Completed`; its systemd-resolved drop-in keeps priority for excluded domains.

**DNS robustness:**
- On startup the daemon checks that `resolvectl` exists and `systemd-resolved` is active — otherwise it warns clearly in the journal (without it, DNS resolution may fail or leak outside Tor).
- Every ~30 s it **re-verifies** that the tunnel interface's DNS config is still in place. If a third-party tool restarted `systemd-resolved` (which wipes the per-interface *runtime* config), it is **re-applied automatically**. In the normal case this is just a read: no rewrite, no needless `reload`.

  Since v3.6.1 the check covers **all three** attributes that were set (DNS servers, `~.` domain, `default-route`) instead of the servers alone. Reason: on an internal reconnect (`SIGUSR1`), OpenVPN 2.6+'s native `dns-updown` hook reinstalls the servers but not necessarily the rest — and without `~.` the tunnel interface stops being the default DNS destination, so public queries can go back out to the local DNS, outside the tunnel, with nothing to signal it.

**Connection sequence:**
When `Initialization Sequence Completed` is detected:
1. Split DNS applied (after OpenVPN's up script)
2. IPv6 blocking enabled (if configured)
3. LAN sharing started (if `lan_auto = true`)

### Sleep/wake hook

`/lib/systemd/system-sleep/tor-vpn-sleep` is called by the kernel on every sleep/wake event. On wake (`post`), it waits 3 seconds then runs `systemctl restart tor-vpn-manager`. This delay gives network interfaces time to reconnect before the daemon relaunches Tor.

---

## iptables Chains

The daemon creates **dedicated named chains** for clean teardown without interfering with other rules.

### IPv6 blocking — `TORVPN_KS6` / `TORVPN_KS6_FWD`

```
OUTPUT/FORWARD:
RETURN  → lo
RETURN  → tunX
RETURN  → ESTABLISHED,RELATED
DROP    → everything else (IPv6)
```

Protects against IPv6 leaks when the VPN provider does not support it.

### LAN sharing — `TORVPN_LAN_FWD` (FORWARD)

```
RETURN  → ESTABLISHED,RELATED
RETURN  → <lan_iface> → tunX
DROP    → <lan_iface> → everything else

NAT POSTROUTING: MASQUERADE source=<lan_subnet> out=tunX
```

---

## Failover & Watchdog

### Reconnection: two causes, two responses

When the OpenVPN process exits, the daemon determines **the nature of the failure** before deciding (v3.6.1 behaviour):

| Detected cause | Response | Delay |
|----------------|----------|-------|
| **Credentials refused** (`AUTH_FAILED` or `SIGTERM[soft,auth-failure]`) | Next account of the same provider | 3 s |
| **Everything else** (network drop, TLS timeout, `ping-exit`) | **Same account**, up to `RECONNECT_MAX` (5) times | 15 s |
| Same account fails 5 times in a row | **Next provider**, account 1 | 3 s |
| No fallback provider left | Give up → anti-inertia net → systemd relaunch | — |

The key point: **switching accounts only helps when the account is at fault.** All accounts of a provider share the same `.ovpn` file, hence the same server list — switching has no effect on a network outage or a server-side problem. Only switching *provider* does.

> **Before v3.6.1**, any disconnect triggered an account failover. A plain network drop burned through all ten iVPN accounts then ProtonVPN's in about thirty seconds (3 s apart), without the 15 s backoff ever coming into play: up to 65 rapid-fire authentication attempts during a sustained outage. The current logic makes 12, spaced 15 s apart — gentler on the provider, and far more likely to succeed since a network drop resolves on its own.

A fault affecting an entire provider (`.ovpn` not found) likewise skips straight to the next provider, without walking its accounts one by one.

### Failure detection

The watchdog checks connectivity every **9 seconds** (after a **30-second grace period** post-connection):

1. `ip link show tunX` — does the interface exist?
2. TCP connection via `SO_BINDTODEVICE tunX` (5s timeout) to `1.1.1.1:443`, then `9.9.9.9:443` as a second opinion — does the tunnel actually route traffic? Two independent endpoints: a transient outage of one never triggers a pointless restart.

If the check fails **2 times in a row** (~28s max): `_full_restart()` — full Tor + OpenVPN shutdown, orphan `/32` route cleanup, full restart.

**Anti-inertia safety net:** the Tor/OpenVPN loops give up after a bounded number of attempts. If no VPN loop has been running for **2 minutes** (with auto-reconnect enabled), the daemon deliberately exits (`exit 1`): systemd relaunches it entirely (`Restart=on-failure`, unlimited attempts). No outage, however long, can leave the daemon permanently inert.

**systemd watchdog:** the monitoring loop sends `WATCHDOG=1` to systemd every ~3s (`sd_notify`, also while waiting for the Tor bootstrap). If the Python process itself freezes — deadlock, stuck syscall — the pings stop and systemd kills then relaunches the daemon after 90s (`WatchdogSec=90`). Complete survival chain: internal loops → anti-inertia net → systemd watchdog.

If connectivity returns after a restart, the counter resets.

### Automatic emergency repair

If **3 consecutive full restarts** all fail (`_full_restart_count`), the watchdog triggers `_emergency_repair()`:

```
1. Runs repair_network.sh --internal
   → cleans iptables (IPv6 + LAN), blocked OpenVPN routes, systemd-resolved DNS
   → does not touch the systemd service (the daemon stays in control)
2. sys.exit(1)
   → systemd detects the crash and automatically relaunches the daemon (Restart=on-failure)
```

**Typical log sequence during a total block:**
```
[WARN] Watchdog: no connectivity (1/2) …
[WARN] Watchdog: no connectivity (2/2) …
[ERROR] Watchdog: full restart (1/3) …
[WARN] Watchdog: no connectivity (1/2) …
[ERROR] Watchdog: full restart (2/3) …
[WARN] Watchdog: no connectivity (1/2) …
[ERROR] Watchdog: full restart (3/3) …
[ERROR] 3 failed restarts — running repair_network.sh …
[WARN]  Repair done — exiting for systemd relaunch.
← systemd automatically relaunches the daemon
```

### Tor circuit quality check

The Tor circuit is **drawn at random on every connection**, and its quality varies wildly (from ~100 KB/s to several MB/s). Right after the tunnel comes up, the daemon runs **a single measurement** of real throughput (a 2 MB download *through* the tunnel):

```
Tunnel up → 5 s to settle → measure throughput
   ├─ ≥ threshold  → circuit kept, no further measurement
   └─ < threshold  → SIGNAL NEWNYM  (forces a fresh circuit)
                     → OpenVPN reconnect (same provider/account)
                     → measure again … up to "maximum attempts"
                     → beyond that: circuit kept (never loops)
```

Two design points worth stating:

- **The measurement creates the demand it measures.** Passively reading interface counters would be uninterpretable: low throughput could mean "the link is slow" *or* "nothing is being requested". Here, a low result unambiguously means the circuit is bad.
- **`NEWNYM` is sent *before* reconnecting.** It does not change the circuit of an already-established connection — it guarantees the *next* connection gets a fresh one. Without it, `MaxCircuitDirtiness` would reuse the same circuit, hence the same slow relays.

**No continuous monitoring**: this test does not run in the background and costs nothing after connection.

Real-world example:
```
[WARN] [circuit] Débit faible : 127 KB/s (~1.0 Mbps) < 250 KB/s — nouveau tirage (1/3) …
[OK  ] [tor] Nouveau circuit demandé (NEWNYM).
[WARN] Reconnexion sur un circuit Tor neuf …
[OK  ] [circuit] Débit OK : 568 KB/s (~4.5 Mbps).
```

### Failover logic

```
Provider 1, Account 1 → Provider 1, Account 2 → ... → Provider 2, Account 1 → ...
All exhausted → back to start → give up after 5 attempts
```

### Clean shutdown (SIGTERM / SIGINT)

```
1. SIGTERM → OpenVPN
2. SIGTERM → Tor
3. Remove Tor /32 routes
4. Teardown LAN sharing + stop dnsmasq
5. Remove ip6tables chains
6. Remove split DNS drop-in
7. Remove auth.tmp
```

---

## LAN Sharing

When LAN sharing is enabled:

1. Gateway IP assigned to the LAN interface (`ip addr add`)
2. IP routing enabled (`sysctl net.ipv4.ip_forward=1`)
3. NAT MASQUERADE so LAN traffic exits through the tunnel
4. `TORVPN_LAN_FWD` chain: blocks all LAN traffic not heading to the tunnel
5. dnsmasq in `--no-daemon` mode: DHCP in the subnet, DNS `1.1.1.1` through the tunnel

If the tunnel drops, LAN traffic is blocked — no leak through the direct connection.

The rules in steps 3 and 4 hard-code the **tunnel interface name**. Since the `.ovpn` files use `dev tun` (first free device), that name can change when the tunnel is rebuilt. Since v3.6.1 the daemon compares the remembered interface against the current one and **rebuilds the rules** when they differ (logging a `WARN`): without this they pointed at nothing and LAN traffic fell through to the final `DROP` rule — a total, silent outage until the service was restarted.

---

## Split DNS — Local Domains

Lets you reach services on your local network with a custom domain name **while the VPN is active**.

### Why it is needed

Without split DNS, OpenVPN's `redirect-gateway def1` routes all traffic through the tunnel — including packets to your local DNS server, which becomes unreachable.

With split DNS:
- `.local` → your local DNS (`10.0.50.253`)
- Everything else → VPN DNS through Tor

### Configuration

**In the GUI Exclusions tab:**

1. Enter the local DNS server IP
2. Add local domains (e.g. `.local`, `.home`)
3. Add the DNS subnet to excluded IPs (e.g. `10.0.50.0/24`) — **critical step**
4. Save + Restart

The daemon automatically generates:

```ini
# /etc/systemd/resolved.conf.d/tor-vpn-split.conf
[Resolve]
DNS=10.0.50.253
Domains=~local
```

### Verification

```bash
resolvectl status            # see routed domains
dig server.local             # must resolve via 10.0.50.253
tor-vpn status               # shows "Split DNS: active (→ 10.0.50.253)"
```

---

## Tor Configuration (torrc)

`install.sh` installs `/etc/tor-vpn-manager/torrc` with the default values (never overwriting an existing file), and the **Tor (torrc)** GUI tab lets you edit it. If this file exists, the daemon passes it to Tor via `--torrc-file`. If absent, Tor starts with the minimal built-in arguments.

### Mandatory parameters (always present)

```ini
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /etc/tor-vpn-manager/tor_data
```

### Default values (long, stable circuits)

```ini
LongLivedPorts 1194,443
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 3600
CircuitBuildTimeout 60
NewCircuitPeriod 60
KeepalivePeriod 60
NumEntryGuards 3
GuardLifetime 2 months
AvoidDiskWrites 1
SafeLogging 1
ClientUseIPv6 0
TestSocks 1
```

For enhanced anonymity, enable e.g. `ConnectionPadding 1` and
`ExcludeExitNodes {us},{gb},{ca},{au},{nz}` — every option can be adjusted
in the tab or in expert mode.

### Reset

The **Reset** button deletes the torrc file. On the next service start, Tor runs with minimal parameters and no external config file.

---

## Automatic Network Repair

`repair_network.sh` is the emergency recovery script. It can be triggered in **three ways**:

| Trigger | Mode | Behavior |
|---------|------|----------|
| GUI "Repair Network" button | manual | Stops service, cleans everything, prompts to restart |
| `sudo bash repair_network.sh` | manual CLI | Same as GUI button |
| Watchdog (3 failed restarts) | automatic | `--internal`: cleans without `systemctl stop`, then `sys.exit(1)` for systemd relaunch |

**What the script cleans:**

1. Residual OpenVPN and Tor processes (`pkill`)
2. ip6tables chains `TORVPN_KS6` / `TORVPN_KS6_FWD` (IPv6 blocking)
3. iptables chain `TORVPN_LAN_FWD`, the sharing dnsmasq, and the matching `MASQUERADE` NAT rule
4. systemd-resolved DNS — `resolvectl revert` on `tun0` and `tun1`, drop-in removal, `systemd-resolved` restart
5. Tor relay `/32` routes, read from `tor-vpn-routes.txt` — otherwise traffic to those IPs would keep bypassing the tunnel after the repair
6. Blocked OpenVPN def1 routes (`0.0.0.0/1`, `128.0.0.0/1`, `default`) on `tun0` and `tun1`
7. Final connectivity check (`ip route get 1.1.1.1`, `getent ahosts`)

> Item 3, item 5 and the extension to `tun1` date from v3.6.1: the script previously left orphaned `/32` routes and a NAT rule behind, and only handled `tun0` even though the `.ovpn` files use `dev tun`.

---

## config.json Format

`/etc/tor-vpn-manager/config.json` — mode `660 root:torvpn`.

```json
{
  "providers": [
    {
      "name": "ProtonVPN",
      "ovpn_file": "providers/ProtonVPN/server.ovpn",
      "accounts": [
        { "u": "dXNlcm5hbWU=", "p": "cGFzc3dvcmQ=" }
      ]
    }
  ],
  "auto_reconnect": true,
  "block_ipv6": false,
  "excluded_ips": ["192.168.1.0/24", "10.0.50.0/24"],
  "excluded_domains": [".local"],
  "local_dns": "10.0.50.253",
  "circuit_check": true,
  "circuit_min_kbs": 250,
  "circuit_max_retries": 3,
  "lan_iface": "",
  "lan_gateway": "10.0.0.1",
  "lan_subnet": "10.0.0.0/24",
  "lan_dhcp": true,
  "lan_auto": false,
  "autostart": false
}
```

| Key | Type | Description |
|-----|------|-------------|
| `providers[].ovpn_file` | string | Path relative to the install directory |
| `providers[].accounts[].u` | string | Base64-encoded username |
| `providers[].accounts[].p` | string | Base64-encoded password |
| `excluded_ips` | list | CIDRs/IPs routed via local gateway |
| `excluded_domains` | list | Domains routed to local DNS |
| `local_dns` | string | Local DNS server IP |
| `circuit_check` | bool | Measure throughput on connect + re-draw if the circuit is slow |
| `circuit_min_kbs` | int | Threshold in KB/s (250 ≈ 2 Mbps; 0 = disabled) |
| `circuit_max_retries` | int | Max re-draws before keeping the circuit |

---

## Tests

The project is covered by a suite of **285 tests** (`unittest`, no external dependency):

```bash
bash run-tests.sh                      # everything
bash run-tests.sh -v                   # test by test
bash run-tests.sh tests.test_openvpn   # one module
```

**The suite never touches the system.** `iptables`, `ip`, `resolvectl`, `systemctl`, `curl`, `openvpn` and `tor` are intercepted and recorded instead of executed: the tests assert *which commands would have been run*, with which arguments and in which order. The suite is therefore safe to run on the production machine with the tunnel up. `run-tests.sh` takes a network fingerprint before and after to prove it, and `tests/test_safety.py` prevents a future test from bypassing that rule.

What is covered, beyond the happy paths:

| Area | Example cases |
|------|---------------|
| Excluded routes | IPv6 rejected, directly-connected network skipped (scope-link trap), CIDR normalisation |
| ControlPort | microdesc (8-field) *and* ns (9-field) consensus, single connection for N queries, 32-relay cap |
| DNS | servers / `~.` domain / default-route checked separately, abstain when state is unreadable |
| Firewall | `DROP` always the last rule, refusal to flush the uplink, rebuild when the tunnel is renamed |
| Circuit quality | exact threshold, retry cap, stale thread must not kill the next tunnel |
| Reconnection | credentials refused vs network drop, bounded attempt count |
| Security | `auth.tmp` 0600 even under a permissive umask, no credentials in the status socket, import path-traversal guard |
| Consistency | version identical in `constants.py` and both READMEs, `--script-security` absent from the code |

Several tests also exercise the system **read-only** to validate parsers against reality rather than a frozen sample (`/proc/net/dev` layout, `resolvectl status` output).

---

## Security

**VPN credentials:** stored as base64 in `config.json`. This is obfuscation, **not encryption**. The file is mode `660 root:torvpn`, inside a `2770 root:torvpn` directory.

**auth.tmp:** created directly as mode `600` (never exposed to the umask) just before launching OpenVPN, deleted in the `finally` block as soon as OpenVPN has read the file.

**torrc:** mode `660 root:torvpn`.

**Scope of the `torvpn` group:** this group exists so the GUI can run **without root**. In exchange, it grants write access to files the daemon consumes as root (`config.json`, `torrc`, `providers/*.ovpn`) — its members must therefore be treated as machine administrators. Only add trusted accounts. v3.6.1 closes the most direct vector by dropping `--script-security 2` (see *OpenVPN management*), but the principle stands: `torvpn` ≈ elevated privileges.

**`.ovpn` scripts:** execution of scripts declared in an `.ovpn` is disabled. An `.ovpn` containing one is flagged in the journal and will fail to connect — remove the directive, the daemon handles DNS itself.

**Tor as proxy:** the VPN server sees a Tor exit node IP, never your real IP. Your ISP sees that you use Tor, but does not know you are using a VPN or what destination you are reaching.

---

## Getting Started

```bash
# 1. Install
sudo bash install.sh

# 2. Open the configuration interface
tor-vpn gui

# 3. Providers tab:
#    a. "+ Add" → provider name
#    b. "Choose / Change" → select your .ovpn file
#    c. "+ Add account" → username + password

# 4. (Optional) Tor (torrc) tab:
#    - Adjust options if needed (defaults suit everyday use)
#    - Click "Apply + Restart"

# 5. (Optional) Exclusions tab:
#    - Local DNS + domains + DNS subnet in excluded IPs

# 6. Save

# 7. Start
sudo tor-vpn start

# 8. Follow the startup
tor-vpn follow
# Wait for "VPN tunnel active." (Tor bootstrap = 1-3 minutes)

# 9. Verify
tor-vpn status
```

---

## Uninstallation

```bash
sudo tor-vpn stop
sudo systemctl disable tor-vpn-manager
sudo rm /etc/systemd/system/tor-vpn-manager.service
sudo rm /lib/systemd/system-sleep/tor-vpn-sleep
sudo rm /usr/local/bin/tor-vpn
sudo rm /usr/local/lib/tor-vpn-cleanup.sh
sudo rm /etc/xdg/autostart/tor-vpn-gui.desktop
sudo rm -f /etc/systemd/resolved.conf.d/tor-vpn-split.conf
sudo rm -rf /etc/tor-vpn-manager
sudo systemctl daemon-reload
sudo resolvectl reload
```
