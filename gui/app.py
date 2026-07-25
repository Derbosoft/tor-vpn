"""
Tor-VPN Manager — Interface graphique de configuration.

Le daemon (tor-vpn-manager.service) gère Tor + OpenVPN de façon autonome.
Ce GUI écrit la config, redémarre le service si demandé.

Usage : python3 main.py   (ou : tor-vpn gui — groupe torvpn, sans root ;
les actions systemctl privilégiées passent par pkexec)
"""

import base64
import copy
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import socket as _socket

from constants import (
    ACCENT, BG, BG2, BG3, CONFIG_DIR, CONFIG_FILE, DEFAULT_CONFIG,
    FG, FONT, FONT_MONO, GRAY, GREEN, PROVIDERS_DIR, RED, SCRIPT_DIR, STATUS_SOCKET,
    SERVICE_NAME, TORRC_FILE, VERSION, YELLOW,
)


def _obf(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def _deobf(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s


class ConfigApp:

    def __init__(self, root: tk.Tk):
        self.root   = root
        self.config = self._load_config()

        root.title(f"Tor-VPN Manager  v{VERSION}  —  Configuration")
        root.geometry("860x620")
        root.configure(bg=BG)
        root.resizable(True, True)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()
        self._restore_config()
        self._poll_status()

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        # deepcopy et non dict() : les défauts contiennent des listes, et le
        # GUI les modifie EN PLACE (_add_provider fait providers.append).  Une
        # copie superficielle ferait grossir DEFAULT_CONFIG lui-même.
        defaults = copy.deepcopy(DEFAULT_CONFIG)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    loaded = json.load(f)
                if not isinstance(loaded, dict):
                    raise ValueError("config.json ne contient pas un objet JSON")
                return {**defaults, **loaded}
            except Exception as e:
                # Ne pas écraser silencieusement une config corrompue :
                # on la met de côté pour pouvoir la récupérer.
                bad = CONFIG_FILE.with_name(CONFIG_FILE.name + ".bad")
                try:
                    CONFIG_FILE.replace(bad)
                    print(f"config.json illisible ({e}) — sauvegardé dans {bad}",
                          file=sys.stderr)
                except Exception:
                    pass
        return defaults

    def _save_config(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # setgid : les fichiers créés héritent du groupe torvpn.
            CONFIG_DIR.chmod(0o2770)
        except PermissionError:
            pass   # non-root : le répertoire appartient à root:torvpn (install.sh)
        # Écriture atomique : tmp + fsync + rename, pour ne jamais laisser
        # un config.json tronqué en cas de crash/coupure.
        tmp = CONFIG_FILE.with_name(CONFIG_FILE.name + ".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            tmp.chmod(0o660)   # lisible/inscriptible par root + groupe torvpn
            os.replace(tmp, CONFIG_FILE)
        except PermissionError:
            messagebox.showerror(
                "Droits insuffisants",
                f"Impossible d'écrire {CONFIG_FILE}.\n\n"
                "Relancez « sudo bash install.sh » pour créer le groupe "
                "torvpn, puis déconnectez/reconnectez votre session.")
            raise

    # ── Construction UI ───────────────────────────────────────────────────────

    def _apply_style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, font=FONT,
                    fieldbackground=BG2, bordercolor=GRAY)
        s.configure("TLabel",      background=BG,  foreground=FG)
        s.configure("TFrame",      background=BG)
        s.configure("TNotebook",   background=BG,  borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=FG, padding=(10, 4))
        s.map("TNotebook.Tab", background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])
        s.configure("TLabelframe",       background=BG,  foreground=ACCENT)
        s.configure("TLabelframe.Label", background=BG,  foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
        s.configure("TEntry",     fieldbackground=BG2, foreground=FG, insertcolor=FG)
        s.configure("TCombobox",  fieldbackground=BG2, foreground=FG, selectbackground=BG2)
        s.map("TCombobox",        fieldbackground=[("readonly", BG2)])
        s.configure("TButton",    background=BG2, foreground=FG, padding=4)
        s.map("TButton",          background=[("active", ACCENT)],
              foreground=[("active", BG)])
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.map("TCheckbutton",       background=[("active", BG)])
        s.configure("TSpinbox",   fieldbackground=BG2, foreground=FG, insertcolor=FG)

    def _lf(self, parent, title) -> ttk.LabelFrame:
        f = ttk.LabelFrame(parent, text=f"  {title}  ", padding=8)
        f.pack(fill=tk.X, pady=4)
        return f

    def _row(self, parent) -> ttk.Frame:
        r = ttk.Frame(parent)
        r.pack(fill=tk.X, pady=3)
        return r

    def _scrollable(self, parent) -> ttk.Frame:
        canvas = tk.Canvas(parent, bg=BG, bd=0, highlightthickness=0)
        vsb    = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inner  = ttk.Frame(canvas, padding=4)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(
            win_id, width=e.width))

        def _enter(e):
            canvas.bind_all("<Button-4>",   lambda ev: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>",   lambda ev: canvas.yview_scroll(1,  "units"))
            canvas.bind_all("<MouseWheel>",
                lambda ev: canvas.yview_scroll(int(-ev.delta / 120), "units"))
        def _leave(e):
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
            canvas.unbind_all("<MouseWheel>")
        canvas.bind("<Enter>", _enter)
        canvas.bind("<Leave>", _leave)
        return inner

    def _build_ui(self):
        self._apply_style()

        status_bar = tk.Frame(self.root, bg=BG2, pady=4)
        status_bar.pack(fill=tk.X, padx=8, pady=(8, 0))

        tk.Label(status_bar, text="Service daemon :", bg=BG2, fg=FG,
                 font=FONT).pack(side=tk.LEFT, padx=(10, 4))
        self._svc_dot = tk.Label(status_bar, text="●", bg=BG2, fg=GRAY,
                                  font=("Segoe UI", 13))
        self._svc_dot.pack(side=tk.LEFT)
        self._svc_lbl = tk.Label(status_bar, text=" Inconnu", bg=BG2, fg=GRAY, font=FONT)
        self._svc_lbl.pack(side=tk.LEFT, padx=4)

        ttk.Button(status_bar, text="⟳",  width=3,
                   command=self._refresh_status).pack(side=tk.LEFT, padx=(12, 2))
        ttk.Button(status_bar, text="Démarrer",
                   command=self._svc_start).pack(side=tk.LEFT, padx=2)
        ttk.Button(status_bar, text="Arrêter",
                   command=self._svc_stop).pack(side=tk.LEFT, padx=2)
        ttk.Button(status_bar, text="Redémarrer",
                   command=self._svc_restart).pack(side=tk.LEFT, padx=2)

        tk.Label(status_bar, text=f"v{VERSION}", bg=BG2, fg=GRAY,
                 font=("Segoe UI", 8)).pack(side=tk.RIGHT, padx=10)

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        tab_prov = ttk.Frame(nb, padding=6)
        tab_excl = ttk.Frame(nb, padding=6)
        tab_set  = ttk.Frame(nb, padding=2)
        tab_lan  = ttk.Frame(nb, padding=2)
        tab_tor  = ttk.Frame(nb, padding=2)

        nb.add(tab_prov, text="  Fournisseurs  ")
        nb.add(tab_excl, text="  Exclusions  ")
        nb.add(tab_set,  text="  Paramètres  ")
        nb.add(tab_lan,  text="  Partage LAN  ")
        nb.add(tab_tor,  text="  Tor (torrc)  ")

        self._build_providers_tab(tab_prov)
        self._build_exclusions_tab(tab_excl)
        self._build_settings_tab(self._scrollable(tab_set))
        self._build_lan_tab(self._scrollable(tab_lan))
        self._build_tor_tab(tab_tor)

        save_bar = tk.Frame(self.root, bg=BG2, pady=6)
        save_bar.pack(fill=tk.X, padx=8, pady=(0, 8))

        ttk.Button(save_bar, text="💾  Sauvegarder",
                   command=self._on_save).pack(side=tk.LEFT, padx=(10, 4))
        ttk.Button(save_bar, text="💾  Sauvegarder + Redémarrer le service",
                   command=self._on_save_restart).pack(side=tk.LEFT, padx=4)

        self._save_lbl = tk.Label(save_bar, text="", bg=BG2, fg=GRAY, font=FONT)
        self._save_lbl.pack(side=tk.LEFT, padx=10)

    # ── Statut service ────────────────────────────────────────────────────────

    # ── systemctl (pkexec si non-root) ────────────────────────────────────────

    @staticmethod
    def _systemctl(*args) -> "subprocess.CompletedProcess":
        """Exécute systemctl, via pkexec si le GUI ne tourne pas en root.
        La lecture d'état (is-active…) reste directe : elle ne requiert
        aucun privilège."""
        cmd = ["systemctl", *args]
        if os.geteuid() != 0 and args and args[0] not in (
                "is-active", "is-enabled", "show", "status"):
            cmd = ["pkexec"] + cmd
        return subprocess.run(cmd, capture_output=True, text=True)

    def _read_daemon_status(self) -> dict:
        """Lit l'état exposé par le daemon sur son socket Unix (lecture
        seule).  Dict vide si le daemon ne tourne pas."""
        try:
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sk:
                sk.settimeout(1.5)
                sk.connect(str(STATUS_SOCKET))
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = sk.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            return json.loads(buf.decode())
        except Exception:
            return {}

    def _refresh_status(self):
        r = self._systemctl("is-active", SERVICE_NAME)
        state = r.stdout.strip()
        if state == "active":
            st = self._read_daemon_status()
            if st.get("tunnel_up"):
                info = (f" Actif — tunnel {st.get('tunnel_iface','?')} UP"
                        f" · {st.get('provider','?')}"
                        f" · {st.get('rx_kbs',0):.0f} KB/s")
            elif st.get("tor_ready"):
                info = " Actif — Tor prêt, VPN en connexion …"
            elif st:
                info = " Actif — bootstrap Tor …"
            else:
                info = " Actif"
            self._svc_dot.config(fg=GREEN)
            self._svc_lbl.config(fg=GREEN,  text=info)
        elif state in ("failed", "error"):
            self._svc_dot.config(fg=RED)
            self._svc_lbl.config(fg=RED,    text=f" {state.capitalize()}")
        elif state in ("inactive", "dead"):
            self._svc_dot.config(fg=GRAY)
            self._svc_lbl.config(fg=GRAY,   text=" Inactif")
        else:
            self._svc_dot.config(fg=YELLOW)
            self._svc_lbl.config(fg=YELLOW, text=f" {state}")

    def _poll_status(self):
        self._refresh_status()
        self.root.after(5000, self._poll_status)

    def _svc_start(self):
        # Pas de « reset-failed » préalable : inutile (StartLimitIntervalSec=0
        # dans l'unité) et il doublerait l'invite pkexec en non-root.
        r = self._systemctl("start", SERVICE_NAME)
        self.root.after(1500, self._refresh_status)
        if r.returncode != 0:
            messagebox.showerror("Erreur", r.stderr.strip() or "Impossible de démarrer.")

    def _svc_stop(self):
        r = self._systemctl("stop", SERVICE_NAME)
        self.root.after(1000, self._refresh_status)
        if r.returncode != 0:
            messagebox.showerror("Erreur", r.stderr.strip() or "Impossible d'arrêter.")

    def _svc_restart(self):
        r = self._systemctl("restart", SERVICE_NAME)
        self.root.after(2000, self._refresh_status)
        if r.returncode != 0:
            messagebox.showerror("Erreur", r.stderr.strip() or "Impossible de redémarrer.")

    # ── Sauvegarde ────────────────────────────────────────────────────────────

    def _collect_config(self):
        self.config["excluded_ips"]     = list(self.ip_list.get(0, tk.END))
        self.config["excluded_domains"] = list(self.domain_list.get(0, tk.END))
        self.config["local_dns"]        = self.dns_var.get().strip()
        self.config["auto_reconnect"]   = self.auto_reconnect_var.get()
        self.config["block_ipv6"]       = self.block_ipv6_var.get()
        self.config["autostart"]        = self.autostart_var.get()
        self.config["circuit_check"]    = self.circuit_check_var.get()
        try:
            self.config["circuit_min_kbs"]     = int(self.circuit_min_var.get())
            self.config["circuit_max_retries"] = int(self.circuit_retries_var.get())
        except ValueError:
            pass
        self.config["lan_iface"]    = self.lan_iface_var.get().strip()
        self.config["lan_gateway"]  = self.lan_gateway_var.get().strip()
        self.config["lan_subnet"]   = self.lan_subnet_var.get().strip()
        self.config["lan_dhcp"]     = self.lan_dhcp_var.get()
        self.config["lan_auto"]     = self.lan_auto_var.get()

    def _on_save(self):
        self._collect_config()
        self._save_config()
        self._set_autostart(self.autostart_var.get())
        self._save_lbl.config(text="Configuration sauvegardée.", fg=GREEN)
        self.root.after(4000, lambda: self._save_lbl.config(text=""))

    def _on_save_restart(self):
        self._collect_config()
        self._save_config()
        self._set_autostart(self.autostart_var.get())
        self._svc_restart()
        self._save_lbl.config(text="Sauvegardé — redémarrage en cours …", fg=YELLOW)
        self.root.after(3000, lambda: self._save_lbl.config(text=""))

    def _restore_config(self):
        self.dns_var.set(self.config.get("local_dns", ""))
        for d in self.config.get("excluded_domains", []):
            self.domain_list.insert(tk.END, d)
        for ip in self.config.get("excluded_ips", []):
            self.ip_list.insert(tk.END, ip)
        self.auto_reconnect_var.set(self.config.get("auto_reconnect", True))
        self.block_ipv6_var.set(self.config.get("block_ipv6", False))
        self.autostart_var.set(self.config.get("autostart", False))
        self.circuit_check_var.set(self.config.get("circuit_check", True))
        self.circuit_min_var.set(str(self.config.get("circuit_min_kbs", 250)))
        self.circuit_retries_var.set(str(self.config.get("circuit_max_retries", 3)))
        self.lan_iface_var.set(self.config.get("lan_iface", ""))
        self.lan_gateway_var.set(self.config.get("lan_gateway", "10.0.0.1"))
        self.lan_subnet_var.set(self.config.get("lan_subnet", "10.0.0.0/24"))
        self.lan_dhcp_var.set(self.config.get("lan_dhcp", True))
        self.lan_auto_var.set(self.config.get("lan_auto", False))
        self._refresh_providers_list()
        self._refresh_lan_interfaces()

    # ── Onglet Fournisseurs ───────────────────────────────────────────────────

    def _build_providers_tab(self, parent):
        paned = tk.PanedWindow(parent, orient=tk.HORIZONTAL, bg=GRAY,
                               sashwidth=4, sashrelief=tk.FLAT, borderwidth=0)
        paned.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(paned, bg=BG)
        paned.add(left, minsize=190, width=230)

        lf = ttk.LabelFrame(left, text="  Fournisseurs  ", padding=8)
        lf.pack(fill=tk.BOTH, expand=True)

        self.prov_listbox = tk.Listbox(
            lf, bg=BG2, fg=FG, selectbackground=ACCENT, selectforeground=BG,
            font=FONT, height=12, relief=tk.FLAT, borderwidth=0, exportselection=False)
        self.prov_listbox.pack(fill=tk.BOTH, expand=True)
        self.prov_listbox.bind("<<ListboxSelect>>", self._on_provider_select)

        btn_row = ttk.Frame(lf)
        btn_row.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btn_row, text="+ Ajouter",  command=self._add_provider).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="↑", width=3, command=self._move_prov_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="↓", width=3, command=self._move_prov_down).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="✕", width=3, command=self._del_provider).pack(side=tk.LEFT, padx=2)

        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=300)

        self._prov_name_lbl = tk.Label(right, text="— Sélectionnez un fournisseur —",
                                        fg=GRAY, bg=BG, font=("Segoe UI", 10, "italic"))
        self._prov_name_lbl.pack(anchor=tk.W, padx=8, pady=(6, 4))

        ovpn_frame = ttk.LabelFrame(right, text="  Fichier .ovpn  ", padding=8)
        ovpn_frame.pack(fill=tk.X, padx=4, pady=4)
        ovpn_row = ttk.Frame(ovpn_frame)
        ovpn_row.pack(fill=tk.X)
        self._prov_ovpn_lbl = tk.Label(ovpn_row, text="Aucun fichier sélectionné",
                                        fg=GRAY, bg=BG, font=FONT_MONO, anchor=tk.W)
        self._prov_ovpn_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ovpn_row, text="Choisir / Changer",
                   command=self._upload_ovpn).pack(side=tk.RIGHT, padx=(8, 0))

        acc_frame = ttk.LabelFrame(right, text="  Comptes  ", padding=8)
        acc_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._acc_listbox = tk.Listbox(
            acc_frame, bg=BG2, fg=FG, selectbackground=ACCENT, selectforeground=BG,
            font=FONT_MONO, height=6, relief=tk.FLAT, borderwidth=0, exportselection=False)
        self._acc_listbox.pack(fill=tk.BOTH, expand=True)
        acc_btn = ttk.Frame(acc_frame)
        acc_btn.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(acc_btn, text="+ Ajouter",   command=self._add_account).pack(side=tk.LEFT, padx=2)
        ttk.Button(acc_btn, text="↑", width=3,  command=self._move_acc_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(acc_btn, text="↓", width=3,  command=self._move_acc_down).pack(side=tk.LEFT, padx=2)
        ttk.Button(acc_btn, text="✕ Supprimer", command=self._del_account).pack(side=tk.LEFT, padx=2)

        tk.Label(right,
                 text="Priorité : premier = principal.  ↑↓ pour réordonner.\n"
                      "Failover automatique : compte suivant → fournisseur suivant.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W, padx=8, pady=(0, 4))

    def _get_sel_prov_idx(self) -> int:
        sel = self.prov_listbox.curselection()
        return sel[0] if sel else -1

    def _on_provider_select(self, _=None):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            self._prov_name_lbl.config(text="— Sélectionnez un fournisseur —", fg=GRAY)
            self._prov_ovpn_lbl.config(text="Aucun fichier sélectionné", fg=GRAY)
            self._acc_listbox.delete(0, tk.END)
            return
        p     = provs[idx]
        label = " ★ Principal" if idx == 0 else f" (priorité {idx+1})"
        self._prov_name_lbl.config(text=f"Fournisseur : {p['name']}{label}", fg=ACCENT)
        ovpn = p.get("ovpn_file", "")
        self._prov_ovpn_lbl.config(
            text=ovpn if ovpn else "Aucun fichier .ovpn",
            fg=FG if ovpn else YELLOW)
        self._acc_listbox.delete(0, tk.END)
        for acc in p.get("accounts", []):
            self._acc_listbox.insert(tk.END, f"  {_deobf(acc.get('u',''))}  ●●●●●●")

    def _refresh_providers_list(self):
        sel   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        self.prov_listbox.delete(0, tk.END)
        for i, p in enumerate(provs):
            prefix = "★ " if i == 0 else f"{i+1}. "
            self.prov_listbox.insert(tk.END, f"  {prefix}{p['name']}")
        if 0 <= sel < len(provs):
            self.prov_listbox.selection_set(sel)
        self._on_provider_select()

    def _add_provider(self):
        name = simpledialog.askstring("Nouveau fournisseur",
                                       "Nom du fournisseur :", parent=self.root)
        if not name:
            return
        name  = name.strip()
        # Le nom sert de dossier sous providers/ : pas de séparateur de chemin.
        if not name or name in (".", "..") or "/" in name or "\\" in name:
            messagebox.showerror("Erreur", "Nom invalide ( / et \\ interdits ).")
            return
        provs = self.config.get("providers", [])
        if any(p["name"].lower() == name.lower() for p in provs):
            messagebox.showerror("Erreur", f"'{name}' existe déjà.")
            return
        provs.append({"name": name, "ovpn_file": "", "accounts": []})
        self.config["providers"] = provs
        self._save_config()
        self._refresh_providers_list()
        self.prov_listbox.selection_set(len(provs) - 1)
        self._on_provider_select()

    def _del_provider(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            return
        name = provs[idx]["name"]
        if not messagebox.askyesno("Confirmation", f"Supprimer '{name}' et tous ses comptes ?"):
            return
        provs.pop(idx)
        self.config["providers"] = provs
        self._save_config()
        self._refresh_providers_list()

    def _move_prov_up(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx <= 0:
            return
        provs[idx-1], provs[idx] = provs[idx], provs[idx-1]
        self.config["providers"] = provs
        self._save_config()
        self._refresh_providers_list()
        self.prov_listbox.selection_set(idx-1)
        self._on_provider_select()

    def _move_prov_down(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs) - 1:
            return
        provs[idx], provs[idx+1] = provs[idx+1], provs[idx]
        self.config["providers"] = provs
        self._save_config()
        self._refresh_providers_list()
        self.prov_listbox.selection_set(idx+1)
        self._on_provider_select()

    def _upload_ovpn(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            messagebox.showwarning("Attention", "Sélectionnez d'abord un fournisseur.")
            return
        p   = provs[idx]
        src = filedialog.askopenfilename(
            title=f"Choisir le fichier .ovpn pour {p['name']}",
            filetypes=[("OpenVPN config", "*.ovpn *.conf"), ("All files", "*.*")])
        if not src:
            return
        dest_dir = PROVIDERS_DIR / p["name"]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(src).name
        try:
            shutil.copy2(src, dest)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de copier :\n{e}")
            return
        rel = str(dest.relative_to(SCRIPT_DIR))
        provs[idx]["ovpn_file"] = rel
        self.config["providers"] = provs
        self._save_config()
        self._prov_ovpn_lbl.config(text=rel, fg=FG)

    def _add_account(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            messagebox.showwarning("Attention", "Sélectionnez d'abord un fournisseur.")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Ajouter un compte")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.grab_set()

        ttk.Label(dlg, text="Identifiant :").grid(row=0, column=0, padx=10, pady=8, sticky=tk.W)
        u_var = tk.StringVar()
        ttk.Entry(dlg, textvariable=u_var, width=30).grid(row=0, column=1, padx=10, pady=8)

        ttk.Label(dlg, text="Mot de passe :").grid(row=1, column=0, padx=10, pady=4, sticky=tk.W)
        p_var   = tk.StringVar()
        p_entry = ttk.Entry(dlg, textvariable=p_var, show="●", width=30)
        p_entry.grid(row=1, column=1, padx=10, pady=4)
        show_var = tk.BooleanVar()
        ttk.Checkbutton(dlg, text="Afficher", variable=show_var,
                        command=lambda: p_entry.config(
                            show="" if show_var.get() else "●")
                        ).grid(row=1, column=2, padx=4)

        result = [False]
        def ok():
            result[0] = True
            dlg.destroy()
        btn_r = ttk.Frame(dlg)
        btn_r.grid(row=2, column=0, columnspan=3, pady=10)
        ttk.Button(btn_r, text="Ajouter",  command=ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_r, text="Annuler", command=dlg.destroy).pack(side=tk.LEFT, padx=6)
        dlg.bind("<Return>", lambda e: ok())
        dlg.wait_window()

        if not result[0] or not u_var.get().strip():
            return
        provs[idx].setdefault("accounts", []).append({
            "u": _obf(u_var.get().strip()),
            "p": _obf(p_var.get()),
        })
        self.config["providers"] = provs
        self._save_config()
        self._on_provider_select()

    def _del_account(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            return
        acc_sel = self._acc_listbox.curselection()
        if not acc_sel:
            return
        ai       = acc_sel[0]
        accounts = provs[idx].get("accounts", [])
        if ai >= len(accounts):
            return
        user = _deobf(accounts[ai].get("u", ""))
        if not messagebox.askyesno("Confirmation", f"Supprimer le compte '{user}' ?"):
            return
        accounts.pop(ai)
        provs[idx]["accounts"] = accounts
        self.config["providers"] = provs
        self._save_config()
        self._on_provider_select()

    def _move_acc_up(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            return
        acc_sel = self._acc_listbox.curselection()
        if not acc_sel:
            return
        ai       = acc_sel[0]
        accounts = provs[idx].get("accounts", [])
        if ai <= 0:
            return
        accounts[ai-1], accounts[ai] = accounts[ai], accounts[ai-1]
        provs[idx]["accounts"] = accounts
        self.config["providers"] = provs
        self._save_config()
        self._on_provider_select()
        self._acc_listbox.selection_set(ai-1)

    def _move_acc_down(self):
        idx   = self._get_sel_prov_idx()
        provs = self.config.get("providers", [])
        if idx < 0 or idx >= len(provs):
            return
        acc_sel = self._acc_listbox.curselection()
        if not acc_sel:
            return
        ai       = acc_sel[0]
        accounts = provs[idx].get("accounts", [])
        if ai >= len(accounts) - 1:
            return
        accounts[ai], accounts[ai+1] = accounts[ai+1], accounts[ai]
        provs[idx]["accounts"] = accounts
        self.config["providers"] = provs
        self._save_config()
        self._on_provider_select()
        self._acc_listbox.selection_set(ai+1)

    # ── Onglet Exclusions ─────────────────────────────────────────────────────

    def _build_exclusions_tab(self, parent):
        dns_frame = self._lf(parent, "DNS split — domaines locaux")
        cols_dns  = ttk.Frame(dns_frame)
        cols_dns.pack(fill=tk.X)

        row_dns = ttk.Frame(cols_dns)
        row_dns.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row_dns, text="Serveur DNS local :", width=20).pack(side=tk.LEFT)
        self.dns_var = tk.StringVar()
        ttk.Entry(row_dns, textvariable=self.dns_var, width=18,
                  font=FONT_MONO).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Label(row_dns, text="ex : 10.0.50.253", foreground=GRAY).pack(side=tk.LEFT)

        dom_frame = ttk.Frame(dns_frame)
        dom_frame.pack(fill=tk.X)
        ttk.Label(dom_frame, text="Domaines (ex : .derbo) :").pack(anchor=tk.W)
        dom_list_fr = ttk.Frame(dom_frame)
        dom_list_fr.pack(fill=tk.X, pady=(2, 0))
        self.domain_list = tk.Listbox(dom_list_fr, bg=BG2, fg=FG, selectbackground=ACCENT,
                                       selectforeground=BG, font=FONT_MONO, height=4,
                                       relief=tk.FLAT, borderwidth=0)
        self.domain_list.pack(side=tk.LEFT, fill=tk.X, expand=True)
        dom_sb = ttk.Frame(dom_list_fr)
        dom_sb.pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(dom_sb, text="+ Ajouter",   command=self._add_domain,  width=10).pack(pady=(0, 2))
        ttk.Button(dom_sb, text="- Supprimer", command=self._del_domain,  width=10).pack()
        dom_er = ttk.Frame(dom_frame)
        dom_er.pack(fill=tk.X, pady=(4, 0))
        self.domain_entry = ttk.Entry(dom_er, font=FONT_MONO)
        self.domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.domain_entry.bind("<Return>", lambda e: self._add_domain())

        tk.Label(dns_frame,
                 text="Important : le réseau du serveur DNS doit aussi figurer dans les IPs exclues ci-dessous.",
                 fg=YELLOW, bg=BG, font=("Segoe UI", 8)).pack(anchor=tk.W, pady=(4, 0))

        ip_frame = ttk.LabelFrame(parent, text="  IPs / Réseaux exclus du tunnel  ", padding=8)
        ip_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 4))
        self.ip_list = tk.Listbox(ip_frame, bg=BG2, fg=FG, selectbackground=ACCENT,
                                   selectforeground=BG, font=FONT_MONO, height=6,
                                   relief=tk.FLAT, borderwidth=0)
        self.ip_list.pack(fill=tk.BOTH, expand=True)
        ip_er = ttk.Frame(ip_frame)
        ip_er.pack(fill=tk.X, pady=(6, 0))
        self.ip_entry = ttk.Entry(ip_er, font=FONT_MONO)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.ip_entry.bind("<Return>", lambda e: self._add_ip())
        ip_br = ttk.Frame(ip_frame)
        ip_br.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(ip_br, text="+ Ajouter",   command=self._add_ip).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(ip_br, text="- Supprimer", command=self._del_ip).pack(side=tk.LEFT)
        tk.Label(parent,
                 text="Ces IPs/réseaux passent par la passerelle locale (--route net_gateway).",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(anchor=tk.W)

    def _add_ip(self):
        raw = self.ip_entry.get().strip()
        if not raw:
            return
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            messagebox.showerror("IP invalide", f"'{raw}' n'est pas une IP/CIDR valide.")
            return
        # L'exclusion repose sur « --route », une option IPv4 uniquement :
        # une entrée IPv6 serait acceptée ici puis ignorée par OpenVPN, en
        # laissant croire que le réseau est bien exclu du tunnel.
        if net.version != 4:
            messagebox.showerror(
                "IPv6 non supporté",
                f"'{raw}' est une adresse IPv6.\n\n"
                "L'exclusion du tunnel repose sur --route, qui ne gère que "
                "l'IPv4. Saisissez une adresse ou un réseau IPv4.")
            return
        entry = str(net)
        if entry not in self.ip_list.get(0, tk.END):
            self.ip_list.insert(tk.END, entry)
            self.ip_entry.delete(0, tk.END)
            self._persist_lists()

    def _del_ip(self):
        sel = self.ip_list.curselection()
        if sel:
            self.ip_list.delete(sel[0])
            self._persist_lists()

    def _add_domain(self):
        raw = self.domain_entry.get().strip()
        if not raw:
            return
        domain = ("." + raw.lstrip(".")).lower()
        if domain not in self.domain_list.get(0, tk.END):
            self.domain_list.insert(tk.END, domain)
            self.domain_entry.delete(0, tk.END)
            self._persist_lists()

    def _del_domain(self):
        sel = self.domain_list.curselection()
        if sel:
            self.domain_list.delete(sel[0])
            self._persist_lists()

    def _persist_lists(self):
        self.config["excluded_ips"]     = list(self.ip_list.get(0, tk.END))
        self.config["excluded_domains"] = list(self.domain_list.get(0, tk.END))
        self._save_config()

    # ── Onglet Paramètres ─────────────────────────────────────────────────────

    def _build_settings_tab(self, parent):
        sec_frame = self._lf(parent, "Sécurité")
        self.block_ipv6_var = tk.BooleanVar()
        ttk.Checkbutton(sec_frame, text="Bloquer IPv6 quand le VPN est actif",
                        variable=self.block_ipv6_var).pack(anchor=tk.W, pady=2)

        rec_frame = self._lf(parent, "Reconnexion")
        self.auto_reconnect_var = tk.BooleanVar()
        ttk.Checkbutton(rec_frame,
                        text="Reconnexion automatique si la connexion tombe",
                        variable=self.auto_reconnect_var).pack(anchor=tk.W, pady=2)

        cir_frame = self._lf(parent, "Qualité du circuit Tor")
        self.circuit_check_var = tk.BooleanVar()
        ttk.Checkbutton(
            cir_frame,
            text="Mesurer le débit à la connexion et re-tirer un circuit s'il est lent",
            variable=self.circuit_check_var).pack(anchor=tk.W, pady=2)

        row_c1 = self._row(cir_frame)
        ttk.Label(row_c1, text="Débit minimum :", width=22).pack(side=tk.LEFT)
        self.circuit_min_var = tk.StringVar(value="250")
        ttk.Spinbox(row_c1, from_=0, to=10000, increment=50, width=7,
                    textvariable=self.circuit_min_var).pack(side=tk.LEFT, padx=4)
        self._circuit_hint = tk.Label(row_c1, text="", fg=GRAY, bg=BG,
                                      font=("Segoe UI", 8))
        self._circuit_hint.pack(side=tk.LEFT, padx=4)
        self.circuit_min_var.trace_add(
            "write", lambda *_: self._update_circuit_hint())

        row_c2 = self._row(cir_frame)
        ttk.Label(row_c2, text="Essais maximum :", width=22).pack(side=tk.LEFT)
        self.circuit_retries_var = tk.StringVar(value="3")
        ttk.Spinbox(row_c2, from_=1, to=10, increment=1, width=7,
                    textvariable=self.circuit_retries_var).pack(side=tk.LEFT, padx=4)
        tk.Label(row_c2, text="avant de conserver le circuit tel quel",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        tk.Label(cir_frame,
                 text="Le circuit Tor est tiré au sort à chaque connexion. Une mesure\n"
                      "unique (2 Mo) juste après l'établissement du tunnel permet de\n"
                      "re-tirer immédiatement un mauvais circuit. Aucune surveillance\n"
                      "continue : ce test ne tourne pas en tâche de fond.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W, pady=(4, 0))

        sys_frame = self._lf(parent, "Système")
        self.autostart_var = tk.BooleanVar()
        ttk.Checkbutton(sys_frame, text="Lancer le service automatiquement au démarrage",
                        variable=self.autostart_var).pack(anchor=tk.W, pady=2)
        tk.Label(sys_frame,
                 text="Active/désactive systemctl enable tor-vpn-manager.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(anchor=tk.W)

        rep_frame = self._lf(parent, "Reparation réseau")
        tk.Label(rep_frame,
                 text="Nettoie les règles iptables, les routes et DNS bloqués,\n"
                      "puis arrête le service pour une relance propre.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W, pady=(0, 6))
        ttk.Button(rep_frame, text="Réparer le réseau",
                   command=self._run_repair).pack(anchor=tk.W)

        self._build_export_import(parent)

    def _update_circuit_hint(self):
        """Affiche l'équivalent en Mbps du seuil : les speed tests parlent en
        mégabits, les débits de téléchargement en kilo-octets (1 o = 8 bits)."""
        try:
            kbs = int(self.circuit_min_var.get())
            self._circuit_hint.config(
                text=f"KB/s   (≈ {kbs * 8 / 1000:.1f} Mbps sur un speed test)")
        except (ValueError, AttributeError):
            self._circuit_hint.config(text="KB/s")

    def _run_repair(self):
        if not messagebox.askyesno(
                "Réparer le réseau",
                "Cela va arrêter le service et nettoyer toutes les règles réseau.\n"
                "Continuer ?"):
            return
        script = SCRIPT_DIR / "repair_network.sh"
        if not script.exists():
            messagebox.showerror("Introuvable", f"{script} introuvable.")
            return
        try:
            # Le script exige root : pkexec quand le GUI tourne en non-root.
            cmd = ["bash", str(script)]
            if os.geteuid() != 0:
                cmd = ["pkexec"] + cmd
            subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            messagebox.showinfo(
                "Réparation lancée",
                "repair_network.sh lancé.\n"
                "Attendez quelques secondes puis redémarrez le service.")
            self.root.after(3000, self._refresh_status)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _build_export_import(self, parent):
        frame = self._lf(parent, "Export / Import de configuration")
        tk.Label(frame,
                 text="Exporte fournisseurs, comptes et fichiers .ovpn dans un .tvpn.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W, pady=(0, 6))
        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="⬆  Exporter",
                   command=self._export_config).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="⬇  Importer",
                   command=self._import_config).pack(side=tk.LEFT)
        tk.Label(frame,
                 text="⚠ Les identifiants sont stockés en base64 dans le fichier .tvpn.",
                 fg=YELLOW, bg=BG, font=("Segoe UI", 8)
                 ).pack(anchor=tk.W, pady=(6, 0))

    def _export_config(self):
        import zipfile
        path = filedialog.asksaveasfilename(
            title="Exporter la configuration",
            defaultextension=".tvpn",
            filetypes=[("Tor-VPN config", "*.tvpn"), ("Tous les fichiers", "*.*")],
            initialfile="tor-vpn-config.tvpn")
        if not path:
            return
        try:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("config.json", json.dumps(self.config, indent=2))
                for p in self.config.get("providers", []):
                    ovpn = p.get("ovpn_file", "")
                    if not ovpn:
                        continue
                    ovpn_path = Path(ovpn)
                    if not ovpn_path.is_absolute():
                        ovpn_path = SCRIPT_DIR / ovpn_path
                    if ovpn_path.exists():
                        zf.write(str(ovpn_path), f"providers/{p['name']}/{ovpn_path.name}")
            messagebox.showinfo("Export réussi", f"Exporté :\n{path}")
        except Exception as e:
            messagebox.showerror("Erreur export", str(e))

    def _import_config(self):
        import zipfile
        path = filedialog.askopenfilename(
            title="Importer une configuration",
            filetypes=[("Tor-VPN config", "*.tvpn"), ("Tous les fichiers", "*.*")])
        if not path:
            return
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if "config.json" not in zf.namelist():
                    messagebox.showerror("Erreur", "Fichier .tvpn invalide.")
                    return
                if not messagebox.askyesno("Importer",
                        "Remplacer la configuration actuelle ?"):
                    return
                new_cfg = json.loads(zf.read("config.json").decode())
                def _safe_component(c: str) -> bool:
                    # Anti path-traversal : composant de chemin simple uniquement.
                    return bool(c) and c not in (".", "..") \
                        and "/" not in c and "\\" not in c \
                        and not c.startswith(".")

                for name in zf.namelist():
                    if name.startswith("providers/") and name.endswith(".ovpn"):
                        parts = name.split("/")
                        if len(parts) == 3 and all(map(_safe_component, parts[1:])):
                            dest_dir = PROVIDERS_DIR / parts[1]
                            dest_dir.mkdir(parents=True, exist_ok=True)
                            (dest_dir / parts[2]).write_bytes(zf.read(name))
                self.config = {**copy.deepcopy(DEFAULT_CONFIG), **new_cfg}
                self._save_config()
                self.ip_list.delete(0, tk.END)
                self.domain_list.delete(0, tk.END)
                self._restore_config()
                messagebox.showinfo("Import réussi", "Configuration importée.")
        except Exception as e:
            messagebox.showerror("Erreur import", str(e))

    # ── Onglet Partage LAN ────────────────────────────────────────────────────

    def _build_lan_tab(self, parent):
        frame = self._lf(parent, "Configuration — 2ème carte réseau")
        tk.Label(frame,
                 text="Branchez un appareil sur la 2ème carte : il recevra une IP DHCP\n"
                      "et son trafic passera par le tunnel Tor+VPN.\n"
                      "Configuration sauvegardée → appliquée au prochain démarrage du service.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W, pady=(0, 6))

        row1 = self._row(frame)
        ttk.Label(row1, text="Interface :", width=22).pack(side=tk.LEFT)
        self.lan_iface_var    = tk.StringVar()
        self._lan_iface_combo = ttk.Combobox(
            row1, textvariable=self.lan_iface_var, width=16, state="readonly")
        self._lan_iface_combo.pack(side=tk.LEFT, padx=4)
        ttk.Button(row1, text="⟳", width=3,
                   command=self._refresh_lan_interfaces).pack(side=tk.LEFT, padx=2)

        row2 = self._row(frame)
        ttk.Label(row2, text="IP de la 2ème carte :", width=22).pack(side=tk.LEFT)
        self.lan_gateway_var = tk.StringVar(value="10.0.0.1")
        ttk.Entry(row2, textvariable=self.lan_gateway_var, width=16).pack(side=tk.LEFT, padx=4)
        tk.Label(row2, text="(passerelle par défaut des appareils)",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        row3 = self._row(frame)
        ttk.Label(row3, text="Sous-réseau CIDR :", width=22).pack(side=tk.LEFT)
        self.lan_subnet_var = tk.StringVar(value="10.0.0.0/24")
        ttk.Entry(row3, textvariable=self.lan_subnet_var, width=16).pack(side=tk.LEFT, padx=4)
        tk.Label(row3, text="ex: 10.0.0.0/24",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        row4 = self._row(frame)
        self.lan_dhcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row4,
                        text="Serveur DHCP automatique (dnsmasq)",
                        variable=self.lan_dhcp_var).pack(side=tk.LEFT)

        # Interrupteur principal, et non une simple option de démarrage : le
        # daemon n'active le partage que par ce réglage (il n'existe aucune
        # activation manuelle).  Le libellé doit le dire, sous peine de
        # laisser croire qu'une autre case reste à cocher quelque part.
        row5 = self._row(frame)
        self.lan_auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row5,
                        text="Activer le partage LAN sur cette interface",
                        variable=self.lan_auto_var).pack(side=tk.LEFT)
        tk.Label(row5, text="(prise en compte au démarrage du service)",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        help_frame = self._lf(parent, "Aide")
        tk.Label(help_frame,
                 text="Prérequis : sudo apt install dnsmasq\n\n"
                      "• L'IP configurée est assignée à la 2ème carte\n"
                      "• dnsmasq distribue des IPs DHCP dans le sous-réseau\n"
                      "• Le trafic LAN est forcé dans le tunnel Tor+VPN\n"
                      "• Si le tunnel tombe, le trafic LAN est bloqué (pas de contournement)",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8), justify=tk.LEFT
                 ).pack(anchor=tk.W)

    def _uplink_iface(self) -> str:
        """Interface portant la route par défaut (uplink Internet) — à ne
        jamais proposer comme carte LAN, sinon on coupe l'accès réseau."""
        try:
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True)
            for line in r.stdout.splitlines():
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return ""

    def _refresh_lan_interfaces(self):
        uplink = self._uplink_iface()
        try:
            ifaces = [i for i in sorted(os.listdir("/sys/class/net"))
                      if i != "lo" and i != uplink and
                      not i.startswith(("tun", "virbr", "docker", "wg", "veth", "br-"))]
        except Exception:
            ifaces = []
        self._lan_iface_combo["values"] = ifaces
        cur = self.lan_iface_var.get()
        if ifaces and (not cur or cur not in ifaces):
            self.lan_iface_var.set(ifaces[0])

    # ── Autostart ─────────────────────────────────────────────────────────────

    def _set_autostart(self, enabled: bool):
        # is-enabled est une lecture sans privilège : on ne déclenche
        # enable/disable (pkexec en non-root) que si l'état doit changer.
        cur = self._systemctl("is-enabled", SERVICE_NAME).stdout.strip() == "enabled"
        if cur == enabled:
            return
        self._systemctl("enable" if enabled else "disable", SERVICE_NAME)

    # ── Onglet Tor (torrc) ────────────────────────────────────────────────────

    # Valeurs par défaut du torrc (circuits longs et stables, adaptées à un
    # tunnel OpenVPN persistant).  Chaque option reste ajustable via les
    # widgets ci-dessous ou le mode expert.
    _TOR_DEFAULTS = {
        "avoid_disk":     True,  "safe_logging":   True,
        "no_ipv6":        True,  "test_socks":     True,
        "conn_padding":   False, "long_lived":     True,
        "learn_timeout":  True,  "max_dirty":      3600,
        "build_timeout":  60,    "new_circuit":    60,
        "keepalive":      60,    "num_guards":     3,
        "guard_lifetime": "2 months",
        "exclude_exits":  "",    "strict_nodes":   False,
    }

    _TORRC_MANDATORY = (
        "# === Paramètres obligatoires — ne pas supprimer ===\n"
        "SocksPort 9050\n"
        "ControlPort 9051\n"
        "CookieAuthentication 1\n"
        "DataDirectory /etc/tor-vpn-manager/tor_data\n"
    )

    def _build_tor_tab(self, parent):
        # Zone scrollable commune (options + expert + actions)
        opts_frame = self._scrollable(parent)

        # ── Circuit ────────────────────────────────────────────────────────
        circ = ttk.LabelFrame(opts_frame, text="  Circuit  ", padding=8)
        circ.pack(fill=tk.X, pady=4)

        self._tor_long_lived_var   = tk.BooleanVar()
        self._tor_learn_timeout_var = tk.BooleanVar()
        for var, text in [
            (self._tor_long_lived_var,    "LongLivedPorts 1194,443 — préfère des relais stables pour OpenVPN"),
            (self._tor_learn_timeout_var, "LearnCircuitBuildTimeout 0 — timeout fixe (plus prévisible)"),
        ]:
            ttk.Checkbutton(circ, text=text, variable=var,
                            command=self._update_torrc_preview).pack(anchor=tk.W, pady=1)

        def _spin_row(parent, label, attr, from_, to_, step, unit=""):
            r = ttk.Frame(parent)
            r.pack(fill=tk.X, pady=2)
            ttk.Label(r, text=label, width=26).pack(side=tk.LEFT)
            var = tk.StringVar()
            setattr(self, attr, var)
            sb = ttk.Spinbox(r, from_=from_, to=to_, increment=step, width=7,
                             textvariable=var, command=self._update_torrc_preview)
            sb.pack(side=tk.LEFT, padx=4)
            if unit:
                tk.Label(r, text=unit, fg=GRAY, bg=BG,
                         font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=2)
            var.trace_add("write", lambda *_: self._update_torrc_preview())

        _spin_row(circ, "MaxCircuitDirtiness :", "_tor_max_dirty_var",
                  0, 7200, 60,  "s   (0 = défaut Tor)")
        _spin_row(circ, "CircuitBuildTimeout :", "_tor_build_timeout_var",
                  0,  300,  5,  "s   (0 = désactivé)")
        _spin_row(circ, "NewCircuitPeriod :",    "_tor_new_circuit_var",
                  0,  600, 10,  "s   (0 = défaut Tor)")
        _spin_row(circ, "KeepalivePeriod :",     "_tor_keepalive_var",
                  0,  300, 10,  "s   (0 = désactivé)")
        _spin_row(circ, "NumEntryGuards :",      "_tor_num_guards_var",
                  0,   10,  1,  "   (0 = défaut Tor)")

        r_gl = ttk.Frame(circ)
        r_gl.pack(fill=tk.X, pady=2)
        ttk.Label(r_gl, text="GuardLifetime :", width=26).pack(side=tk.LEFT)
        self._tor_guard_lifetime_var = tk.StringVar()
        gl_combo = ttk.Combobox(r_gl, textvariable=self._tor_guard_lifetime_var,
                                width=12, state="readonly",
                                values=["", "1 months", "2 months", "3 months", "6 months"])
        gl_combo.pack(side=tk.LEFT, padx=4)
        tk.Label(r_gl, text="(vide = défaut Tor)", fg=GRAY, bg=BG,
                 font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)
        self._tor_guard_lifetime_var.trace_add("write", lambda *_: self._update_torrc_preview())

        # ── Confidentialité ────────────────────────────────────────────────
        priv = ttk.LabelFrame(opts_frame, text="  Confidentialité  ", padding=8)
        priv.pack(fill=tk.X, pady=4)
        self._tor_avoid_disk_var   = tk.BooleanVar()
        self._tor_safe_logging_var = tk.BooleanVar()
        self._tor_no_ipv6_var      = tk.BooleanVar()
        self._tor_test_socks_var   = tk.BooleanVar()
        self._tor_conn_padding_var = tk.BooleanVar()
        for var, text in [
            (self._tor_avoid_disk_var,   "AvoidDiskWrites 1 — limite les écritures disque"),
            (self._tor_safe_logging_var, "SafeLogging 1 — masque les IPs dans les logs Tor"),
            (self._tor_no_ipv6_var,      "ClientUseIPv6 0 — désactive IPv6 pour Tor"),
            (self._tor_test_socks_var,   "TestSocks 1 — avertit si une requête DNS locale est détectée"),
            (self._tor_conn_padding_var, "ConnectionPadding 1 — résistance à l'analyse de trafic (↑ bande passante)"),
        ]:
            ttk.Checkbutton(priv, text=text, variable=var,
                            command=self._update_torrc_preview).pack(anchor=tk.W, pady=1)

        # ── Nœuds exclus ──────────────────────────────────────────────────
        excl = ttk.LabelFrame(opts_frame, text="  Nœuds de sortie exclus  ", padding=8)
        excl.pack(fill=tk.X, pady=4)
        tk.Label(excl,
                 text="Format ISO 3166-1 : {us},{gb},{ca}  —  laisser vide pour désactiver.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(anchor=tk.W)
        r_ex = ttk.Frame(excl)
        r_ex.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(r_ex, text="ExcludeExitNodes :", width=20).pack(side=tk.LEFT)
        self._tor_exclude_var = tk.StringVar()
        ttk.Entry(r_ex, textvariable=self._tor_exclude_var,
                  width=32, font=FONT_MONO).pack(side=tk.LEFT, padx=4)
        self._tor_exclude_var.trace_add("write", lambda *_: self._update_torrc_preview())
        self._tor_strict_var = tk.BooleanVar()
        ttk.Checkbutton(excl,
                        text="StrictNodes 1 — strict (peut couper si aucun nœud disponible)",
                        variable=self._tor_strict_var,
                        command=self._update_torrc_preview).pack(anchor=tk.W, pady=(4, 0))

        # ── Mode expert ────────────────────────────────────────────────────
        exp = ttk.LabelFrame(opts_frame, text="  Mode expert — torrc complet  ", padding=8)
        exp.pack(fill=tk.X, pady=4)
        tk.Label(exp,
                 text="Édition directe. Les paramètres obligatoires sont toujours préservés à l'application.",
                 fg=GRAY, bg=BG, font=("Segoe UI", 8)).pack(anchor=tk.W)
        self._torrc_text = scrolledtext.ScrolledText(
            exp, font=FONT_MONO, bg=BG2, fg=FG, insertbackground=FG,
            height=10, wrap=tk.NONE, relief=tk.FLAT, borderwidth=1)
        self._torrc_text.pack(fill=tk.X, pady=(4, 0))

        # ── Actions ────────────────────────────────────────────────────────
        act = ttk.LabelFrame(opts_frame, text="  Actions  ", padding=8)
        act.pack(fill=tk.X, pady=4)
        btn_r = ttk.Frame(act)
        btn_r.pack(fill=tk.X)
        ttk.Button(btn_r, text="▶  Appliquer + Redémarrer le service",
                   command=self._apply_torrc).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_r, text="↺  Réinitialiser (config minimale)",
                   command=self._reset_torrc).pack(side=tk.LEFT)
        self._tor_status_lbl = tk.Label(act, text="", bg=BG, fg=GRAY, font=FONT)
        self._tor_status_lbl.pack(anchor=tk.W, pady=(6, 0))

        # ── Init ───────────────────────────────────────────────────────────
        self._set_tor_defaults()
        if TORRC_FILE.exists():
            self._load_torrc_file()

    def _set_tor_defaults(self):
        prof = self._TOR_DEFAULTS
        self._tor_avoid_disk_var.set(prof["avoid_disk"])
        self._tor_safe_logging_var.set(prof["safe_logging"])
        self._tor_no_ipv6_var.set(prof["no_ipv6"])
        self._tor_test_socks_var.set(prof["test_socks"])
        self._tor_conn_padding_var.set(prof["conn_padding"])
        self._tor_long_lived_var.set(prof["long_lived"])
        self._tor_learn_timeout_var.set(prof["learn_timeout"])
        self._tor_max_dirty_var.set(str(prof["max_dirty"]))
        self._tor_build_timeout_var.set(str(prof["build_timeout"]))
        self._tor_new_circuit_var.set(str(prof["new_circuit"]))
        self._tor_keepalive_var.set(str(prof["keepalive"]))
        self._tor_num_guards_var.set(str(prof["num_guards"]))
        self._tor_guard_lifetime_var.set(prof["guard_lifetime"])
        self._tor_exclude_var.set(prof["exclude_exits"])
        self._tor_strict_var.set(prof["strict_nodes"])
        self._update_torrc_preview()

    def _update_torrc_preview(self):
        if not hasattr(self, "_torrc_text"):
            return
        self._torrc_text.delete("1.0", tk.END)
        self._torrc_text.insert("1.0", self._build_torrc_from_widgets())

    def _build_torrc_from_widgets(self) -> str:
        lines = [self._TORRC_MANDATORY.rstrip(), "", "# === Paramètres personnalisés ==="]

        if self._tor_avoid_disk_var.get():
            lines.append("AvoidDiskWrites 1")
        if self._tor_safe_logging_var.get():
            lines.append("SafeLogging 1")
        if self._tor_no_ipv6_var.get():
            lines.append("ClientUseIPv6 0")
        if self._tor_test_socks_var.get():
            lines.append("TestSocks 1")
        if self._tor_conn_padding_var.get():
            lines.append("ConnectionPadding 1")
        if self._tor_long_lived_var.get():
            lines.append("LongLivedPorts 1194,443")
        if self._tor_learn_timeout_var.get():
            lines.append("LearnCircuitBuildTimeout 0")

        for attr, key in [
            ("_tor_max_dirty_var",      "MaxCircuitDirtiness"),
            ("_tor_build_timeout_var",  "CircuitBuildTimeout"),
            ("_tor_new_circuit_var",    "NewCircuitPeriod"),
            ("_tor_keepalive_var",      "KeepalivePeriod"),
            ("_tor_num_guards_var",     "NumEntryGuards"),
        ]:
            try:
                v = int(getattr(self, attr).get())
                if v > 0:
                    lines.append(f"{key} {v}")
            except (ValueError, AttributeError):
                pass

        gl = self._tor_guard_lifetime_var.get().strip()
        if gl:
            lines.append(f"GuardLifetime {gl}")

        excl = self._tor_exclude_var.get().strip()
        if excl:
            lines.append(f"ExcludeExitNodes {excl}")
            lines.append(f"StrictNodes {'1' if self._tor_strict_var.get() else '0'}")

        return "\n".join(lines) + "\n"

    def _load_torrc_file(self):
        try:
            content = TORRC_FILE.read_text()
            self._torrc_text.delete("1.0", tk.END)
            self._torrc_text.insert("1.0", content)
        except Exception:
            pass

    def _apply_torrc(self):
        content = self._torrc_text.get("1.0", tk.END).strip() + "\n"
        # Garantit les paramètres obligatoires, clé par clé : on n'ajoute que
        # les lignes réellement manquantes (préfixer tout le bloc dupliquerait
        # SocksPort/ControlPort → conflit de bind, Tor refuserait de démarrer).
        # Les lignes commentées sont ignorées ; comparaison insensible à la
        # casse (les clés torrc le sont pour Tor).
        present = {
            ln.strip().split()[0].lower()
            for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        }
        missing = [
            ln for ln in self._TORRC_MANDATORY.splitlines()
            if ln.strip() and not ln.startswith("#")
            and ln.split()[0].lower() not in present
        ]
        if missing:
            content = ("# === Paramètres obligatoires (réinjectés) ===\n"
                       + "\n".join(missing) + "\n\n" + content)
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            TORRC_FILE.write_text(content)
            try:
                TORRC_FILE.chmod(0o660)
            except PermissionError:
                pass
            self._tor_status_lbl.config(
                text="torrc sauvegardé — redémarrage du service …", fg=YELLOW)
            self._svc_restart()
            self.root.after(3500, lambda: self._tor_status_lbl.config(
                text="✓ Appliqué.", fg=GREEN))
            self.root.after(7000, lambda: self._tor_status_lbl.config(text=""))
        except PermissionError:
            self._tor_status_lbl.config(
                text="Erreur : droits insuffisants — relancez install.sh "
                     "(groupe torvpn) puis reconnectez votre session.", fg=RED)
        except Exception as e:
            self._tor_status_lbl.config(text=f"Erreur : {e}", fg=RED)

    def _reset_torrc(self):
        if not messagebox.askyesno(
                "Réinitialiser",
                "Supprimer le torrc personnalisé et redémarrer avec la configuration minimale ?"):
            return
        try:
            TORRC_FILE.unlink(missing_ok=True)
            self._set_tor_defaults()
            self._tor_status_lbl.config(
                text="torrc supprimé — redémarrage avec config minimale …", fg=YELLOW)
            self._svc_restart()
            self.root.after(3500, lambda: self._tor_status_lbl.config(
                text="✓ Réinitialisé.", fg=GREEN))
            self.root.after(7000, lambda: self._tor_status_lbl.config(text=""))
        except PermissionError:
            self._tor_status_lbl.config(
                text="Erreur : droits insuffisants — relancez install.sh "
                     "(groupe torvpn) puis reconnectez votre session.", fg=RED)
        except Exception as e:
            self._tor_status_lbl.config(text=f"Erreur : {e}", fg=RED)

    # ── Fermeture ─────────────────────────────────────────────────────────────

    def _on_close(self):
        self.root.destroy()
