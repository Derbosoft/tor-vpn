#!/usr/bin/env python3
"""
Tor-VPN Manager GUI
Usage : python3 main.py   (ou : tor-vpn gui)

Le GUI ne requiert plus les droits root : la configuration est accessible
via le groupe « torvpn » (créé par install.sh) et les actions systemctl
privilégiées passent par pkexec/polkit.
"""

import os
import sys
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from constants import CONFIG_DIR

if os.geteuid() != 0 and CONFIG_DIR.exists() and not os.access(CONFIG_DIR, os.W_OK):
    msg = (f"Pas d'accès en écriture à {CONFIG_DIR}.\n\n"
           "Relancez « sudo bash install.sh » (création du groupe torvpn), "
           "puis déconnectez/reconnectez votre session pour que le groupe "
           "prenne effet.\n\n"
           "Vous pouvez aussi lancer :  sudo python3 main.py")
    print(f"Avertissement : {msg}")
    # Lancé depuis le menu applications, stdout est invisible : on double
    # l'avertissement d'une boîte de dialogue.
    try:
        from tkinter import messagebox
        _tmp = tk.Tk()
        _tmp.withdraw()
        messagebox.showwarning("Tor-VPN Manager — droits insuffisants", msg)
        _tmp.destroy()
    except Exception:
        pass

from gui.app import ConfigApp

root = tk.Tk()
app  = ConfigApp(root)
root.mainloop()
