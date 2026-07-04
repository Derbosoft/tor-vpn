#!/usr/bin/env python3
"""
Tor-VPN Manager GUI
Usage : sudo python3 main.py
"""

import os
import sys
import tkinter as tk

if os.geteuid() != 0:
    print("Ce programme doit être lancé en root.")
    print("  sudo python3 main.py")
    sys.exit(1)

from gui.app import ConfigApp

root = tk.Tk()
app  = ConfigApp(root)
root.mainloop()
