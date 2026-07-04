"""
DNS : split DNS via systemd-resolved drop-in.
"""

import subprocess

from .core import RESOLVED_DROP_IN


class DNSMixin:

    def _apply_dns_split(self):
        dns     = self.config.get("local_dns", "").strip()
        domains = self.config.get("excluded_domains", [])
        if not dns or not domains:
            self._remove_dns_split()
            return
        domain_str = " ".join(f"~{d.lstrip('.')}" for d in domains)
        try:
            RESOLVED_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
            RESOLVED_DROP_IN.write_text(f"[Resolve]\nDNS={dns}\nDomains={domain_str}\n")
            r = subprocess.run(["resolvectl", "reload"], capture_output=True, timeout=10)
            if r.returncode != 0:
                subprocess.run(["systemctl", "reload", "systemd-resolved"],
                               capture_output=True, timeout=10)
            self._log(f"DNS split actif : {len(domains)} domaine(s) → {dns}", "OK")
        except Exception as e:
            self._log(f"DNS split : {e}", "WARN")

    def _remove_dns_split(self):
        if RESOLVED_DROP_IN.exists():
            try:
                RESOLVED_DROP_IN.unlink()
                r = subprocess.run(["resolvectl", "reload"],
                                   capture_output=True, timeout=10)
                if r.returncode != 0:
                    subprocess.run(["systemctl", "reload", "systemd-resolved"],
                                   capture_output=True, timeout=10)
                self._log("DNS split désactivé.", "OK")
            except Exception:
                pass
