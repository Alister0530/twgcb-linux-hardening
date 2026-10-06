# -*- coding: utf-8 -*-
"""讀取 config.ini。"""
import configparser
import os

from .util import split_csv

DEFAULTS = {
    "test_user": "",
    "critical_services": "",
    "exclude_rules": "",
    "manual_login_confirm": "yes",
    "auto_rollback": "yes",
    "dns_test_name": "",
    "report_dir": "reports",
    "package_timeout": "300",
    "firewall_backend": "auto",
}


class Config(object):
    def __init__(self, path, base_dir):
        cp = configparser.ConfigParser()
        cp["general"] = DEFAULTS
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                cp.read_string(f.read().decode("utf-8"))
        g = cp["general"]
        self.path = path
        self.test_user = g.get("test_user", "").strip()
        self.critical_services = split_csv(g.get("critical_services"))
        self.exclude_rules = split_csv(g.get("exclude_rules"))
        self.manual_login_confirm = g.getboolean("manual_login_confirm")
        self.auto_rollback = g.getboolean("auto_rollback")
        self.dns_test_name = g.get("dns_test_name", "").strip()
        rd = g.get("report_dir", "reports").strip() or "reports"
        self.report_dir = rd if os.path.isabs(rd) else os.path.join(base_dir, rd)
        self.package_timeout = g.getint("package_timeout")
        # auto / firewalld / nftables / iptables / ufw：多選一的防火牆規則依此判斷適用哪一套
        self.firewall_backend = (g.get("firewall_backend", "auto").strip() or "auto").lower()
