# -*- coding: utf-8 -*-
"""RHEL selinux.py（SELinux、cron、防火牆）的單元測試：只測解析與判斷，不修改系統。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import pkgsvc  # noqa: E402
from gcb.rules.rhel import selinux as s  # noqa: E402

RULESET = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\tiif "lo" accept
\t\tip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
\t\tip6 saddr ::1 counter packets 3 bytes 120 drop
\t\ttcp dport { 22, 2222 } accept
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t}
}
table inet firewalld {
\tchain filter_INPUT {
\t\ttype filter hook input priority filter + 10; policy accept;
\t\treject with icmpx admin-prohibited
\t}
}
"""

IPT_NFT = """# Warning: table ip filter is managed by iptables-nft, do not touch!
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t}
}
"""


class Grub(unittest.TestCase):
    def test_default_grub(self):
        t = 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="crashkernel=auto selinux=0 rhgb"\n' \
            'GRUB_CMDLINE_LINUX_DEFAULT="quiet enforcing=0"\n#GRUB_CMDLINE_LINUX="selinux=0"\n'
        self.assertEqual(s.grub_default_bad_args(t), ["selinux=0", "enforcing=0"])
        out = s.grub_default_remove_args(t)
        self.assertIn('GRUB_CMDLINE_LINUX="crashkernel=auto rhgb"', out)
        self.assertIn('GRUB_CMDLINE_LINUX_DEFAULT="quiet"', out)
        self.assertIn('#GRUB_CMDLINE_LINUX="selinux=0"', out)  # 註解行不動
        self.assertEqual(s.grub_default_bad_args(out), [])

    def test_grubby(self):
        info = ('index=0\nkernel="/boot/vmlinuz-5.14"\nargs="ro selinux=0 quiet"\n'
                'index=1\nkernel="/boot/vmlinuz-rescue"\nargs="ro quiet"\n')
        self.assertEqual(s.grubby_bad_entries(info), [("/boot/vmlinuz-5.14", ["selinux=0"])])
        self.assertEqual(s.grubenv_kernelopts("saved_entry=x\nkernelopts=root=/dev/sda ro enforcing=0\n"),
                         "root=/dev/sda ro enforcing=0")


class Rsyslog(unittest.TestCase):
    def test_cron_line(self):
        self.assertTrue(s.rsyslog_cron_lines("cron.*                                  /var/log/cron\n"))
        self.assertTrue(s.rsyslog_cron_lines("cron.*  -/var/log/cron\n"))
        self.assertTrue(s.rsyslog_cron_lines("authpriv.*;cron.* /var/log/cron\n"))
        self.assertFalse(s.rsyslog_cron_lines("*.info;mail.none;cron.none /var/log/messages\n"))
        self.assertFalse(s.rsyslog_cron_lines("#cron.* /var/log/cron\n"))
        self.assertFalse(s.rsyslog_cron_lines("cron.info /var/log/cron\n"))


class Nft(unittest.TestCase):
    def test_parse(self):
        chains = s.nft_parse(RULESET)
        self.assertEqual(s.nft_hooks(chains), {"input", "forward", "output"})
        self.assertTrue(s.nft_loopback_ok(chains))
        self.assertEqual(s.nft_policies(chains), {"input": True, "forward": False, "output": False})
        self.assertEqual(s.nft_tables(RULESET), [("inet", "filter"), ("inet", "firewalld")])
        # firewalld 的表不檢查；SSH 22、2222 皆放行
        self.assertEqual(s.nft_ssh_problems(chains, ["22", "2222"]), [])
        self.assertEqual(len(s.nft_ssh_problems(chains, ["22", "2200"])), 1)

    def test_ssh_problems_blocking(self):
        t = "table inet t {\n chain i {\n  type filter hook input priority 0; policy drop;\n }\n}\n"
        probs = s.nft_ssh_problems(s.nft_parse(t), ["22"])
        self.assertEqual(len(probs), 3)
        t2 = "table inet t {\n chain i {\n  type filter hook input priority 0; policy accept;\n }\n}\n"
        self.assertEqual(s.nft_ssh_problems(s.nft_parse(t2), ["22"]), [])

    def test_service_name_port(self):
        t = ("table inet t {\n chain i {\n  type filter hook input priority 0; policy drop;\n"
             "  ct state established,related accept\n  iif lo accept\n  tcp dport ssh accept\n }\n}\n")
        self.assertEqual(s.nft_ssh_problems(s.nft_parse(t), ["22"]), [])

    def test_loopback_order(self):
        t = ("table inet filter {\n chain input {\n  type filter hook input priority 0;\n"
             "  ip saddr 127.0.0.0/8 counter drop\n  ip6 saddr ::1 counter drop\n  iif lo accept\n }\n}\n")
        self.assertFalse(s.nft_loopback_ok(s.nft_parse(t)))

    def test_command_format(self):
        t = ("add table inet filter\n"
             "add chain inet filter input { type filter hook input priority 0 ; policy drop ; }\n"
             "add rule inet filter input iif lo accept\n"
             "add rule inet filter input ip saddr 127.0.0.0/8 counter drop\n"
             "add rule inet filter input ip6 saddr ::1 counter drop\n")
        chains = s.nft_parse(t)
        self.assertTrue(s.nft_loopback_ok(chains))
        self.assertEqual(s.nft_policies(chains), {"input": True})

    def test_ip_ip6_hooks(self):
        t = ("table ip a {\n chain o {\n  type filter hook output priority 0;\n }\n}\n"
             "table ip6 b {\n chain o {\n  type filter hook output priority 0;\n }\n}\n"
             "table ip c {\n chain f {\n  type filter hook forward priority 0;\n }\n}\n")
        self.assertEqual(s.nft_hooks(s.nft_parse(t)), {"output"})

    def test_render_roundtrip(self):
        text = s.nft_render({"loopback", "input_drop", "forward_drop"}, ["22", "2222"])
        chains = s.nft_parse(text)
        self.assertEqual(s.nft_hooks(chains), {"input", "forward", "output"})
        self.assertTrue(s.nft_loopback_ok(chains))
        self.assertEqual(s.nft_policies(chains), {"input": True, "forward": True, "output": False})
        self.assertEqual(s.nft_ssh_problems(chains, ["22", "2222"]), [])
        flags, ports = s.nft_managed_state(text)
        self.assertEqual(flags, {"chains", "loopback", "input_drop", "forward_drop"})
        self.assertEqual(ports, ["22", "2222"])
        self.assertEqual(s.nft_managed_state(None), (None, None))
        # 只建立表：沒有基本鏈
        self.assertEqual(s.nft_hooks(s.nft_parse(s.nft_render(set(), []))), set())
        # 只有回送規則：policy 仍為 accept
        self.assertEqual(s.nft_policies(s.nft_parse(s.nft_render({"loopback"}, []))),
                         {"input": False, "forward": False, "output": False})

    def test_conf_include(self):
        t = '#include "/etc/nftables/main.nft"\n'
        self.assertEqual(s.nft_conf_includes(t), [])
        t2 = s.nft_conf_add_include(t)
        self.assertEqual(s.nft_conf_includes(t2), [s.MANAGED_NFT])
        self.assertEqual(s.nft_conf_add_include(t2), t2)

    def test_foreign(self):
        self.assertEqual(s.nft_foreign_tables(IPT_NFT), ["ip filter"])
        self.assertEqual(s.nft_foreign_tables(RULESET), [])


IPT_S = """-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j DROP
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A OUTPUT -o lo -j ACCEPT
"""

IPT_FILE = """# sample
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
"""


class Ipt(unittest.TestCase):
    def test_parse_runtime(self):
        pol, rules = s.ipt_parse(IPT_S)
        self.assertEqual(pol["INPUT"], "ACCEPT")
        self.assertEqual(s.ipt_loopback_missing(rules, False), [])
        self.assertEqual(s.ipt_ssh_problems(pol, rules, ["22"]), [])
        self.assertEqual(s.ipt_ssh_problems(pol, rules, ["2222"]), ["INPUT 未放行 SSH 埠 2222"])

    def test_parse_file(self):
        pol, rules = s.ipt_parse(IPT_FILE, saved=True)
        self.assertEqual(pol, {"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT"})
        self.assertEqual(len(s.ipt_ssh_problems(pol, rules, ["22"])), 3)
        add = ["-A INPUT -i lo -j ACCEPT", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
               "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"]
        new = s.ipt_file_add_allows(IPT_FILE, add)
        pol2, rules2 = s.ipt_parse(new, saved=True)
        self.assertEqual(s.ipt_ssh_problems(pol2, rules2, ["22"]), [])
        self.assertLess(new.index("--dport 22"), new.index("REJECT"))
        empty = s.ipt_file_add_allows("", add)
        self.assertIn("*filter", empty)
        self.assertIn("COMMIT", empty)

    def test_loopback_v6_order(self):
        rules = ["-A INPUT -s ::1/128 -j DROP", "-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
        miss = s.ipt_loopback_missing(rules, True)
        self.assertEqual(len(miss), 1)
        self.assertTrue(miss[0].startswith("（"))
        self.assertEqual(s.ipt_loopback_missing(["-A INPUT -i lo -j ACCEPT"], True),
                         ["-A OUTPUT -o lo -j ACCEPT", "-A INPUT -s ::1/128 -j DROP"])


class Firewalld(unittest.TestCase):
    def test_parse_zones(self):
        t = ("block\n  target: %%REJECT%%\n  interfaces: \n\npublic (active)\n  target: default\n"
             "  interfaces: eth0\n  sources: \n  services: cockpit dhcpv6-client ssh\n  ports: 2222/tcp\n"
             "internal\n  interfaces: \n  sources: 10.0.0.0/8\n")
        z = s.fw_parse_zones(t)
        self.assertEqual(z["public"]["interfaces"], ["eth0"])
        self.assertEqual(z["public"]["ports"], ["2222/tcp"])
        self.assertEqual(z["internal"]["sources"], ["10.0.0.0/8"])
        self.assertEqual(z["block"]["interfaces"], [])


class Cfg(object):
    def __init__(self, b):
        self.firewall_backend = b


class Osi(object):
    def __init__(self, key):
        self.key = key
        self.family = "rhel"


class Ctx(object):
    def __init__(self, b, key="rhel9"):
        self.cfg = Cfg(b)
        self.osi = Osi(key)


class Backend(unittest.TestCase):
    def setUp(self):
        self.states = {}
        self.pkgs = set()
        self.conf = None
        self._saved = (pkgsvc.svc_state, pkgsvc.pkg_installed, s.read_text)
        pkgsvc.svc_state = lambda u: self.states.get(u, ("not-found", "inactive"))
        pkgsvc.pkg_installed = lambda osi, p: p in self.pkgs
        s.read_text = lambda p: self.conf if p == s.NFT_CONF else None

    def tearDown(self):
        pkgsvc.svc_state, pkgsvc.pkg_installed, s.read_text = self._saved

    def test_config_wins(self):
        self.states["firewalld.service"] = ("enabled", "active")
        self.assertEqual(s.fw_backend(Ctx("nftables"))[0], "nftables")

    def test_auto_order(self):
        self.assertEqual(s.fw_backend(Ctx("auto"))[0], "firewalld")  # 預設
        self.states["nftables.service"] = ("enabled", "active")
        self.assertEqual(s.fw_backend(Ctx("auto"))[0], "firewalld")  # 沒有 include
        self.conf = 'include "/etc/nftables/main.nft"\n'
        self.assertEqual(s.fw_backend(Ctx("auto"))[0], "nftables")
        self.states["firewalld.service"] = ("enabled", "inactive")
        self.assertEqual(s.fw_backend(Ctx("auto"))[0], "firewalld")

    def test_iptables_rhel8_only(self):
        self.pkgs.add("iptables-services")
        self.states["iptables.service"] = ("enabled", "active")
        self.assertEqual(s.fw_backend(Ctx("auto", "rhel8"))[0], "iptables")
        self.assertEqual(s.fw_backend(Ctx("auto", "rhel9"))[0], "firewalld")

    def test_when(self):
        self.assertIsNone(s.backend_is("firewalld")(Ctx("auto")))
        self.assertEqual(s.backend_is("nftables")(Ctx("auto")),
                         "GCB 防火牆規則 firewalld／nftables／iptables 三選一；本機採用 firewalld"
                         "（依據：未啟用其他防火牆，依 RHEL 預設採用 firewalld），本項目屬 nftables，不需設定")


class Rules(unittest.TestCase):
    def test_counts(self):
        r8 = [r for r in s.RULES if "rhel8" in r.ids]
        r9 = [r for r in s.RULES if "rhel9" in r.ids]
        self.assertEqual((len(r8), len(r9)), (40, 34))
        for r in s.RULES:
            if "rhel8" in r.ids and "rhel9" in r.ids:
                self.assertEqual(int(r.ids["rhel8"][-4:]) - 2, int(r.ids["rhel9"][-4:]))


if __name__ == "__main__":
    unittest.main()
