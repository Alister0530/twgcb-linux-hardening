# -*- coding: utf-8 -*-
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.rules.ubuntu import optional as o  # noqa: E402

UBUNTU_NFT_CONF = """#!/usr/sbin/nft -f

flush ruleset

table inet filter {
\tchain input {
\t\ttype filter hook input priority filter;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter;
\t}
\tchain output {
\t\ttype filter hook output priority filter;
\t}
}
"""

RULESET = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiif "lo" accept
\t\tip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
\t\tip6 saddr ::1 counter packets 0 bytes 0 drop
\t\tct state established,related accept
\t\ttcp dport { 22, 2222 } accept
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t}
}
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t}
}
"""


class ChoiceTest(unittest.TestCase):
    def st(self, chrony=(False, False), ntp=(False, False), tsd=(False, False)):
        return {"chrony": chrony, "ntp": ntp, "timesyncd": tsd}

    def test_time_default_and_priority(self):
        self.assertEqual(o.choose_time(self.st())[0], "timesyncd")
        self.assertEqual(o.choose_time(self.st(tsd=(True, True)))[0], "timesyncd")
        g, why = o.choose_time(self.st(chrony=(True, True), tsd=(True, True)))
        self.assertEqual(g, "chrony")
        self.assertIn("同時啟用", why)
        # 都沒運作時，已安裝的 chrony/ntp 優先於預設
        self.assertEqual(o.choose_time(self.st(ntp=(True, False)))[0], "ntp")
        # timesyncd 運作中、chrony 只安裝未啟用 → timesyncd
        self.assertEqual(o.choose_time(self.st(chrony=(True, False), tsd=(True, True)))[0], "timesyncd")

    def test_firewall(self):
        self.assertEqual(o.choose_firewall({})[0], "ufw")
        self.assertEqual(o.choose_firewall({"nftables": True})[0], "nftables")
        self.assertEqual(o.choose_firewall({"ufw": True, "nftables": True})[0], "ufw")
        self.assertEqual(o.choose_firewall({"ipt_installed": True})[0], "iptables")
        self.assertEqual(o.choose_firewall({"iptables": True, "ipt_installed": True})[0], "iptables")


class BackendTest(unittest.TestCase):
    def test_config_override(self):
        class C(object):
            firewall_backend = "nftables"

        class X(object):
            cfg = C()
            osi = None
        self.assertEqual(o.firewall_choice(X())[0], "nftables")
        X.cfg.firewall_backend = "firewalld"
        self.assertTrue(o.fw_is("ufw")(X()))
        self.assertTrue(o.fw_is("nftables")(X()))


class UfwTest(unittest.TestCase):
    V4 = """*filter
### RULES ###

### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo
-A ufw-user-input -i lo -j ACCEPT
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 out_lo
### tuple ### deny any any 0.0.0.0/0 any 127.0.0.0/8 in
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in comment=x
"""
    V6 = """### tuple ### allow any any ::/0 any ::/0 in_lo
### tuple ### deny any any ::/0 any ::1 in
"""

    def test_loopback_ok(self):
        self.assertEqual(o.ufw_loopback_status(o.ufw_tuples(self.V4), o.ufw_tuples(self.V6)), [])

    def test_loopback_missing_and_order(self):
        t4 = o.ufw_tuples("### tuple ### deny any any 0.0.0.0/0 any 127.0.0.0/8 in\n"
                          "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo\n")
        miss = o.ufw_loopback_status(t4, [], v6=True)
        self.assertIn("allow out on lo", miss)
        self.assertIn("deny in from ::1", miss)
        self.assertTrue(any("排在" in m for m in miss))
        self.assertNotIn("deny in from ::1", o.ufw_loopback_status(t4, [], v6=False))

    def test_ssh_port(self):
        t = o.ufw_tuples(self.V4)
        self.assertTrue(o.ufw_allows_port(t, "22"))
        self.assertFalse(o.ufw_allows_port(t, "2222"))
        t = o.ufw_tuples("### tuple ### limit tcp 2000:3000 0.0.0.0/0 any 0.0.0.0/0 in\n")
        self.assertTrue(o.ufw_allows_port(t, "2222"))


class NftTest(unittest.TestCase):
    def test_parse_conf(self):
        tables, chains = o.nft_parse(UBUNTU_NFT_CONF)
        self.assertEqual(tables, [("inet", "filter")])
        self.assertEqual(sorted(c["hook"] for c in o.nft_base(chains)), ["forward", "input", "output"])
        c = o.nft_base(chains, "input")[0]
        self.assertIsNone(c["policy"])
        self.assertEqual(c["hook_line"], 6)

    def test_parse_ruleset_and_safety(self):
        tables, chains = o.nft_parse(RULESET)
        self.assertEqual(o.nft_foreign_tables(tables, chains), ["ip filter"])
        inp = [c for c in o.nft_base(chains, "input") if c["family"] == "inet"][0]
        self.assertEqual(inp["policy"], "drop")
        self.assertIn("tcp dport { 22, 2222 } accept", inp["rules"])
        self.assertEqual(o.nft_loopback_missing(inp), [])
        with mock.patch.object(o, "ipv6_active", return_value=False):
            self.assertEqual(o.nft_chain_ssh_safe(inp, ["22", "2222"]), (True, ""))
        with mock.patch.object(o, "ipv6_active", return_value=True):
            ok, miss = o.nft_chain_ssh_safe(inp, ["22", "2222"])
            self.assertFalse(ok)
            self.assertIn("ICMPv6", miss)
        ok, miss = o.nft_chain_ssh_safe(inp, ["22", "2200"])
        self.assertFalse(ok)
        self.assertIn("2200", miss)

    def test_one_line_chain(self):
        _, chains = o.nft_parse("table inet f {\n chain input { type filter hook input priority 0; policy accept; }\n}\n")
        self.assertEqual(chains[0]["policy"], "accept")
        key = ("inet", "f", "input")
        self.assertIsNone(o.nft_conf_insert_rules("table inet f {\n chain input { type filter hook input priority 0; policy accept; }\n}\n", key, ["x"]))
        new = o.nft_conf_set_policy("table inet f {\n chain input { type filter hook input priority 0; policy accept; }\n}\n", key, "drop")
        self.assertIn("policy drop;", new)

    def test_conf_edit(self):
        key = ("inet", "filter", "input")
        t = o.nft_conf_insert_rules(UBUNTU_NFT_CONF, key, [o.NFT_LO, o.NFT_LO4, o.NFT_LO6])
        t = o.nft_conf_set_policy(t, key, "drop")
        _, chains = o.nft_parse(t)
        inp = o.nft_base(chains, "input")[0]
        self.assertEqual(inp["policy"], "drop")
        self.assertEqual(o.nft_loopback_missing(inp), [])
        self.assertIn("\t\ttype filter hook input priority filter; policy drop;\n\t\tiif \"lo\" accept", t)
        # 已有 lo accept 時，drop 規則插在其後
        t2 = o.nft_conf_insert_rules(UBUNTU_NFT_CONF, key, [o.NFT_LO])
        t2 = o.nft_conf_insert_rules(t2, key, ["ct state established,related accept"])
        t2 = o.nft_conf_insert_rules(t2, key, [o.NFT_LO4, o.NFT_LO6], after_lo=True)
        inp = o.nft_base(o.nft_parse(t2)[1], "input")[0]
        self.assertEqual(o.nft_loopback_missing(inp), [])


class IptTest(unittest.TestCase):
    S = ["-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT ACCEPT",
         "-A INPUT -i lo -j ACCEPT",
         "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
         "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
         "-A INPUT -s 127.0.0.0/8 -j DROP"]

    def test_safe(self):
        self.assertEqual(o.ipt_input_safe(self.S, ["22"]), (True, ""))
        ok, miss = o.ipt_input_safe(self.S[:5], ["22"])
        self.assertFalse(ok)
        self.assertIn("SSH 埠 22", miss)
        self.assertTrue(o.ipt_input_safe(["-P INPUT ACCEPT"], ["22"])[0])

    def test_loopback_order(self):
        r = o.IptLoopback("x", {}, v6=False)
        self.assertEqual(r.missing(self.S), ["-A OUTPUT -o lo -j ACCEPT"])
        bad = ["-A INPUT -s 127.0.0.0/8 -j DROP", "-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
        self.assertTrue(any("排在" in m for m in r.missing(bad)))

    def test_file_policies(self):
        text = "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [1:2]\nCOMMIT\n"
        self.assertEqual(o.ipt_file_policies(text), {"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT"})


class IniTest(unittest.TestCase):
    def test_gdm_custom_conf(self):
        text = "# GDM\n[daemon]\n# WaylandEnable=false\n\n[security]\n\n[xdmcp]\n\n[chooser]\n\n[debug]\n"
        new = o.ini_set(text, "xdmcp", "Enable", "false")
        self.assertIn("[xdmcp]\nEnable=false\n\n[chooser]", new)
        self.assertEqual(o.ini_get(new, "xdmcp", "Enable"), "false")
        self.assertEqual(o.ini_set(new, "xdmcp", "Enable", "false"), new)

    def test_dconf_keyfile(self):
        t = o.ini_set("", "org/gnome/desktop/session", "idle-delay", "uint32 900")
        t = o.ini_set(t, "org/gnome/desktop/screensaver", "lock-delay", "uint32 0")
        self.assertEqual(t, "[org/gnome/desktop/session]\nidle-delay=uint32 900\n\n"
                            "[org/gnome/desktop/screensaver]\nlock-delay=uint32 0\n")
        self.assertEqual(o.dconf_uint("uint32 900"), 900)
        self.assertTrue(o._idle_ok("uint32 300"))
        self.assertFalse(o._idle_ok("uint32 0"))
        self.assertFalse(o._idle_ok("1200"))
        self.assertIsNone(o.ini_get(o.ini_comment(t, "org/gnome/desktop/session", "idle-delay"),
                                    "org/gnome/desktop/session", "idle-delay"))

    def test_profile_merge(self):
        self.assertEqual(o.profile_merge("", o.USER_PROFILE), "user-db:user\nsystem-db:local\n")
        self.assertEqual(o.profile_merge("system-db:ibus\n", o.USER_PROFILE),
                         "user-db:user\nsystem-db:ibus\nsystem-db:local\n")

    def test_chrony_directives(self):
        text = "! pool 2.debian.pool.ntp.org iburst\npool ntp.ubuntu.com iburst maxsources 4\n# user x\nuser _chrony\n"
        self.assertEqual(o.chrony_directives(text, "pool"), ["ntp.ubuntu.com iburst maxsources 4"])
        self.assertEqual(o.chrony_directives(text, "user"), ["_chrony"])


if __name__ == "__main__":
    unittest.main()
