# -*- coding: utf-8 -*-
"""Ubuntu 22.04 network.py 的單元測試（以假資料取代 /proc、設定檔，不修改系統）。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import pkgsvc  # noqa: E402
from gcb.rules.base import FAIL, NA, PASS  # noqa: E402
from gcb.rules.ubuntu import network as net  # noqa: E402


class FakeFx(object):
    def __init__(self, files):
        self.files = files
        self.edits = []
        self.cmds = []
        self.notes = []
        self.partial = False

    def edit_file(self, path, func, mode=0o644):
        self.files[path] = func(self.files.get(path, ""))
        self.edits.append(path)

    def sysctl_set(self, key, value):
        self.cmds.append(("sysctl", key, value))

    def run(self, cmd, desc, check=True, **kw):
        self.cmds.append(tuple(cmd))
        return None

    def note(self, text):
        self.notes.append(text)


class Ctx(object):
    include_risky = False


class Patch(unittest.TestCase):
    """以 dict 模擬檔案內容。"""

    def setUp(self):
        self.files = {}
        self.runtime = {}
        self.persist = {}
        self._saved = [(net, "read_text", net.read_text),
                       (pkgsvc, "sysctl_runtime", pkgsvc.sysctl_runtime),
                       (pkgsvc, "sysctl_persistent", pkgsvc.sysctl_persistent)]
        net.read_text = lambda p: self.files.get(p)
        pkgsvc.sysctl_runtime = lambda k: self.runtime.get(k)

        def persistent(k):
            where = self.persist.get(k, [])
            return (where[-1][1], where[-1][0], where) if where else (None, None, [])
        pkgsvc.sysctl_persistent = persistent

    def tearDown(self):
        for mod, name, fn in self._saved:
            setattr(mod, name, fn)


class SysctlTest(Patch):
    def rule(self):
        return net.NetSysctl("記錄可疑封包", [("net.ipv4.conf.all.log_martians", "1")], 98)

    def test_ufw_enabled_overrides(self):
        k = "net.ipv4.conf.all.log_martians"
        self.runtime[k] = "1"
        self.persist[k] = [(net.OWN_SYSCTL, "1")]
        self.files["/etc/ufw/sysctl.conf"] = "net/ipv4/conf/all/log_martians=0\n"
        self.assertEqual(self.rule().check(Ctx()).status, PASS)  # ufw 未啟用只提示
        self.files["/etc/ufw/ufw.conf"] = "ENABLED=yes\n"
        c = self.rule().check(Ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("ufw", c.current)

    def test_fix_comments_ufw_and_symlink_target(self):
        k = "net.ipv4.conf.all.log_martians"
        self.runtime[k] = "0"
        self.persist[k] = [("/etc/sysctl.d/99-sysctl.conf", "0")]
        for f in ("/etc/ufw/sysctl.conf", os.path.realpath("/etc/ufw/sysctl.conf")):
            self.files[f] = "net/ipv4/conf/all/log_martians=0\n"
        fx = FakeFx(self.files)
        self.rule().fix(Ctx(), fx)
        # 傳入連結路徑即可：write_text_atomic 會寫入連結實際指向的檔案並保留連結
        self.assertIn("/etc/sysctl.d/99-sysctl.conf", fx.edits)
        self.assertIn("*REMOVED*", self.files[os.path.realpath("/etc/ufw/sysctl.conf")])
        self.assertIn("net.ipv4.conf.all.log_martians = 1", self.files[net.OWN_SYSCTL])
        self.assertIn(("sysctl", k, "1"), fx.cmds)
        self.assertNotIn(("sysctl", "-w", "net.ipv6.route.flush=1"), fx.cmds)

    def test_ipv6_disabled(self):
        r = net.NetSysctl("x", [("net.ipv4.conf.all.accept_redirects", "0"),
                                ("net.ipv6.conf.all.accept_redirects", "0")], 94)
        self.runtime["net.ipv4.conf.all.accept_redirects"] = "0"
        self.persist["net.ipv4.conf.all.accept_redirects"] = [(net.OWN_SYSCTL, "0")]
        c = r.check(Ctx())
        self.assertEqual(c.status, PASS)
        self.assertNotIn("ipv6", c.current)
        ra = net.NetSysctl("ra", [("net.ipv6.conf.all.accept_ra", "0")], 105)
        self.assertEqual(ra.check(Ctx()).status, NA)


class ModuleTest(Patch):
    def test_in_use(self):
        self.files["/proc/modules"] = ("sctp 409600 4 xfrm_algo, Live 0x0\n"
                                       "dccp 90112 0 - Live 0x0\n")
        self.assertIn("參照數 4", net.module_in_use("sctp"))
        self.assertIn("xfrm_algo", net.module_in_use("sctp"))
        self.assertIsNone(net.module_in_use("dccp"))
        self.assertIsNone(net.module_in_use("rds"))


class RouteTest(Patch):
    def test_default_route(self):
        self.files["/proc/net/route"] = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n")
        self.files["/proc/net/ipv6_route"] = (
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
            "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth1\n")
        self.assertEqual(net.default_route_ifaces(), {"wlan0", "eth1"})


class PackageTest(Patch):
    def test_nsswitch(self):
        self.files["/etc/nsswitch.conf"] = "passwd: files nis\ngroup: files # nis\nhosts: files dns\n"
        r = net.PackagePurge("NIS", "nis", net.U(85), nsswitch_key="nis")
        self.assertEqual(r._nsswitch_uses(), ["passwd"])


class Catalog(unittest.TestCase):
    def test_ids(self):
        ids = sorted(r.ids["ubuntu2204"] for r in net.RULES)
        want = ["TWGCB-01-014-%04d" % n for n in range(80, 112) if n not in (88, 89, 90, 91)]
        self.assertEqual(ids, want)


if __name__ == "__main__":
    unittest.main()
