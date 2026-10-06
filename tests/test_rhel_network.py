# -*- coding: utf-8 -*-
"""RHEL network.py 的單元測試（以假資料取代設定檔與 /proc，不修改系統）。"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import pkgsvc  # noqa: E402
from gcb.rules.base import FAIL, NA, PASS  # noqa: E402
from gcb.rules.rhel import network as net  # noqa: E402


class FakeFx(object):
    def __init__(self, files):
        self.files = files
        self.writes = []
        self.cmds = []
        self.notes = []
        self.partial = False

    def write_file(self, path, text, mode=0o644):
        self.files[path] = text
        self.writes.append(path)

    def edit_file(self, path, func, mode=0o644):
        self.write_file(path, func(self.files.get(path, "")))

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
    def setUp(self):
        self.files = {}
        self.runtime = {}
        self.persist = {}
        self._saved = [(net, "read_text", net.read_text), (net, "nm_active", net.nm_active),
                       (pkgsvc, "sysctl_runtime", pkgsvc.sysctl_runtime),
                       (pkgsvc, "sysctl_persistent", pkgsvc.sysctl_persistent)]
        net.read_text = lambda p: self.files.get(p)
        net.nm_active = lambda: False
        pkgsvc.sysctl_runtime = lambda k: self.runtime.get(k)

        def persistent(k):
            where = self.persist.get(k, [])
            return (where[-1][1], where[-1][0], where) if where else (None, None, [])
        pkgsvc.sysctl_persistent = persistent

    def tearDown(self):
        for mod, name, fn in self._saved:
            setattr(mod, name, fn)


class Rules(unittest.TestCase):
    def test_ids(self):
        from gcb.osinfo import OSInfo
        from gcb.rules import rules_for
        for key in ("rhel8", "rhel9"):
            osi = OSInfo(key, "rhel", "x", "rocky", "9")
            ids = [int(r.rule_id(osi)[-4:]) for r in net.RULES if r.rule_id(osi)]
            self.assertEqual(len(ids), len(set(ids)))
            common = {95, 103, 108, 109, 110}
            self.assertEqual(sorted(set(ids) | common), list(range(92, 132)))
            rules_for(osi)  # 不可重複定義

    def test_titles_per_version(self):
        from gcb.osinfo import OSInfo
        r8 = dict((r.rule_id(OSInfo("rhel8", "rhel", "", "", "8")), r) for r in net.RULES)
        r9 = dict((r.rule_id(OSInfo("rhel9", "rhel", "", "", "9")), r) for r in net.RULES)
        self.assertEqual(r8["TWGCB-01-008-0111"].title, "所有網路介面接受來源路由封包")
        self.assertEqual(r9["TWGCB-01-012-0111"].title, "所有網路介面阻擋來源路由封包")
        self.assertEqual(r9["TWGCB-01-012-0124"].risk, "B")
        self.assertEqual(r8["TWGCB-01-008-0101"].risk, "B")
        self.assertEqual(r8["TWGCB-01-008-0093"].risk, "C")
        self.assertEqual(r8["TWGCB-01-008-0131"].risk, "C")


class Sysctl(Patch):
    def test_vendor_conflict_override(self):
        k = "net.ipv4.tcp_syncookies"
        self.runtime[k] = "0"
        self.persist[k] = [("/usr/lib/sysctl.d/50-default.conf", "0"), ("/usr/lib/sysctl.d/99-x.conf", "2"),
                           ("/etc/sysctl.conf", "0")]
        self.files["/usr/lib/sysctl.d/99-x.conf"] = "a.b = 1\nnet.ipv4.tcp_syncookies = 2\n"
        self.files["/etc/sysctl.conf"] = "net.ipv4.tcp_syncookies=0\nnet.ipv4.tcp_syncookies = 1\n"
        fx = FakeFx(self.files)
        net.RhelSysctl("t", [(k, "1")], {}).fix(Ctx(), fx)
        self.assertNotIn("/usr/lib/sysctl.d/50-default.conf", fx.writes)
        self.assertNotIn("/usr/lib/sysctl.d/99-x.conf", fx.writes)
        ov = self.files["/etc/sysctl.d/99-x.conf"]
        self.assertIn("a.b = 1", ov)
        self.assertIn("*REMOVED*", ov)
        # 只註解值不為 1 的行（文件 grep 樣式會連 = 1 一起註解）
        self.assertIn("\nnet.ipv4.tcp_syncookies = 1\n", self.files["/etc/sysctl.conf"])
        self.assertIn("*REMOVED*", self.files["/etc/sysctl.conf"].splitlines()[0])
        self.assertIn("net.ipv4.tcp_syncookies = 1", self.files[net.OWN_SYSCTL])
        self.assertIn(("sysctl", k, "1"), fx.cmds)

    def test_ipv6_missing(self):
        ra = net.AcceptRa("ra", "net.ipv6.conf.all.accept_ra", {})
        self.assertEqual(ra.check(Ctx()).status, NA)


class Dnf(unittest.TestCase):
    def test_ini(self):
        t = "[main]\ngpgcheck=1\nclean_requirements_on_remove=1\n\n[repo]\nclean_requirements_on_remove=0\n"
        self.assertEqual(net.ini_get(t, "main", "clean_requirements_on_remove"), "1")
        n = net.ini_set(t, "main", "clean_requirements_on_remove", "True")
        self.assertEqual(net.ini_get(n, "main", "clean_requirements_on_remove"), "True")
        self.assertEqual(net.ini_get(n, "repo", "clean_requirements_on_remove"), "0")
        n = net.ini_set("[main]\ngpgcheck=1\n\n[x]\na=1\n", "main", "clean_requirements_on_remove", "True")
        self.assertEqual(n, "[main]\ngpgcheck=1\nclean_requirements_on_remove=True\n\n[x]\na=1\n")
        self.assertEqual(net.ini_set("", "main", "k", "v"), "[main]\nk=v\n")


class Chrony(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_sources(self):
        conf = os.path.join(self.d, "chrony.conf")
        dd = os.path.join(self.d, "chrony.d")
        os.mkdir(dd)
        with open(conf, "w") as f:
            f.write("# server x\n! pool y\nconfdir %s\nsourcedir %s\ndriftfile /x\n" % (dd, dd))
        self.assertEqual(net.chrony_sources(conf), [])
        with open(os.path.join(dd, "a.conf"), "w") as f:
            f.write("server ntp.gov.tw iburst\n")
        with open(os.path.join(dd, "b.sources"), "w") as f:
            f.write("pool 2.rocky.pool.ntp.org\n")
        self.assertEqual([l for _, l in net.chrony_sources(conf)],
                         ["server ntp.gov.tw iburst", "pool 2.rocky.pool.ntp.org"])


class Snmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_v1v2_v3(self):
        conf = os.path.join(self.d, "snmpd.conf")
        inc = os.path.join(self.d, "inc.conf")
        with open(conf, "w") as f:
            f.write("#com2sec a default public\ngroup g usm u\nincludeFile %s\n" % inc)
        with open(inc, "w") as f:
            f.write("rocommunity public\nrouser admin\n")
        files = net.snmp_conf_files(conf)
        self.assertEqual(files, [conf, inc])
        self.assertEqual(len(net.snmp_v1v2_lines(files)), 1)
        self.assertEqual(net.snmp_v3_users(files, var=os.path.join(self.d, "none")), ["rouser admin"])


class Misc(Patch):
    def test_nsswitch(self):
        self.assertEqual(net.nsswitch_uses("nis", "passwd: files nis\ngroup: files\n#shadow: nis\n"), ["passwd"])

    def test_promisc(self):
        d = tempfile.mkdtemp()
        try:
            for name, flags in (("eth0", "0x1103"), ("eth1", "0x1003")):
                os.mkdir(os.path.join(d, name))
                self.files[os.path.join(d, name, "flags")] = flags
            os.mkdir(os.path.join(d, "eth0", "brport"))
            self.assertEqual(net.Promisc.interfaces(d), [("eth0", "橋接器成員")])
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
