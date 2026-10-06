# -*- coding: utf-8 -*-
"""RHEL／Ubuntu network.py 規則的 check／precondition／fix 測試（全部以假資料模擬，不碰真實系統）。"""
import fnmatch
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402
from fakes import FakeCtx, FakeFx, FakeRunner, res  # noqa: E402
from gcb import pkgsvc  # noqa: E402
from gcb import textedit as te  # noqa: E402
from gcb.fixer import ManualRequired  # noqa: E402
from gcb.rules import common  # noqa: E402
from gcb.rules.base import FAIL, PASS  # noqa: E402
from gcb.rules.rhel import network as rnet  # noqa: E402
from gcb.rules.ubuntu import network as unet  # noqa: E402

REAL = {n: getattr(os.path, n) for n in ("exists", "isdir", "isfile", "islink", "realpath")}
ZERO6 = "0" * 32
ROUTE_HDR = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"


class FakeGlob(object):
    def __init__(self, paths):
        self.paths = paths

    def glob(self, pat):
        return sorted(p for p in self.paths if fnmatch.fnmatchcase(p, pat))


def find(mod, n, key):
    osi = fakes.make_osi(key)
    rs = [r for r in mod.RULES if (r.rule_id(osi) or "").endswith("-%04d" % n)]
    assert len(rs) == 1, (n, rs)
    return rs[0]


def idx(events, ev):
    return events.index(ev)


class Base(unittest.TestCase):
    """mod：受測模組；檔案、指令、服務、套件、sysctl、路徑皆為假資料。"""
    mod = rnet
    key = "rhel9"

    def setUp(self):
        self.fs = {}
        self.bins = set(["systemctl"])
        self.svc = {}
        self.pkgs = set()
        self.builtin = set()
        self.exist, self.links = set(), set()
        self.real = {}
        self.globs = []
        self.rt, self.persist = {}, {}
        self.runner = FakeRunner()
        m = self.mod
        self.p(m, "read_text", fakes.fs_reader(self.fs))
        self.p(common, "read_text", fakes.fs_reader(self.fs))
        self.p(m, "which", lambda n: "/usr/bin/" + n if n in self.bins else None)
        self.p(m, "run", self.runner)
        self.p(m, "glob", FakeGlob(self.globs))
        self.p(m, "module_builtin", lambda x: x in self.builtin)
        self.p(m, "modprobe_files", lambda: sorted(p for p in self.fs if p.startswith("/etc/modprobe.d/")))
        self.p(pkgsvc, "svc_state", lambda u: self.svc.get(u, ("disabled", "inactive")))
        self.p(pkgsvc, "pkg_installed", lambda osi, p: p in self.pkgs)
        self.p(pkgsvc, "sysctl_runtime", lambda k: self.rt.get(k))

        def persistent(k):
            w = self.persist.get(k, [])
            return (w[-1][1], w[-1][0], w) if w else (None, None, [])
        self.p(pkgsvc, "sysctl_persistent", persistent)
        self.p(os.path, "exists", lambda p: p in self.exist)
        self.p(os.path, "isfile", lambda p: p in self.exist)
        self.p(os.path, "islink", lambda p: p in self.links)
        self.p(os.path, "realpath", lambda p: self.real.get(p, p))

    def p(self, obj, name, val):
        pt = mock.patch.object(obj, name, val)
        pt.start()
        self.addCleanup(pt.stop)

    def rule(self, n, key=None):
        return find(self.mod, n, key or self.key)

    def fx(self, **kw):
        return FakeFx(FakeCtx(self.key, **kw), fs=self.fs, runner=self.runner)

    def nm(self):
        self.bins.add("nmcli")
        self.svc["NetworkManager.service"] = ("enabled", "active")

    def wlan(self, driver=True):
        self.globs += ["/sys/class/net/wlan0/wireless", "/sys/class/net/eth0/device"]
        link = "/sys/class/net/wlan0/device/driver/module"
        if driver:
            self.exist.add(link)
            self.real[link] = "/sys/module/iwlwifi"


# ====================================================================
# RHEL 共用小工具
# ====================================================================

# RHEL8 0124–0130 / RHEL9 0124–0130 使用的路由、模組、nsswitch、INI 小工具
class RhelHelpersTest(Base):
    def test_module_in_use(self):
        self.fs["/proc/modules"] = "sctp 1 2 a,b, Live 0x0\ndccp 1 0 - Live 0x0\nbad x y\nrds 1 z - Live\n"
        self.assertEqual(rnet.module_in_use("sctp"), "sctp 模組使用中（參照數 2，被 a、b 使用）")
        self.assertIsNone(rnet.module_in_use("dccp"))
        self.assertIsNone(rnet.module_in_use("rds"))  # 參照數無法解析視為 0

    def test_default_route_ifaces(self):
        self.fs["/proc/net/route"] = ROUTE_HDR + "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n" \
                                                 "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
        self.fs["/proc/net/ipv6_route"] = "%s 00 %s 00 fe80 00000400 1 0 00000003 wwan0\n" \
                                          "%s 00 %s 00 %s 00 1 0 00200200 lo\n" % (ZERO6, ZERO6, ZERO6, ZERO6, ZERO6)
        self.assertEqual(rnet.default_route_ifaces(), set(["wlan0", "wwan0"]))

    def test_ra_default_routes(self):
        self.assertEqual(rnet.ra_default_routes(), [])
        self.bins.add("ip")
        self.runner.add("ip -6 route show default",
                        res(0, out="default via fe80::1 dev eth0 proto ra metric 100\ndefault via fe80::2 dev eth1 proto static\n"))
        self.assertEqual(rnet.ra_default_routes(), ["default via fe80::1 dev eth0 proto ra metric 100"])

    def test_nsswitch_and_ini(self):
        self.fs["/etc/nsswitch.conf"] = "passwd: files nis\n# group: nis\nhosts: files dns\n"
        self.assertEqual(rnet.nsswitch_uses("nis"), ["passwd"])
        t = "[main]\nclean_requirements_on_remove=0\nclean_requirements_on_remove=1\n"
        out = rnet.ini_set(t, "main", "clean_requirements_on_remove", "True")
        self.assertEqual(out, "[main]\nclean_requirements_on_remove=True\n%sclean_requirements_on_remove=1\n" % te.MARK)
        self.assertEqual(rnet.ini_set("[other]\nx=1\n", "main", "k", "v"), "[other]\nx=1\n\n[main]\nk=v\n")

    def test_chrony_sources(self):
        self.globs += ["/etc/chrony.d/a.conf"]
        self.fs["/etc/chrony.conf"] = "include /etc/chrony.d/*.conf\npool 2.pool.ntp.org iburst\n"
        self.fs["/etc/chrony.d/a.conf"] = "server ntp.gov.tw iburst\ninclude /etc/chrony.conf\n"
        self.globs.append("/etc/chrony.conf")
        self.assertEqual(rnet.chrony_sources(), [("/etc/chrony.conf", "pool 2.pool.ntp.org iburst"),
                                                 ("/etc/chrony.d/a.conf", "server ntp.gov.tw iburst")])

    def test_snmp_helpers(self):
        self.exist.update(["/etc/snmp/snmpd.conf", "/etc/snmp/d/x.conf"])
        self.globs.append("/etc/snmp/d/x.conf")
        self.fs["/etc/snmp/snmpd.conf"] = "includeDir /etc/snmp/d\nincludeFile /etc/snmp/snmpd.conf\n"
        self.fs["/etc/snmp/d/x.conf"] = "rouser admin priv\n"
        files = rnet.snmp_conf_files()
        self.assertEqual(files, ["/etc/snmp/snmpd.conf", "/etc/snmp/d/x.conf"])
        self.fs["/var/lib/net-snmp/snmpd.conf"] = "usmUser 1 3 0x80\nother x\n"
        self.assertEqual(rnet.snmp_v3_users(files), ["usmUser", "rouser admin"])


# ====================================================================
# RHEL 套件與服務
# ====================================================================

# RHEL8 0092 / RHEL9 0092 xinetd 套件、0104–0106 telnet／rsh／tftp 伺服器套件
class PkgAbsentTest(Base):
    def test_precondition(self):
        r = self.rule(92)
        self.svc["xinetd.service"] = ("enabled", "active")
        self.assertIn("xinetd.service 運作中", r.precondition(FakeCtx(include_risky=False)))
        self.assertIsNone(r.precondition(FakeCtx(include_risky=True)))
        self.svc.clear()
        self.assertIsNone(r.precondition(FakeCtx(include_risky=False)))

    def test_fix_registers_service_restore_before_remove(self):
        r = self.rule(106)  # tftp：tftp.socket 啟用中、tftp.service 運作中
        self.svc["tftp.socket"] = ("enabled", "inactive")
        self.svc["tftp.service"] = ("static", "active")
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "systemctl enable tftp.socket"), ("undo", "systemctl start tftp.service"),
                                     ("pkg_remove", "tftp-server")])
        self.assertIn("tftp.service", fx.notes[0])


# RHEL8 0102 / RHEL9 0102 NIS 用戶端套件
class NisClientTest(Base):
    def test_nsswitch_in_use_is_manual(self):
        r = self.rule(102)
        self.fs["/etc/nsswitch.conf"] = "passwd: files nis\nshadow: files nis\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            r.fix(fx.ctx, fx)
        self.assertIn("passwd、shadow", str(cm.exception))
        self.assertIn("未運作", str(cm.exception))
        self.svc["ypbind.service"] = ("enabled", "active")
        with self.assertRaises(ManualRequired) as cm:
            r.fix(fx.ctx, fx)
        self.assertIn("運作中", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_fix_removes(self):
        self.fs["/etc/nsswitch.conf"] = "passwd: files sss\n"
        r = self.rule(102)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("pkg_remove", "ypbind")])


# RHEL8 0093 / RHEL9 0093 chrony 校時設定（C 類）
class ChronyTest(Base):
    def test_check(self):
        r = self.rule(93)
        self.assertEqual(r.check(FakeCtx()).current, "未安裝 chrony")
        self.pkgs.add("chrony")
        self.assertIn("未設定 server 或 pool", r.check(FakeCtx()).current)
        self.fs["/etc/chrony.conf"] = "pool 2.rocky.pool.ntp.org iburst\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("僅使用公用 NTP 池", c.current)
        self.assertIn("chronyd 未運作", c.current)
        self.fs["/etc/chrony.conf"] = "server 10.0.0.1 iburst\n"
        self.svc["chronyd.service"] = ("enabled", "active")
        c = r.check(FakeCtx())
        self.assertNotIn("公用", c.current)
        self.assertNotIn("未運作", c.current)


# RHEL8 0096 / RHEL9 0096 SNMP 服務
class SnmpTest(Base):
    def test_check(self):
        r = self.rule(96)
        self.svc["snmpd.service"] = ("not-found", "inactive")
        self.assertEqual(r.check(FakeCtx()).current, "未安裝")
        self.svc["snmpd.service"] = ("disabled", "inactive")
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        self.svc["snmpd.service"] = ("enabled", "active")
        self.exist.add("/etc/snmp/snmpd.conf")
        self.fs["/etc/snmp/snmpd.conf"] = "rouser admin priv\n"
        self.assertIn("僅啟用 SNMPv3", r.check(FakeCtx()).current)
        self.fs["/etc/snmp/snmpd.conf"] = "com2sec a default public\nrocommunity x\nrwcommunity y\n" \
                                          "group g v2c a\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("…", c.current)
        self.assertIn("未設定 SNMPv3 使用者", c.current)

    def test_fix_masks(self):
        r = self.rule(96)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0], ("mask", "snmpd.service"))
        self.assertIn("snmpd.service", fx.ctx.intended_stops)
        self.assertIn("方案 2", fx.notes[0])


# RHEL8 0101 / RHEL9 0101 kdump 服務
class KdumpTest(Base):
    def test_check(self):
        r = self.rule(101)
        self.assertEqual(r.check(FakeCtx()).current, "未安裝 kexec-tools")
        self.pkgs.add("kexec-tools")
        self.fs["/sys/kernel/kexec_crash_size"] = "0\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("kexec_crash_size=0", c.current)
        self.fs["/sys/kernel/kexec_crash_size"] = "abc"
        self.assertIsNone(r.crash_size())
        self.svc["kdump.service"] = ("enabled", "active")
        self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_fix_guards(self):
        r = self.rule(101)
        self.fs["/sys/kernel/kexec_crash_size"] = "0\n"
        for key, cmd in (("rhel8", "grubby"), ("rhel9", "kdumpctl reset-crashkernel")):
            fx = FakeFx(FakeCtx(key), fs=self.fs, runner=self.runner)
            with self.assertRaises(ManualRequired) as cm:
                find(rnet, 101, key).fix(fx.ctx, fx)
            self.assertIn(cmd, str(cm.exception))
        self.fs["/sys/kernel/kexec_crash_size"] = "268435456\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            r.fix(fx.ctx, fx)
        self.assertIn("未安裝 kexec-tools", str(cm.exception))  # 不自動安裝
        self.assertEqual(fx.events, [])

    def test_fix_unmask_and_enable(self):
        r = self.rule(101)
        self.pkgs.add("kexec-tools")
        self.svc["kdump.service"] = ("masked", "inactive")
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "systemctl mask kdump.service"), ("run", "systemctl unmask kdump.service"),
                                     ("enable", "kdump.service"), ("run", "systemctl --now enable kdump.service")])


# RHEL8 0107 / RHEL9 0107 更新套件後移除舊版本元件
class DnfCleanTest(Base):
    def test_check_and_fix(self):
        r = self.rule(107)
        self.assertEqual(r._files(), ["/etc/dnf/dnf.conf"])  # /etc/yum.conf 不存在
        self.exist.add("/etc/yum.conf")
        self.fs["/etc/dnf/dnf.conf"] = "[main]\nclean_requirements_on_remove=1\n"
        self.fs["/etc/yum.conf"] = "[main]\nclean_requirements_on_remove=True\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("dnf 視為等同 True", c.current)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), ["/etc/dnf/dnf.conf"])
        self.assertEqual(self.fs["/etc/dnf/dnf.conf"], "[main]\nclean_requirements_on_remove=True\n")
        # yum.conf 為 dnf.conf 的連結時只處理一次
        self.real["/etc/yum.conf"] = "/etc/dnf/dnf.conf"
        self.assertEqual(r._files(), ["/etc/dnf/dnf.conf"])


# ====================================================================
# RHEL 網路核心參數
# ====================================================================

# RHEL8 0121 / RHEL9 0121 所有網路介面啟用逆向路徑過濾功能（RhelSysctl）
class RhelSysctlTest(Base):
    def test_fix_conflicts(self):
        r = self.rule(121)
        key = "net.ipv4.conf.all.rp_filter"
        # 各介面皆為嚴格模式（不讀取本機 /proc，避免依測試環境而變）
        p = mock.patch("gcb.rules.common.rp_filter_loose", return_value=([], None, None))
        p.start()
        self.addCleanup(p.stop)
        self.rt[key] = "2"
        self.persist[key] = [("/etc/sysctl.d/10-ok.conf", "1"), ("/usr/lib/sysctl.d/50-default.conf", "2"),
                             ("/usr/lib/sysctl.d/99-vendor.conf", "2"), ("/etc/sysctl.d/80-local.conf", "0"),
                             (rnet.OWN_SYSCTL, "2")]
        self.fs["/usr/lib/sysctl.d/99-vendor.conf"] = "%s = 2\nkernel.x = 1\n" % key
        self.fs["/etc/sysctl.d/80-local.conf"] = "%s=0\n" % key
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs["/etc/sysctl.d/99-vendor.conf"],
                         "# *REMOVED* by gcb-checker: %s = 2\nkernel.x = 1\n" % key)
        self.assertNotIn("/etc/sysctl.d/50-default.conf", self.fs)  # 排序在前的套件檔不需處理
        self.assertNotIn("/usr/lib/sysctl.d/99-vendor.conf", fx.kinds("write"))
        self.assertIn("# *REMOVED*", self.fs["/etc/sysctl.d/80-local.conf"])
        self.assertEqual(self.fs[rnet.OWN_SYSCTL], "%s = 1\n" % key)
        self.assertIn(("sysctl", key, "1"), fx.events)
        self.assertEqual(fx.events[-1], ("run", "sysctl -w net.ipv4.route.flush=1"))
        self.assertEqual(fx.notes[-1], rnet.RP_NOTE)
        self.assertIn("99-vendor.conf", fx.notes[0])

    def test_rp_filter_all_checks_interfaces(self):
        # RHEL 0121：all=1 但各介面寬鬆 → 不合格
        r = self.rule(121)
        key = "net.ipv4.conf.all.rp_filter"
        self.rt[key] = "1"
        self.persist[key] = [(rnet.OWN_SYSCTL, "1")]
        self.p(common, "rp_filter_loose", lambda: ([("ens192", "2")], None, None))
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("ens192 rp_filter=2", c.current)

    def test_vendor_symlink(self):
        self.links.add("/etc/sysctl.d/99-sysctl.conf")
        self.real["/etc/sysctl.d/99-sysctl.conf"] = "/usr/lib/sysctl.d/99.conf"
        self.assertTrue(rnet.RhelSysctl._vendor("/etc/sysctl.d/99-sysctl.conf"))
        self.assertFalse(rnet.RhelSysctl._vendor("/run/sysctl.d/x.conf"))


# RHEL8 0124 / RHEL9 0124 所有網路介面阻擋 IPv6 路由器公告訊息
class AcceptRaTest(Base):
    def test_check_and_fix_notes(self):
        r = self.rule(124)
        key = "net.ipv6.conf.all.accept_ra"
        self.rt[key] = "1"
        self.nm()
        self.assertIn("NetworkManager 運作中", r.check(FakeCtx()).current)
        self.bins.add("ip")
        self.runner.add("ip -6 route show default", res(0, out="default via fe80::1 dev eth0 proto ra metric 1024\n"))
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertIn(("sysctl", key, "0"), fx.events)
        self.assertIn(("run", "sysctl -w net.ipv6.route.flush=1"), fx.events)
        self.assertIn("proto ra", fx.notes[0])
        self.assertEqual(fx.notes[1], rnet.RA_NM_NOTE)


# ====================================================================
# 協定模組、無線網路、混雜模式（RHEL 與 Ubuntu 共用相同邏輯，各自測試）
# ====================================================================

# RHEL8 0127 / RHEL9 0127 SCTP 協定
class RhelNetModuleTest(Base):
    target = "/bin/true"
    n = 127

    def test_check_in_use(self):
        self.fs["/proc/modules"] = "sctp 409600 3 - Live 0x0\n"
        r = self.rule(self.n)
        c = r.check(FakeCtx())
        self.assertIn("sctp 模組使用中（參照數 3）", c.current)
        self.assertIn("--include-risky", r.precondition(FakeCtx(include_risky=False)))

    def test_fix(self):
        r = self.rule(self.n)
        self.builtin.add("sctp")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(fx.ctx, fx)
        self.builtin.clear()
        # 未載入：只寫設定
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs["/etc/modprobe.d/sctp.conf"], "install sctp %s\nblacklist sctp\n" % self.target)
        self.assertEqual(fx.kinds("run"), [])
        # 已載入但使用中：卸載失敗列為部分修復
        self.fs["/proc/modules"] = "sctp 409600 2 - Live 0x0\n"
        self.runner.add("modprobe -r sctp", res(1, err="in use"))
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("run"), ["modprobe -r sctp"])
        self.assertTrue(fx.partial)
        self.assertIn("參照數 2", fx.notes[0])
        # 卸載成功
        self.runner.rules[0] = ("modprobe -r sctp", res(0))
        self.fs["/proc/modules"] = "sctp 409600 0 - Live 0x0\n"
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertFalse(fx.partial)


# RHEL8 0130 / RHEL9 0130 無線網路介面
class RhelWirelessTest(Base):
    target = "/bin/true"
    n = 130

    def test_no_interface(self):
        # 沒有無線介面即符合「停用」（與 GCB 修復腳本一致），判定合格而非不適用
        r = self.rule(self.n)
        self.assertIsNone(r.not_applicable(FakeCtx()))
        c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "系統沒有無線網路介面（已符合停用）"))

    def test_check_networkmanager(self):
        self.wlan()
        self.nm()
        r = self.rule(self.n)
        self.runner.add("nmcli radio wifi", res(0, out="enabled\n"))
        self.runner.add("nmcli radio wwan", res(8))
        c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "NetworkManager：wifi=enabled、wwan=未知"))
        self.runner.rules[:2] = [("nmcli radio", res(0, out="disabled\n"))]
        self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_check_modprobe(self):
        r = self.rule(self.n)
        self.wlan()
        c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "wlan0（驅動 iwlwifi）：未封鎖"))
        self.fs["/etc/modprobe.d/w.conf"] = "install iwlwifi /bin/true\nblacklist iwlwifi\n"
        self.fs["/proc/modules"] = "iwlwifi 1 0 - Live 0x0\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("需重開機生效", c.current)
        self.globs.append("/sys/class/net/wlp2/phy80211")
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("找不到驅動模組：wlp2", c.current)

    def test_fix_default_route_guard(self):
        self.wlan()
        self.fs["/proc/net/route"] = ROUTE_HDR + "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            self.rule(self.n).fix(fx.ctx, fx)
        self.assertIn("wlan0", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_fix_networkmanager(self):
        # 只有 NetworkManager（nmcli）運作中才用 nmcli 關閉
        self.wlan()
        self.nm()
        self.runner.add("nmcli radio wifi", res(0, out="enabled\n"))
        self.runner.add("nmcli radio wwan", res(0, out="disabled\n"))
        fx = self.fx()
        self.rule(self.n).fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "nmcli radio wifi on"), ("run", "nmcli radio all off")])
        self.assertNotIn(self.mod.Wireless.CONF, self.fs)

    def test_fix_modprobe(self):
        self.wlan()
        self.bins.add("nmcli")  # nmcli 存在但 NetworkManager 未運作
        fx = self.fx()
        self.rule(self.n).fix(fx.ctx, fx)
        self.assertEqual(self.fs[self.mod.Wireless.CONF], "install iwlwifi %s\nblacklist iwlwifi\n" % self.target)
        self.assertFalse(self.runner.ran("nmcli radio all"))
        self.assertIn("iwlwifi", fx.notes[0])

    def test_fix_missing_driver(self):
        self.wlan(driver=False)
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule(self.n).fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# RHEL8 0131 / RHEL9 0131 網路介面混雜模式（C 類）
class PromiscTest(Base):
    def test_interfaces(self):
        b = "/sys/class/net"
        self.globs += [b + "/br0p", b + "/bond1", b + "/veth9", b + "/bad", b + "/eth0"]
        self.fs.update({b + "/br0p/flags": "0x1103", b + "/bond1/flags": "0x1903", b + "/veth9/flags": "0x1103",
                        b + "/bad/flags": "zz", b + "/eth0/flags": "0x1003",
                        b + "/veth9/iflink": "7\n", b + "/veth9/ifindex": "8\n"})
        self.exist.update([b + "/br0p/brport", b + "/bond1/master"])
        self.assertEqual(rnet.Promisc.interfaces(), [("bond1", "bond／team 成員"), ("br0p", "橋接器成員"),
                                                     ("veth9", "veth 或虛擬介面")])
        c = self.rule(131).check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("bond1（bond／team 成員）", c.current)
        self.globs[:] = [b + "/eth0"]
        self.assertEqual(self.rule(131).check(FakeCtx()).status, PASS)


# ====================================================================
# Ubuntu
# ====================================================================

class UBase(Base):
    mod = unet
    key = "ubuntu2204"


# TWGCB-01-014-0084 rsync 服務
class RsyncTest(UBase):
    def test_precondition(self):
        r = self.rule(84)
        self.assertIsNone(r.precondition(FakeCtx(include_risky=False)))  # 沒有 rsyncd.conf
        self.exist.add("/etc/rsyncd.conf")
        self.assertIsNone(r.precondition(FakeCtx(include_risky=False)))  # 服務未執行
        self.svc["rsync.service"] = ("enabled", "active")
        self.assertIn("rsync.service 執行中", r.precondition(FakeCtx(include_risky=False)))
        self.assertIsNone(r.precondition(FakeCtx(include_risky=True)))


# TWGCB-01-014-0085 NIS 用戶端套件、0086 rsh 用戶端套件
class PackagePurgeTest(UBase):
    def test_nis_in_nsswitch_is_manual(self):
        self.fs["/etc/nsswitch.conf"] = "passwd: files nis # x\ngroup: files\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            self.rule(85).fix(fx.ctx, fx)
        self.assertIn("passwd", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_backup_conffiles_then_purge(self):
        self.fs["/etc/nsswitch.conf"] = "passwd: files nis\n"  # rsh 不檢查 nsswitch
        self.exist.add("/etc/rsh.conf")
        self.runner.add("dpkg-query -W", res(0, out="\n /etc/rsh.conf 0123abcd\n /etc/gone.conf 4567\nrelative x\n"))
        fx = self.fx()
        self.rule(86).fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("backup", "/etc/rsh.conf"), ("pkg_remove", "rsh-client")])

    def test_conffiles_query_failed(self):
        self.runner.add("dpkg-query -W", res(1, out=" /etc/x.conf 1\n"))
        self.exist.add("/etc/x.conf")
        fx = self.fx()
        self.rule(87).fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("pkg_remove", "talk")])


# TWGCB-01-014-0105 所有網路介面阻擋 IPv6 路由器公告訊息（NetSysctl，含 ufw 覆寫）
class UbuntuNetSysctlTest(UBase):
    def test_fix_ipv6_with_ufw_conflict(self):
        r = self.rule(105)
        key = "net.ipv6.conf.all.accept_ra"
        self.rt[key] = "1"
        self.fs["/etc/default/ufw"] = 'IPT_SYSCTL="/etc/ufw/sysctl.conf"\n'
        self.fs["/etc/ufw/sysctl.conf"] = "%s=1\n" % key
        self.fs["/etc/ufw/ufw.conf"] = "ENABLED=yes\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("ufw 啟用中", c.current)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs[unet.OWN_SYSCTL], "%s = 0\n" % key)
        self.assertIn("# *REMOVED*", self.fs["/etc/ufw/sysctl.conf"])
        self.assertIn(("sysctl", key, "0"), fx.events)
        self.assertEqual(fx.kinds("run"), ["sysctl -w net.ipv4.route.flush=1", "sysctl -w net.ipv6.route.flush=1"])
        self.assertEqual(fx.notes, [unet.RA_NOTE])

    def test_rp_filter_all_checks_interfaces(self):
        # TWGCB-01-014-0102：all=1 但 eth0=2（寬鬆）→ 不合格；修復時覆寫萬用字元設定並調整 eth0
        r = self.rule(102)
        key = "net.ipv4.conf.all.rp_filter"
        self.rt[key] = "1"
        self.persist[key] = [(unet.OWN_SYSCTL, "1")]
        self.fs[unet.OWN_SYSCTL] = "%s = 1\n" % key
        loose = ([("eth0", "2")], "2", "/usr/lib/sysctl.d/50-default.conf")
        self.p(common, "rp_filter_loose", lambda: loose)
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("介面 eth0 rp_filter=2 為寬鬆模式", c.current)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs[unet.OWN_SYSCTL], "%s = 1\nnet.ipv4.conf.*.rp_filter = 1\n" % key)
        self.assertIn(("sysctl", "net.ipv4.conf.eth0.rp_filter", "1"), fx.events)

    def test_loaded_modules_bad_refcount(self):
        self.fs["/proc/modules"] = "tipc 1 x - Live 0x0\n"
        self.assertEqual(unet.loaded_modules(), {"tipc": (0, [])})


# TWGCB-01-014-0108 SCTP 協定（/bin/false）
class UbuntuNetModuleTest(UBase, RhelNetModuleTest):
    target = "/bin/false"
    n = 108


# TWGCB-01-014-0111 無線網路介面（/bin/false）
class UbuntuWirelessTest(UBase, RhelWirelessTest):
    target = "/bin/false"
    n = 111


if __name__ == "__main__":
    unittest.main()
