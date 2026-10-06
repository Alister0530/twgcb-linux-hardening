# -*- coding: utf-8 -*-
"""跨平台共用規則（gcb/rules/common.py）模擬測試：檢測結果、修復動作與回滾登記順序。"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fakes import FakeCtx, FakeFx, FakeRunner, fs_reader, res  # noqa: E402
from gcb import textedit as te  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules import common as c  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS  # noqa: E402


class Base(unittest.TestCase):
    """以記憶體檔案系統與假指令取代 common 模組的 read_text / run / which / glob。"""

    def env(self, fs=None, runner=None, which=None, globs=None):
        self.fs = fs if fs is not None else {}
        self.runner = runner or FakeRunner()
        which = which or {}
        globs = globs or {}
        for name, val in (("read_text", fs_reader(self.fs)), ("run", self.runner),
                          ("which", lambda n: which.get(n))):
            p = mock.patch.object(c, name, val)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(c.glob, "glob", lambda pat: list(globs.get(pat, [])))
        p.start()
        self.addCleanup(p.stop)

    def patch(self, obj, attr, val):
        p = mock.patch.object(obj, attr, val)
        p.start()
        self.addCleanup(p.stop)

    def fx(self, key="rhel9", **kw):
        ctx = FakeCtx(key, **kw)
        return ctx, FakeFx(ctx, fs=self.fs, runner=self.runner)

    def idx(self, fx, ev):
        return fx.events.index(ev)


# TWGCB-01-008-0001 / 012-0001 / 014-0001 cramfs 檔案系統
class TestModuleDisabled(Base):
    def test_fix_unloads_loaded_module(self):
        self.env(fs={"/proc/modules": "cramfs 16384 0 - Live 0x0\n"})
        ctx, fx = self.fx("ubuntu2204")
        c.ModuleDisabled("cramfs", {}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/modprobe.d/cramfs.conf"], "install cramfs /bin/false\nblacklist cramfs\n")
        self.assertIn(("run", "modprobe -r cramfs"), fx.events)

    def test_fix_not_loaded(self):
        self.env(fs={"/proc/modules": ""})
        ctx, fx = self.fx("rhel9")
        c.ModuleDisabled("cramfs", {}).fix(ctx, fx)
        self.assertIn("install cramfs /bin/true", fx.fs["/etc/modprobe.d/cramfs.conf"])
        self.assertEqual(fx.kinds("run"), [])


class TestModprobeFiles(Base):
    def test_order_and_dedup(self):
        globs = {"/etc/modprobe.d/*.conf": ["/etc/modprobe.d/b.conf", "/etc/modprobe.d/link.conf"],
                 "/usr/lib/modprobe.d/*.conf": ["/usr/lib/modprobe.d/b.conf", "/usr/lib/modprobe.d/a.conf"]}
        self.env(globs=globs)
        real = {"/etc/modprobe.d/link.conf": "/usr/lib/modprobe.d/a.conf"}
        self.patch(c.os.path, "realpath", lambda p: real.get(p, p))
        # 同檔名以 /etc 優先；連結到同一實際檔案只列一次
        self.assertEqual(c.modprobe_files(), ["/usr/lib/modprobe.d/a.conf", "/etc/modprobe.d/b.conf"])

    def test_check_uses_all_files(self):
        self.env(fs={"/etc/modprobe.d/a.conf": "install cramfs /bin/true\n",
                     "/usr/lib/modprobe.d/b.conf": "blacklist cramfs\n", "/proc/modules": ""},
                 globs={"/etc/modprobe.d/*.conf": ["/etc/modprobe.d/a.conf"],
                        "/usr/lib/modprobe.d/*.conf": ["/usr/lib/modprobe.d/b.conf"]})
        chk = c.ModuleDisabled("cramfs", {}).check(FakeCtx())
        self.assertEqual((chk.status, chk.current), (PASS, "install 停用:是、blacklist:是、目前已載入:否"))


# TWGCB-01-008-0008 / 012-0008 / 014-0011 設定 /var 目錄之檔案系統
class TestSeparatePartition(Base):
    def test_pass_and_fail(self):
        self.env(fs={"/proc/self/mounts": "/dev/sda1 / xfs rw 0 0\n/dev/sdb1 /var xfs rw 0 0\n"})
        r = c.SeparatePartition("/var", {})
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, PASS)
        self.assertIn("/dev/sdb1", chk.current)
        self.fs["/proc/self/mounts"] = "/dev/sda1 / xfs rw 0 0\n"
        self.assertEqual(r.check(FakeCtx()).status, FAIL)
        with self.assertRaises(ManualRequired):
            r.fix(FakeCtx(), FakeFx())


class _Pw(object):
    def __init__(self, name):
        self.pw_name = name
        self.gr_name = name
        self.gr_gid = 42


# TWGCB-01-008-0045/0047、012-0045/0047、014-0043/0045 /etc/passwd、/etc/shadow 檔案所有權
class TestFileOwner(Base):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.path = os.path.join(self.d, "shadow")
        open(self.path, "w").close()

    def test_missing_file(self):
        r = c.FileOwner(os.path.join(self.d, "none"), ["root"], {})
        self.assertEqual(r.check(FakeCtx()).status, ERROR)

    def test_unknown_ids_shown_as_numbers(self):
        self.patch(c.pwd, "getpwuid", mock.Mock(side_effect=KeyError))
        self.patch(c.grp, "getgrgid", mock.Mock(side_effect=KeyError))
        st = os.stat(self.path)
        chk = c.FileOwner(self.path, ["root"], {}).check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertEqual(chk.current, "%d:%d" % (st.st_uid, st.st_gid))

    def test_check_and_fix_keeps_allowed_group(self):
        self.patch(c.pwd, "getpwuid", lambda uid: _Pw("root"))
        self.patch(c.grp, "getgrgid", lambda gid: _Pw("shadow"))
        getgrnam = mock.Mock(return_value=_Pw("shadow"))
        self.patch(c.grp, "getgrnam", getgrnam)
        r = c.FileOwner(self.path, ["root", "shadow"], {})
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        getgrnam.assert_called_with("shadow")
        self.assertEqual(fx.events, [("chown", self.path, "root:shadow")])

    def test_fix_uses_first_group_when_not_allowed(self):
        self.patch(c.pwd, "getpwuid", lambda uid: _Pw("bob"))
        self.patch(c.grp, "getgrgid", lambda gid: _Pw("staff"))
        self.patch(c.grp, "getgrnam", lambda g: _Pw(g))
        r = c.FileOwner(self.path, ["root"], {})
        self.assertEqual(r.check(FakeCtx()).current, "bob:staff")
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chown", self.path, "root:root")])


# TWGCB-01-008-0046/0048、012-0046/0048、014-0044/0046 /etc/passwd、/etc/shadow 檔案權限
class TestFileMode(Base):
    def test_missing_and_mode(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.assertEqual(c.FileMode(os.path.join(d, "x"), 0o644, {}).check(FakeCtx()).status, ERROR)
        p = os.path.join(d, "passwd")
        open(p, "w").close()
        os.chmod(p, 0o666)
        r = c.FileMode(p, 0o644, {})
        self.assertEqual(r.expected, "644 或更低權限")
        self.assertEqual(c.FileMode(p, 0, {}).expected, "000")
        chk = r.check(FakeCtx())
        self.assertEqual((chk.status, chk.current), (FAIL, "666"))
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chmod", p, 0o644)])


# TWGCB-01-008-0072 / 012-0072 / 014-0062 帳號不使用空白通行碼
class TestEmptyPassword(Base):
    def test_status(self):
        self.env(fs={})
        r = c.EmptyPassword({})
        self.assertEqual(r.check(FakeCtx()).status, ERROR)
        self.fs["/etc/shadow"] = "root:$6$x:19000:0:99999:7:::\nbob::19000:0:99999:7:::\n"
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertIn("bob", chk.current)
        self.fs["/etc/shadow"] = "root:$6$x:19000:0:99999:7:::\n"
        self.assertEqual(r.check(FakeCtx()).status, PASS)


# TWGCB-01-008-0095 / 012-0095 / 014-0079 avahi-daemon 服務
class TestServiceDisabled(Base):
    UNITS = ["avahi-daemon.service", "avahi-daemon.socket"]

    def test_check(self):
        states = {"avahi-daemon.service": ("enabled", "active"), "avahi-daemon.socket": ("not-found", "inactive")}
        self.patch(c.pkgsvc, "svc_state", lambda u: states[u])
        r = c.ServiceDisabled("avahi", self.UNITS, {})
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertEqual(chk.current, "avahi-daemon.service=enabled/active")
        states["avahi-daemon.service"] = ("masked", "inactive")
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        states["avahi-daemon.service"] = ("not-found", "inactive")
        self.assertEqual(r.check(FakeCtx()).current, "未安裝")

    def test_fix_masks_existing_units_only(self):
        self.patch(c.pkgsvc, "svc_exists", lambda u: u.endswith(".service"))
        fx = FakeFx()
        c.ServiceDisabled("avahi", self.UNITS, {}).fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("mask"), ["avahi-daemon.service"])
        self.assertEqual(fx.ctx.intended_stops, {"avahi-daemon.service"})


# TWGCB-01-008-0133 / 012-0133 / 014-0113 auditd 服務；008-0175 / 012-0175 / 014-0150 rsyslog 服務
class TestServiceEnabled(Base):
    def test_check_and_fix_masked(self):
        inst = {"v": False}
        self.patch(c.pkgsvc, "pkg_installed", lambda osi, p: inst["v"])
        self.patch(c.pkgsvc, "svc_state", lambda u: ("masked", "inactive"))
        r = c.ServiceEnabled("auditd", "日誌與稽核", "auditd", {"rhel": "audit", "debian": "auditd"}, {})
        chk = r.check(FakeCtx("ubuntu2204"))
        self.assertEqual((chk.status, chk.current), (FAIL, "未安裝套件 auditd"))
        fx = FakeFx(FakeCtx("rhel9"))
        r.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("pkg_install", "audit"))
        self.assertLess(ev.index(("run", "systemctl unmask auditd")), ev.index(("enable", "auditd")))
        inst["v"] = True
        self.assertEqual(r.check(FakeCtx()).current, "masked / inactive")


# TWGCB-01-008-0103 / 012-0103 / 014-0088 telnet 用戶端套件
class TestPackageAbsent(Base):
    def test_check_fix(self):
        self.patch(c.pkgsvc, "pkg_installed", lambda osi, p: True)
        r = c.PackageAbsent("telnet", "telnet", {})
        self.assertEqual(r.check(FakeCtx()).status, FAIL)
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("pkg_remove"), ["telnet"])


# TWGCB-01-008-0108 / 012-0108 / 014-0089 IP 轉送
class TestSysctl(Base):
    def test_precondition_detects_virtualization(self):
        self.patch(c.pkgsvc, "svc_state", lambda u: ("enabled", "active" if u == "docker" else "inactive"))
        self.patch(c.os.path, "isdir", lambda p: p == "/sys/class/net")
        self.patch(c.os, "listdir", lambda p: ["eth0", "virbr0"])
        r = c.Sysctl("IP 轉送", [("net.ipv4.ip_forward", "0")], {}, forwarding=True)
        why = r.precondition(FakeCtx(include_risky=False))
        self.assertIn("docker, virbr0", why)
        self.assertIsNone(r.precondition(FakeCtx(include_risky=True)))

    def test_precondition_clean(self):
        self.patch(c.pkgsvc, "svc_state", lambda u: ("disabled", "inactive"))
        self.patch(c.os.path, "isdir", lambda p: False)
        r = c.Sysctl("IP 轉送", [("net.ipv4.ip_forward", "0")], {}, forwarding=True)
        self.assertIsNone(r.precondition(FakeCtx(include_risky=False)))

    def test_fix_comments_conflicts_and_overrides_vendor_file(self):
        vendor = "/usr/lib/sysctl.d/50-default.conf"
        own = "/etc/sysctl.d/60-gcb-checker.conf"
        self.env(fs={vendor: "net.ipv4.ip_forward = 1\nkernel.x = 1\n",
                     own: "net.ipv6.conf.all.forwarding = 0\n"})
        where = {"net.ipv4.ip_forward": [(vendor, "1")],
                 "net.ipv6.conf.all.forwarding": [(own, "0")]}
        rt = {"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "0"}
        self.patch(c.pkgsvc, "sysctl_runtime", lambda k: rt[k])
        self.patch(c.pkgsvc, "sysctl_persistent", lambda k: (where[k][-1][1], where[k][-1][0], where[k]))
        r = c.Sysctl("IP 轉送", [("net.ipv4.ip_forward", "0"), ("net.ipv6.conf.all.forwarding", "0")], {})
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        ctx, fx = self.fx()
        r.fix(ctx, fx)
        # 套件檔不直接修改，改寫 /etc/sysctl.d 同名檔覆蓋
        self.assertEqual(fx.fs[vendor], "net.ipv4.ip_forward = 1\nkernel.x = 1\n")
        self.assertEqual(fx.fs["/etc/sysctl.d/50-default.conf"],
                         "# *REMOVED* by gcb-checker: net.ipv4.ip_forward = 1\nkernel.x = 1\n")
        self.assertEqual(te.get_kv(fx.fs[own], "net.ipv4.ip_forward"), "0")
        self.assertEqual(fx.kinds("sysctl"), ["net.ipv4.ip_forward"])
        self.assertIn(("run", "sysctl -w net.ipv6.route.flush=1"), fx.events)


class TestGrubCmdline(Base):
    def test_effective_with_dropins(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n',
                     "/etc/default/grub.d/50-cloud.cfg": 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} console=ttyS0"\n',
                     "/etc/default/grub.d/60-x.cfg": "GRUB_CMDLINE_LINUX='$GRUB_CMDLINE_LINUX a=1' # 註解\n"},
                 globs={"/etc/default/grub.d/*.cfg": ["/etc/default/grub.d/60-x.cfg",
                                                      "/etc/default/grub.d/50-cloud.cfg"]})
        self.assertEqual(c.grub_effective_cmdline(), "quiet console=ttyS0 a=1")


GRUBBY = """index=0
kernel="/boot/vmlinuz-5.14"
args="ro quiet"
root="/dev/sda1"
index=1
kernel="/boot/vmlinuz-5.10"
args="ro audit=1"
"""


# TWGCB-01-008-0134 / 012-0134 / 014-0114 稽核 auditd 服務啟動前之程序（audit=1）
class TestGrubArg(Base):
    def rule(self):
        return c.GrubArg("audit", "audit=1", {})

    def test_rhel_entries_errors(self):
        self.env(which={})
        self.assertEqual(self.rule()._entries_missing(FakeCtx("rhel9")), (None, "找不到 grubby"))
        self.env(which={"grubby": "/usr/sbin/grubby"}, runner=FakeRunner({"grubby": res(1)}))
        self.assertEqual(self.rule()._entries_missing(FakeCtx("rhel9")), (None, "grubby 執行失敗"))

    def test_rhel_check(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="ro audit=1"\n', "/proc/cmdline": "ro audit=1"},
                 which={"grubby": "/usr/sbin/grubby"}, runner=FakeRunner({"grubby --info=ALL": res(0, GRUBBY)}))
        chk = self.rule().check(FakeCtx("rhel9"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("開機項目缺少:1 個", chk.current)
        self.assertIn("目前核心已生效:是", chk.current)
        self.runner.add("grubby --info=ALL", res(0, GRUBBY.replace("ro quiet", "ro audit=1")))
        self.assertEqual(self.rule().check(FakeCtx("rhel9")).status, PASS)

    def test_check_errors(self):
        self.env(fs={})
        self.assertEqual(self.rule().check(FakeCtx("rhel9")).status, ERROR)
        self.fs["/etc/default/grub"] = 'GRUB_CMDLINE_LINUX="audit=1"\n'
        chk = self.rule().check(FakeCtx("ubuntu2204"))   # 找不到 /boot/grub/grub.cfg
        self.assertEqual((chk.status, chk.current), (ERROR, "找不到 /boot/grub/grub.cfg"))

    def test_debian_check(self):
        cfg = "menuentry x {\n  linux /vmlinuz root=/dev/sda ro audit=1\n}\n  linux /vmlinuz.old root=/dev/sda ro\n"
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="audit=1"\n', "/boot/grub/grub.cfg": cfg})
        chk = self.rule().check(FakeCtx("ubuntu2204"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("開機項目缺少:1 個", chk.current)
        self.assertIn("否（需重開機）", chk.current)

    def test_debian_fix_adds_dropin_when_overridden(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n',
                     "/etc/default/grub.d/50-cloud.cfg": 'GRUB_CMDLINE_LINUX="console=ttyS0"\n'},
                 globs={"/etc/default/grub.d/*.cfg": ["/etc/default/grub.d/50-cloud.cfg"]})
        ctx, fx = self.fx("ubuntu2204")
        self.rule().fix(ctx, fx)
        drop = "/etc/default/grub.d/99-gcb-audit.cfg"
        self.assertEqual(fx.fs[drop], 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1"\n')
        self.assertEqual(fx.fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX="quiet audit=1"\n')
        # 回滾的 update-grub 要先登記，反向執行時才會在還原檔案後重新產生
        self.assertEqual(fx.events[0], ("undo", "update-grub"))
        self.assertEqual(fx.events[-1], ("run", "update-grub"))

    def test_debian_fix_without_override(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n'})
        ctx, fx = self.fx("ubuntu2204")
        self.rule().fix(ctx, fx)
        self.assertEqual(fx.kinds("write"), ["/etc/default/grub"])

    def test_debian_fix_dry_run(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n',
                     "/etc/default/grub.d/50-cloud.cfg": 'GRUB_CMDLINE_LINUX="console=ttyS0"\n'},
                 globs={"/etc/default/grub.d/*.cfg": ["/etc/default/grub.d/50-cloud.cfg"]})
        ctx, fx = self.fx("ubuntu2204", dry_run=True)
        self.rule().fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX="quiet"\n')
        self.assertNotIn("/etc/default/grub.d/99-gcb-audit.cfg", fx.fs)

    def test_rhel_fix(self):
        self.env(fs={"/etc/default/grub": 'GRUB_CMDLINE_LINUX="ro"\n'}, which={"grubby": "/usr/sbin/grubby"},
                 runner=FakeRunner({"grubby --info=ALL": res(0, GRUBBY)}),
                 globs={"/boot/loader/entries/*.conf": ["/boot/loader/entries/a.conf"]})
        ctx, fx = self.fx("rhel9")
        self.rule().fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX="ro audit=1"\n')
        self.assertEqual(fx.kinds("backup"), ["/boot/loader/entries/a.conf", "/boot/grub2/grubenv"])
        undo = ("undo", "grubby --update-kernel /boot/vmlinuz-5.14 --remove-args audit=1")
        do = ("run", "grubby --update-kernel /boot/vmlinuz-5.14 --args audit=1")
        self.assertLess(fx.events.index(undo), fx.events.index(do))
        self.assertEqual(len(fx.kinds("undo")), 1)   # 已有 audit=1 的項目不處理

    def test_rhel_fix_grubby_missing(self):
        self.env(fs={"/etc/default/grub": ""})
        ctx, fx = self.fx("rhel9")
        with self.assertRaises(FixError):
            self.rule().fix(ctx, fx)


# TWGCB-01-008-0188 / 012-0186 SELinux 啟用狀態
class TestSELinux(Base):
    def test_check(self):
        self.env(which={})
        r = c.SELinuxEnforcing({})
        self.assertEqual(r.check(FakeCtx()).status, ERROR)
        self.env(fs={"/etc/selinux/config": "SELINUX=enforcing\n"}, which={"getenforce": "/usr/sbin/getenforce"},
                 runner=FakeRunner({"getenforce": res(0, "Enforcing\n")}))
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        self.runner.add("getenforce", res(1))
        chk = r.check(FakeCtx())
        self.assertEqual((chk.status, chk.current), (FAIL, "設定檔=enforcing、目前=未知"))
        self.fs.clear()
        self.assertIn("設定檔=未設定", r.check(FakeCtx()).current)

    def test_fix_from_disabled_is_two_stage(self):
        self.env(fs={"/etc/selinux/config": "SELINUX=disabled\n"}, runner=FakeRunner({"getenforce": res(0, "Disabled")}))
        ctx, fx = self.fx()
        c.SELinuxEnforcing({}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/selinux/config"], "SELINUX=permissive\n")
        self.assertEqual(fx.fs["/.autorelabel"], "")
        self.assertTrue(fx.partial)
        self.assertEqual(len(fx.notes), 1)
        self.assertEqual(fx.kinds("run"), [])

    def test_fix_from_permissive(self):
        self.env(fs={"/etc/selinux/config": "SELINUX=permissive\n"},
                 runner=FakeRunner({"getenforce": res(0, "Permissive")}))
        ctx, fx = self.fx()
        c.SELinuxEnforcing({}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/selinux/config"], "SELINUX=enforcing\n")
        self.assertLess(fx.events.index(("undo", "setenforce 0")), fx.events.index(("run", "setenforce 1")))

    def test_fix_runtime_already_enforcing(self):
        self.env(fs={"/etc/selinux/config": "SELINUX=permissive\n"},
                 runner=FakeRunner({"getenforce": res(0, "Enforcing")}))
        ctx, fx = self.fx()
        c.SELinuxEnforcing({}).fix(ctx, fx)
        self.assertEqual(fx.kinds("undo"), [])
        self.assertFalse(fx.partial)


# TWGCB-01-014-0157 AppArmor 啟用狀態
class TestAppArmor(Base):
    EN = "/sys/module/apparmor/parameters/enabled"
    PROF = "/sys/kernel/security/apparmor/profiles"

    def test_check(self):
        self.env(fs={})
        r = c.AppArmorEnforce({})
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).current, "AppArmor 未啟用")
        self.fs[self.EN] = "Y\n"
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).status, ERROR)
        self.fs[self.PROF] = ""
        self.assertIn("沒有載入任何設定檔", r.check(FakeCtx("ubuntu2204")).current)
        self.fs[self.PROF] = "/usr/sbin/a (enforce)\nb (complain)\n"
        chk = r.check(FakeCtx("ubuntu2204"))
        self.assertEqual((chk.status, chk.current), (FAIL, "complain 模式設定檔 1 個：b"))
        self.fs[self.PROF] = "/usr/sbin/a (enforce)\n"
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).status, PASS)

    def test_fix_requires_kernel_support(self):
        self.env(fs={})
        ctx, fx = self.fx("ubuntu2204")
        with self.assertRaises(ManualRequired):
            c.AppArmorEnforce({}).fix(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_switches_only_complain_files(self):
        files = ["/etc/apparmor.d/a", "/etc/apparmor.d/b", "/etc/apparmor.d/c", "/etc/apparmor.d/tunables"]
        self.env(fs={self.EN: "Y", "/etc/apparmor.d/a": "profile a flags=(attach_disconnected,complain) {}",
                     "/etc/apparmor.d/b": "profile b flags=(complain) {}", "/etc/apparmor.d/c": "profile c {}"},
                 globs={"/etc/apparmor.d/*": files, "/etc/apparmor.d/disable/*": ["/etc/apparmor.d/disable/b"]})
        self.patch(c.os.path, "isfile", lambda p: p != "/etc/apparmor.d/tunables")
        self.patch(c.os.path, "exists", lambda p: p == "/etc/apparmor.d/disable/b")
        ctx, fx = self.fx("ubuntu2204")
        c.AppArmorEnforce({}).fix(ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("pkg_install", "apparmor-utils"))     # 沒有 aa-enforce 時先安裝
        self.assertLess(ev.index(("undo", "systemctl reload apparmor")), ev.index(("backup_dir", "/etc/apparmor.d")))
        self.assertEqual(fx.kinds("run"), ["aa-enforce /etc/apparmor.d/a"])   # 已停用的 b 不重新啟用
        self.assertIn("b", fx.notes[0])

    def test_fix_nothing_to_switch(self):
        self.env(fs={self.EN: "Y"}, which={"aa-enforce": "/usr/sbin/aa-enforce"})
        ctx, fx = self.fx("ubuntu2204")
        c.AppArmorEnforce({}).fix(ctx, fx)
        self.assertEqual(fx.kinds("run"), [])
        self.assertEqual(fx.kinds("pkg_install"), [])
        self.assertEqual(fx.notes, [])


SHADOW = ("root:$6$x:19990:0:90:7:::\n"
          "locked:!:19990:0:99999:7:::\n"
          "old:$6$y::0:99999:7:::\n"
          "new:$6$z:19990:0::7:::\n"
          "bad:$6$w:19990:0:abc:7:::\n")


# TWGCB-01-008-0227 / 012-0225 / 014-0184 通行碼最長使用期限
class TestPassMaxDays(Base):
    def test_check(self):
        self.env(fs={"/etc/shadow": SHADOW, "/etc/login.defs": "PASS_MAX_DAYS\tabc\n"})
        r = c.PassMaxDays({})
        self.assertEqual([u["name"] for u in r._bad_users()], ["old", "new", "bad"])
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertIn("new(未設定)", chk.current)
        self.fs["/etc/shadow"] = "root:$6$x:19990:0:90:7:::\n"
        self.fs["/etc/login.defs"] = "PASS_MAX_DAYS\t90\n"
        self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_fix_skips_expired_unless_risky(self):
        self.env(fs={"/etc/shadow": SHADOW, "/etc/login.defs": "PASS_MAX_DAYS\t99999\n"})
        self.patch(c.time, "time", lambda: 20000 * 86400.0)
        ctx, fx = self.fx(include_risky=False)
        c.PassMaxDays({}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/login.defs"], "PASS_MAX_DAYS\t90\n")
        # old 的 lastchg 空白 → 視為很久沒改，套用後立即過期，略過
        self.assertEqual(fx.kinds("chage"), ["new", "bad"])
        self.assertTrue(fx.partial)
        self.assertIn("old", fx.notes[0])
        ctx, fx = self.fx(include_risky=True)
        c.PassMaxDays({}).fix(ctx, fx)
        self.assertEqual(fx.kinds("chage"), ["old", "new", "bad"])
        self.assertFalse(fx.partial)


# TWGCB-01-008-0210 / 012-0208 / 014-0173 通行碼最小長度
class TestPassMinLen(Base):
    DROP = "/etc/security/pwquality.conf.d/10-x.conf"

    def test_rhel_check_with_pam_override(self):
        self.env(fs={"/etc/security/pwquality.conf": "minlen = 12\n", self.DROP: "minlen = x\n",
                     "/etc/login.defs": "PASS_MIN_LEN\t12\n",
                     "/etc/pam.d/system-auth": "password requisite pam_pwquality.so minlen=8\n"
                                               "#password requisite pam_pwquality.so minlen=1\n"},
                 globs={"/etc/security/pwquality.conf.d/*.conf": [self.DROP]})
        r = c.PassMinLen({})
        self.assertFalse(r._ge12("x"))
        chk = r.check(FakeCtx("rhel9"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("PAM 參數覆寫：/etc/pam.d/system-auth minlen=8", chk.current)
        self.assertIn("10-x.conf=x", chk.current)

    def test_debian_check_pam_not_enabled(self):
        self.env(fs={"/etc/security/pwquality.conf": "minlen=12\n",
                     "/etc/pam.d/common-password": "password [success=1] pam_unix.so\n"})
        self.patch(c.pkgsvc, "pkg_installed", lambda osi, p: True)
        chk = c.PassMinLen({}).check(FakeCtx("ubuntu2204"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("未啟用 pam_pwquality", chk.current)
        self.fs["/etc/pam.d/common-password"] = "password requisite pam_pwquality.so retry=3\n"
        self.assertEqual(c.PassMinLen({}).check(FakeCtx("ubuntu2204")).status, PASS)

    def test_debian_check_package_missing(self):
        self.env(fs={"/etc/security/pwquality.conf": "minlen=12\n"})
        self.patch(c.pkgsvc, "pkg_installed", lambda osi, p: False)
        chk = c.PassMinLen({}).check(FakeCtx("ubuntu2204"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("未安裝 libpam-pwquality", chk.current)

    def test_debian_fix_installs_package_with_backup(self):
        self.env(fs={}, globs={"/var/lib/pam/*": ["/var/lib/pam/password"]})
        self.patch(c.pkgsvc, "pkg_installed", lambda osi, p: False)
        ctx, fx = self.fx("ubuntu2204")
        c.PassMinLen({}).fix(ctx, fx)
        ev = fx.events
        # pam-auth-update 會改寫 common-password，安裝前先備份
        self.assertLess(ev.index(("backup", "/etc/pam.d/common-password")), ev.index(("pkg_install", "libpam-pwquality")))
        self.assertIn(("backup", "/var/lib/pam/password"), ev)
        self.assertEqual(fx.fs["/etc/security/pwquality.conf"], "minlen=12\n")
        self.assertNotIn("/etc/login.defs", fx.fs)

    def test_rhel_fix(self):
        self.env(fs={"/etc/security/pwquality.conf": "minlen = 8\n", self.DROP: "minlen = 9\n",
                     "/etc/pam.d/password-auth": "password requisite pam_pwquality.so minlen=6\n"},
                 globs={"/etc/security/pwquality.conf.d/*.conf": [self.DROP]})
        ctx, fx = self.fx("rhel9")
        c.PassMinLen({}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/security/pwquality.conf"], "minlen = 12\n")
        self.assertEqual(fx.fs[self.DROP], te.MARK + "minlen = 9\n")
        self.assertEqual(fx.fs["/etc/login.defs"], "PASS_MIN_LEN\t12\n")
        self.assertTrue(fx.partial)
        self.assertIn("password-auth minlen=6", fx.notes[0])
        # PAM 檔不自動修改
        self.assertEqual(fx.fs["/etc/pam.d/password-auth"], "password requisite pam_pwquality.so minlen=6\n")


# TWGCB-01-008-0220 / 012-0218 / 014-0178 帳戶鎖定閾值
class TestFaillock(Base):
    # pam-auth-update 產生的 common-auth（success=2 是因其後有 pam_deny／pam_permit，與 GCB 範本的 success=1 等效）
    UBUNTU_AUTH = ("auth\trequired\tpam_faillock.so preauth\n"
                   "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n"
                   "auth\t[default=die]\tpam_faillock.so authfail\n"
                   "auth\trequisite\tpam_deny.so\nauth\trequired\tpam_permit.so\nauth\toptional\tpam_cap.so\n"
                   "auth\tsufficient\tpam_faillock.so authsucc\n")

    def test_check(self):
        self.env(fs={c.Faillock.CONF: "deny = 5\n", "/etc/pam.d/common-auth": self.UBUNTU_AUTH,
                     "/etc/pam.d/common-account": "account required pam_faillock.so\n"})
        r = c.Faillock({})
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).status, PASS)
        # 缺 GCB 範本的 authsucc 行（或 preauth 為 requisite）→ 未完整啟用
        self.fs["/etc/pam.d/common-auth"] = self.UBUNTU_AUTH.replace("auth\tsufficient\tpam_faillock.so authsucc\n", "")
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).current, "deny=5、pam_faillock:未啟用")
        self.fs["/etc/pam.d/common-auth"] = self.UBUNTU_AUTH.replace("required\tpam_faillock.so preauth",
                                                                     "requisite\tpam_faillock.so preauth")
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).status, FAIL)
        self.fs["/etc/pam.d/common-auth"] = self.UBUNTU_AUTH
        pam = "auth required pam_faillock.so preauth\n"
        chk = r.check(FakeCtx("rhel9"))      # RHEL 的 system-auth 沒有 pam_faillock
        self.assertEqual((chk.status, chk.current), (FAIL, "deny=5、pam_faillock:未啟用"))
        self.fs[c.Faillock.CONF] = "deny = 0\n"
        self.assertEqual(r.check(FakeCtx("ubuntu2204")).status, FAIL)
        self.fs.pop(c.Faillock.CONF)
        self.assertIn("deny=未設定", r.check(FakeCtx("ubuntu2204")).current)

    def test_rhel81_manual(self):
        self.env()
        ctx, fx = self.fx("rhel8", version="8.1")
        with self.assertRaises(ManualRequired):
            c.Faillock({}).fix(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_already_active_only_sets_deny(self):
        pam = "auth required pam_faillock.so preauth\n"
        self.env(fs={"/etc/pam.d/system-auth": pam, "/etc/pam.d/password-auth": pam})
        ctx, fx = self.fx("rhel9")
        c.Faillock({}).fix(ctx, fx)
        self.assertEqual(fx.fs[c.Faillock.CONF], "deny = 5\n")
        self.assertEqual(fx.kinds("run"), [])

    def test_rhel_without_authselect(self):
        self.env(runner=FakeRunner({"authselect current": res(2)}))
        ctx, fx = self.fx("rhel9")
        with self.assertRaises(ManualRequired):
            c.Faillock({}).fix(ctx, fx)

    def test_rhel_authselect(self):
        self.env(globs={"/etc/authselect/*": ["/etc/authselect/authselect.conf", "/etc/authselect/custom"],
                        "/var/lib/authselect/*": ["/var/lib/authselect/system-auth"]})
        self.patch(c.os.path, "isfile", lambda p: p != "/etc/authselect/custom")
        ctx, fx = self.fx("rhel9")
        c.Faillock({}).fix(ctx, fx)
        self.assertEqual(fx.kinds("backup"), ["/etc/authselect/authselect.conf", "/var/lib/authselect/system-auth"])
        undo = ("undo", "authselect disable-feature with-faillock")
        do = ("run", "authselect enable-feature with-faillock")
        self.assertLess(fx.events.index(undo), fx.events.index(do))
        self.assertLess(fx.events.index(("backup", "/var/lib/authselect/system-auth")), fx.events.index(do))

    def test_ubuntu_pam_auth_update(self):
        self.env()
        ctx, fx = self.fx("ubuntu2204")
        c.Faillock({}).fix(ctx, fx)
        for path, content in c.UBUNTU_FAILLOCK_PROFILES.items():
            self.assertEqual(fx.fs[path], content)
        self.assertIn("/etc/pam.d/common-auth", fx.kinds("backup"))
        self.assertEqual(fx.kinds("run")[-1],
                         "pam-auth-update --enable gcb_faillock gcb_faillock_authsucc gcb_faillock_notify")
        self.assertIn("\trequired\tpam_faillock.so preauth", fx.fs["/usr/share/pam-configs/gcb_faillock_notify"])
        self.assertIn("Auth-Type: Additional", fx.fs["/usr/share/pam-configs/gcb_faillock_authsucc"])
        self.assertIn("Priority: -1", fx.fs["/usr/share/pam-configs/gcb_faillock_authsucc"])  # 排在 pam_cap 之後

    def test_ubuntu_pam_auth_update_failures(self):
        for r in (res(1, "", "boom"), res(0, "", "Local modifications to /etc/pam.d/common-*, not updating.")):
            self.env(runner=FakeRunner({"pam-auth-update": r}))
            ctx, fx = self.fx("ubuntu2204")
            with self.assertRaises(FixError):
                c.Faillock({}).fix(ctx, fx)

    def test_ubuntu_dry_run(self):
        self.env()
        ctx, fx = self.fx("ubuntu2204", dry_run=True)
        c.Faillock({}).fix(ctx, fx)   # 預覽時 run 回傳 None，不可誤判失敗
        self.assertEqual(fx.fs, {})


class TestSshdArgs(Base):
    def test_hook(self):
        self.patch(c, "SSHD_ARGS_HOOK", None)
        self.assertEqual(c.sshd_args(FakeCtx()), [])
        self.patch(c, "SSHD_ARGS_HOOK", lambda ctx: ("-oCiphers=x",))
        self.assertEqual(c.sshd_args(FakeCtx()), ["-oCiphers=x"])
        self.patch(c, "SSHD_ARGS_HOOK", mock.Mock(side_effect=OSError("x")))
        self.assertEqual(c.sshd_args(FakeCtx()), [])


# TWGCB-01-008-0277 / 012-0269 SSH PermitRootLogin 參數
class TestSshdOption(Base):
    def setUp(self):
        self.patch(c, "SSHD_ARGS_HOOK", None)

    def rule(self):
        return c.SshdOption("PermitRootLogin", "PermitRootLogin", "no", {})

    def test_check(self):
        self.env(which={})
        self.assertEqual(self.rule().check(FakeCtx()).status, NA)
        self.env(which={"sshd": "/usr/sbin/sshd"}, runner=FakeRunner({"sshd -T": res(255, "", "bad config")}))
        chk = self.rule().check(FakeCtx())
        self.assertEqual((chk.status, chk.current), (ERROR, "sshd -T 執行失敗：bad config"))
        self.runner.add("sshd -T", res(0, "port 22\npermitrootlogin no\n"))
        self.assertEqual(self.rule().check(FakeCtx()).status, PASS)

    def test_precondition(self):
        ctx = FakeCtx()
        self.assertIsNone(self.rule().precondition(ctx))
        ctx.pre_health_status["H05"] = "失敗"
        self.assertIn("略過", self.rule().precondition(ctx))

    def test_fix(self):
        drop = "/etc/ssh/sshd_config.d/50-cloud.conf"
        self.env(fs={c.SshdOption.MAIN: "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
                     drop: "PermitRootLogin yes\n"},
                 which={"sshd": "/usr/sbin/sshd"}, globs={"/etc/ssh/sshd_config.d/*.conf": [drop]})
        ctx, fx = self.fx("rhel9")
        self.rule().fix(ctx, fx)
        self.assertIn("PermitRootLogin no", fx.fs[c.SshdOption.MAIN])
        self.assertEqual(fx.fs[drop], te.MARK + "PermitRootLogin yes\n")
        self.assertEqual(fx.events[0], ("undo", "systemctl reload sshd"))
        self.assertEqual(fx.kinds("run"), ["/usr/sbin/sshd -t", "systemctl reload sshd"])

    def test_fix_syntax_error_no_reload(self):
        self.env(fs={c.SshdOption.MAIN: ""}, which={"sshd": "/usr/sbin/sshd"},
                 runner=FakeRunner({"sshd -t": res(1)}))
        ctx, fx = self.fx("ubuntu2204")
        with self.assertRaises(FixError):
            self.rule().fix(ctx, fx)
        self.assertNotIn(("run", "systemctl reload ssh"), fx.events)


# Ubuntu 0102 / RHEL 0121 所有網路介面啟用逆向路徑過濾功能：各介面實際值（核心取 all 與介面值的較大者）
class TestRpFilterIfaces(unittest.TestCase):
    PROC = {"/proc/sys/net/ipv4/conf/all/rp_filter": "1\n", "/proc/sys/net/ipv4/conf/default/rp_filter": "2\n",
            "/proc/sys/net/ipv4/conf/eth0/rp_filter": "2\n", "/proc/sys/net/ipv4/conf/lo/rp_filter": "0\n"}

    def env(self, proc, glob_val=None):
        fs = dict(proc)
        pats = sorted(fs)
        persist = (glob_val, "/usr/lib/sysctl.d/50-default.conf", []) if glob_val else (None, None, [])
        for target, val in ((c.glob, "glob"),):
            p = mock.patch.object(target, val, lambda pat: [x for x in pats if x.startswith("/proc/sys/net/ipv4/conf/")])
            p.start()
            self.addCleanup(p.stop)
        for p in (mock.patch.object(c, "read_text", fs_reader(fs)),
                  mock.patch.object(c.pkgsvc, "sysctl_persistent",
                                    lambda key: persist if key == c.RP_GLOB else (None, None, []))):
            p.start()
            self.addCleanup(p.stop)

    def test_loose_detected(self):
        self.env(self.PROC, glob_val="2")
        loose, pv, src = c.rp_filter_loose()
        self.assertEqual(loose, [("eth0", "2")])  # all、default 不算；lo=0 取 all 的 1 為嚴格
        self.assertEqual((pv, src), ("2", "/usr/lib/sysctl.d/50-default.conf"))
        chk = c.RpFilterIfaces()._rp_check(c.Check(PASS, "net.ipv4.conf.all.rp_filter 目前=1 開機=1"))
        self.assertEqual(chk.status, FAIL)
        self.assertIn("介面 eth0 rp_filter=2 為寬鬆模式", chk.current)
        self.assertIn("50-default.conf 設定 net.ipv4.conf.*.rp_filter=2，重開機後各介面會回到寬鬆模式", chk.current)

    def test_fix_overrides_glob_and_runtime(self):
        self.env(self.PROC, glob_val="2")
        fx = FakeFx(FakeCtx("ubuntu2204"), fs={})
        c.RpFilterIfaces()._rp_fix(fx, "/etc/sysctl.d/60-gcb-checker.conf")
        self.assertEqual(fx.fs["/etc/sysctl.d/60-gcb-checker.conf"], "net.ipv4.conf.*.rp_filter = 1\n")
        self.assertEqual(fx.events[-1], ("sysctl", "net.ipv4.conf.eth0.rp_filter", "1"))  # 以 sysctl_set 記錄原值供回滾

    def test_strict_everywhere_passes(self):
        proc = dict(self.PROC, **{"/proc/sys/net/ipv4/conf/eth0/rp_filter": "1\n"})
        self.env(proc)
        chk = c.RpFilterIfaces()._rp_check(c.Check(PASS, "ok"))
        self.assertEqual((chk.status, chk.current), (PASS, "ok"))
        fx = FakeFx(FakeCtx(), fs={})
        c.RpFilterIfaces()._rp_fix(fx, "/etc/sysctl.d/60-gcb-checker.conf")
        self.assertEqual(fx.events, [])
        na = c.Check(NA, "x")
        self.assertIs(c.RpFilterIfaces()._rp_check(na), na)


if __name__ == "__main__":
    unittest.main()
