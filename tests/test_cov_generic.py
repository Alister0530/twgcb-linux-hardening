# -*- coding: utf-8 -*-
"""通用規則類型（gcb/rules/generic.py）模擬測試：掛載選項、設定檔參數、檔案權限、稽核規則。"""
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
from gcb.rules import generic as g  # noqa: E402
from gcb.rules.base import FAIL, NA, PASS  # noqa: E402


class Base(unittest.TestCase):
    def env(self, fs=None, runner=None, which=None, globs=None):
        self.fs = fs if fs is not None else {}
        self.runner = runner or FakeRunner()
        which = which or {}
        globs = globs or {}
        for obj, name, val in ((g, "read_text", fs_reader(self.fs)), (g, "run", self.runner),
                               (g, "which", lambda n: which.get(n)),
                               (g.glob, "glob", lambda pat: list(globs.get(pat, [])))):
            self.patch(obj, name, val)

    def patch(self, obj, attr, val):
        p = mock.patch.object(obj, attr, val)
        p.start()
        self.addCleanup(p.stop)

    def fx(self, key="rhel9", **kw):
        ctx = FakeCtx(key, **kw)
        return ctx, FakeFx(ctx, fs=self.fs, runner=self.runner)


class TestHelpers(Base):
    def test_ids_and_all_of(self):
        self.assertEqual(g._ids("rhel9", 7, "TWGCB-01-012"), {"rhel9": "TWGCB-01-012-0007"})
        self.assertIsNone(g.all_of(lambda ctx: None, lambda ctx: None)(FakeCtx()))
        self.assertEqual(g.all_of(lambda ctx: None, lambda ctx: "x")(FakeCtx()), "x")

    def test_installed_when(self):
        self.patch(g.pkgsvc, "pkg_installed", lambda osi, p: p == "audit")
        self.assertIsNone(g.installed(g.AUDIT_PKG)(FakeCtx("rhel9")))
        self.assertEqual(g.installed(g.AUDIT_PKG)(FakeCtx("ubuntu2204")), "未安裝 auditd，沒有需要檢查的設定")

    def test_compare(self):
        self.assertFalse(g.compare(None, "eq", "x"))
        self.assertTrue(g.compare(" Yes ", "eq", "yes"))
        self.assertTrue(g.compare("INFO", "in", ["verbose", "info"]))
        self.assertFalse(g.compare("abc", "ge", 1))           # 非數字
        self.assertFalse(g.compare("", "le", 1))              # 空字串
        self.assertTrue(g.compare("5 # 註解", "le", 5))
        self.assertTrue(g.compare("90", "ge", 90))
        self.assertTrue(g.compare("3", "range", (1, 4)))
        with self.assertRaises(ValueError):
            g.compare("3", "xx", 1)
        self.assertIsNone(g._num("x"))


# 磁碟與檔案系統：停用核心模組（cramfs、squashfs、udf…）
class TestModule(Base):
    def test_builtin(self):
        self.env(fs={"/proc/modules": ""})
        self.patch(g, "module_builtin", lambda m: True)
        r = g.Module("squashfs", {}, risk="B", title="squashfs 檔案系統")
        self.assertIn("已編入核心", r.check(FakeCtx()).current)
        ctx, fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_module_builtin_reads_file(self):
        self.env(fs={})
        self.patch(g.os, "uname", lambda: mock.Mock(release="5.15.0"))
        self.fs["/lib/modules/5.15.0/modules.builtin"] = "kernel/fs/udf/udf.ko\n"
        self.assertTrue(g.module_builtin("udf"))
        self.assertFalse(g.module_builtin("cramfs"))

    def test_in_use_precondition_and_fix(self):
        self.env(fs={"/proc/modules": ""})
        self.patch(g, "module_builtin", lambda m: False)
        r = g.Module("squashfs", {}, in_use=lambda ctx: "snap 正在使用 squashfs")
        self.assertIn("--include-risky", r.precondition(FakeCtx(include_risky=False)))
        self.assertIsNone(r.precondition(FakeCtx(include_risky=True)))
        self.assertIsNone(g.Module("x", {}).precondition(FakeCtx(include_risky=False)))
        ctx, fx = self.fx()
        r.fix(ctx, fx)
        self.assertIn("blacklist squashfs", fx.fs["/etc/modprobe.d/squashfs.conf"])


MOUNTS = "tmpfs /tmp tmpfs rw,nosuid 0 0\n/dev/sdb1 /home xfs rw,nodev 0 0\n"


# 磁碟與檔案系統：/tmp、/home、/dev/shm 等掛載選項（nodev / nosuid / noexec）
class TestMountOption(Base):
    def test_not_separate_partition_is_fail(self):
        # GCB 掛載選項條目沒有「若為獨立分割」的前提，非獨立分割依字面判定不合格、需人工
        self.env(fs={"/proc/self/mounts": MOUNTS})
        r = g.MountOption("/var/tmp", "nodev", {})
        self.assertIsNone(r.not_applicable(FakeCtx()))
        c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "/var/tmp 不是獨立的磁碟分割，無法設定掛載選項；"
                                                       "需先完成「設定 /var/tmp 目錄之檔案系統」（建立獨立分割）"))
        ctx, fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            r.fix(ctx, fx)
        self.assertIn("建立獨立分割", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_unmounted_with_boot_config(self):
        # /tmp 已寫入 fstab（例如改為 tmpfs）但尚未重開機：有選項判合格，缺選項只改 fstab、不 remount
        fstab = "tmpfs /tmp tmpfs defaults,nodev 0 0\n"
        self.env(fs={"/proc/self/mounts": "", "/etc/fstab": fstab})
        c = g.MountOption("/tmp", "nodev", {}).check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "目前未掛載；開機設定（fstab）已含 nodev，重開機後生效"))
        r = g.MountOption("/tmp", "noexec", {})
        self.assertEqual(r.check(FakeCtx()).current, "目前未掛載；開機設定（fstab）無 noexec")
        ctx, fx = self.fx()
        r.fix(ctx, fx)
        self.assertEqual(te.fstab_options(fx.fs["/etc/fstab"], "/tmp"), ["defaults", "nodev", "noexec"])
        self.assertEqual(fx.kinds("run"), ["findmnt --verify"])
        self.assertEqual(fx.kinds("undo"), [])
        self.assertIn("重開機後生效", fx.notes[-1])

    def test_dev_shm_unmounted(self):
        self.env(fs={"/proc/self/mounts": ""})
        c = g.MountOption("/dev/shm", "nodev", {}).check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "目前未掛載；開機設定（未設定）未設定"))

    def test_tmp_mount_unit_sources(self):
        self.env(fs={"/proc/self/mounts": MOUNTS, "/usr/lib/systemd/system/tmp.mount": "Options=mode=1777,nosuid\n"})
        r = g.MountOption("/tmp", "nodev", {})
        self.assertEqual(r._persistent(), ("tmp.mount", ["mode=1777", "nosuid"]))
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertEqual(chk.current, "目前：無；開機設定（tmp.mount）：無")
        self.fs.pop("/usr/lib/systemd/system/tmp.mount")
        self.assertEqual(r._persistent(), ("未設定", None))

    def test_fix_tmp_mount_dropin(self):
        self.env(fs={"/proc/self/mounts": MOUNTS, "/usr/share/systemd/tmp.mount": "[Mount]\nOptions=mode=1777,strictatime\n"})
        ctx, fx = self.fx("ubuntu2204")
        g.MountOption("/tmp", "nodev", {}).fix(ctx, fx)
        self.assertEqual(fx.fs["/etc/systemd/system/tmp.mount.d/60-gcb.conf"],
                         "[Mount]\nOptions=mode=1777,nodev,strictatime\n")
        ev = fx.events
        # 先登記 daemon-reload，再寫 drop-in；remount 的還原也先於 remount 登記
        self.assertEqual(ev[0], ("undo", "systemctl daemon-reload"))
        self.assertLess(ev.index(("undo", "mount -o remount,dev /tmp")), ev.index(("run", "mount -o remount,nodev /tmp")))

    def test_fix_fstab(self):
        fstab = "/dev/sdb1 /home xfs defaults 0 0\n"
        self.env(fs={"/proc/self/mounts": MOUNTS, "/etc/fstab": fstab})
        r = g.MountOption("/home", "nosuid", {})
        ctx, fx = self.fx()
        r.fix(ctx, fx)
        self.assertEqual(te.fstab_options(fx.fs["/etc/fstab"], "/home"), ["defaults", "nosuid"])
        self.assertEqual(fx.kinds("run"), ["findmnt --verify", "mount -o remount,nosuid /home"])
        self.assertEqual(fx.kinds("undo"), ["mount -o remount,suid /home"])

    def test_fix_dev_shm_without_fstab_line(self):
        self.env(fs={"/etc/fstab": ""})
        ctx, fx = self.fx()
        g.MountOption("/dev/shm", "noexec", {}).fix(ctx, fx)
        self.assertEqual(te.fstab_options(fx.fs["/etc/fstab"], "/dev/shm"), ["defaults", "nodev", "nosuid", "noexec"])

    def test_fix_not_in_fstab(self):
        # 已掛載但不在 fstab（例如 autofs）→ 需人工
        self.env(fs={"/proc/self/mounts": MOUNTS, "/etc/fstab": ""})
        ctx, fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            g.MountOption("/home", "nodev", {}).fix(ctx, fx)
        self.assertIn("沒有寫在 /etc/fstab", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_fix_fstab_verify_error(self):
        self.env(fs={"/etc/fstab": "/dev/sdb1 /home xfs defaults 0 0\n"},
                 runner=FakeRunner({"findmnt": res(1, "[E] parse error at line 3")}))
        ctx, fx = self.fx()
        with self.assertRaises(FixError):
            g.MountOption("/home", "nodev", {}).fix(ctx, fx)
        self.assertNotIn("mount -o remount,nodev /home", fx.kinds("run"))

    def test_fix_fstab_verify_warning_only(self):
        self.env(fs={"/proc/self/mounts": MOUNTS, "/etc/fstab": "/dev/sdb1 /home xfs defaults 0 0\n"},
                 runner=FakeRunner({"findmnt": res(1, "[W] target not found")}))
        ctx, fx = self.fx()
        g.MountOption("/home", "nodev", {}).fix(ctx, fx)
        self.assertIn("mount -o remount,nodev /home", fx.kinds("run"))


# 安裝與維護軟體：安裝套件（例：aide、sudo）
class TestPackagePresent(Base):
    def test_check_fix(self):
        self.patch(g.pkgsvc, "pkg_installed", lambda osi, p: False)
        r = g.PackagePresent("aide", "aide", {}, "安裝與維護軟體")
        self.assertEqual(r.check(FakeCtx()).current, "未安裝")
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("pkg_install"), ["aide"])


# 設定檔參數：login.defs、auditd.conf、journald drop-in 等
class TestKvSetting(Base):
    DROP = "/etc/systemd/journald.conf.d/*.conf"

    def test_missing_ok(self):
        self.env(fs={})
        r = g.KvSetting("t", "c", {}, "/etc/x.conf", "Key", "1", missing_ok=True)
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        r.missing_ok = False
        self.assertEqual(r.check(FakeCtx()).current, "Key 未設定")

    def test_check_lists_bad_dropins(self):
        self.env(fs={"/etc/systemd/journald.conf": "Storage=persistent\n",
                     "/etc/systemd/journald.conf.d/a.conf": "Storage=volatile\n",
                     "/etc/systemd/journald.conf.d/b.conf": "Storage=persistent\n"},
                 globs={self.DROP: ["/etc/systemd/journald.conf.d/b.conf", "/etc/systemd/journald.conf.d/a.conf"]})
        r = g.KvSetting("t", "c", {}, "/etc/systemd/journald.conf", "Storage", "persistent", dropins=self.DROP)
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertIn("不符合：Storage=volatile（/etc/systemd/journald.conf.d/a.conf）", chk.current)

    def test_fix_writes_dropin_with_section_and_applies(self):
        self.env(fs={"/etc/systemd/journald.conf": "[Journal]\nStorage=auto\n",
                     "/etc/systemd/journald.conf.d/a.conf": "[Journal]\nStorage=volatile\n"},
                 globs={self.DROP: ["/etc/systemd/journald.conf.d/a.conf"]})
        target = "/etc/systemd/journald.conf.d/60-gcb.conf"
        r = g.KvSetting("t", "c", {}, "/etc/systemd/journald.conf", "Storage", "persistent", sep="=",
                        dropins=self.DROP, write_to=target, section="Journal",
                        apply=["systemctl", "restart", "systemd-journald"])
        ctx, fx = self.fx()
        r.fix(ctx, fx)
        self.assertEqual(fx.fs[target], "[Journal]\nStorage=persistent\n")
        self.assertEqual(fx.fs["/etc/systemd/journald.conf"], "[Journal]\n" + te.MARK + "Storage=auto\n")
        self.assertEqual(fx.fs["/etc/systemd/journald.conf.d/a.conf"], "[Journal]\n" + te.MARK + "Storage=volatile\n")
        self.assertEqual(fx.events[0], ("undo", "systemctl restart systemd-journald"))
        self.assertEqual(fx.events[-1], ("run", "systemctl restart systemd-journald"))

    def test_helpers(self):
        r = g.login_defs("t", {}, "PASS_MIN_DAYS", "1", "ge", 1)
        self.assertEqual((r.path, r.sep, r.category), ("/etc/login.defs", "\t", "帳號與存取控制"))
        a = g.auditd_conf("t", {}, "max_log_file", "32", "ge", 32)
        self.assertEqual(a.apply, ["service", "auditd", "reload"])
        self.assertIsNotNone(a.when)


class _N(object):
    def __init__(self, name, gid=0, uid=0):
        self.pw_name = self.gr_name = name
        self.gr_gid = gid
        self.pw_uid = uid


# 檔案與目錄權限（cron、sshd 金鑰、log 檔等）
class TestFilePerm(Base):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(os.path.join(self.d, "sub"))
        self.files = []
        for n in ("a", "sub/b"):
            p = os.path.join(self.d, n)
            with open(p, "w") as f:
                f.write("x")
            os.chmod(p, 0o666)
            self.files.append(p)
        os.symlink(self.files[0], os.path.join(self.d, "link"))

    def test_targets_recursive_and_files_only(self):
        r = g.FilePerm("t", "c", {}, self.d, max_mode=0o644, recursive=True)
        self.assertEqual(sorted(r._targets()), sorted([self.d, os.path.join(self.d, "sub")] + self.files))
        r = g.FilePerm("t", "c", {}, self.d, max_mode=0o644, recursive=True, files_only=True)
        self.assertEqual(sorted(r._targets()), sorted(self.files))   # 不含目錄與連結
        r = g.FilePerm("t", "c", {}, os.path.join(self.d, "*"), max_mode=0o644, files_only=True)
        self.assertEqual(r._targets(), [self.files[0]])

    def test_check_missing(self):
        for missing, st in (("na", NA), ("pass", PASS), ("fail", FAIL)):
            r = g.FilePerm("t", "c", {}, os.path.join(self.d, "none*"), missing=missing)
            self.assertEqual(r.check(FakeCtx()).status, st)

    def test_check_many_bad_and_pass(self):
        for i in range(5):
            p = os.path.join(self.d, "m%d" % i)
            open(p, "w").close()
            os.chmod(p, 0o666)
        r = g.FilePerm("t", "c", {}, os.path.join(self.d, "*"), max_mode=0o600, files_only=True)
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertTrue(chk.current.endswith("…另 1 個"))
        r = g.FilePerm("t", "c", {}, os.path.join(self.d, "*"), max_mode=0o777, files_only=True)
        self.assertEqual(r.check(FakeCtx()).current, "共 6 個檔案皆符合")

    def test_owner_group_check_and_fix(self):
        self.patch(g.pwd, "getpwuid", mock.Mock(side_effect=KeyError))
        self.patch(g.grp, "getgrgid", mock.Mock(side_effect=KeyError))
        self.patch(g.pwd, "getpwnam", lambda n: _N(n, uid=0))
        self.patch(g.grp, "getgrnam", lambda n: _N(n, gid=0))
        st = os.stat(self.files[0])
        r = g.FilePerm("t", "c", {}, self.files[0], owner="root", groups=["root", "adm"], max_mode=0o640)
        self.assertEqual(r.expected, "root:root或adm、640 或更低權限")
        chk = r.check(FakeCtx())
        self.assertEqual(chk.status, FAIL)
        self.assertIn("擁有者 %d" % st.st_uid, chk.current)
        self.assertIn("群組 %d" % st.st_gid, chk.current)
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chown", self.files[0], "root:root"), ("chmod", self.files[0], 0o640)])

    def test_fix_mode_only_and_skip_good(self):
        os.chmod(self.files[1], 0o600)
        r = g.FilePerm("t", "c", {}, self.files, max_mode=0o600)
        fx = FakeFx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chmod", self.files[0], 0o600)])

    def test_pass_single(self):
        self.patch(g.pwd, "getpwuid", lambda uid: _N("root"))
        self.patch(g.grp, "getgrgid", lambda gid: _N("root"))
        os.chmod(self.files[0], 0o600)
        chk = g.FilePerm("t", "c", {}, self.files[0], owner="root", max_mode=0o600).check(FakeCtx())
        self.assertEqual((chk.status, chk.current), (PASS, "root:root 600"))


class TestAuditFilter(Base):
    LINE = "-a always,exit -F arch=b64 -S init_module,create_module -k modules"

    def test_without_ausyscall(self):
        self.env(which={})
        self.assertEqual(g.audit_filter_syscalls(self.LINE), self.LINE)

    def test_with_ausyscall(self):
        self.env(which={"ausyscall": "/usr/bin/ausyscall"},
                 runner=FakeRunner({"create_module": res(1)}))
        self.assertEqual(g.audit_filter_syscalls(self.LINE),
                         "-a always,exit -F arch=b64 -S init_module -k modules")
        self.assertEqual(self.runner.calls, ["ausyscall b64 init_module", "ausyscall b64 create_module"])


# 日誌與稽核：auditd 稽核規則
class TestAuditRules(Base):
    LINES = ["-w /etc/passwd -p wa -k identity", "-a always,exit -F arch=b64 -S create_module -k modules"]

    def rule(self):
        return g.AuditRules("帳號異動", {"rhel9": "TWGCB-01-012-0150"}, self.LINES)

    def test_check(self):
        self.env(which={})
        self.assertEqual(self.rule().check(FakeCtx()).current, "未安裝 auditd")
        self.env(which={"auditctl": "/sbin/auditctl"},
                 runner=FakeRunner({"auditctl -l": res(0, "-w /etc/passwd -p wa -k identity\n")}),
                 globs={"/etc/audit/rules.d/*.rules": ["/etc/audit/rules.d/a.rules"]},
                 fs={"/etc/audit/rules.d/a.rules": "-w /etc/passwd -p wa -k identity\n"})
        chk = self.rule().check(FakeCtx())   # ausyscall 不存在 → 不過濾
        self.assertEqual(chk.status, FAIL)
        self.assertEqual(chk.current, "未生效 1 條、未寫入設定檔 1 條（例：%s）" % self.LINES[1])
        self.runner.add("auditctl -l", res(0, "\n".join(self.LINES)))
        self.fs["/etc/audit/rules.d/a.rules"] = "\n".join(self.LINES)
        self.assertEqual(self.rule().check(FakeCtx()).current, "2 條規則皆已生效")

    def test_fix_requires_auditd(self):
        self.env(which={})
        ctx, fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule().fix(ctx, fx)

    def test_fix_writes_rules_and_loads(self):
        self.env(which={"augenrules": "/sbin/augenrules"},
                 runner=FakeRunner({"augenrules --load": res(0, "enabled 2\n")}))
        ctx, fx = self.fx()
        self.rule().fix(ctx, fx)
        path = "/etc/audit/rules.d/gcb-0150.rules"
        self.assertEqual(fx.fs[path], "## GCB TWGCB-01-012-0150 帳號異動（gcb-checker 產生）\n%s\n" % "\n".join(self.LINES))
        self.assertEqual(fx.modes[path], 0o600)
        self.assertLess(fx.events.index(("undo", "augenrules --load")), fx.events.index(("write", path)))
        self.assertIn("重開機", fx.notes[0])

    def test_fix_normal_load(self):
        self.env(which={"augenrules": "/sbin/augenrules"})
        ctx, fx = self.fx()
        self.rule().fix(ctx, fx)
        self.assertEqual(fx.notes, [])


if __name__ == "__main__":
    unittest.main()
