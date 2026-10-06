# -*- coding: utf-8 -*-
"""ubuntu/system.py 補充單元測試：所有指令、檔案、帳號查詢皆以模擬環境取代（sudoers 驗證暫存檔放在暫存目錄）。"""
import collections
import contextlib
import fnmatch
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import FakeCtx, FakeFx, FakeRunner, fs_reader, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS, Check  # noqa: E402
from gcb.rules.ubuntu import system as sysm  # noqa: E402
from gcb.rules.ubuntu.helpers import U  # noqa: E402


class _St(object):
    def __init__(self, mode=0o100644, uid=0, gid=0, dev=1):
        self.st_mode, self.st_uid, self.st_gid, self.st_dev = mode, uid, gid, dev


@contextlib.contextmanager
def env(fs, runner=None, which=(), dirs=(), pkgs=(), stats=None, listdir=None, exists=(),
        svc=None, sysctl=None):
    """模擬 read_text／run／which／glob／os.path／os.stat／套件、服務與 sysctl 查詢。

    sysctl：{key: (目前值, (開機值, 來源, [(檔案, 值)]))}
    """
    runner = runner or FakeRunner()
    dirs = set(dirs)
    stats = stats or {}
    listdir = listdir or {}
    svc = svc or {}
    sysctl = sysctl or {}

    def _glob(pat):
        return sorted(p for p in fs if fnmatch.fnmatch(p, pat))

    def _stat(p):
        if p not in stats:
            raise OSError(p)
        return stats[p]

    def _listdir(p):
        if p not in listdir:
            raise OSError(p)
        return list(listdir[p])

    patches = [
        (sysm, "read_text", fs_reader(fs)),
        (sysm, "run", runner),
        (sysm, "which", lambda n: "/usr/sbin/" + n if n in which else None),
        (sysm.glob, "glob", _glob),
        (sysm.os.path, "exists", lambda p: p in fs or p in dirs or p in exists),
        (sysm.os.path, "isdir", lambda p: p in dirs),
        (sysm.os.path, "isfile", lambda p: p in fs),
        (sysm.os.path, "realpath", lambda p: p),
        (sysm.os, "access", lambda p, m: p in fs),
        (sysm.os, "stat", _stat),
        (sysm.os, "lstat", _stat),
        (sysm.os, "listdir", _listdir),
        (sysm.pkgsvc, "pkg_installed", lambda osi, p: p in pkgs),
        (sysm.pkgsvc, "svc_state", lambda u: svc.get(u, ("disabled", "inactive"))),
        (sysm.pkgsvc, "sysctl_runtime", lambda k: sysctl[k][0] if k in sysctl else None),
        (sysm.pkgsvc, "sysctl_persistent", lambda k: sysctl[k][1] if k in sysctl else (None, None, [])),
    ]
    with contextlib.ExitStack() as st:
        for obj, name, val in patches:
            st.enter_context(mock.patch.object(obj, name, val))
        yield runner


def fx_for(fs, runner=None, dry_run=False, include_risky=True):
    ctx = FakeCtx("ubuntu2204", dry_run=dry_run, include_risky=include_risky)
    return FakeFx(ctx, fs=fs, runner=runner or FakeRunner())


def ctx():
    return FakeCtx("ubuntu2204")


def idx(events, ev):
    return events.index(ev)


SUDOERS_OK = "Defaults env_reset\n@includedir /etc/sudoers.d\n"


# sudoers 解析共用工具（0030–0032）
class SudoersParseTest(unittest.TestCase):
    def test_include_forms_and_depth_limit(self):
        fs = {"/etc/sudoers": "#include /etc/sudoers\n#include extra\nDefaults use_pty, 1bad\n",
              "/etc/extra": "Defaults logfile=/var/log/s.log\n"}
        with env(fs):
            out = sysm.sudoers_defaults()
        names = [(e[0], e[2]) for e in out]
        # 相對路徑以所在目錄解析；自我引入在深度上限後停止；「1bad」非合法參數略過
        self.assertIn(("/etc/extra", "logfile"), names)
        self.assertIn(("/etc/sudoers", "use_pty"), names)
        self.assertNotIn("1bad", [e[2] for e in out])
        # /etc/sudoers 讀到深度 8 為止，每層引入一次 extra（深度 9 的 extra 不再讀取）
        self.assertEqual(names.count(("/etc/extra", "logfile")), 8)

    def test_includedir_reads_real_and_extra_files(self):
        fs = {"/etc/sudoers": SUDOERS_OK, "/etc/sudoers.d/a": "Defaults use_pty\n", "/etc/sudoers.d/b.bak": "x"}
        with env(fs, dirs={"/etc/sudoers.d"}, listdir={"/etc/sudoers.d": ["a", "b.bak", "c~"]}):
            out = sysm.sudoers_defaults({"/etc/sudoers.d/99-gcb-0030": "Defaults !use_pty\n"})
        self.assertEqual([(e[0], e[3]) for e in out if e[2] == "use_pty"],
                         [("/etc/sudoers.d/99-gcb-0030", True), ("/etc/sudoers.d/a", False)])

    def test_visudo_problems_and_float(self):
        self.assertEqual(sysm.visudo_problems(res(1, "/etc/sudoers: parsed OK\nwarning: x\n")), ["warning: x"])
        self.assertEqual(sysm.visudo_problems(res(1)), ["visudo -c 失敗（rc=1）"])
        self.assertIsNone(sysm._to_float("abc"))


# TWGCB-01-014-0030 設定 sudo 指令使用 pty、0032 sudo 身分鑑別逾時時間
class SudoDefaultFixTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        real = tempfile.mkstemp
        p = mock.patch.object(sysm.tempfile, "mkstemp", lambda prefix: real(prefix=prefix, dir=self.tmp))
        p.start()
        self.addCleanup(p.stop)
        self.pty = sysm.SudoDefault("設定 sudo 指令使用 pty", U(30), "flag", "use_pty", "Defaults use_pty", "x")
        self.tmo = sysm.SudoDefault("sudo 身分鑑別逾時時間", U(32), "timeout", "timestamp_timeout",
                                    "Defaults timestamp_timeout=5", "x")
        self.path = "/etc/sudoers.d/99-gcb-0030"

    def _env(self, fs, runner, listing=()):
        return env(fs, runner, which={"visudo"}, dirs={"/etc/sudoers.d"}, listdir={"/etc/sudoers.d": list(listing)})

    def test_check_missing_sudoers(self):
        with env({}):
            self.assertEqual(self.pty.check(ctx()).status, ERROR)

    def test_guards(self):
        with env({}):
            self.assertRaises(ManualRequired, self.pty.fix, ctx(), fx_for({}))
        with self._env({"/etc/sudoers": "Defaults env_reset\n"}, FakeRunner()):
            self.assertRaises(ManualRequired, self.pty.fix, ctx(), fx_for({}))
        runner = FakeRunner({"visudo -c": res(1, ">>> /etc/sudoers: syntax error near line 3 <<<")})
        with self._env({"/etc/sudoers": SUDOERS_OK}, runner):
            self.assertRaises(ManualRequired, self.pty.fix, ctx(), fx_for({}))

    def test_overridden_by_later_file(self):
        fs = {"/etc/sudoers": SUDOERS_OK, "/etc/sudoers.d/zz": "Defaults !use_pty\n"}
        with self._env(fs, FakeRunner(), ["zz"]):
            with self.assertRaises(ManualRequired) as cm:
                self.pty.fix(ctx(), fx_for(fs))
        self.assertIn("!use_pty", str(cm.exception))

    def test_validates_temp_before_write_then_checks_all(self):
        fs = {"/etc/sudoers": SUDOERS_OK}
        fx = fx_for(fs)
        seen = []

        def cf(cmd):
            # 驗證時檔案尚未寫入，暫存檔內容即為要寫入的內容
            tmp = cmd.split()[-1]
            with open(tmp) as f:
                seen.append((f.read(), self.path in fs))
            return res(0)
        warn = res(1, "warning: unused alias X")
        runner = FakeRunner({"-cf": cf, "visudo -c": warn})
        fx.runner = FakeRunner({"visudo -c": warn})
        with self._env(fs, runner):
            self.pty.fix(fx.ctx, fx)
        self.assertEqual(seen, [("# TWGCB-01-014-0030 (gcb-checker)\nDefaults use_pty\n", False)])
        self.assertEqual(fs[self.path], seen[0][0])
        self.assertEqual(fx.modes[self.path], 0o440)
        self.assertLess(idx(fx.events, ("write", self.path)), idx(fx.events, ("run", "/usr/sbin/visudo -c")))
        self.assertIn("unused alias", fx.notes[0])  # 既有警告只提示
        self.assertEqual(os.listdir(self.tmp), [])  # 暫存檔已刪除

    def test_temp_validation_fails_no_write(self):
        fs = {"/etc/sudoers": SUDOERS_OK}
        fx = fx_for(fs)
        with self._env(fs, FakeRunner({"-cf": res(1, "syntax error")})):
            self.assertRaises(FixError, self.pty.fix, fx.ctx, fx)
        self.assertNotIn(self.path, fs)
        self.assertEqual(fx.events, [])

    def test_post_write_validation_fails(self):
        fs = {"/etc/sudoers": SUDOERS_OK}
        fx = fx_for(fs, FakeRunner({"visudo -c": res(1, "parse error in /etc/sudoers.d/99-gcb-0030")}))
        with self._env(fs, FakeRunner()):
            with self.assertRaises(FixError) as cm:
                self.pty.fix(fx.ctx, fx)
        self.assertIn("將還原", str(cm.exception))
        self.assertIn(("write", self.path), fx.events)

    def test_timeout_scoped_is_partial(self):
        fs = {"/etc/sudoers": SUDOERS_OK + "Defaults:bob timestamp_timeout=30\n"}
        fx = fx_for(fs)
        with self._env(fs, FakeRunner()):
            self.tmo.fix(fx.ctx, fx)
        self.assertTrue(fx.partial)
        self.assertIn("Defaults:bob timestamp_timeout=30", fx.notes[0])
        self.assertIn("timestamp_timeout=5", fs["/etc/sudoers.d/99-gcb-0032"])


# TWGCB-01-014-0033 AIDE 套件
class AidePackageTest(unittest.TestCase):
    rule = sysm.AidePackage(U(33))

    @contextlib.contextmanager
    def accounts(self, users=(), groups=()):
        def lookup(names):
            def f(n):
                if n not in names:
                    raise KeyError(n)
                return n
            return f
        with mock.patch.object(sysm.pwd, "getpwnam", lookup(users)), \
                mock.patch.object(sysm.grp, "getgrnam", lookup(groups)):
            yield

    def test_check_not_initialized(self):
        with env({}, pkgs={"aide", "aide-common"}):
            c = self.rule.check(ctx())
        self.assertIn("尚未初始化", c.current)

    def test_cleanup_only_new_leftovers(self):
        fx = fx_for({})
        with env({"/etc/aliases": ""}), self.accounts(users={"postfix"}, groups={"crontab", "ssl-cert"}):
            self.rule._register_cleanup(fx)
        cmd = fx.events[0][1]
        self.assertIn("groupdel postfix", cmd)
        self.assertIn("rm -f /etc/aliases.db", cmd)
        for kept in ("userdel postfix", "groupdel crontab", "/etc/aliases >"):
            self.assertNotIn(kept, cmd)

    def test_fix_installs_both_and_copies_db(self):
        fs = {"/usr/sbin/sendmail": "", sysm.AIDE_DB + ".new": ""}
        fx = fx_for(fs)
        with env(fs), self.accounts():
            self.rule.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(fx.kinds("pkg_install"), ["aide-common", "aide"])
        self.assertLess(idx(ev, ("undo", "rm -f %s %s.new" % (sysm.AIDE_DB, sysm.AIDE_DB))),
                        idx(ev, ("run", "aideinit -y -f")))
        self.assertIn(("run", "cp -p %s.new %s" % (sysm.AIDE_DB, sysm.AIDE_DB)), ev)
        # 已有 sendmail：不預設 postfix
        self.assertFalse([e for e in ev if "debconf" in e[1]])

    def test_fix_db_exists(self):
        fx = fx_for({})
        with env({sysm.AIDE_DB: ""}, pkgs={"aide", "aide-common"}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# TWGCB-01-014-0034 定期檢查檔案系統完整性
class AideScheduleTest(unittest.TestCase):
    rule = sysm.AideSchedule(U(34))

    def test_cron_fields_short(self):
        self.assertIsNone(sysm._cron_fields("0 5 * *", False))

    def test_schedules_sources(self):
        fs = {"/var/spool/cron/crontabs/root": "@daily /usr/bin/aide --check\n",
              "/etc/cron.d/aide": "0 5 * * * root aide --check\n",
              "/etc/cron.d/x.dpkg-old": "0 5 * * * root aide --check\n",
              "/etc/cron.daily/aide": "", "/etc/default/aide": "COMMAND=update\n"}
        runner = FakeRunner({"is-enabled dailyaidecheck.timer": res(0, "enabled\n")})
        with env(fs, runner, which={"systemctl"}):
            found = sysm.aide_schedules()
        self.assertEqual(found, ["root crontab", "/etc/cron.d/aide",
                                 "/etc/cron.daily/aide（aide-common 內附，COMMAND=update）", "dailyaidecheck.timer"])

    def test_check(self):
        with env({}, which={"aide"}):
            self.assertEqual(self.rule.check(ctx()).current, "未設定每日 AIDE 檢查排程")
        with env({"/etc/crontab": "0 5 * * * root aide --check\n"}, which={"aide"}):
            c = self.rule.check(ctx())
        self.assertIn("未安裝 cron", c.current)

    def test_fix(self):
        fs = {}
        fx = fx_for(fs)
        with env(fs, which={"aide"}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("pkg_install"), ["cron"])
        self.assertIn(self.rule.LINE, fs[self.rule.CRON])
        fx = fx_for({})
        with env({"/etc/crontab": "0 5 * * * root aide --check\n"}, which={"aide", "cron"}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


MOUNTS_EFI = "/dev/sda1 /boot/efi vfat rw,fmask=0022,dmask=0022,uid=0 0 0\n"
FSTAB_EFI = "UUID=1 /boot/efi vfat fmask=0177 0 1\n"


# TWGCB-01-014-0035 開機載入程式設定檔之所有權、0036 權限（含 UEFI /boot/efi）
class GrubCfgPermTest(unittest.TestCase):
    def _rule(self, kind):
        return sysm.GrubCfgPerm("x", U(35 if kind == "owner" else 36), kind)

    def test_efi_status(self):
        with env({}):
            self.assertIsNone(sysm.efi_status("mode"))
        with env({"/proc/self/mounts": "/dev/sda1 /boot ext4 rw 0 0\n"}, dirs={"/sys/firmware/efi"}):
            self.assertIsNone(sysm.efi_status("mode"))
        fs = {"/proc/self/mounts": MOUNTS_EFI, "/etc/fstab": FSTAB_EFI}
        with env(fs, dirs={"/sys/firmware/efi"}):
            # fstab 合格、目前掛載不合格（需重開機）
            self.assertEqual(sysm.efi_status("mode"), (True, False, "/boot/efi 掛載選項：fmask=0022"))
            self.assertEqual(sysm.efi_status("owner"), (True, True, "/boot/efi 掛載選項：uid=0"))
        fs = {"/proc/self/mounts": "/dev/sda1 /boot/efi vfat rw 0 0\n", "/etc/fstab": "x /boot/efi vfat fmask=zz 0 1\n"}
        with env(fs, dirs={"/sys/firmware/efi"}):
            self.assertEqual(sysm.efi_status("mode"), (False, False, "/boot/efi 掛載選項：預設"))
        with env({"/proc/self/mounts": MOUNTS_EFI}, dirs={"/sys/firmware/efi"}):
            self.assertEqual(sysm.efi_status("mode")[0], False)

    def test_check(self):
        r = self._rule("mode")
        with env({}), mock.patch.object(r.perm, "check", return_value=Check(FAIL, "權限 644")):
            self.assertIn(sysm.GRUB_NOTE, r.check(ctx()).current)
        with mock.patch.object(sysm, "efi_status", return_value=(True, False, "efi")), \
                mock.patch.object(r.perm, "check", return_value=Check(PASS, "ok")):
            c = r.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "ok；efi（fstab 已設定，需重開機生效）"))
        with mock.patch.object(sysm, "efi_status", return_value=(False, False, "efi")), \
                mock.patch.object(r.perm, "check", return_value=Check(PASS, "ok")):
            c = r.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "ok；efi（fstab 不符合）"))

    def test_bios_boot_with_efi_partition_note(self):
        # BIOS 開機但有 /boot/efi：GCB 的 UEFI 規定不適用，說明中註明
        r = self._rule("owner")
        with env({"/proc/self/mounts": MOUNTS_EFI}), mock.patch.object(r.perm, "check", return_value=Check(PASS, "ok")):
            c = r.check(ctx())
        self.assertEqual(c.status, PASS)
        self.assertEqual(c.current, "ok；本機為 BIOS 開機，/boot/efi 的 UEFI 規定（fmask=0177）不適用，改為 UEFI 開機後需重新檢測")

    def test_fix_without_risky_is_partial(self):
        r = self._rule("owner")
        fx = fx_for({}, include_risky=False)
        with mock.patch.object(sysm, "efi_status", return_value=(False, False, "")), mock.patch.object(r.perm, "fix"):
            r.fix(fx.ctx, fx)
        self.assertTrue(fx.partial)
        self.assertEqual(fx.events, [])

    def test_fix_edits_fstab(self):
        r = self._rule("mode")
        fs = {"/etc/fstab": "UUID=1 /boot/efi vfat defaults,umask=0077 0 1\n"}
        fx = fx_for(fs)
        with mock.patch.object(sysm, "efi_status", return_value=(False, False, "")), mock.patch.object(r.perm, "fix"):
            r.fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/fstab"], "UUID=1\t/boot/efi\tvfat\tumask=0077,fmask=0177\t0\t1\n")
        self.assertIn(("run", "findmnt --verify"), fx.events)
        self.assertEqual(fx.notes[0], sysm.GRUB_NOTE)

    def test_fix_fstab_verify_error(self):
        r = self._rule("owner")
        fs = {"/etc/fstab": FSTAB_EFI}
        fx = fx_for(fs, FakeRunner({"findmnt": res(1, "[E] error: bad option")}))
        with mock.patch.object(sysm, "efi_status", return_value=(False, False, "")), mock.patch.object(r.perm, "fix"):
            self.assertRaises(FixError, r.fix, fx.ctx, fx)

    def test_fix_efi_ok(self):
        r = self._rule("owner")
        fx = fx_for({})
        with mock.patch.object(sysm, "efi_status", return_value=None), mock.patch.object(r.perm, "fix") as pf:
            r.fix(fx.ctx, fx)
        pf.assert_called_once()
        self.assertEqual(fx.notes, [])


# TWGCB-01-014-0037 開機載入程式之通行碼（人工項目，只檢查）
class GrubPasswordTest(unittest.TestCase):
    rule = sysm.GrubPassword(U(37))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)
        cfg = 'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.AA.BB\n'
        with env({"/boot/grub/grub.cfg": cfg}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "superusers=admin、password_pbkdf2 帳號=admin"))
        with env({"/boot/grub/grub.cfg": "password_pbkdf2 other grub.pbkdf2.sha512.x\n"}):
            self.assertEqual(self.rule.check(ctx()).status, FAIL)
        self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))  # C 類維持人工


# TWGCB-01-014-0038 單一使用者模式身分鑑別
class SingleUserAuthTest(unittest.TestCase):
    rule = sysm.SingleUserAuth(U(38))

    def _cur(self, shadow, **extra):
        fs = {"/etc/shadow": shadow}
        fs.update(extra)
        with env(fs):
            return self.rule.check(ctx())

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)
        self.assertEqual(self._cur("a:x:1::::::\n").current, "/etc/shadow 無 root 帳號")
        self.assertIn("空白", self._cur("root::1::::::\n").current)
        c = self._cur("root:$y$h:1::::::\n",
                      **{"/etc/systemd/system/rescue.service.d/x.conf": "Environment=SYSTEMD_SULOGIN_FORCE=1\n"})
        self.assertIn("SYSTEMD_SULOGIN_FORCE", c.current)
        self.assertIn("鎖定", self._cur("root:!:1::::::\n").current)
        self.assertEqual(self._cur("root:$y$h:1::::::\n").status, PASS)


# TWGCB-01-014-0039 核心傾印功能
class CoreDumpTest(unittest.TestCase):
    rule = sysm.CoreDump(U(39))

    def test_check_apport_and_coredump(self):
        fs = {"/etc/security/limits.conf": "* hard core 0\n",
              "/usr/lib/systemd/coredump.conf.d/a.conf": "[Coredump]\nStorage=none\n",
              "/etc/systemd/coredump.conf.d/b.conf": "[Coredump]\nProcessSizeMax=0\n"}
        with env(fs, pkgs={"systemd-coredump"}, sysctl={"fs.suid_dumpable": ("2", ("2", None, []))},
                 svc={"apport.service": ("enabled", "active"), "systemd-coredump.socket": ("masked", "inactive")}):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("apport 執行中", c.current)
        self.assertIn("coredump Storage=none ProcessSizeMax=0 socket=masked", c.current)

    def test_fix(self):
        fs = {"/etc/security/limits.conf": "* hard core unlimited\n",
              "/etc/sysctl.d/10-x.conf": "fs.suid_dumpable = 2\n",
              "/usr/lib/sysctl.d/50-pkg.conf": "fs.suid_dumpable = 2\n"}
        where = [("/etc/sysctl.d/10-x.conf", "2"), ("/usr/lib/sysctl.d/50-pkg.conf", "2"),
                 (sysm.SYSCTL_OWN, "0"), ("/etc/sysctl.d/20-ok.conf", "0")]
        fx = fx_for(fs)
        with env(fs, pkgs={"systemd-coredump"}, sysctl={"fs.suid_dumpable": ("2", ("2", None, where))}):
            self.rule.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("undo", "systemctl daemon-reload"))
        self.assertTrue(fs["/etc/security/limits.conf"].startswith(sysm.te.MARK))
        self.assertIn("* hard core 0", fs[sysm.LIMITS_OWN])
        self.assertEqual(fs[sysm.COREDUMP_OWN], "[Coredump]\nStorage=none\nProcessSizeMax=0\n")
        self.assertIn(("mask", "systemd-coredump.socket"), ev)
        # /etc 檔案直接註解；套件檔以 /etc/sysctl.d 同名檔覆蓋
        self.assertNotIn("fs.suid_dumpable = 2", [l for l in fs["/etc/sysctl.d/10-x.conf"].splitlines()
                                                  if not l.startswith("#")])
        self.assertIn("/etc/sysctl.d/50-pkg.conf", fs)
        self.assertEqual(fs["/usr/lib/sysctl.d/50-pkg.conf"], "fs.suid_dumpable = 2\n")
        self.assertNotIn(("write", "/etc/sysctl.d/20-ok.conf"), ev)
        self.assertIn(("sysctl", "fs.suid_dumpable", "0"), ev)


# TWGCB-01-014-0040 記憶體位址空間配置隨機載入
class SysctlValueTest(unittest.TestCase):
    def test_missing_param_is_na(self):
        with env({}):
            c = sysm.SysctlValue("x", U(40), "kernel.randomize_va_space", "2").check(ctx())
        self.assertEqual(c.status, NA)


# TWGCB-01-014-0041 prelink 套件
class PrelinkTest(unittest.TestCase):
    def test_fix_undoes_prelink_first(self):
        rule = sysm._prelink
        fx = fx_for({})
        with env({}, which={"prelink"}), mock.patch.object(sysm.PackageAbsent, "fix") as base:
            rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("run", "prelink -ua")])
        base.assert_called_once()


MOUNTS = """/dev/sda1 / ext4 rw 0 0
/dev/sda1 /home ext4 rw 0 0
/dev/sdb1 /data xfs rw 0 0
/dev/sdc1 /gone xfs rw 0 0
proc /proc proc rw 0 0
"""


# TWGCB-01-014-0059 全域寫入權限之檔案、0060 擁有者、0061 擁有群組
class FsScanTest(unittest.TestCase):
    def setUp(self):
        sysm._scan_cache.clear()
        self.addCleanup(sysm._scan_cache.clear)

    def _env(self, runner):
        stats = {"/": _St(dev=1), "/home": _St(dev=1)}  # /data 無法 stat
        return env({"/proc/self/mounts": MOUNTS}, runner, dirs={"/", "/home", "/data"}, stats=stats)

    def test_scan_roots(self):
        with self._env(FakeRunner()):
            self.assertEqual(sysm.scan_roots(), ["/"])

    def test_errors(self):
        with env({}):
            self.assertEqual(sysm.fs_scan(), "找不到可掃描的本機檔案系統")
            self.assertEqual(sysm.FsScan("x", U(59), "ww", "", "").check(ctx()).status, ERROR)
        with self._env(FakeRunner({"find": res(124)})):
            self.assertIn("逾時", sysm.fs_scan())
        with self._env(FakeRunner({"find": res(127)})):
            self.assertEqual(sysm.fs_scan(), "找不到 find 指令")

    def test_parse_and_check(self):
        out = "W\t/tmp/a\0U\t1234\t/opt/x\0G\t999\t/opt/y\0junk\0"
        with self._env(FakeRunner({"find": res(0, out)})):
            ww = sysm.FsScan("x", U(59), "ww", "", "").check(ctx())
            nu = sysm.FsScan("x", U(60), "nouser", "", "").check(ctx())
            ng = sysm.FsScan("x", U(61), "nogroup", "", "").check(ctx())
        self.assertEqual(ww.current, "1 個：/tmp/a；掃描範圍：/")
        self.assertEqual(nu.current, "1 個：/opt/x（uid=1234）；掃描範圍：/")
        self.assertEqual(ng.current, "1 個：/opt/y（gid=999）；掃描範圍：/")
        sysm._scan_cache.clear()
        with self._env(FakeRunner({"find": res(0, "")})):
            self.assertEqual(sysm.FsScan("x", U(59), "ww", "", "").check(ctx()).status, PASS)


# TWGCB-01-014-0063 root 帳號之路徑變數
class RootPathTest(unittest.TestCase):
    rule = sysm.RootPath(U(63))

    def test_check(self):
        with env({}, FakeRunner({"su -": res(1, "", "su: Authentication failure")})):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, ERROR)
        self.assertIn("Authentication failure", c.current)
        with env({}, FakeRunner({"su -": res(0, "__GCB_PATH__/usr/bin:.:__GCB_PATH__")})):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "PATH=/usr/bin:.:；不合格：「.」、第 3 個為空元素"))


PASSWD = "root:x:0:0::/root:/bin/bash\n+nis\nshort:x\n"
GROUP = "root:x:0:\n-bad\nshadow:x:42:alice,bob\n"


# TWGCB-01-014-0064 UID=0 之帳號、0072–0077 帳號與群組資料庫
class AccountDbTest(unittest.TestCase):
    def test_check(self):
        rule = sysm.AccountDb("x", U(64), "", sysm.bad_uid0, "", "僅 root")
        with env({}):
            self.assertEqual(rule.check(ctx()).status, ERROR)
        fs = {"/etc/passwd": PASSWD + "toor:x:0:0::/root:/bin/bash\n", "/etc/group": GROUP}
        with env(fs):
            c = rule.check(ctx())
            self.assertEqual(len(sysm.parse_passwd()), 2)
            self.assertEqual([g["name"] for g in sysm.parse_group()], ["root", "shadow"])
        self.assertEqual((c.status, c.current), (FAIL, "toor（UID 0）"))


# TWGCB-01-014-0078 shadow 群組成員
class ShadowGroupTest(unittest.TestCase):
    rule = sysm.ShadowGroup(U(78))

    def test_no_shadow_group(self):
        self.assertEqual(sysm.shadow_group_problems([], [{"name": "x", "gid": "1", "members": []}]), ([], []))

    def test_check_and_fix(self):
        fs = {"/etc/passwd": PASSWD + "svc:x:900:42::/home/svc:/bin/sh\n", "/etc/group": GROUP}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "成員：alice,bob；主要群組為 shadow 的帳號：svc"))
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        ev = fx.events
        self.assertLess(idx(ev, ("backup", "/etc/gshadow")), idx(ev, ("run", "gpasswd -d alice shadow")))
        self.assertIn(("run", "gpasswd -d bob shadow"), ev)
        self.assertTrue(fx.partial)
        self.assertIn("svc", fx.notes[0])
        with env({"/etc/passwd": PASSWD, "/etc/group": "shadow:x:42:\n"}):
            self.assertEqual(self.rule.check(ctx()).status, PASS)


HOME_PASSWD = ("root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
               "bob:x:1001:1001::/home/bob:/bin/bash\nweird:x:abc:1::/home/w:/bin/bash\n"
               "svc:x:1002:1002::/var/lib/svc:/bin/bash\n")


# TWGCB-01-014-0065 使用者家目錄權限、0066 擁有者、0067 擁有群組、0068「.」檔案權限
class HomeDirsTest(unittest.TestCase):
    def _env(self, stats, listdir=None):
        fs = {"/etc/passwd": HOME_PASSWD, "/etc/login.defs": "UID_MIN abc\nUID_MAX x\n"}
        return env(fs, dirs={"/root", "/home/alice"}, stats=stats, listdir=listdir or {})

    def test_uid_range_invalid(self):
        with env({"/etc/login.defs": "UID_MIN abc\nUID_MAX x\n"}):
            self.assertEqual(sysm._uid_range(), (1000, 60000))

    def test_owner_and_group(self):
        stats = {"/root": _St(0o40700), "/home/alice": _St(0o40700, uid=5, gid=6)}
        with self._env(stats):
            o = sysm.HomeDirs("x", U(66), "owner", "", "C").check(ctx())
            g = sysm.HomeDirs("x", U(67), "group", "", "C").check(ctx())
        self.assertIn("/home/alice 擁有者 uid=5（應為 alice 1000）", o.current)
        self.assertIn("帳號 bob 的家目錄不存在", o.current)
        self.assertIn("略過：svc（/var/lib/svc 為系統或共用目錄）", o.current)
        self.assertNotIn("weird", o.current)
        self.assertIn("/home/alice 群組 gid=6（應為 1000）", g.current)

    def test_dotfiles_fix(self):
        stats = {"/root": _St(0o40700), "/home/alice": _St(0o40700, uid=1000, gid=1000),
                 "/home/alice/.bashrc": _St(0o100666), "/home/alice/.ok": _St(0o100600),
                 "/home/alice/.dir": _St(0o40777)}
        listdir = {"/home/alice": ["..", ".bashrc", ".ok", ".dir", "plain"]}  # /root 無法列出
        rule = sysm.HomeDirs("x", U(68), "dotfiles", "", "B")
        fx = fx_for({})
        with self._env(stats, listdir):
            rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("chmod"), ["/home/alice/.bashrc"])
        self.assertIn(("chmod", "/home/alice/.bashrc", 0o644), fx.events)
        # 家目錄不存在無法自動處理
        self.assertTrue(fx.partial)
        self.assertIn("帳號 bob 的家目錄不存在", fx.notes[0])
        self.assertIn("請通知使用者", fx.notes[-1])


# TWGCB-01-014-0030 設定 sudo 指令使用 pty（檢查）
class SudoDefaultCheckTest(unittest.TestCase):
    def test_check(self):
        rule = sysm.SudoDefault("x", U(30), "flag", "use_pty", "Defaults use_pty", "x")
        with env({"/etc/sudoers": "Defaults use_pty\n"}):
            c = rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "use_pty（/etc/sudoers）"))
        with env({"/etc/sudoers": "Defaults !use_pty\n"}):
            self.assertEqual(rule.check(ctx()).status, FAIL)


# TWGCB-01-014-0033 AIDE 套件（檢查與無郵件程式時安裝）
class AidePackageMoreTest(unittest.TestCase):
    rule = sysm.AidePackage(U(33))

    def test_check(self):
        with env({}, pkgs={"aide"}):
            self.assertEqual(self.rule.check(ctx()).current, "未安裝 aide-common")
        with env({sysm.AIDE_DB: ""}, pkgs={"aide", "aide-common"}):
            self.assertEqual(self.rule.check(ctx()).status, PASS)

    def test_fix_presets_postfix_local_only(self):
        fx = fx_for({})
        with env({}, pkgs={"aide"}), mock.patch.object(self.rule, "_register_cleanup") as cleanup:
            self.rule.fix(fx.ctx, fx)
        cleanup.assert_called_once()
        ev = fx.events
        self.assertLess(idx(ev, ("run", "echo 'postfix postfix/main_mailer_type select Local only' | "
                                        "debconf-set-selections")), idx(ev, ("pkg_install", "aide-common")))
        self.assertEqual(fx.kinds("pkg_install"), ["aide-common"])  # aide 已安裝
        self.assertIn("postfix", fx.notes[0])
        # aideinit 後資料庫與 .new 都不存在：不複製
        self.assertNotIn("cp", " ".join(fx.kinds("run")))


# TWGCB-01-014-0034 定期檢查檔案系統完整性（基本路徑）
class AideScheduleMoreTest(unittest.TestCase):
    rule = sysm.AideSchedule(U(34))

    def test_check_and_fix_without_aide(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).current, "未安裝 AIDE")
            self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))
        with env({"/etc/crontab": "0 5 * * * root aide --check\n"}, which={"aide", "crond"}):
            self.assertEqual(self.rule.check(ctx()).current, "已設定：/etc/crontab")


# TWGCB-01-014-0035／0037 適用條件（未使用 GRUB）
class GrubWhenTest(unittest.TestCase):
    def test_when(self):
        rules = [sysm.GrubCfgPerm("x", U(35), "owner"), sysm.GrubPassword(U(37))]
        with env({}):
            for r in rules:
                self.assertIn("未使用 GRUB", r.when(ctx()))
        with env({"/boot/grub/grub.cfg": ""}):
            for r in rules:
                self.assertIsNone(r.when(ctx()))


# TWGCB-01-014-0040 記憶體位址空間配置隨機載入
class SysctlValueMoreTest(unittest.TestCase):
    rule = sysm.SysctlValue("x", U(40), "kernel.randomize_va_space", "2")

    def test_check_and_fix(self):
        sc = {"kernel.randomize_va_space": ("2", ("2", "/etc/sysctl.d/10-x.conf", [("/etc/sysctl.d/10-x.conf", "2")]))}
        with env({}, sysctl=sc):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current),
                         (PASS, "kernel.randomize_va_space 目前=2 開機=2（/etc/sysctl.d/10-x.conf）"))
        fs = {}
        fx = fx_for(fs)
        sc = {"kernel.randomize_va_space": ("0", (None, None, []))}
        with env(fs, sysctl=sc):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(sysm.te.get_kv(fs[sysm.SYSCTL_OWN], "kernel.randomize_va_space"), "2")
        self.assertEqual(fx.events[-1], ("sysctl", "kernel.randomize_va_space", "2"))


# TWGCB-01-014-0059 檔案系統掃描範圍（排除虛擬與網路檔案系統）
class ScanRootsMoreTest(unittest.TestCase):
    def test_skip_non_local(self):
        mounts = "/dev/sda1 / ext4 rw 0 0\nsrv:/x /mnt/nfs nfs4 rw 0 0\n/dev/sdb1 /data xfs rw 0 0\n"
        with env({"/proc/self/mounts": mounts}, dirs={"/", "/data", "/mnt/nfs"},
                 stats={"/": _St(dev=1), "/data": _St(dev=2), "/mnt/nfs": _St(dev=3)}):
            self.assertEqual(sysm.scan_roots(), ["/", "/data"])


# TWGCB-01-014-0063 root 帳號之路徑變數、0064 UID=0 之帳號（合格）
class AccountPassTest(unittest.TestCase):
    def test_root_path_pass(self):
        with env({}, FakeRunner({"su -": res(0, "__GCB_PATH__/usr/sbin:/usr/bin__GCB_PATH__")})):
            c = sysm.RootPath(U(63)).check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "PATH=/usr/sbin:/usr/bin"))

    def test_account_db_pass(self):
        rule = sysm.AccountDb("x", U(64), "", sysm.bad_uid0, "", "僅 root 帳號之 UID 為 0")
        with env({"/etc/passwd": "root:x:0:0::/root:/bin/bash\n", "/etc/group": "root:x:0:\n"}):
            self.assertEqual(rule.check(ctx()).current, "僅 root 帳號之 UID 為 0")


# TWGCB-01-014-0065 使用者家目錄權限
class HomeModeTest(unittest.TestCase):
    def test_mode_fix(self):
        fs = {"/etc/passwd": "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"}
        stats = {"/root": _St(0o40700), "/home/alice": _St(0o42755, uid=1000, gid=1000)}
        rule = sysm.HomeDirs("x", U(65), "mode", "700", "B")
        with env(fs, dirs={"/root", "/home/alice"}, stats=stats):
            c = rule.check(ctx())
            fx = fx_for({})
            rule.fix(fx.ctx, fx)
        self.assertEqual((c.status, c.current), (FAIL, "/home/alice 權限 755"))
        # 保留 setgid 等特殊位元，只移除群組與其他人權限
        self.assertEqual(fx.events, [("chmod", "/home/alice", 0o2700)])
        self.assertFalse(fx.partial)


if __name__ == "__main__":
    unittest.main()
